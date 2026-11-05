// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	secret_model "forgejo.org/models/secret"
	actions_module "forgejo.org/modules/actions"
	"forgejo.org/modules/container"
	"forgejo.org/modules/log"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"code.forgejo.org/forgejo/runner/v13/act/jobparser"
	"go.yaml.in/yaml/v3"
	"xorm.io/builder"
)

// maxDueDeploymentRuns is how many runs one tick of the wait timer task looks at.
const maxDueDeploymentRuns = 100

// errEnvironmentNotReleased is what a job gets when no released deployment of an existing environment stands behind it, for
// example because the environment was deleted after its release: such a job fails, it is never retried.
var errEnvironmentNotReleased = errors.New("the environment of the job did not release it")

// blockedJobEnvironment returns the `environment:` of the job as stored in its payload, nil if it has none.
func blockedJobEnvironment(job *actions_model.ActionRunJob) (*actions_module.JobEnvironment, error) {
	sw, err := job.DecodeWorkflowPayload()
	if err != nil {
		return nil, err
	}
	return actions_module.GetJobEnvironment(sw)
}

// jobHasEnvironment tells if the job names an environment, so that it only starts after the environment gate.
func jobHasEnvironment(job *actions_model.ActionRunJob) (bool, error) {
	env, err := blockedJobEnvironment(job)
	return env != nil, err
}

// evaluateEnvironmentText evaluates an expression in the name or url of an environment of job with the contexts GitHub
// allows there (github, needs, strategy, matrix, vars, inputs). jobparser interpolates the name of a job with them, so
// the text is parsed as the name of the job's own payload, which holds its matrix and, for a job of a reusable workflow,
// the inputs of the call.
func evaluateEnvironmentText(ctx context.Context, job *actions_model.ActionRunJob, vars map[string]string, raw string) (string, error) {
	if !strings.Contains(raw, "${{") {
		return raw, nil
	}
	sw := new(jobparser.SingleWorkflow) // not job.DecodeWorkflowPayload: SetJob would change the cached copy
	if err := yaml.Unmarshal(job.WorkflowPayload, sw); err != nil {
		return "", err
	}
	id, j := sw.Job()
	j.Name = raw
	if err := sw.SetJob(id, j); err != nil {
		return "", err
	}
	payload, err := sw.Marshal()
	if err != nil {
		return "", err
	}
	jobs, err := actions_model.GetRunJobsByRunID(ctx, job.RunID)
	if err != nil {
		return "", err
	}
	needs, outputs, results, err := jobNeedsContext(ctx, job, jobs)
	if err != nil {
		return "", err
	}
	parsed, err := jobparser.Parse(payload, false,
		jobparser.WithJobOutputs(outputs),
		jobparser.WithJobResults(results),
		jobparser.WithWorkflowNeeds(needs),
		jobparser.WithVars(vars),
		jobparser.WithInputs(getRunInputs(job.Run)),
		jobparser.WithGitContext(generateGiteaContextForRun(job.Run)),
		jobparser.EnableNamespaces(),
	)
	if err != nil {
		return "", err
	} else if len(parsed) != 1 {
		return "", errors.New("the environment of the job could not be evaluated")
	}
	_, j = parsed[0].Job()
	return j.Name, nil
}

// findOrCreateEnvironment is GetOrCreateRepoEnvironment, except for a fork pull request (not pull_request_target): its
// author may be no writer of the repository and its job gets no environment secrets anyway, so it can only name an
// environment that exists.
func findOrCreateEnvironment(ctx context.Context, run *actions_model.ActionRun, name string) (*actions_model.ActionEnvironment, error) {
	if isForkRun(run) {
		return actions_model.GetRepoEnvironmentByName(ctx, run.RepoID, name)
	}
	return actions_model.GetOrCreateRepoEnvironment(ctx, run.RepoID, name)
}

// isForkRun tells if the run is of a fork pull request that gets no secrets: not pull_request_target.
func isForkRun(run *actions_model.ActionRun) bool {
	return run.IsForkPullRequest && run.TriggerEvent != actions_module.GithubEventPullRequestTarget
}

// refAllowed tells if the environment accepts a deployment of the run's ref. The ref is the one the server set on the
// run, never a value of the workflow.
func refAllowed(ctx context.Context, repoID int64, env *actions_model.ActionEnvironment, ref string) (bool, error) {
	if env.RefPolicy != actions_model.EnvironmentRefProtectedBranches {
		return env.AllowsRef(ref), nil
	}
	kind, name := actions_model.EnvironmentRefKind(ref)
	if kind != actions_model.EnvironmentPatternBranch {
		return false, nil
	}
	rules, err := git_model.GetMatchedProtectedBranchRules(ctx, repoID, name)
	return len(rules) > 0, err
}

// gateEnvironment is the one place that lets a job with an environment through, called when the job would run. It
// finds or creates the environment, records the deployment of this attempt of the job and decides: the ref policy
// refuses the job (it fails), the wait timer holds it (it stays blocked and a later pass looks again), otherwise the
// deployment is released and the runner labels of the environment are added to the labels the job runs on. Another
// condition, such as required reviewers, goes between the ref policy and the timer.
func gateEnvironment(ctx context.Context, job *actions_model.ActionRunJob) (behaviour, error) {
	jobEnv, err := blockedJobEnvironment(job)
	if err != nil {
		return behaviourError, fmt.Errorf("job environment: %w", err)
	} else if jobEnv == nil {
		return behaviourExecuteJob, nil
	}
	if err := job.LoadRun(ctx); err != nil {
		return behaviourError, err
	}
	run := job.Run
	if err := run.LoadRepo(ctx); err != nil {
		return behaviourError, err
	}
	if audit_model.ActorFromContext(ctx) == nil { // the emitter's queue has no request
		ctx = audit_model.WithSystem(ctx, "actions")
	}

	d, err := actions_model.GetDeployment(ctx, job.ID, job.Attempt)
	if err != nil {
		return behaviourError, err
	}
	isNew := d == nil
	var env *actions_model.ActionEnvironment
	reason := ""
	if isNew {
		ref, _ := util.SplitStringAtByteN(run.Ref, 255)
		d = &actions_model.ActionDeployment{
			RepoID: job.RepoID, RunID: job.RunID, JobID: job.ID, Attempt: job.Attempt,
			Ref: ref, CommitSHA: run.CommitSHA, TriggerUserID: run.TriggerUserID,
		}
		vars, err := actions_model.GetVariablesOfRun(ctx, run)
		if err != nil {
			return behaviourError, err
		}
		name, err := evaluateEnvironmentText(ctx, job, vars, jobEnv.Name)
		if jobEnv.Unsupported {
			reason = actions_model.DeploymentReasonUnsupported
		} else if name = strings.Trim(name, " "); err != nil || name == "" {
			reason = actions_model.DeploymentReasonInvalidName
		} else if env, err = findOrCreateEnvironment(ctx, run, name); errors.Is(err, actions_model.ErrEnvironmentNotFound) && isForkRun(run) {
			reason = actions_model.DeploymentReasonNotFound
		} else if errors.Is(err, actions_model.ErrEnvironmentLimit) {
			reason = actions_model.DeploymentReasonEnvironmentLimit
		} else if errors.Is(err, util.ErrInvalidArgument) {
			reason = actions_model.DeploymentReasonInvalidName
		} else if err != nil {
			return behaviourError, err
		}
		if env != nil {
			d.EnvironmentID = env.ID
			if url, err := evaluateEnvironmentText(ctx, job, vars, jobEnv.URL); err == nil {
				d.URL = actions_model.DeploymentURL(url)
			}
		}
	} else {
		switch d.Status {
		case actions_model.DeploymentRefused:
			return behaviourFailJob, nil
		case actions_model.DeploymentCancelled:
			return behaviourHoldJob, nil
		}
		if env, err = actions_model.GetRepoEnvironmentByID(ctx, d.RepoID, d.EnvironmentID); errors.Is(err, actions_model.ErrEnvironmentNotFound) {
			reason = actions_model.DeploymentReasonEnvironmentDeleted
		} else if err != nil {
			return behaviourError, err
		}
	}

	if reason == "" {
		// the rules of the environment apply to a waiting job as they are now
		if ok, err := refAllowed(ctx, job.RepoID, env, run.Ref); err != nil {
			return behaviourError, err
		} else if !ok {
			reason = actions_model.DeploymentReasonRefNotAllowed
		}
	}

	prior := d.Status
	now := timeutil.TimeStampNow()
	switch {
	case reason != "":
		d.Status, d.Reason = actions_model.DeploymentRefused, reason
	case prior == 0 && env.WaitTimerMinutes > 0:
		d.Status, d.ReleaseAfterUnix = actions_model.DeploymentWaitingTimer, now+timeutil.TimeStamp(env.WaitTimerMinutes)*60
	case prior == actions_model.DeploymentWaitingTimer && now < d.ReleaseAfterUnix:
	default:
		d.Status = actions_model.DeploymentReleased
	}
	if err := saveDeployment(ctx, d, isNew, prior); err != nil {
		return behaviourError, err
	}

	switch d.Status {
	case actions_model.DeploymentRefused:
		if err := recordDeploymentRefused(ctx, run, d, env); err != nil {
			return behaviourError, err
		}
		return behaviourFailJob, nil
	case actions_model.DeploymentWaitingTimer:
		return behaviourHoldJob, nil
	}
	// A job that runs on no label stays so: the labels of the environment only narrow the runners that can take it.
	if len(job.RunsOn) > 0 {
		for _, label := range env.RunnerLabels {
			if !slices.Contains(job.RunsOn, label) {
				job.RunsOn = append(job.RunsOn, label)
			}
		}
	}
	return behaviourExecuteJob, nil
}

// saveDeployment inserts a new deployment, or moves an existing one from prior to its status; a deployment that
// another server moved meanwhile is an error, so that the pass of the emitter is repeated.
func saveDeployment(ctx context.Context, d *actions_model.ActionDeployment, isNew bool, prior actions_model.DeploymentStatus) error {
	if isNew {
		return db.Insert(ctx, d)
	}
	if d.Status == prior {
		return nil
	}
	if moved, err := actions_model.SetDeploymentStatus(ctx, d, prior); err != nil {
		return err
	} else if !moved {
		return fmt.Errorf("deployment %d was changed by another request", d.ID)
	}
	return nil
}

// recordDeploymentRefused records the refusal; like every change of an environment, it fails the pass if it can't be
// written, so that a refusal is never unrecorded.
func recordDeploymentRefused(ctx context.Context, run *actions_model.ActionRun, d *actions_model.ActionDeployment, env *actions_model.ActionEnvironment) error {
	name := ""
	if env != nil {
		name = env.Name
	}
	return audit_model.Record(ctx, audit_model.Event{
		Action: "repo.actions_deployment.refused", Result: audit_model.ResultRefused,
		OwnerID: run.Repo.OwnerID, GroupID: run.Repo.GroupID, RepoID: run.RepoID,
		TargetType: "actions_deployment", TargetID: d.ID, TargetName: name,
		Data: map[string]any{"reason": d.Reason, "environment_id": d.EnvironmentID, "ref": run.Ref, "run_id": d.RunID, "job_id": d.JobID},
	})
}

// jobOfTask is the task's job at the attempt the task runs: the deployment that released it is read for that attempt,
// whatever the job row says by then.
func jobOfTask(task *actions_model.ActionTask) *actions_model.ActionRunJob {
	job := *task.Job
	job.Attempt = task.Attempt
	return &job
}

// releasedEnvironment returns the environment that released this attempt of the job. Without a released deployment of
// an environment that still exists in the job's repository there is none: a job that names an environment never runs
// without its gate.
func releasedEnvironment(ctx context.Context, job *actions_model.ActionRunJob) (*actions_model.ActionEnvironment, error) {
	d, err := actions_model.GetDeployment(ctx, job.ID, job.Attempt)
	if err != nil {
		return nil, err
	}
	if d == nil || d.Status != actions_model.DeploymentReleased || d.RepoID != job.RepoID {
		return nil, errEnvironmentNotReleased
	}
	env, err := actions_model.GetRepoEnvironmentByID(ctx, job.RepoID, d.EnvironmentID)
	if errors.Is(err, actions_model.ErrEnvironmentNotFound) {
		return nil, errEnvironmentNotReleased
	}
	return env, err
}

// getEnvironmentSecrets returns the secrets of the environment that released the job; it fails if none did.
func getEnvironmentSecrets(ctx context.Context, job *actions_model.ActionRunJob) (map[string]string, error) {
	env, err := releasedEnvironment(ctx, job)
	if err != nil {
		return nil, err
	}
	secrets, err := secret_model.FetchEnvironmentSecrets(ctx, env.RepoID, env.ID)
	if err != nil {
		// no details, as for the other secrets: FetchEnvironmentSecrets logs them. Not errEnvironmentNotReleased: a
		// failure of the database or of decryption fails the request and the job stays queued.
		return nil, errors.New("failure to fetch environment secrets")
	}
	return secrets, nil
}

// getVariablesOfJob returns the variables of the job's run with those of the job's environment on top. As for secrets,
// a job of a fork pull request gets no environment variables, except for pull_request_target.
func getVariablesOfJob(ctx context.Context, job *actions_model.ActionRunJob) (map[string]string, error) {
	if err := job.LoadRun(ctx); err != nil {
		return nil, err
	}
	vars, err := actions_model.GetVariablesOfRun(ctx, job.Run)
	if err != nil || job.EnvironmentName == "" {
		return vars, err
	}
	env, err := releasedEnvironment(ctx, job)
	if err != nil {
		return nil, err
	}
	if job.Run.IsForkPullRequest && job.Run.TriggerEvent != actions_module.GithubEventPullRequestTarget {
		return vars, nil
	}
	envVars, err := actions_model.FindVariables(ctx, actions_model.FindVariablesOpts{RepoID: env.RepoID, EnvironmentID: env.ID})
	if err != nil {
		return nil, fmt.Errorf("failure to fetch environment variables: %w", err)
	}
	for _, v := range envVars {
		vars[v.Name] = v.Data
	}
	return vars, nil
}

// StartDueDeployments runs the emitter for the runs with a job whose wait timer ended, which releases the job. It
// holds nothing between runs: the gate moves a deployment with a conditional update, so two servers can run it.
func StartDueDeployments(ctx context.Context) error {
	runIDs, err := actions_model.FindDueDeploymentRunIDs(ctx, timeutil.TimeStampNow(), maxDueDeploymentRuns)
	if err != nil {
		return err
	}
	for _, runID := range runIDs {
		if err := EmitJobsIfReady(runID); err != nil {
			log.Error("EmitJobsIfReady for run %d after a wait timer: %v", runID, err)
		}
	}
	return nil
}

// jobFailure is a job that failed at the gate after it was loaded, with the status it had.
type jobFailure struct {
	job   *actions_model.ActionRunJob
	prior actions_model.Status
}

// failUnpickedJob fails a job that no runner took, because its environment is gone: the job fails and the deployment
// of this attempt, if it still waits or was released, is refused as environment_deleted. It does so in the caller's
// transaction and reports false if another server moved the job first. Notifications go with notifyFailedJobs after
// the commit.
func failUnpickedJob(ctx context.Context, job *actions_model.ActionRunJob, env *actions_model.ActionEnvironment) (*jobFailure, error) {
	prior := job.Status
	job.Status, job.Stopped = actions_model.StatusFailure, timeutil.TimeStampNow()
	cond := builder.And(builder.In("status", actions_model.StatusBlocked, actions_model.StatusWaiting), builder.Eq{"task_id": 0})
	if n, err := actions_model.UpdateRunJobWithoutNotification(ctx, job, cond, "status", "stopped"); err != nil || n != 1 {
		return nil, err
	}
	d, err := actions_model.GetDeployment(ctx, job.ID, job.Attempt)
	if err != nil || d == nil || (d.Status != actions_model.DeploymentReleased && !d.Status.IsWaiting()) {
		return &jobFailure{job, prior}, err
	}
	if err := job.LoadRun(ctx); err != nil {
		return nil, err
	}
	if err := job.Run.LoadRepo(ctx); err != nil {
		return nil, err
	}
	from := d.Status
	d.Status, d.Reason = actions_model.DeploymentRefused, actions_model.DeploymentReasonEnvironmentDeleted
	if moved, err := actions_model.SetDeploymentStatus(ctx, d, from); err != nil || !moved {
		return nil, errors.Join(err, errors.New("deployment changed by another request"))
	}
	return &jobFailure{job, prior}, recordDeploymentRefused(ctx, job.Run, d, env)
}

// notifyFailedJobs sends what the failed jobs call for, once their transaction is committed: the notifications, the
// commit statuses and the run of each, and a pass of the emitter for the jobs that needed them.
func notifyFailedJobs(ctx context.Context, failures []*jobFailure) {
	var jobs []*actions_model.ActionRunJob
	runs := container.Set[int64]{}
	for _, f := range failures {
		jobs = append(jobs, f.job)
		runs.Add(f.job.RunID)
		if err := PropagateJobStatus(ctx, f.job.ID, f.prior); err != nil {
			log.Error("PropagateJobStatus for job %d: %v", f.job.ID, err)
		}
	}
	CreateCommitStatus(ctx, jobs...)
	for runID := range runs {
		if err := RefreshAndPropagateRunStatus(ctx, runID); err != nil {
			log.Error("RefreshAndPropagateRunStatus for run %d: %v", runID, err)
		}
		if err := EmitJobsIfReady(runID); err != nil {
			log.Error("EmitJobsIfReady for run %d: %v", runID, err)
		}
	}
}

// DeleteEnvironment deletes the environment (see actions_model.DeleteEnvironment) and, in the same transaction, fails
// the jobs of it that no runner took yet, whether their deployment waits or was released: the environment can't
// release them any more, and a job never runs without its gate.
func DeleteEnvironment(ctx context.Context, e *actions_model.ActionEnvironment) error {
	var failures []*jobFailure
	if err := actions_model.DeleteEnvironment(ctx, e, func(ctx context.Context) error {
		failures = failures[:0]
		jobs, err := actions_model.FindUnpickedEnvironmentJobs(ctx, e.RepoID, e.ID)
		if err != nil {
			return err
		}
		for _, job := range jobs {
			if f, err := failUnpickedJob(ctx, job, e); err != nil {
				return err
			} else if f != nil {
				failures = append(failures, f)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	notifyFailedJobs(ctx, failures)
	return nil
}
