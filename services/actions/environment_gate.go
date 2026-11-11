// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	secret_model "forgejo.org/models/secret"
	user_model "forgejo.org/models/user"
	actions_module "forgejo.org/modules/actions"
	"forgejo.org/modules/cache"
	"forgejo.org/modules/container"
	"forgejo.org/modules/log"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"code.forgejo.org/forgejo/runner/v13/act/jobparser"
	"go.yaml.in/yaml/v3"
	"xorm.io/builder"
)

// maxDueDeploymentRuns is how many runs one tick of the wait timer task looks at.
var maxDueDeploymentRuns = 100

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

// errInvalidEnvironmentText marks a text of the workflow that can't be evaluated. Any other error of
// evaluateEnvironmentText (the database, the stored payload) is transient: the pass of the emitter is repeated.
var errInvalidEnvironmentText = errors.New("the environment text could not be evaluated")

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
		return "", fmt.Errorf("%w: %w", errInvalidEnvironmentText, err)
	} else if len(parsed) != 1 {
		return "", fmt.Errorf("%w: the text gave %d jobs", errInvalidEnvironmentText, len(parsed))
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

// resolveNewEnvironment evaluates the name of the environment of a job that has no deployment yet and finds or creates
// it, and sets the environment and URL of d. A refusal is a reason; only an error of the database or of the stored
// payload is an error (the pass is repeated), never an invalid name.
func resolveNewEnvironment(ctx context.Context, job *actions_model.ActionRunJob, jobEnv *actions_module.JobEnvironment, d *actions_model.ActionDeployment) (env *actions_model.ActionEnvironment, reason string, err error) {
	run := job.Run
	vars, err := actions_model.GetVariablesOfRun(ctx, run)
	if err != nil {
		return nil, "", err
	}
	if jobEnv.Unsupported {
		return env, actions_model.DeploymentReasonUnsupported, nil
	}
	name, err := evaluateEnvironmentText(ctx, job, vars, jobEnv.Name)
	if errors.Is(err, errInvalidEnvironmentText) {
		return env, actions_model.DeploymentReasonInvalidName, nil
	} else if err != nil {
		return nil, "", err
	}
	if name = strings.Trim(name, " "); name == "" {
		return env, actions_model.DeploymentReasonInvalidName, nil
	}
	env, err = findOrCreateEnvironment(ctx, run, name)
	switch {
	case errors.Is(err, actions_model.ErrEnvironmentNotFound) && isForkRun(run):
		return env, actions_model.DeploymentReasonNotFound, nil
	case errors.Is(err, actions_model.ErrEnvironmentLimit):
		return env, actions_model.DeploymentReasonEnvironmentLimit, nil
	case errors.Is(err, util.ErrInvalidArgument):
		return env, actions_model.DeploymentReasonInvalidName, nil
	case err != nil:
		return nil, "", err
	}
	d.EnvironmentID = env.ID
	if url, err := evaluateEnvironmentText(ctx, job, vars, jobEnv.URL); err == nil {
		d.URL = actions_model.DeploymentURL(url)
	}
	return env, "", nil
}

// triggerUser is the user who started this attempt of the job: whoever reran it, else the run's trigger user.
func triggerUser(job *actions_model.ActionRunJob, run *actions_model.ActionRun) int64 {
	if job.AttemptTriggerUserID != 0 {
		return job.AttemptTriggerUserID
	}
	return run.TriggerUserID
}

// refusalReason returns why the environment's rules refuse the run, "" if they don't.
func refusalReason(ctx context.Context, run *actions_model.ActionRun, env *actions_model.ActionEnvironment) (string, error) {
	if ok, err := refAllowed(ctx, run.RepoID, env, run.Ref); err != nil {
		return "", err
	} else if !ok {
		return actions_model.DeploymentReasonRefNotAllowed, nil
	}
	if !env.AllowsWorkflow(run.WorkflowID) {
		// run.WorkflowID is the file of the run, so a job of a reusable workflow is decided by the file that called
		// it, never by the called one (a workflow author can't pick the called file's name to pass)
		return actions_model.DeploymentReasonWorkflowNotAllowed, nil
	}
	return "", nil
}

// nextDeploymentStatus sets the status of d after this pass, from the one it has (0 for a new deployment). The rules of
// the environment are those it has now, so reviewers added while a job waits for its timer hold it for an approval, and
// reviewers removed by an edit release a job that waits for one (editing the rules is the break-glass). A review that
// waited longer than the timeout expires here, whether or not the expiry task ran.
func nextDeploymentStatus(d *actions_model.ActionDeployment, env *actions_model.ActionEnvironment, reason string, now timeutil.TimeStamp) {
	if reason != "" { // env may be nil
		d.Status, d.Reason = actions_model.DeploymentRefused, reason
		return
	}
	timer := now + timeutil.TimeStamp(env.WaitTimerMinutes)*60
	if d.Status.IsWaiting() {
		d.ReleaseAfterUnix = waitingRelease(d, env)
	}
	timerRuns := d.ReleaseAfterUnix > now
	switch prior := d.Status; {
	case prior == 0 && env.ReviewsRequired:
		// the review and the wait timer run in parallel: the job needs an approval and the timer due
		d.Status = actions_model.DeploymentWaitingReview
		if env.WaitTimerMinutes > 0 {
			d.ReleaseAfterUnix = timer
		}
	case prior == actions_model.DeploymentWaitingReview && env.ReviewsRequired && d.Created != 0 && d.Created <= ReviewCutoff():
		d.Status = actions_model.DeploymentExpired
	case prior == actions_model.DeploymentWaitingTimer && d.ReviewedBy == 0 && env.ReviewsRequired:
		d.Status = actions_model.DeploymentWaitingReview // the timer keeps running next to the review
	case prior == actions_model.DeploymentWaitingReview && env.ReviewsRequired: // only ReviewDeployments or the expiry moves it
	case prior == actions_model.DeploymentWaitingReview && timerRuns:
		d.Status = actions_model.DeploymentWaitingTimer // no reviewer is required any more
	case prior == 0 && env.WaitTimerMinutes > 0:
		d.Status, d.ReleaseAfterUnix = actions_model.DeploymentWaitingTimer, timer
	case prior == actions_model.DeploymentWaitingTimer && timerRuns:
	default:
		d.Status = actions_model.DeploymentReleased
	}
}

// waitingRelease is the release time of a waiting deployment: always its ready time plus the environment's current
// timer, recomputed on every pass, so raising the timer holds the job and lowering or removing it releases it at once
// (editing the rules is the break-glass). The stored value is only this result; 0 means no timer.
func waitingRelease(d *actions_model.ActionDeployment, env *actions_model.ActionEnvironment) timeutil.TimeStamp {
	if env.WaitTimerMinutes <= 0 {
		return 0
	}
	return d.Created + timeutil.TimeStamp(env.WaitTimerMinutes)*60
}

// gateEnvironment is the one place that lets a job with an environment through, called when the job would run. It
// finds or creates the environment, records the deployment of this attempt of the job and decides: the ref policy
// refuses the job (it fails), the required reviewers and the wait timer hold it (it stays blocked and a later pass looks
// again; the timer counts from the creation of the deployment, in parallel with the review, and the job is released
// when it has been approved and the timer is due), otherwise the deployment is released and the runner labels of the
// environment are added to the labels the job runs on. A rejected or expired deployment fails the job here too.
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
			Ref: ref, CommitSHA: run.CommitSHA, TriggerUserID: triggerUser(job, run),
		}
		if env, reason, err = resolveNewEnvironment(ctx, job, jobEnv, d); err != nil {
			return behaviourError, err
		}
	} else {
		switch d.Status {
		case actions_model.DeploymentRefused:
			return behaviourFailJob, nil
		case actions_model.DeploymentCancelled:
			return behaviourHoldJob, nil
		case actions_model.DeploymentRejected, actions_model.DeploymentExpired:
			// decided by ReviewDeployments or the expiry, which ran the emitter so that the job fails here
			return behaviourFailJob, nil
		}
		if env, err = actions_model.GetRepoEnvironmentByID(ctx, d.RepoID, d.EnvironmentID); errors.Is(err, actions_model.ErrEnvironmentNotFound) {
			reason = actions_model.DeploymentReasonEnvironmentDeleted
		} else if err != nil {
			return behaviourError, err
		}
	}

	if reason == "" {
		// the rules of the environment apply to a waiting job as they are now
		if reason, err = refusalReason(ctx, run, env); err != nil {
			return behaviourError, err
		}
	}

	prior, priorRelease := d.Status, d.ReleaseAfterUnix
	now := timeutil.TimeStampNow()
	if isNew {
		d.Created = now // the ready time: the timer and the expiry count from it
	}
	if reason == "" && !isNew && prior == actions_model.DeploymentWaitingTimer && d.ReviewedBy != 0 && env != nil && env.ReviewsRequired && waitingRelease(d, env) <= now {
		// about to be released on an approval: the approver must still be one who may review
		if revoked, err := revokeApprovalIfIneligible(ctx, run, env, d); err != nil {
			return behaviourError, err
		} else if revoked {
			// it waits for a review again (RevokeDeploymentApproval stored the current release time): tell the reviewers
			d.Status, d.ReviewedBy = actions_model.DeploymentWaitingReview, 0
			mailDeploymentReviewers(ctx, run, job.Name, env, d)
			return behaviourHoldJob, nil
		}
	}
	nextDeploymentStatus(d, env, reason, now)
	if err := saveDeployment(ctx, d, isNew, prior, priorRelease); err != nil {
		return behaviourError, err
	}

	switch d.Status {
	case actions_model.DeploymentRefused:
		if err := recordDeploymentRefused(ctx, run, d, env); err != nil {
			return behaviourError, err
		}
		return behaviourFailJob, nil
	case actions_model.DeploymentExpired:
		if err := recordDeploymentReview(ctx, run.Repo, env, d, audit_model.Event{Action: "repo.actions_deployment.expired", Result: audit_model.ResultFailure}, 0); err != nil {
			return behaviourError, err
		}
		mailDeploymentDecided(ctx, env, d)
		return behaviourFailJob, nil
	case actions_model.DeploymentWaitingReview:
		if prior != actions_model.DeploymentWaitingReview { // it starts to wait for a review: once per deployment
			mailDeploymentReviewers(ctx, run, job.Name, env, d)
		}
		return behaviourHoldJob, nil
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

// revokeApprovalIfIneligible withdraws the approval of d when its approver may no longer review it (removed from the
// reviewers or the team, deactivated, lost access, ...): the deployment waits for a review again, with the review
// cleared, and the change is recorded. It reports if it did.
func revokeApprovalIfIneligible(ctx context.Context, run *actions_model.ActionRun, env *actions_model.ActionEnvironment, d *actions_model.ActionDeployment) (bool, error) {
	approver, err := user_model.GetUserByID(ctx, d.ReviewedBy)
	if err != nil && !user_model.IsErrUserNotExist(err) {
		return false, err
	}
	if approver != nil {
		checker, err := NewReviewChecker(ctx, approver, run)
		if err != nil {
			return false, err
		}
		if ok, err := checker.May(ctx, d); err != nil || ok {
			return false, err
		}
	}
	// on the caller's transaction (the emitter's): a nested one that fails would roll it back and leave the rest of the
	// pass outside it. A lost race is an error, so the pass is repeated, as in saveDeployment.
	revokedBy := d.ReviewedBy
	d.ReleaseAfterUnix = waitingRelease(d, env)
	if moved, err := actions_model.RevokeDeploymentApproval(ctx, d); err != nil {
		return false, err
	} else if !moved {
		return false, fmt.Errorf("deployment %d was changed by another request", d.ID)
	}
	return true, recordDeploymentReview(ctx, run.Repo, env, d, audit_model.Event{
		Action: "repo.actions_deployment.approval_revoked", Result: audit_model.ResultSuccess,
		Data: map[string]any{"revoked_reviewer_id": revokedBy},
	}, 0)
}

// saveDeployment inserts a new deployment, or moves an existing one from prior to its status and release time; one that
// another server moved meanwhile is an error, so that the pass of the emitter is repeated.
func saveDeployment(ctx context.Context, d *actions_model.ActionDeployment, isNew bool, prior actions_model.DeploymentStatus, priorRelease timeutil.TimeStamp) error {
	if isNew { // Created is the ready time the gate set from its clock, so xorm must not stamp it again
		// Updated is compared with the environment's update time, which xorm stamps from the real clock (staleDeployment):
		// stamp it the same way, or a gate clock behind the real one makes a new deployment read as stale
		d.Updated = timeutil.TimeStamp(time.Now().Unix())
		_, err := db.GetEngine(ctx).NoAutoTime().Insert(d)
		return err
	}
	if d.Status == prior && d.ReleaseAfterUnix == priorRelease {
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
	// the secrets, the variables and the context of one pick all ask: the request's cache context answers the later ones
	return cache.GetWithContextCache(ctx, "actions_released_environment", fmt.Sprintf("%d:%d", job.ID, job.Attempt), func() (*actions_model.ActionEnvironment, error) {
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
	})
}

// releasedEnvironmentName returns the name of the environment that released the job, "" if it names none.
func releasedEnvironmentName(ctx context.Context, job *actions_model.ActionRunJob) (string, error) {
	if job.EnvironmentName == "" {
		return "", nil
	}
	env, err := releasedEnvironment(ctx, job)
	if err != nil {
		return "", err
	}
	return env.Name, nil
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
	if isForkRun(job.Run) {
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

// StartDueDeployments runs the emitter for the runs with a job whose wait timer ended, which releases the job, and for
// the runs with a deployment that waits under rules changed since it last did, which the gate decides again: a change
// of rules whose own pass failed (emitEnvironmentRuns) takes effect here, a tick later. It holds nothing between runs:
// the gate moves a deployment with a conditional update, so two servers can run it.
func StartDueDeployments(ctx context.Context) error {
	runIDs, err := actions_model.FindDueDeploymentRunIDs(ctx, timeutil.TimeStampNow(), maxDueDeploymentRuns)
	if err != nil {
		return err
	}
	for _, runID := range runIDs {
		if err := EmitJobsIfReady(runID); err != nil {
			log.Error("EmitJobsIfReady for run %d after a wait timer or a change of rules: %v", runID, err)
		} else if err := actions_model.TouchStaleDeployments(ctx, runID); err != nil {
			log.Error("TouchStaleDeployments for run %d: %v", runID, err)
		}
		// to the back of the line, so that runs that always fail don't starve the others
		if err := actions_model.TouchDueDeployments(ctx, runID, timeutil.TimeStampNow()); err != nil {
			log.Error("TouchDueDeployments for run %d: %v", runID, err)
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
// release them any more, and a job never runs without its gate. Like a change of its rules, only the doer's own act
// deletes it (audit_model.ErrNotOwnAct otherwise).
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
