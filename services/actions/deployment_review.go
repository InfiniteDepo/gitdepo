// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
)

var (
	ErrReviewForbidden      = util.NewPermissionDeniedErrorf("you are not allowed to review this deployment")
	ErrReviewNotWaiting     = util.NewInvalidArgumentErrorf("the deployment is no longer waiting for a review")
	ErrReviewCommentMissing = util.NewInvalidArgumentErrorf("a rejection needs a comment")
)

// maxExpiredPerTick is how many deployments one run of the expiry task fails; the next run takes the rest.
const maxExpiredPerTick = 100

// reviewComment returns comment as stored: line breaks as "\n". It must be valid UTF-8 of at most
// actions_model.MaxReviewComment bytes without control characters except newline and tab, and a rejection needs one.
// The comment is plain text; no page of this feature renders it as HTML.
func reviewComment(comment string, approve bool) (string, error) {
	comment = strings.TrimSpace(strings.ReplaceAll(comment, "\r\n", "\n"))
	if len(comment) > actions_model.MaxReviewComment || !utf8.ValidString(comment) ||
		strings.ContainsFunc(comment, func(r rune) bool { return (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f }) {
		return "", util.NewInvalidArgumentErrorf("invalid review comment")
	}
	if !approve && comment == "" {
		return "", ErrReviewCommentMissing
	}
	return comment, nil
}

// mayReview decides if doer may review the deployment d of environment env at this moment. Nobody is exempt, site
// administrators included: whoever is not a listed reviewer edits the rules of the environment, which is audited.
func mayReview(ctx context.Context, doer *user_model.User, run *actions_model.ActionRun, d *actions_model.ActionDeployment, env *actions_model.ActionEnvironment, reviewers []*actions_model.ActionEnvironmentReviewer) (bool, error) {
	repo := run.Repo
	if doer == nil || doer.ID <= 0 || doer.IsActions() || doer.IsAccessTokenBot() || doer.IsOrganization() || !doer.IsActive || doer.ProhibitLogin {
		return false, nil
	}
	// the one who triggered the run, and the one who triggered this attempt (a rerun may differ)
	if env.PreventSelfReview && (doer.ID == run.TriggerUserID || doer.ID == d.TriggerUserID) {
		return false, nil
	}
	if blocked, err := doer.TwoFactorBlocked(ctx, repo.Owner); err != nil || blocked {
		return false, err
	}
	perm, err := access_model.GetUserRepoPermission(ctx, repo, doer)
	if err != nil || !perm.CanRead(unit.TypeActions) {
		return false, err
	}
	for _, r := range reviewers {
		if r.UserID == doer.ID {
			return true, nil
		}
		if r.TeamID > 0 { // read now, and only a team of the organization that owns the repository counts
			if member, err := org_model.IsTeamMember(ctx, repo.OwnerID, r.TeamID, doer.ID); err != nil || member {
				return member, err
			}
		}
	}
	return false, nil
}

// ReviewDeployments approves or rejects the deployments of run that wait for a review: those of jobIDs, or every one
// the doer may review when jobIDs is empty. One approval releases a job (when its wait timer is due too), one
// rejection fails it. Nothing changes unless every deployment can be reviewed: a job that doesn't wait any more
// (another reviewer, the expiry or a cancel came first) is ErrReviewNotWaiting, a deployment the doer may not review
// is ErrReviewForbidden.
func ReviewDeployments(ctx context.Context, doer *user_model.User, run *actions_model.ActionRun, jobIDs []int64, approve bool, comment string) ([]*actions_model.ActionDeployment, error) {
	comment, err := reviewComment(comment, approve)
	if err != nil {
		return nil, err
	}
	if err := run.LoadRepo(ctx); err != nil {
		return nil, err
	}
	if err := run.Repo.LoadOwner(ctx); err != nil {
		return nil, err
	}
	waiting, err := actions_model.FindReviewableDeployments(ctx, run.ID)
	if err != nil {
		return nil, err
	}
	if len(jobIDs) > 0 {
		jobs, err := actions_model.GetRunJobsByRunID(ctx, run.ID)
		if err != nil {
			return nil, err
		}
		for _, id := range jobIDs {
			if !slices.ContainsFunc(jobs, func(j *actions_model.ActionRunJob) bool { return j.ID == id }) {
				return nil, util.NewInvalidArgumentErrorf("job %d is not a job of the run", id)
			}
			if !slices.ContainsFunc(waiting, func(d *actions_model.ActionDeployment) bool { return d.JobID == id }) {
				return nil, ErrReviewNotWaiting
			}
		}
		waiting = slices.DeleteFunc(waiting, func(d *actions_model.ActionDeployment) bool { return !slices.Contains(jobIDs, d.JobID) })
	} else if len(waiting) == 0 {
		return nil, ErrReviewNotWaiting
	}

	var selected []*actions_model.ActionDeployment
	envs := map[int64]*actions_model.ActionEnvironment{}
	for _, d := range waiting {
		env, ok := envs[d.EnvironmentID]
		if !ok {
			if env, err = actions_model.GetRepoEnvironmentByID(ctx, run.RepoID, d.EnvironmentID); err != nil {
				return nil, err
			}
			envs[d.EnvironmentID] = env
		}
		reviewers, err := actions_model.FindEnvironmentReviewers(ctx, env.ID)
		if err != nil {
			return nil, err
		}
		if ok, err := mayReview(ctx, doer, run, d, env, reviewers); err != nil {
			return nil, err
		} else if ok {
			selected = append(selected, d)
		} else if len(jobIDs) > 0 {
			return nil, ErrReviewForbidden
		}
	}
	if len(selected) == 0 {
		return nil, ErrReviewForbidden
	}

	now := timeutil.TimeStampNow()
	action := "repo.actions_deployment.approved"
	to := actions_model.DeploymentWaitingTimer // approved: released by the gate once the wait timer is due
	if !approve {
		action, to = "repo.actions_deployment.rejected", actions_model.DeploymentRejected
	}
	if err := db.WithTx(ctx, func(ctx context.Context) error {
		for _, d := range selected {
			d.Status, d.ReviewedBy, d.ReviewedUnix, d.ReviewComment = to, doer.ID, now, comment
			if moved, err := actions_model.ReviewDeployment(ctx, d); err != nil {
				return err
			} else if !moved {
				return ErrReviewNotWaiting
			}
			// every change is recorded in its transaction; the comment is not (its length only)
			ev := audit_model.Event{Result: audit_model.ResultSuccess}
			ev.Action = action
			if err := recordDeploymentReview(ctx, run.Repo, envs[d.EnvironmentID], d, ev, len(comment)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	// the gate releases or fails the jobs in its one place, outside the transaction as after a rerun
	if err := EmitJobsIfReady(run.ID); err != nil {
		log.Error("EmitJobsIfReady for run %d after a review: %v", run.ID, err)
	}
	// show what the gate did with them
	for i, d := range selected {
		if fresh, has, err := db.GetByID[actions_model.ActionDeployment](ctx, d.ID); err == nil && has {
			selected[i] = fresh
		}
	}
	return selected, nil
}

// recordDeploymentReview records a decision about a deployment: review, rejection or expiry.
func recordDeploymentReview(ctx context.Context, repo *repo_model.Repository, env *actions_model.ActionEnvironment, d *actions_model.ActionDeployment, ev audit_model.Event, commentLength int) error {
	ev.OwnerID, ev.GroupID, ev.RepoID = repo.OwnerID, repo.GroupID, repo.ID
	ev.TargetType, ev.TargetID = "actions_deployment", d.ID
	if env != nil {
		ev.TargetName = env.Name
	}
	ev.Data = map[string]any{
		"environment_id": d.EnvironmentID, "ref": d.Ref, "run_id": d.RunID, "job_id": d.JobID, "attempt": d.Attempt,
		"comment_length": commentLength,
	}
	return audit_model.Record(ctx, ev)
}

// ExpireDeploymentReviews fails the deployments that waited longer than [actions] DEPLOYMENT_APPROVAL_TIMEOUT for a
// review, whatever their wait timer says; the gate fails their jobs. It holds nothing between runs: the deployment moves with
// a conditional update, so two servers can run it.
func ExpireDeploymentReviews(ctx context.Context) error {
	if audit_model.ActorFromContext(ctx) == nil {
		ctx = audit_model.WithSystem(ctx, "actions")
	}
	cutoff := timeutil.TimeStampNow().Add(-int64(setting.Actions.DeploymentApprovalTimeout.Seconds()))
	expired, err := actions_model.FindExpiredReviews(ctx, cutoff, maxExpiredPerTick)
	if err != nil {
		return err
	}
	runs := map[int64]bool{}
	for _, d := range expired {
		if err := expireDeployment(ctx, d); err != nil {
			log.Error("expire the review of deployment %d: %v", d.ID, err)
			continue
		}
		runs[d.RunID] = true
	}
	for runID := range runs {
		if err := EmitJobsIfReady(runID); err != nil {
			log.Error("EmitJobsIfReady for run %d after an expired review: %v", runID, err)
		}
	}
	return nil
}

func expireDeployment(ctx context.Context, d *actions_model.ActionDeployment) error {
	repo, err := repo_model.GetRepositoryByID(ctx, d.RepoID)
	if err != nil {
		return err
	}
	env, err := actions_model.GetRepoEnvironmentByID(ctx, d.RepoID, d.EnvironmentID)
	if err != nil && !errors.Is(err, util.ErrNotExist) {
		return err
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		d.Status = actions_model.DeploymentExpired
		if moved, err := actions_model.SetDeploymentStatus(ctx, d, actions_model.DeploymentWaitingReview); err != nil || !moved {
			return err // not waiting any more: nothing to do
		}
		return recordDeploymentReview(ctx, repo, env, d, audit_model.Event{Action: "repo.actions_deployment.expired", Result: audit_model.ResultFailure}, 0)
	})
}

// CanReviewDeployment tells if doer may review the deployment d of run now (it must wait for a review).
func CanReviewDeployment(ctx context.Context, doer *user_model.User, run *actions_model.ActionRun, d *actions_model.ActionDeployment) (bool, error) {
	if d.Status != actions_model.DeploymentWaitingReview {
		return false, nil
	}
	if err := run.LoadRepo(ctx); err != nil {
		return false, err
	}
	if err := run.Repo.LoadOwner(ctx); err != nil {
		return false, err
	}
	env, err := actions_model.GetRepoEnvironmentByID(ctx, run.RepoID, d.EnvironmentID)
	if err != nil {
		return false, err
	}
	reviewers, err := actions_model.FindEnvironmentReviewers(ctx, env.ID)
	if err != nil {
		return false, err
	}
	return mayReview(ctx, doer, run, d, env, reviewers)
}
