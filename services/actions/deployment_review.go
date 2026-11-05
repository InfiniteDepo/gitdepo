// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"slices"
	"strings"
	"unicode"
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
// actions_model.MaxReviewComment bytes, and hold no control character except newline and tab (C0, DEL and C1), no
// format character (bidi overrides and isolates, zero-width characters) and no line or paragraph separator: a reason
// can't be made to read differently from what was written. A rejection needs one. The comment is plain text; no page of
// this feature renders it as HTML.
func reviewComment(comment string, approve bool) (string, error) {
	comment = strings.TrimSpace(strings.ReplaceAll(comment, "\r\n", "\n"))
	if len(comment) > actions_model.MaxReviewComment || !utf8.ValidString(comment) ||
		strings.ContainsFunc(comment, func(r rune) bool {
			return (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
		}) {
		return "", util.NewInvalidArgumentErrorf("invalid review comment")
	}
	if !approve && comment == "" {
		return "", ErrReviewCommentMissing
	}
	return comment, nil
}

// ReviewCutoff is the creation time before which a deployment waiting for a review has waited too long: it is expired,
// by the gate or the expiry task, and can no longer be approved.
func ReviewCutoff() timeutil.TimeStamp {
	return timeutil.TimeStampNow().Add(-int64(setting.Actions.DeploymentApprovalTimeout.Seconds()))
}

// reviewEnvironment is an environment of the run with its reviewers and whether the doer is one of them.
type reviewEnvironment struct {
	env       *actions_model.ActionEnvironment // nil if the environment is deleted
	reviewers []*actions_model.ActionEnvironmentReviewer
	listed    *bool
}

// ReviewChecker is the one decision of who may review the deployments of one run: ReviewDeployments and the list of
// deployments (can_review) use it, and it loads what it needs once per run, doer and environment.
// Nobody is exempt, site administrators included: whoever is not a listed reviewer edits the rules of the
// environment, which is audited.
type ReviewChecker struct {
	run    *actions_model.ActionRun
	doer   *user_model.User
	doerOK *bool
	envs   map[int64]*reviewEnvironment
}

// NewReviewChecker returns the checker of doer for the run; it loads the repository and its owner.
func NewReviewChecker(ctx context.Context, doer *user_model.User, run *actions_model.ActionRun) (*ReviewChecker, error) {
	if err := run.LoadRepo(ctx); err != nil {
		return nil, err
	}
	if err := run.Repo.LoadOwner(ctx); err != nil {
		return nil, err
	}
	return &ReviewChecker{run: run, doer: doer, envs: map[int64]*reviewEnvironment{}}, nil
}

// Environment returns the environment with its reviewers; the environment is nil if it is deleted.
func (c *ReviewChecker) Environment(ctx context.Context, id int64) (*actions_model.ActionEnvironment, []*actions_model.ActionEnvironmentReviewer, error) {
	e, err := c.environment(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	return e.env, e.reviewers, nil
}

func (c *ReviewChecker) environment(ctx context.Context, id int64) (*reviewEnvironment, error) {
	if e, ok := c.envs[id]; ok {
		return e, nil
	}
	e := &reviewEnvironment{}
	env, err := actions_model.GetRepoEnvironmentByID(ctx, c.run.RepoID, id)
	if err != nil && !errors.Is(err, actions_model.ErrEnvironmentNotFound) {
		return nil, err
	}
	if e.env = env; env != nil {
		if e.reviewers, err = actions_model.FindEnvironmentReviewers(ctx, env.ID); err != nil {
			return nil, err
		}
	}
	c.envs[id] = e
	return e, nil
}

// doerMayAct checks what holds for every deployment of the run: the doer is a usable person with read access to the
// repository's Actions.
func (c *ReviewChecker) doerMayAct(ctx context.Context) (bool, error) {
	if c.doerOK != nil {
		return *c.doerOK, nil
	}
	ok := false
	doer, repo := c.doer, c.run.Repo
	if doer != nil && doer.ID > 0 && !doer.IsActions() && !doer.IsAccessTokenBot() && !doer.IsOrganization() && doer.IsActive && !doer.ProhibitLogin {
		blocked, err := doer.TwoFactorBlocked(ctx, repo.Owner)
		if err != nil {
			return false, err
		}
		if !blocked {
			perm, err := access_model.GetUserRepoPermission(ctx, repo, doer)
			if err != nil {
				return false, err
			}
			ok = perm.CanRead(unit.TypeActions)
		}
	}
	c.doerOK = &ok
	return ok, nil
}

// May decides if the doer may review the deployment d at this moment (its status is not looked at): a listed user, or a
// member of a listed team (read now; only a team of the organization that owns the repository counts), who can read
// the repository's Actions. With the environment's PreventSelfReview, the run's trigger user and the user who started
// this attempt (a rerun) can't review.
func (c *ReviewChecker) May(ctx context.Context, d *actions_model.ActionDeployment) (bool, error) {
	if ok, err := c.doerMayAct(ctx); err != nil || !ok {
		return false, err
	}
	e, err := c.environment(ctx, d.EnvironmentID)
	if err != nil || e.env == nil {
		return false, err
	}
	if e.env.PreventSelfReview && (c.doer.ID == c.run.TriggerUserID || c.doer.ID == d.TriggerUserID) {
		return false, nil
	}
	if e.listed == nil {
		listed := false
		for _, r := range e.reviewers {
			if r.UserID == c.doer.ID {
				listed = true
			} else if r.TeamID > 0 {
				if listed, err = org_model.IsTeamMember(ctx, c.run.Repo.OwnerID, r.TeamID, c.doer.ID); err != nil {
					return false, err
				}
			}
			if listed {
				break
			}
		}
		e.listed = &listed
	}
	return *e.listed, nil
}

// notWaiting lets the gate look at the run (it expires a review that waited too long) and answers that the
// deployment doesn't wait for a review any more.
func notWaiting(runID int64) error {
	if err := EmitJobsIfReady(runID); err != nil {
		log.Error("EmitJobsIfReady for run %d after a review that found nothing waiting: %v", runID, err)
	}
	return ErrReviewNotWaiting
}

// ReviewDeployments approves or rejects the deployments of run that wait for a review: those of jobIDs, or every one
// the doer may review when jobIDs is empty. One approval releases a job (when its wait timer is due too), one
// rejection fails it. Nothing changes unless every deployment can be reviewed: a job that doesn't wait any more
// (another reviewer, the expiry or a cancel came first, or it waited longer than the timeout) is ErrReviewNotWaiting,
// a deployment the doer may not review is ErrReviewForbidden. A review made under sudo is refused: a decision about
// a deployment is its reviewer's own, so there is no way for an administrator to give it in somebody's name.
func ReviewDeployments(ctx context.Context, doer *user_model.User, run *actions_model.ActionRun, jobIDs []int64, approve bool, comment string) ([]*actions_model.ActionDeployment, error) {
	if actor := audit_model.ActorFromContext(ctx); actor != nil && actor.SudoByID != 0 {
		return nil, ErrReviewForbidden
	}
	comment, err := reviewComment(comment, approve)
	if err != nil {
		return nil, err
	}
	checker, err := NewReviewChecker(ctx, doer, run)
	if err != nil {
		return nil, err
	}
	cutoff := ReviewCutoff()
	waiting, err := actions_model.FindReviewableDeployments(ctx, run.ID, cutoff)
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
				return nil, notWaiting(run.ID)
			}
		}
		waiting = slices.DeleteFunc(waiting, func(d *actions_model.ActionDeployment) bool { return !slices.Contains(jobIDs, d.JobID) })
	} else if len(waiting) == 0 {
		return nil, notWaiting(run.ID)
	}

	var selected []*actions_model.ActionDeployment
	for _, d := range waiting {
		if ok, err := checker.May(ctx, d); err != nil {
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
			if moved, err := actions_model.ReviewDeployment(ctx, d, cutoff); err != nil {
				return err
			} else if !moved {
				return ErrReviewNotWaiting
			}
			// every change is recorded in its transaction; the comment is not (its length only)
			ev := audit_model.Event{Result: audit_model.ResultSuccess}
			ev.Action = action
			env, _, err := checker.Environment(ctx, d.EnvironmentID)
			if err != nil {
				return err
			}
			if err := recordDeploymentReview(ctx, run.Repo, env, d, ev, len(comment)); err != nil {
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
// a conditional update, so two servers can run it. The gate and the review itself enforce the same timeout, so this
// task only makes sure that nothing stays waiting when nobody looks at the run. A deployment that can't be processed
// goes to the back of the line, so it can't block the others.
func ExpireDeploymentReviews(ctx context.Context) error {
	if audit_model.ActorFromContext(ctx) == nil {
		ctx = audit_model.WithSystem(ctx, "actions")
	}
	expired, err := actions_model.FindExpiredReviews(ctx, ReviewCutoff(), maxExpiredPerTick)
	if err != nil {
		return err
	}
	runs := map[int64]bool{}
	for _, d := range expired {
		if err := expireDeployment(ctx, d); err != nil {
			log.Error("expire the review of deployment %d: %v", d.ID, err)
			if err := actions_model.TouchDeployment(ctx, d.ID, timeutil.TimeStampNow()); err != nil {
				log.Error("TouchDeployment %d: %v", d.ID, err)
			}
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
	repo, err := repo_model.GetRepositoryByIDIncludingTrashed(ctx, d.RepoID) // only the audit scope is needed
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
