// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"net/url"

	"forgejo.org/models/db"
	"forgejo.org/modules/timeutil"

	"xorm.io/builder"
)

// DeploymentStatus is the state of the gate of a job that names an environment. The outcome of a released deployment
// is not stored: it is the result of the job's task of that attempt.
type DeploymentStatus int

const (
	DeploymentWaitingTimer  DeploymentStatus = 1 // waits for the wait timer of the environment
	DeploymentReleased      DeploymentStatus = 2 // the job may be given to a runner
	DeploymentRefused       DeploymentStatus = 3 // the job failed at the gate, see Reason
	DeploymentCancelled     DeploymentStatus = 4 // the run was cancelled while the job waited
	DeploymentWaitingReview DeploymentStatus = 5 // waits for a reviewer of the environment; the wait timer runs meanwhile
	DeploymentRejected      DeploymentStatus = 6 // a reviewer rejected it, the job fails
	DeploymentExpired       DeploymentStatus = 7 // nobody reviewed it in time, the job fails
)

// IsWaiting tells if the gate still holds the job: the timer and the reviewers have their own expiry, so the cron that
// cancels abandoned jobs leaves such a job alone. An approved deployment waits for the timer, so it is
// DeploymentWaitingTimer with ReviewedBy set (the timer is due at once without one).
func (s DeploymentStatus) IsWaiting() bool {
	return s == DeploymentWaitingTimer || s == DeploymentWaitingReview
}

// String is the name the API shows.
func (s DeploymentStatus) String() string {
	switch s {
	case DeploymentWaitingTimer:
		return "waiting_timer"
	case DeploymentReleased:
		return "released"
	case DeploymentRefused:
		return "refused"
	case DeploymentCancelled:
		return "cancelled"
	case DeploymentWaitingReview:
		return "waiting_review"
	case DeploymentRejected:
		return "rejected"
	case DeploymentExpired:
		return "expired"
	}
	return "unknown"
}

// Reasons of a refused deployment; the only values of ActionDeployment.Reason
const (
	DeploymentReasonRefNotAllowed      = "ref_not_allowed"
	DeploymentReasonEnvironmentLimit   = "environment_limit"
	DeploymentReasonEnvironmentDeleted = "environment_deleted"
	DeploymentReasonInvalidName        = "invalid_name"
	DeploymentReasonNotFound           = "environment_not_found"   // a fork pull request names an environment that doesn't exist
	DeploymentReasonUnsupported        = "environment_unsupported" // a job of a reusable workflow whose environment can't be read
	DeploymentReasonWorkflowNotAllowed = "workflow_not_allowed"    // the run's workflow file is not in the environment's allowed workflows
)

const (
	maxDeploymentURL = 1024
	// MaxReviewComment is the longest comment of a review, in bytes.
	MaxReviewComment = 2000
)

// ActionDeployment is the gate of one attempt of a job that names an environment: a job attempt never gets the
// secrets of its environment unless its deployment is released.
type ActionDeployment struct {
	ID               int64
	RepoID           int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	EnvironmentID    int64              `xorm:"INDEX NOT NULL DEFAULT 0"` // 0 when the name was invalid
	RunID            int64              `xorm:"NOT NULL DEFAULT 0"`
	JobID            int64              `xorm:"UNIQUE(job_attempt) NOT NULL DEFAULT 0"`
	Attempt          int64              `xorm:"UNIQUE(job_attempt) NOT NULL DEFAULT 0"`
	Ref              string             `xorm:"VARCHAR(255)"`
	CommitSHA        string             `xorm:"VARCHAR(64)"`
	URL              string             `xorm:"VARCHAR(1024)"` // `environment.url` of the workflow, http(s) only
	TriggerUserID    int64              `xorm:"NOT NULL DEFAULT 0"`
	Status           DeploymentStatus   `xorm:"INDEX NOT NULL DEFAULT 0"`
	Reason           string             `xorm:"VARCHAR(64)"` // a short code, never free text
	ReleaseAfterUnix timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
	// the review that decided it: one approval releases and one rejection fails, so one row is enough
	ReviewedBy    int64              `xorm:"NOT NULL DEFAULT 0"`
	ReviewedUnix  timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
	ReviewComment string             `xorm:"TEXT"` // plain text, never rendered as HTML
	Created       timeutil.TimeStamp `xorm:"created"`
	Updated       timeutil.TimeStamp `xorm:"updated"`
	// the last time the due-deployments task queued, or failed to queue, a pass of the gate for it (0: never)
	CheckedUnix timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
	// the status whose mail was sent for it (ClaimDeploymentMail); a revoked approval clears it
	MailedStatus DeploymentStatus `xorm:"NOT NULL DEFAULT 0"`
}

func init() {
	db.RegisterModel(new(ActionDeployment))
}

// DeploymentURL returns raw if it is an http or https URL with a host that fits the column, else "".
func DeploymentURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > maxDeploymentURL || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return raw
}

// GetDeployment returns the deployment of that attempt of the job, nil if it has none.
func GetDeployment(ctx context.Context, jobID, attempt int64) (*ActionDeployment, error) {
	d := new(ActionDeployment)
	has, err := db.GetEngine(ctx).Where("job_id = ? AND attempt = ?", jobID, attempt).Get(d)
	if err != nil || !has {
		return nil, err
	}
	return d, nil
}

// SetDeploymentStatus moves d from one of the statuses in from to its Status, Reason and ReleaseAfterUnix, and
// reports if it was in one of them (another server may have moved it first).
func SetDeploymentStatus(ctx context.Context, d *ActionDeployment, from ...DeploymentStatus) (bool, error) {
	n, err := db.GetEngine(ctx).Where("id = ?", d.ID).And(builder.In("status", from)).
		Cols("status", "reason", "release_after_unix").Update(d)
	return n == 1, err
}

// ReviewDeployment moves d from DeploymentWaitingReview to its Status with the review it carries, and reports if it
// was waiting (another reviewer, or the expiry, may have decided first). A deployment created at or before cutoff has
// waited too long: it can't be reviewed any more, whether or not the expiry ran yet.
func ReviewDeployment(ctx context.Context, d *ActionDeployment, cutoff timeutil.TimeStamp) (bool, error) {
	n, err := db.GetEngine(ctx).Where("id = ? AND status = ? AND created > ?", d.ID, DeploymentWaitingReview, cutoff).
		Cols("status", "reviewed_by", "reviewed_unix", "review_comment").Update(d)
	return n == 1, err
}

// RevokeDeploymentApproval puts an approved deployment that still waits for its timer back to waiting for a review,
// with the review cleared and the release time of d, and reports if it was still approved by the same reviewer (another
// pass may have moved it).
func RevokeDeploymentApproval(ctx context.Context, d *ActionDeployment) (bool, error) {
	n, err := db.GetEngine(ctx).Where("id = ? AND status = ? AND reviewed_by = ?", d.ID, DeploymentWaitingTimer, d.ReviewedBy).
		Cols("status", "release_after_unix", "reviewed_by", "reviewed_unix", "review_comment", "mailed_status").
		Update(&ActionDeployment{Status: DeploymentWaitingReview, ReleaseAfterUnix: d.ReleaseAfterUnix})
	return n == 1, err
}

// ClaimDeploymentMail claims the mail about d's status for its run attempt and environment (the jobs of a matrix share
// it): it marks d mailed unless d still has another status or a deployment of the same run, environment and attempt
// with that status is marked already. It locks the run's row first, so of the servers that try at once one sends.
func ClaimDeploymentMail(ctx context.Context, d *ActionDeployment) (claimed bool, err error) {
	return claimed, db.WithTx(ctx, func(ctx context.Context) error {
		e := db.GetEngine(ctx)
		if _, err := e.Exec("UPDATE action_run SET id = id WHERE id = ?", d.RunID); err != nil {
			return err
		}
		taken, err := e.Where("run_id = ? AND environment_id = ? AND attempt = ? AND status = ? AND mailed_status = ?",
			d.RunID, d.EnvironmentID, d.Attempt, d.Status, d.Status).Exist(new(ActionDeployment))
		if err != nil || taken {
			return err
		}
		res, err := e.Exec("UPDATE action_deployment SET mailed_status = ? WHERE id = ? AND status = ?", d.Status, d.ID, d.Status)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		claimed = n == 1
		return err
	})
}

// FindExpiredReviews returns at most limit deployments that have waited for a review since before the cutoff, the ones
// looked at longest ago first (TouchDeployments moves one that failed to the back, so none can block the others).
func FindExpiredReviews(ctx context.Context, cutoff timeutil.TimeStamp, limit int) ([]*ActionDeployment, error) {
	var ds []*ActionDeployment
	return ds, db.GetEngine(ctx).Where("status = ? AND created <= ?", DeploymentWaitingReview, cutoff).
		OrderBy("updated, id").Limit(limit).Find(&ds)
}

// TouchDeployment sets the update time of the deployment to now.
func TouchDeployment(ctx context.Context, id int64, now timeutil.TimeStamp) error {
	_, err := db.GetEngine(ctx).Table("action_deployment").Where("id = ?", id).Update(map[string]any{"updated": now})
	return err
}

// staleDeployment is true for a deployment that waits (for its timer or a review) whose environment changed after the
// deployment last did: an edit of the rules whose own pass of the gate (emitEnvironmentRuns) failed, or didn't decide
// it yet. Times have second resolution, so an edit in the same second as the deployment's last change isn't seen here;
// that edit's own pass decides it.
const staleDeployment = "(action_deployment.status IN (?, ?) AND EXISTS (SELECT 1 FROM action_environment " +
	"WHERE action_environment.id = action_deployment.environment_id AND action_environment.repo_id = action_deployment.repo_id " +
	"AND action_environment.updated > action_deployment.updated))"

// MaxDueRunsPerRepo is how many runs of one repository one tick of the due-deployments task takes, so that one
// repository with many runs (an edit of its rules makes every waiting one stale) can't hold back the others.
const MaxDueRunsPerRepo = 10

// FindDueDeploymentRunIDs returns the runs, at most limit and MaxDueRunsPerRepo of each repository, with a blocked job
// whose deployment waits for a wait timer that ended, was rejected or expired and whose job the gate has not failed
// yet, or waits under rules that changed since (staleDeployment). The runs the task looked at least recently come
// first (TouchDueDeployments), then the ones that wait longest, so runs whose pass always fails, however many, can't
// starve the others.
func FindDueDeploymentRunIDs(ctx context.Context, now timeutil.TimeStamp, limit int) ([]int64, error) {
	cond, args, err := builder.ToSQL(builder.And(builder.Eq{"action_run_job.status": StatusBlocked}, builder.Or(
		builder.And(builder.Eq{"action_deployment.status": DeploymentWaitingTimer}, builder.Lte{"action_deployment.release_after_unix": now}),
		builder.In("action_deployment.status", DeploymentRejected, DeploymentExpired),
		builder.Expr(staleDeployment, DeploymentWaitingTimer, DeploymentWaitingReview),
	)))
	if err != nil {
		return nil, err
	}
	order := "MAX(action_deployment.checked_unix), MIN(action_deployment.updated), action_deployment.run_id"
	var ids []int64
	return ids, db.GetEngine(ctx).SQL("SELECT run_id FROM (SELECT action_deployment.run_id AS run_id, "+
		"MAX(action_deployment.checked_unix) AS checked, MIN(action_deployment.updated) AS waited, "+
		"ROW_NUMBER() OVER (PARTITION BY action_deployment.repo_id ORDER BY "+order+") AS n "+
		"FROM action_deployment INNER JOIN action_run_job ON action_run_job.id = action_deployment.job_id AND action_run_job.attempt = action_deployment.attempt "+
		"WHERE "+cond+" GROUP BY action_deployment.repo_id, action_deployment.run_id) due "+
		"WHERE n <= ? ORDER BY checked, waited, run_id LIMIT ?", append(args, MaxDueRunsPerRepo, limit)...).Find(&ids)
}

// TouchDueDeployments records that the task looked at the run now, whether its pass was queued or not: the run goes
// to the back of the line. It changes no update time, so a stale deployment stays stale until TouchStaleDeployments.
func TouchDueDeployments(ctx context.Context, runID int64, now timeutil.TimeStamp) error {
	_, err := db.GetEngine(ctx).Table("action_deployment").Where("run_id = ?", runID).
		And(builder.In("status", DeploymentWaitingTimer, DeploymentWaitingReview, DeploymentRejected, DeploymentExpired)).
		Update(map[string]any{"checked_unix": now})
	return err
}

// TouchStaleDeployments marks the run's stale deployments (staleDeployment) as seen once the gate was queued for the
// run: their update time becomes their environment's, so they are no longer stale until the rules change again.
func TouchStaleDeployments(ctx context.Context, runID int64) error {
	_, err := db.GetEngine(ctx).Exec("UPDATE action_deployment SET updated = (SELECT action_environment.updated FROM action_environment "+
		"WHERE action_environment.id = action_deployment.environment_id) WHERE action_deployment.run_id = ? AND "+staleDeployment,
		runID, DeploymentWaitingTimer, DeploymentWaitingReview)
	return err
}

// CancelOpenDeployments marks the deployments of the job that still wait as cancelled.
func CancelOpenDeployments(ctx context.Context, jobID int64) error {
	_, err := db.GetEngine(ctx).Table("action_deployment").
		Where("job_id = ?", jobID).And(builder.In("status", DeploymentWaitingTimer, DeploymentWaitingReview)).
		Update(map[string]any{"status": DeploymentCancelled, "updated": timeutil.TimeStampNow()})
	return err
}

// FindUnpickedEnvironmentJobs returns the jobs of the environment that no runner took yet, whose current attempt waits
// for the gate or was released by it.
func FindUnpickedEnvironmentJobs(ctx context.Context, repoID, environmentID int64) ([]*ActionRunJob, error) {
	var jobs []*ActionRunJob
	return jobs, db.GetEngine(ctx).Table("action_run_job").Select("action_run_job.*").
		Join("INNER", "action_deployment", "action_run_job.id = action_deployment.job_id AND action_run_job.attempt = action_deployment.attempt").
		Where("action_deployment.repo_id = ? AND action_deployment.environment_id = ?", repoID, environmentID).
		And(builder.In("action_deployment.status", DeploymentWaitingTimer, DeploymentWaitingReview, DeploymentReleased)).
		And(builder.In("action_run_job.status", StatusBlocked, StatusWaiting)).
		And("action_run_job.task_id = 0").
		Find(&jobs)
}

// FindReviewableDeployments returns the deployments of the run that wait for a review: the current attempt of a job that
// is still blocked, created after cutoff (older ones have expired).
func FindReviewableDeployments(ctx context.Context, runID int64, cutoff timeutil.TimeStamp) ([]*ActionDeployment, error) {
	var ds []*ActionDeployment
	return ds, db.GetEngine(ctx).Table("action_deployment").Select("action_deployment.*").
		Join("INNER", "action_run_job", "action_run_job.id = action_deployment.job_id AND action_run_job.attempt = action_deployment.attempt").
		Where("action_deployment.run_id = ? AND action_deployment.status = ? AND action_run_job.status = ? AND action_deployment.created > ?", runID, DeploymentWaitingReview, StatusBlocked, cutoff).
		OrderBy("action_deployment.job_id").Find(&ds)
}

// FindRunDeployments returns every deployment of the run, past attempts included, by job and attempt.
func FindRunDeployments(ctx context.Context, runID int64) ([]*ActionDeployment, error) {
	var ds []*ActionDeployment
	return ds, db.GetEngine(ctx).Where("run_id = ?", runID).OrderBy("job_id, attempt").Find(&ds)
}

// FindLastDeployments returns the newest deployment of each of the environments of the repository that has one.
func FindLastDeployments(ctx context.Context, repoID int64, environmentIDs []int64) (map[int64]*ActionDeployment, error) {
	var ids []int64
	if err := db.GetEngine(ctx).Table("action_deployment").Select("MAX(id)").Where("repo_id = ?", repoID).
		In("environment_id", environmentIDs).GroupBy("environment_id").Find(&ids); err != nil {
		return nil, err
	}
	var ds []*ActionDeployment
	if err := db.GetEngine(ctx).In("id", ids).Find(&ds); err != nil {
		return nil, err
	}
	out := make(map[int64]*ActionDeployment, len(ds))
	for _, d := range ds {
		out[d.EnvironmentID] = d
	}
	return out, nil
}

// FindDeploymentTasks returns, by deployment ID, the task of the job attempt of each released deployment: its outcome,
// which is not stored on the deployment. One query, bound to the repository; a released job no runner took yet has none.
func FindDeploymentTasks(ctx context.Context, repoID int64, ds []*ActionDeployment) (map[int64]*ActionTask, error) {
	jobIDs := make([]int64, 0, len(ds))
	for _, d := range ds {
		if d.Status == DeploymentReleased {
			jobIDs = append(jobIDs, d.JobID)
		}
	}
	out := make(map[int64]*ActionTask, len(jobIDs))
	if len(jobIDs) == 0 {
		return out, nil
	}
	var tasks []*ActionTask
	if err := db.GetEngine(ctx).Where("repo_id = ?", repoID).In("job_id", jobIDs).
		Cols("id", "job_id", "attempt", "status", "started", "stopped", "updated").OrderBy("id").Find(&tasks); err != nil {
		return nil, err
	}
	type attempt struct{ job, n int64 }
	byAttempt := make(map[attempt]*ActionTask, len(tasks))
	for _, t := range tasks {
		byAttempt[attempt{t.JobID, t.Attempt}] = t // the newest task of the attempt wins
	}
	for _, d := range ds {
		if t := byAttempt[attempt{d.JobID, d.Attempt}]; t != nil && d.Status == DeploymentReleased {
			out[d.ID] = t
		}
	}
	return out, nil
}

// DeploymentFilter narrows FindRepoDeployments; its zero value takes every deployment of the repository.
type DeploymentFilter struct {
	EnvironmentID int64
	Statuses      []DeploymentStatus
	TriggerUserID int64
	Refs          []string // full ref names: a deployment of any of them
}

// FindRepoDeployments returns a page of the deployments of the repository that the filter takes, newest first, and
// how many there are.
func FindRepoDeployments(ctx context.Context, repoID int64, f DeploymentFilter, opts db.ListOptions) ([]*ActionDeployment, int64, error) {
	cond := builder.NewCond().And(builder.Eq{"repo_id": repoID})
	if f.EnvironmentID != 0 {
		cond = cond.And(builder.Eq{"environment_id": f.EnvironmentID})
	}
	if len(f.Statuses) > 0 {
		cond = cond.And(builder.In("status", f.Statuses))
	}
	if f.TriggerUserID != 0 {
		cond = cond.And(builder.Eq{"trigger_user_id": f.TriggerUserID})
	}
	if len(f.Refs) > 0 {
		cond = cond.And(builder.In("ref", f.Refs))
	}
	var ds []*ActionDeployment
	count, err := db.SetSessionPagination(db.GetEngine(ctx).Where(cond), &opts).OrderBy("id DESC").FindAndCount(&ds)
	return ds, count, err
}

// FindDeploymentTriggerUsers returns the users who triggered a deployment of the environment of the repository, at
// most MaxDeploymentTriggerUsers of them (the lowest IDs).
func FindDeploymentTriggerUsers(ctx context.Context, repoID, environmentID int64) ([]int64, error) {
	var ids []int64
	return ids, db.GetEngine(ctx).Table("action_deployment").Distinct("trigger_user_id").
		Where("repo_id = ? AND environment_id = ? AND trigger_user_id <> 0", repoID, environmentID).
		OrderBy("trigger_user_id").Limit(MaxDeploymentTriggerUsers).Find(&ids)
}

// MaxDeploymentTriggerUsers is how many users the actor filter of the deployments view offers at most.
const MaxDeploymentTriggerUsers = 100
