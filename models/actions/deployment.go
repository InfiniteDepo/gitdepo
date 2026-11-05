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
// with the review cleared, and reports if it was still approved by the same reviewer (another pass may have moved it).
func RevokeDeploymentApproval(ctx context.Context, d *ActionDeployment) (bool, error) {
	n, err := db.GetEngine(ctx).Where("id = ? AND status = ? AND reviewed_by = ?", d.ID, DeploymentWaitingTimer, d.ReviewedBy).
		Cols("status", "reviewed_by", "reviewed_unix", "review_comment").
		Update(&ActionDeployment{Status: DeploymentWaitingReview})
	return n == 1, err
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

// FindDueDeploymentRunIDs returns the runs, at most limit, with a blocked job whose deployment waits for a wait timer
// that ended, or was rejected or expired and whose job the gate has not failed yet, the ones looked at longest ago first (TouchDueDeployments moves a run whose pass failed to the back, so
// runs that always fail can't starve the others).
func FindDueDeploymentRunIDs(ctx context.Context, now timeutil.TimeStamp, limit int) ([]int64, error) {
	var ids []int64
	return ids, db.GetEngine(ctx).Table("action_deployment").
		Join("INNER", "action_run_job", "action_run_job.id = action_deployment.job_id AND action_run_job.attempt = action_deployment.attempt").
		Where("action_run_job.status = ?", StatusBlocked).
		And(builder.Or(
			builder.And(builder.Eq{"action_deployment.status": DeploymentWaitingTimer}, builder.Lte{"action_deployment.release_after_unix": now}),
			builder.In("action_deployment.status", DeploymentRejected, DeploymentExpired),
		)).
		Select("action_deployment.run_id").GroupBy("action_deployment.run_id").
		OrderBy("MIN(action_deployment.updated), action_deployment.run_id").Limit(limit).Find(&ids)
}

// TouchDueDeployments sets the update time of the run's deployments that wait for a timer to now.
func TouchDueDeployments(ctx context.Context, runID int64, now timeutil.TimeStamp) error {
	_, err := db.GetEngine(ctx).Table("action_deployment").Where("run_id = ?", runID).And(builder.In("status", DeploymentWaitingTimer, DeploymentRejected, DeploymentExpired)).
		Update(map[string]any{"updated": now})
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
