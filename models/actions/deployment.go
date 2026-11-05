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
	DeploymentWaitingTimer DeploymentStatus = 1 // waits for the wait timer of the environment
	DeploymentReleased     DeploymentStatus = 2 // the job may be given to a runner
	DeploymentRefused      DeploymentStatus = 3 // the job failed at the gate, see Reason
	DeploymentCancelled    DeploymentStatus = 4 // the run was cancelled while the job waited
	// 5 and up: waiting for reviewers, rejected, expired
)

// Reasons of a refused deployment; the only values of ActionDeployment.Reason
const (
	DeploymentReasonRefNotAllowed      = "ref_not_allowed"
	DeploymentReasonEnvironmentLimit   = "environment_limit"
	DeploymentReasonEnvironmentDeleted = "environment_deleted"
	DeploymentReasonInvalidName        = "invalid_name"
)

const maxDeploymentURL = 1024

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
	Created          timeutil.TimeStamp `xorm:"created"`
	Updated          timeutil.TimeStamp `xorm:"updated"`
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

// FindDueDeploymentRunIDs returns the runs, at most limit, with a blocked job whose deployment waits for a wait timer
// that ended.
func FindDueDeploymentRunIDs(ctx context.Context, now timeutil.TimeStamp, limit int) ([]int64, error) {
	var ids []int64
	return ids, db.GetEngine(ctx).Table("action_deployment").
		Join("INNER", "action_run_job", "action_run_job.id = action_deployment.job_id AND action_run_job.attempt = action_deployment.attempt").
		Where("action_deployment.status = ? AND action_deployment.release_after_unix <= ? AND action_run_job.status = ?", DeploymentWaitingTimer, now, StatusBlocked).
		Distinct("action_deployment.run_id").Limit(limit).Find(&ids)
}

// CancelOpenDeployments marks the deployments of the job that still wait as cancelled.
func CancelOpenDeployments(ctx context.Context, jobID int64) error {
	_, err := db.GetEngine(ctx).Table("action_deployment").
		Where("job_id = ? AND status = ?", jobID, DeploymentWaitingTimer).
		Update(map[string]any{"status": DeploymentCancelled, "updated": timeutil.TimeStampNow()})
	return err
}
