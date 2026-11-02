// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"slices"
	"time"

	"forgejo.org/models/db"
	"forgejo.org/modules/timeutil"
)

// Values of ActionScheduledDispatch.Status
const (
	ScheduledDispatchPending   = 0
	ScheduledDispatchClaimed   = 1 // taken by the due job, being started
	ScheduledDispatchCancelled = 2 // kept for the list, with CancelReason
)

const (
	scheduledDispatchCancelledKeep = 7 * 24 * time.Hour
	scheduledDispatchClaimedStale  = 10 * time.Minute
)

var ErrScheduledDispatchNotFound = errors.New("scheduled dispatch does not exist")

// ScheduledDispatchCancelReasons are the only values of CancelReason; the web list maps each one to a locale key
var ScheduledDispatchCancelReasons = []string{
	"repo_missing", "doer_missing", "doer_disabled", "repo_archived", "actions_disabled", "no_permission",
	"workflow_missing", "trigger_missing", "workflow_disabled", "inputs_invalid", "ref_changed", "missed",
	"internal_error", "interrupted",
}

// cancelReason returns reason if it is a known code, else "internal_error"
func cancelReason(reason string) string {
	if slices.Contains(ScheduledDispatchCancelReasons, reason) {
		return reason
	}
	return "internal_error"
}

// ActionScheduledDispatch is a manual workflow run ("workflow_dispatch") that starts at RunAt
type ActionScheduledDispatch struct {
	ID         int64
	RepoID     int64  `xorm:"INDEX NOT NULL"`
	WorkflowID string `xorm:"VARCHAR(255) NOT NULL"`
	// Ref is resolved again when the run starts; CommitID is what it pointed to when the run was scheduled
	Ref      string `xorm:"VARCHAR(255) NOT NULL"`
	CommitID string `xorm:"VARCHAR(64) NOT NULL DEFAULT ''"`
	// Inputs is the JSON of the resolved inputs, emptied once the row is cancelled
	Inputs       string             `xorm:"TEXT NOT NULL"`
	DoerID       int64              `xorm:"NOT NULL"`
	RunAt        timeutil.TimeStamp `xorm:"INDEX NOT NULL"`
	Status       int                `xorm:"NOT NULL DEFAULT 0"`
	CancelReason string             `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"` // a short code, e.g. "no_permission"
	Created      timeutil.TimeStamp `xorm:"created"`
	Updated      timeutil.TimeStamp `xorm:"updated"`
}

func init() {
	db.RegisterModel(new(ActionScheduledDispatch))
}

func InsertScheduledDispatch(ctx context.Context, sd *ActionScheduledDispatch) error {
	_, err := db.GetEngine(ctx).Insert(sd)
	return err
}

// ListScheduledDispatches returns the pending and cancelled rows of a repository, by time
func ListScheduledDispatches(ctx context.Context, repoID int64, opts db.ListOptions) ([]*ActionScheduledDispatch, int64, error) {
	sess := db.GetEngine(ctx).Where("repo_id = ? AND status IN (?, ?)", repoID, ScheduledDispatchPending, ScheduledDispatchCancelled).
		Asc("run_at", "id")
	if opts.PageSize > 0 {
		sess = db.SetSessionPagination(sess, &opts)
	}
	var list []*ActionScheduledDispatch
	total, err := sess.FindAndCount(&list)
	return list, total, err
}

func CountPendingScheduledDispatches(ctx context.Context, repoID int64) (int64, error) {
	return db.GetEngine(ctx).Where("repo_id = ? AND status = ?", repoID, ScheduledDispatchPending).Count(new(ActionScheduledDispatch))
}

// GetScheduledDispatch returns a row that is pending or cancelled; the repository is always part of the lookup
func GetScheduledDispatch(ctx context.Context, repoID, id int64) (*ActionScheduledDispatch, error) {
	sd := &ActionScheduledDispatch{}
	has, err := db.GetEngine(ctx).Where("id = ? AND repo_id = ? AND status IN (?, ?)", id, repoID, ScheduledDispatchPending, ScheduledDispatchCancelled).Get(sd)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrScheduledDispatchNotFound
	}
	return sd, nil
}

// UpdateScheduledDispatchRunAt changes the time of a pending row
func UpdateScheduledDispatchRunAt(ctx context.Context, repoID, id int64, runAt timeutil.TimeStamp) error {
	affected, err := db.GetEngine(ctx).Where("id = ? AND repo_id = ? AND status = ?", id, repoID, ScheduledDispatchPending).
		Cols("run_at").Update(&ActionScheduledDispatch{RunAt: runAt})
	if err != nil {
		return err
	} else if affected != 1 {
		return ErrScheduledDispatchNotFound
	}
	return nil
}

// TakeDueScheduledDispatch claims the oldest pending row that is due and returns it, or nil. A row is only returned
// to the caller that claimed it, so it starts once; a crash leaves it claimed, and CleanupOldScheduledDispatches
// cancels it. Callers take one row at a time and finish it before taking the next.
func TakeDueScheduledDispatch(ctx context.Context, now timeutil.TimeStamp) (*ActionScheduledDispatch, error) {
	for {
		sd := &ActionScheduledDispatch{}
		has, err := db.GetEngine(ctx).Where("status = ? AND run_at <= ?", ScheduledDispatchPending, now).Asc("run_at", "id").Get(sd)
		if err != nil || !has {
			return nil, err
		}
		// the claim also refreshes `updated`, which CleanupOldScheduledDispatches measures from
		affected, err := db.GetEngine(ctx).Where("id = ? AND status = ?", sd.ID, ScheduledDispatchPending).
			Cols("status").Update(&ActionScheduledDispatch{Status: ScheduledDispatchClaimed})
		if err != nil {
			return nil, err
		}
		if affected == 1 {
			return sd, nil
		}
	}
}

// DeleteScheduledDispatch deletes a pending or cancelled row
func DeleteScheduledDispatch(ctx context.Context, repoID, id int64) error {
	affected, err := db.GetEngine(ctx).Where("id = ? AND repo_id = ? AND status IN (?, ?)", id, repoID, ScheduledDispatchPending, ScheduledDispatchCancelled).
		Delete(new(ActionScheduledDispatch))
	if err != nil {
		return err
	} else if affected != 1 {
		return ErrScheduledDispatchNotFound
	}
	return nil
}

// DeleteScheduledDispatchByID deletes a row by its ID, whatever its status; used after a successful start
func DeleteScheduledDispatchByID(ctx context.Context, id int64) error {
	_, err := db.GetEngine(ctx).ID(id).Delete(new(ActionScheduledDispatch))
	return err
}

// CleanupOldScheduledDispatches removes cancelled rows after a week and cancels claimed rows that have been stuck for
// 10 minutes with the reason "interrupted"; they never run again, a crash must not start a run twice.
func CleanupOldScheduledDispatches(ctx context.Context, now timeutil.TimeStamp) error {
	if _, err := db.GetEngine(ctx).Where("status = ? AND updated < ?", ScheduledDispatchCancelled, int64(now)-int64(scheduledDispatchCancelledKeep.Seconds())).
		Delete(new(ActionScheduledDispatch)); err != nil {
		return err
	}
	_, err := db.GetEngine(ctx).Where("status = ? AND updated < ?", ScheduledDispatchClaimed, int64(now)-int64(scheduledDispatchClaimedStale.Seconds())).
		Cols("status", "cancel_reason", "inputs").Update(&ActionScheduledDispatch{Status: ScheduledDispatchCancelled, CancelReason: "interrupted"})
	return err
}

// CancelClaimedScheduledDispatch turns a row that the due job claimed into a cancelled one, kept for the list
func CancelClaimedScheduledDispatch(ctx context.Context, id int64, reason string) error {
	_, err := db.GetEngine(ctx).Where("id = ? AND status = ?", id, ScheduledDispatchClaimed).
		Cols("status", "cancel_reason", "inputs").Update(&ActionScheduledDispatch{Status: ScheduledDispatchCancelled, CancelReason: cancelReason(reason)})
	return err
}
