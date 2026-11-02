// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"time"

	actions_model "forgejo.org/models/actions"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
)

const (
	maxScheduledDispatchInputsBytes = 64 << 10
	maxPendingScheduledDispatches   = 100
	maxScheduledDispatchesPerTick   = 50
	scheduledDispatchMissedAfter    = time.Hour // a row that is overdue by more than this is cancelled, not started
)

var (
	ErrScheduleDisabled       = util.NewInvalidArgumentErrorf("scheduling manual runs is turned off")
	ErrScheduleInPast         = util.NewInvalidArgumentErrorf("the time must be in the future")
	ErrScheduleTooFar         = util.NewInvalidArgumentErrorf("the time is too far ahead")
	ErrScheduleInputsTooLarge = util.NewInvalidArgumentErrorf("the inputs are too large")
	ErrScheduleLimit          = util.NewInvalidArgumentErrorf("too many scheduled runs in this repository")
)

// CheckScheduleTime refuses a time that is not in the future or beyond [actions] MAX_DELAYED_RUN_DAYS
func CheckScheduleTime(runAt time.Time) error {
	if setting.Actions.MaxDelayedRunDays <= 0 {
		return ErrScheduleDisabled
	}
	now := timeutil.TimeStampNow().AsTime()
	if !runAt.After(now) {
		return ErrScheduleInPast
	}
	// the clamp keeps AddDate from overflowing on an absurd setting
	if runAt.After(now.AddDate(0, 0, min(setting.Actions.MaxDelayedRunDays, 36500))) {
		return ErrScheduleTooFar
	}
	return nil
}

// ScheduleDispatch saves a manual run of workflow that starts at runAt. The inputs are validated now and stored
// resolved; the permission of doer, the workflow and its trigger are checked again when the run starts.
func ScheduleDispatch(ctx context.Context, repo *repo_model.Repository, doer *user_model.User, workflow *Workflow, getter InputValueGetter, runAt time.Time) (*actions_model.ActionScheduledDispatch, error) {
	// a job token acts as the Actions user, who has no account to run as later
	if doer.ID <= 0 || doer.IsActions() {
		return nil, util.NewPermissionDeniedErrorf("only a user can schedule a run")
	}
	if err := CheckScheduleTime(runAt); err != nil {
		return nil, err
	}
	// ponytail: count then insert is not atomic, concurrent requests can pass the cap by a few rows
	if n, err := actions_model.CountPendingScheduledDispatches(ctx, repo.ID); err != nil {
		return nil, err
	} else if n >= maxPendingScheduledDispatches {
		return nil, ErrScheduleLimit
	}
	inputs, err := workflow.ResolveInputs(ctx, getter, repo)
	if err != nil {
		return nil, err
	}
	inputsJSON, err := json.Marshal(inputs)
	if err != nil {
		return nil, err
	}
	if len(inputsJSON) > maxScheduledDispatchInputsBytes {
		return nil, ErrScheduleInputsTooLarge
	}
	sd := &actions_model.ActionScheduledDispatch{
		RepoID:     repo.ID,
		WorkflowID: workflow.WorkflowID,
		Ref:        workflow.Ref,
		CommitID:   workflow.Commit.ID.String(),
		Inputs:     string(inputsJSON),
		DoerID:     doer.ID,
		RunAt:      timeutil.TimeStamp(runAt.Unix()),
	}
	return sd, actions_model.InsertScheduledDispatch(ctx, sd)
}

// ChangeScheduledRunAt moves a pending row to runAt, which must be inside the same window as when scheduling.
// The caller decides who may do it.
func ChangeScheduledRunAt(ctx context.Context, repoID, id int64, runAt time.Time) error {
	if err := CheckScheduleTime(runAt); err != nil {
		return err
	}
	return actions_model.UpdateScheduledDispatchRunAt(ctx, repoID, id, timeutil.TimeStamp(runAt.Unix()))
}

// StartDueScheduledDispatches starts the scheduled runs that are due; each one is claimed first, so it starts once
func StartDueScheduledDispatches(ctx context.Context) error {
	now := timeutil.TimeStampNow()
	if err := actions_model.CleanupOldScheduledDispatches(ctx, now); err != nil {
		return err
	}
	// one row at a time, each finished before the next is claimed, so a crash leaves at most one claimed row
	for range maxScheduledDispatchesPerTick {
		sd, err := actions_model.TakeDueScheduledDispatch(ctx, now)
		if err != nil {
			return err
		} else if sd == nil {
			return nil
		}
		reason, err := startScheduledDispatch(ctx, sd, now)
		if err != nil {
			log.Error("Scheduled dispatch %d of repository %d: %v", sd.ID, sd.RepoID, err)
			reason = "internal_error"
		}
		if reason == "" {
			err = actions_model.DeleteScheduledDispatchByID(ctx, sd.ID)
		} else {
			log.Warn("Cancelling scheduled dispatch %d of repository %d: %s", sd.ID, sd.RepoID, reason)
			err = actions_model.CancelClaimedScheduledDispatch(ctx, sd.ID, reason)
		}
		if err != nil {
			log.Error("Scheduled dispatch %d of repository %d: %v", sd.ID, sd.RepoID, err)
		}
	}
	return nil
}

// startScheduledDispatch starts the run and returns "" or the code why it was refused; an error is not retried.
// Nothing the row stored is trusted: the repository, the doer and their permission are loaded again.
func startScheduledDispatch(ctx context.Context, sd *actions_model.ActionScheduledDispatch, now timeutil.TimeStamp) (string, error) {
	if now-sd.RunAt > timeutil.TimeStamp(scheduledDispatchMissedAfter.Seconds()) {
		return "missed", nil // e.g. the server was down at the time
	}
	repo, err := repo_model.GetRepositoryByID(ctx, sd.RepoID) // hides a trashed repository
	if repo_model.IsErrRepoNotExist(err) {
		return "repo_missing", nil
	} else if err != nil {
		return "", err
	}
	doer, err := user_model.GetPossibleUserByID(ctx, sd.DoerID)
	if user_model.IsErrUserNotExist(err) {
		return "doer_missing", nil
	} else if err != nil {
		return "", err
	}
	switch {
	case doer.ID <= 0:
		return "doer_missing", nil
	case !doer.IsActive || doer.ProhibitLogin:
		return "doer_disabled", nil
	case repo.IsArchived:
		return "repo_archived", nil
	case !repo.UnitEnabled(ctx, unit.TypeActions):
		return "actions_disabled", nil
	}
	perm, err := access_model.GetUserRepoPermission(ctx, repo, doer)
	if err != nil {
		return "", err
	}
	if !perm.CanWrite(unit.TypeActions) {
		return "no_permission", nil
	}

	gitRepo, err := gitrepo.OpenRepository(ctx, repo)
	if err != nil {
		return "", err
	}
	defer gitRepo.Close()
	workflow, err := GetWorkflowFromCommit(gitRepo, sd.Ref, sd.WorkflowID)
	if errors.Is(err, util.ErrNotExist) || errors.Is(err, util.ErrInvalidArgument) {
		return "workflow_missing", nil
	} else if err != nil {
		return "", err
	}

	// the run executes as the scheduler: code pushed to the ref since then, maybe by someone else, must not run in their name
	if workflow.Commit.ID.String() != sd.CommitID {
		return "ref_changed", nil
	}

	var inputs map[string]string
	if err := json.Unmarshal([]byte(sd.Inputs), &inputs); err != nil {
		return "", err
	}
	// Dispatch checks the saved inputs against the workflow as it is now, e.g. a new required input
	if _, _, err := workflow.DispatchWithInputs(ctx, inputs, repo, doer); err != nil {
		return dispatchRefusal(err)
	}
	return "", nil
}

func dispatchRefusal(err error) (string, error) {
	switch {
	case errors.Is(err, ErrWorkflowNoDispatchTrigger):
		return "trigger_missing", nil
	case errors.Is(err, ErrWorkflowDisabled):
		return "workflow_disabled", nil
	case IsInputRequiredErr(err):
		return "inputs_invalid", nil
	}
	return "", err
}
