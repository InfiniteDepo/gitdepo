// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"errors"
	"net/http"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/translation"
	actions_service "forgejo.org/services/actions"
	app_context "forgejo.org/services/context"
)

const scheduledListSize = 50

// scheduledRun is what the page shows of a scheduled run; the inputs are never loaded into it
type scheduledRun struct {
	ID        int64
	Workflow  string
	Ref       string
	RunAt     timeutil.TimeStamp
	RunAtISO  string
	DoerName  string
	Cancelled bool
	Reason    string
	CanManage bool
}

// canManageScheduled: the scheduler, a repository admin and a site admin, as in the API
func canManageScheduled(ctx *app_context.Context, sd *actions_model.ActionScheduledDispatch) bool {
	return sd.DoerID == ctx.Doer.ID || ctx.Repo.IsAdmin() || ctx.IsUserSiteAdmin()
}

// scheduledReasonText is the text of a cancel code; the stored value is never shown or used to build a key
func scheduledReasonText(locale translation.Locale, code string) string {
	switch code {
	case "repo_missing":
		return locale.TrString("actions.scheduled.reason.repo_missing")
	case "doer_missing":
		return locale.TrString("actions.scheduled.reason.doer_missing")
	case "doer_disabled":
		return locale.TrString("actions.scheduled.reason.doer_disabled")
	case "repo_archived":
		return locale.TrString("actions.scheduled.reason.repo_archived")
	case "actions_disabled":
		return locale.TrString("actions.scheduled.reason.actions_disabled")
	case "no_permission":
		return locale.TrString("actions.scheduled.reason.no_permission")
	case "workflow_missing":
		return locale.TrString("actions.scheduled.reason.workflow_missing")
	case "trigger_missing":
		return locale.TrString("actions.scheduled.reason.trigger_missing")
	case "workflow_disabled":
		return locale.TrString("actions.scheduled.reason.workflow_disabled")
	case "inputs_invalid":
		return locale.TrString("actions.scheduled.reason.inputs_invalid")
	case "ref_changed":
		return locale.TrString("actions.scheduled.reason.ref_changed")
	case "missed":
		return locale.TrString("actions.scheduled.reason.missed")
	case "interrupted":
		return locale.TrString("actions.scheduled.reason.interrupted")
	}
	return locale.TrString("actions.scheduled.reason.unknown") // includes internal_error
}

// loadScheduled fills the page data of "Run later"; it is for users who can run workflows only, the list and the
// time zone are not for readers (the htmx fragment of the list goes through List as well)
func loadScheduled(ctx *app_context.Context) error {
	ctx.Data["ScheduleEnabled"] = setting.Actions.MaxDelayedRunDays > 0
	ctx.Data["MaxDelayedRunDays"] = setting.Actions.MaxDelayedRunDays
	tz, err := user_model.GetUserTimeZone(ctx, ctx.Doer.ID)
	if err != nil {
		return err
	}
	ctx.Data["UserTimeZone"] = tz

	list, total, err := actions_model.ListScheduledDispatches(ctx, ctx.Repo.Repository.ID, db.ListOptions{Page: 1, PageSize: scheduledListSize})
	if err != nil {
		return err
	}
	ids := make([]int64, len(list))
	for i, sd := range list {
		ids[i] = sd.DoerID
	}
	doers, err := user_model.GetPossibleUserByIDs(ctx, ids)
	if err != nil {
		return err
	}
	names := make(map[int64]string, len(doers))
	for _, u := range doers {
		names[u.ID] = u.Name
	}
	runs := make([]scheduledRun, len(list))
	for i, sd := range list {
		runs[i] = scheduledRun{
			ID:        sd.ID,
			Workflow:  sd.WorkflowID,
			Ref:       git.RefName(sd.Ref).ShortName(),
			RunAt:     sd.RunAt,
			RunAtISO:  sd.RunAt.AsTime().UTC().Format("2006-01-02T15:04:05Z"),
			DoerName:  names[sd.DoerID],
			Cancelled: sd.Status == actions_model.ScheduledDispatchCancelled,
			CanManage: canManageScheduled(ctx, sd),
		}
		if runs[i].Cancelled {
			runs[i].Reason = scheduledReasonText(ctx.Locale, sd.CancelReason)
		}
	}
	ctx.Data["ScheduledRuns"] = runs
	ctx.Data["ScheduledMore"] = total - int64(len(list))
	return nil
}

// getManagedScheduled loads the row of this repository from the path, then checks the user may change it
func getManagedScheduled(ctx *app_context.Context) *actions_model.ActionScheduledDispatch {
	sd, err := actions_model.GetScheduledDispatch(ctx, ctx.Repo.Repository.ID, ctx.ParamsInt64("id"))
	if errors.Is(err, actions_model.ErrScheduledDispatchNotFound) {
		ctx.NotFound("GetScheduledDispatch", err)
		return nil
	} else if err != nil {
		ctx.ServerError("GetScheduledDispatch", err)
		return nil
	}
	if !canManageScheduled(ctx, sd) {
		ctx.Error(http.StatusForbidden)
		return nil
	}
	return sd
}

// CancelScheduled removes a scheduled run (or a cancelled one from the list)
func CancelScheduled(ctx *app_context.Context) {
	sd := getManagedScheduled(ctx)
	if sd == nil {
		return
	}
	err := actions_model.DeleteScheduledDispatch(ctx, ctx.Repo.Repository.ID, sd.ID)
	if errors.Is(err, actions_model.ErrScheduledDispatchNotFound) {
		ctx.NotFound("DeleteScheduledDispatch", err)
		return
	} else if err != nil {
		ctx.ServerError("DeleteScheduledDispatch", err)
		return
	}
	ctx.Flash.Info(ctx.Locale.Tr("actions.scheduled.removed"))
	ctx.Redirect(actionsLocation(ctx, ctx.FormString("workflow")))
}

// ChangeScheduledTime moves a pending run to the time in run_at
func ChangeScheduledTime(ctx *app_context.Context) {
	sd := getManagedScheduled(ctx)
	if sd == nil {
		return
	}
	location := actionsLocation(ctx, ctx.FormString("workflow"))
	runAt, ok := parseRunAt(ctx, location)
	if !ok {
		return
	}
	err := actions_service.ChangeScheduledRunAt(ctx, ctx.Repo.Repository.ID, sd.ID, runAt)
	if errors.Is(err, actions_model.ErrScheduledDispatchNotFound) {
		ctx.Flash.Error(ctx.Locale.Tr("actions.scheduled.not_pending"))
	} else if msg, ok := dispatchErrorFlash(ctx, err); ok {
		ctx.Flash.Error(msg)
	} else if err != nil {
		ctx.ServerError("ChangeScheduledRunAt", err)
		return
	} else {
		ctx.Flash.Info(ctx.Locale.Tr("actions.scheduled.time_changed"))
	}
	ctx.Redirect(location)
}
