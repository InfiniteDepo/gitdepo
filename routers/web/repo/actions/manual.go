// Copyright 2024 The Forgejo Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	actions_service "forgejo.org/services/actions"
	app_context "forgejo.org/services/context"
)

func ManualRunWorkflow(ctx *app_context.Context) {
	workflowID := ctx.FormString("workflow")
	if len(workflowID) == 0 {
		ctx.ServerError("workflow", nil)
		return
	}

	ref := ctx.FormString("ref")
	if len(ref) == 0 {
		ctx.ServerError("ref", nil)
		return
	}

	if empty, err := ctx.Repo.GitRepo.IsEmpty(); err != nil {
		ctx.ServerError("IsEmpty", err)
		return
	} else if empty {
		ctx.NotFound("IsEmpty", nil)
		return
	}

	workflow, err := actions_service.GetWorkflowFromCommit(ctx.Repo.GitRepo, ref, workflowID)
	if errors.Is(err, util.ErrInvalidArgument) {
		ctx.Error(http.StatusBadRequest, err.Error())
		return
	} else if err != nil {
		ctx.ServerError("GetWorkflowFromCommit", err)
		return
	}

	location := actionsLocation(ctx, workflowID)

	formKeyGetter := func(key string) string {
		formKey := "inputs[" + key + "]"
		return ctx.Req.PostFormValue(formKey)
	}

	success := ctx.Locale.Tr("actions.workflow.dispatch.success")
	if ctx.FormString("run_mode") == "later" {
		runAt, ok := parseRunAt(ctx, location)
		if !ok {
			return
		}
		_, err = actions_service.ScheduleDispatch(ctx, ctx.Repo.Repository, ctx.Doer, workflow, formKeyGetter, runAt)
		success = ctx.Locale.Tr("actions.workflow.dispatch.scheduled")
	} else {
		_, _, err = workflow.Dispatch(ctx, formKeyGetter, ctx.Repo.Repository, ctx.Doer)
	}
	if err != nil {
		if msg, ok := dispatchErrorFlash(ctx, err); ok {
			ctx.Flash.Error(msg)
			ctx.Redirect(location)
			return
		}
		ctx.ServerError("workflow.Dispatch", err)
		return
	}

	// forward to the page of the run which was just created
	ctx.Flash.Info(success)
	ctx.Redirect(location)
}

func actionsLocation(ctx *app_context.Context, workflowID string) string {
	return ctx.Repo.RepoLink + "/actions?workflow=" + url.QueryEscape(workflowID) +
		"&actor=" + url.QueryEscape(ctx.FormString("actor")) +
		"&status=" + url.QueryEscape(ctx.FormString("status"))
}

// parseRunAt reads the form value run_at, an RFC 3339 instant; otherwise it flashes and redirects to location
func parseRunAt(ctx *app_context.Context, location string) (time.Time, bool) {
	value := ctx.FormString("run_at")
	runAt, err := time.Parse(time.RFC3339, value)
	switch {
	case value == "":
		ctx.Flash.Error(ctx.Locale.Tr("actions.workflow.dispatch.run_at_missing"))
	case err != nil:
		ctx.Flash.Error(ctx.Locale.Tr("actions.workflow.dispatch.run_at_invalid"))
	default:
		return runAt, true
	}
	ctx.Redirect(location)
	return runAt, false
}

// dispatchErrorFlash is the text for the errors of a dispatch or a scheduled one that the user can fix
func dispatchErrorFlash(ctx *app_context.Context, err error) (template.HTML, bool) {
	switch {
	case errors.Is(err, actions_service.ErrWorkflowNoDispatchTrigger):
		return ctx.Locale.Tr("actions.workflow.dispatch.no_trigger"), true
	case errors.Is(err, actions_service.ErrWorkflowDisabled):
		return ctx.Locale.Tr("actions.workflow.dispatch.disabled"), true
	case actions_service.IsInputRequiredErr(err):
		return ctx.Locale.Tr("actions.workflow.dispatch.input_required", err.(actions_service.InputRequiredErr).Name), true
	case errors.Is(err, actions_service.ErrScheduleDisabled):
		return ctx.Locale.Tr("actions.workflow.dispatch.schedule_disabled"), true
	case errors.Is(err, actions_service.ErrScheduleInPast):
		return ctx.Locale.Tr("actions.workflow.dispatch.schedule_in_past"), true
	case errors.Is(err, actions_service.ErrScheduleTooFar):
		return ctx.Locale.Tr("actions.workflow.dispatch.schedule_too_far", setting.Actions.MaxDelayedRunDays), true
	case errors.Is(err, actions_service.ErrScheduleInputsTooLarge):
		return ctx.Locale.Tr("actions.workflow.dispatch.schedule_inputs_too_large"), true
	case errors.Is(err, actions_service.ErrScheduleLimit):
		return ctx.Locale.Tr("actions.workflow.dispatch.schedule_limit"), true
	}
	return "", false
}
