// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"forgejo.org/models/db"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	shared_actions "forgejo.org/routers/web/shared/actions"
	actions_service "forgejo.org/services/actions"
	"forgejo.org/services/context"
)

const (
	tplActionsRuns  base.TplName = "admin/actions/runs"
	tplActionsUsage base.TplName = "admin/actions/usage"
)

// RunsExportMax is the most runs the CSV export holds.
var RunsExportMax = 10000

// instanceActions refuses the request unless the doer is an active site admin, and answers 404 if Actions is off.
func instanceActions(ctx *context.Context) bool {
	if !actions_service.OrgRunsEnabled() {
		ctx.NotFound("Actions", nil)
		return false
	}
	if !actions_service.IsActiveSiteAdmin(ctx.Doer) {
		ctx.Error(http.StatusForbidden)
		return false
	}
	return true
}

// ActionsRuns lists the workflow runs of all repositories.
func ActionsRuns(ctx *context.Context) {
	if !instanceActions(ctx) || !shared_actions.LoadRuns(ctx, nil, true, setting.AppSubURL+"/admin/actions/runs", setting.AppSubURL+"/admin/actions/runs/export") {
		return
	}
	ctx.Data["Title"] = ctx.Tr("actions.actions")
	ctx.Data["PageIsAdminActionsRuns"] = true
	ctx.HTML(http.StatusOK, tplActionsRuns)
}

// ActionsRunsExport sends the runs of the filter as CSV, at most RunsExportMax of them.
func ActionsRunsExport(ctx *context.Context) {
	if !instanceActions(ctx) {
		return
	}
	filter, err := actions_service.ParseOrgRunFilter(ctx.Base)
	if err != nil {
		ctx.Error(http.StatusBadRequest, err.Error())
		return
	}
	runs, total, err := actions_service.FindOrgRuns(ctx, nil, ctx.Doer, true, nil, filter, db.ListOptions{Page: 1, PageSize: RunsExportMax})
	if err == nil {
		runs, err = actions_service.LoadOrgRunRepos(ctx, runs)
	}
	if err == nil {
		err = runs.LoadTriggerUser(ctx)
	}
	if err != nil {
		ctx.ServerError("ActionsRunsExport", err)
		return
	}

	ctx.SetServeHeaders(&context.ServeHeaderOptions{ContentType: "text/csv", ContentTypeCharset: "utf-8", Filename: "actions-runs.csv"})
	ctx.Resp.Header().Set("X-Content-Type-Options", "nosniff")
	if total > int64(RunsExportMax) {
		ctx.Resp.Header().Set("X-Truncated", "true")
	}
	w := csv.NewWriter(ctx.Resp)
	_ = w.Write([]string{"id", "repository", "workflow", "run_number", "title", "ref", "event", "status", "actor", "created", "started", "stopped", "duration_seconds", "url"})
	for _, run := range runs {
		_ = w.Write([]string{
			strconv.FormatInt(run.ID, 10), util.CSVSafe(run.Repo.FullName()), util.CSVSafe(run.WorkflowID), strconv.FormatInt(run.Index, 10),
			util.CSVSafe(run.Title), util.CSVSafe(run.PrettyRef()), util.CSVSafe(run.Event.Event()), util.CSVSafe(run.Status.String()), util.CSVSafe(run.TriggerUser.Name),
			run.Created.AsTime().UTC().Format(time.RFC3339), csvTime(run.Started), csvTime(run.Stopped),
			strconv.FormatInt(int64(run.Duration()/time.Second), 10), util.CSVSafe(run.HTMLURL()),
		})
	}
	w.Flush()
}

func csvTime(t timeutil.TimeStamp) string {
	if t == 0 {
		return ""
	}
	return t.AsTime().UTC().Format(time.RFC3339)
}

// ActionsUsage shows the job minutes per owner, repository or runner, and the top repositories.
func ActionsUsage(ctx *context.Context) {
	if !instanceActions(ctx) {
		return
	}
	group := actions_service.UsageGroupRepo
	if s := ctx.FormString("group_by"); s != "" {
		var err error
		if group, err = actions_service.ParseUsageGroup(s); err != nil {
			ctx.Error(http.StatusBadRequest, err.Error())
			return
		}
	}
	from, to, err := actions_service.ParseUsageRange(ctx.FormString("from"), ctx.FormString("to"), timeutil.TimeStampNow())
	if err != nil {
		ctx.Error(http.StatusBadRequest, err.Error())
		return
	}
	report, err := actions_service.GetUsageReport(ctx, group, from, to, nil, 100)
	if err != nil {
		ctx.ServerError("GetUsageReport", err)
		return
	}
	ctx.Data["Title"] = ctx.Tr("actions.actions")
	ctx.Data["PageIsAdminActionsUsage"] = true
	ctx.Data["GroupBy"] = string(group)
	ctx.Data["From"] = from.AsTime().UTC().Format(time.DateOnly)
	ctx.Data["To"] = to.AsTime().UTC().Format(time.DateOnly)
	ctx.Data["Report"] = report
	ctx.HTML(http.StatusOK, tplActionsUsage)
}
