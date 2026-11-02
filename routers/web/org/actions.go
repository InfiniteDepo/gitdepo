// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"net/http"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/modules/base"
	"forgejo.org/modules/timeutil"
	shared_actions "forgejo.org/routers/web/shared/actions"
	shared_user "forgejo.org/routers/web/shared/user"
	actions_service "forgejo.org/services/actions"
	"forgejo.org/services/context"
)

// tplRuns is the template of the workflow runs of an organization
const tplRuns base.TplName = "org/actions/runs"

// tplOverview is the template of the overview of the Actions of an organization
const tplOverview base.TplName = "org/actions/overview"

// overviewLimit is how many failing runs and queued jobs the overview lists
const overviewLimit = 50

// Runs lists the workflow runs of the repositories of the organization that the doer can read the Actions of.
func Runs(ctx *context.Context) {
	if !actions_service.OrgRunsEnabled() || repo_model.HiddenUnits(ctx, ctx.ContextUser).Contains(unit.TypeActions) {
		ctx.NotFound("Runs", nil)
		return
	}
	if !shared_actions.LoadRuns(ctx, ctx.Org.Organization, ctx.IsUserSiteAdmin(), ctx.Org.OrgLink+"/actions", "") {
		return
	}
	if err := shared_user.LoadHeaderCount(ctx); err != nil {
		ctx.ServerError("Runs", err)
		return
	}
	ctx.Data["Title"] = ctx.Tr("actions.actions")
	ctx.Data["PageIsOrgActions"] = true
	ctx.Data["PageIsOrgActionsRuns"] = true

	ctx.HTML(http.StatusOK, tplRuns)
}

// Overview shows the numbers, the failing default branches and the queue of the runs that the doer can see.
func Overview(ctx *context.Context) {
	if !actions_service.OrgRunsEnabled() || repo_model.HiddenUnits(ctx, ctx.ContextUser).Contains(unit.TypeActions) {
		ctx.NotFound("Overview", nil)
		return
	}
	org, doer, admin, now := ctx.Org.Organization, ctx.Doer, ctx.IsUserSiteAdmin(), timeutil.TimeStampNow()
	overview, err := actions_service.GetOrgOverview(ctx, org, doer, admin, nil, now)
	if err != nil {
		ctx.ServerError("GetOrgOverview", err)
		return
	}
	failing, failingTotal, err := actions_service.FindOrgFailingNow(ctx, org, doer, admin, nil, overviewLimit)
	var queue []*actions_service.QueuedJob
	var queueTotal int64
	if err == nil {
		queue, queueTotal, err = actions_service.FindOrgQueue(ctx, org, doer, admin, nil, overviewLimit, now)
	}
	if err == nil {
		err = shared_user.LoadHeaderCount(ctx)
	}
	if err != nil {
		ctx.ServerError("Overview", err)
		return
	}
	ctx.Data["Title"] = ctx.Tr("actions.actions")
	ctx.Data["PageIsOrgActions"] = true
	ctx.Data["PageIsOrgActionsOverview"] = true
	ctx.Data["Overview"] = overview
	ctx.Data["Failing"] = failing
	ctx.Data["FailingTotal"] = failingTotal
	ctx.Data["Queue"] = queue
	ctx.Data["QueueTotal"] = queueTotal
	ctx.HTML(http.StatusOK, tplOverview)
}
