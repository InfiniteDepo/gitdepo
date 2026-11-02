// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"net/http"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/modules/base"
	"forgejo.org/modules/timeutil"
	"forgejo.org/routers/web/repo"
	shared_user "forgejo.org/routers/web/shared/user"
	"forgejo.org/services/context"
	metrics_service "forgejo.org/services/metrics"
)

const tplMetrics base.TplName = "org/metrics"

// Metrics shows the pull request metrics of the repositories of the organization the doer can read the pull requests
// of, or sends them as CSV with ?format=csv. It is for members and site admins.
func Metrics(ctx *context.Context) {
	if unit.TypePullRequests.UnitGlobalDisabled() || repo_model.HiddenUnits(ctx, ctx.ContextUser).Contains(unit.TypePullRequests) {
		ctx.NotFound("Metrics", nil)
		return
	}
	days := metrics_service.ParsePeriod(ctx.FormString("period"))
	report, err := metrics_service.OrgReport(ctx, ctx.Org.Organization.ID, ctx.Doer, ctx.IsUserSiteAdmin(), days, ctx.Org.IsOwner, timeutil.TimeStampNow())
	if err != nil {
		ctx.ServerError("OrgReport", err)
		return
	}
	if ctx.FormString("format") == "csv" {
		repo.ServeMetricsCSV(ctx, report)
		return
	}
	if err := shared_user.LoadHeaderCount(ctx); err != nil {
		ctx.ServerError("LoadHeaderCount", err)
		return
	}
	ctx.Data["Title"] = ctx.Tr("metrics.title")
	ctx.Data["PageIsOrgMetrics"] = true
	ctx.Data["Report"] = report
	ctx.Data["MaxPRs"] = metrics_service.MaxPRs
	ctx.Data["MetricsLink"] = ctx.Org.OrgLink + "/metrics"
	ctx.HTML(http.StatusOK, tplMetrics)
}
