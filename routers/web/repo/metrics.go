// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"net/http"

	"forgejo.org/modules/log"
	"forgejo.org/modules/timeutil"
	"forgejo.org/services/context"
	metrics_service "forgejo.org/services/metrics"
)

// Metrics shows the pull request metrics of the repository, or sends them as CSV with ?format=csv.
func Metrics(ctx *context.Context) {
	days := metrics_service.ParsePeriod(ctx.FormString("period"))
	report, err := metrics_service.RepoReport(ctx, ctx.Repo.Repository.ID, days, ctx.Repo.IsAdmin(), timeutil.TimeStampNow())
	if err != nil {
		ctx.ServerError("RepoReport", err)
		return
	}
	if ctx.FormString("format") == "csv" {
		ServeMetricsCSV(ctx, report)
		return
	}
	ctx.Data["Title"] = ctx.Tr("metrics.title")
	ctx.Data["PageIsActivity"] = true
	ctx.Data["PageIsMetrics"] = true
	ctx.Data["Report"] = report
	ctx.Data["MaxPRs"] = metrics_service.MaxPRs
	ctx.Data["MetricsLink"] = ctx.Repo.RepoLink + "/activity/metrics"
	ctx.HTML(http.StatusOK, tplActivity)
}

// ServeMetricsCSV sends the rows of report as a CSV attachment.
func ServeMetricsCSV(ctx *context.Context, report *metrics_service.Report) {
	ctx.SetServeHeaders(&context.ServeHeaderOptions{ContentType: "text/csv", ContentTypeCharset: "utf-8", Filename: "pull-request-metrics.csv"})
	ctx.Resp.Header().Set("X-Content-Type-Options", "nosniff")
	if report.Truncated {
		ctx.Resp.Header().Set("X-Truncated", "true")
	}
	if err := metrics_service.WriteCSV(ctx.Resp, report); err != nil {
		log.Error("WriteCSV: %v", err)
	}
}
