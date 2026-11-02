// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package shared

import (
	"net/http"

	"forgejo.org/models/unit"
	"forgejo.org/modules/base"
	"forgejo.org/routers/common"
	"forgejo.org/services/accessreport"
	"forgejo.org/services/context"
)

// AccessReport shows who can access the repositories of the owner, or of the instance if ownerID is 0, paged by
// repository, or exports every page with ?format=csv|json.
func AccessReport(ctx *context.Context, ownerID int64, tpl base.TplName) {
	report := &common.AccessReport{OwnerID: ownerID, Doer: ctx.Doer, Admin: ctx.Doer.IsAdmin, Filter: accessreport.ParseFilter(ctx.FormString)}
	if format := ctx.FormString("format"); format == "csv" || format == "json" {
		if err := report.Export(ctx.Base, format); err != nil {
			ctx.ServerError("AccessReport", err)
		}
		return
	}

	page := max(ctx.FormInt("page"), 1)
	limit := ctx.FormInt("limit")
	if limit <= 0 {
		limit = 20
	}
	limit = min(limit, 100)
	lines, total, activity, err := report.Page(ctx.Base, page, limit)
	if err != nil {
		ctx.ServerError("AccessReport", err)
		return
	}
	ctx.Data["Title"] = ctx.Tr("access_report.title")
	ctx.Data["Lines"] = lines
	ctx.Data["ShowActivity"] = activity
	ctx.Data["ShowPeople"] = ctx.Doer.IsAdmin
	ctx.Data["Units"] = unit.Units
	ctx.Data["Filter"] = ctx.Req.URL.Query()
	query := ctx.Req.URL.Query()
	query.Del("page")
	query.Set("format", "csv")
	ctx.Data["CSVLink"] = "?" + query.Encode()
	query.Set("format", "json")
	ctx.Data["JSONLink"] = "?" + query.Encode()

	pager := context.NewPagination(int(total), limit, page, 5)
	for _, k := range []string{"mode", "unit", "type", "external", "inactive_days", "limit"} {
		pager.AddParamString(k, ctx.FormString(k))
	}
	ctx.Data["Page"] = pager
	ctx.HTML(http.StatusOK, tpl)
}
