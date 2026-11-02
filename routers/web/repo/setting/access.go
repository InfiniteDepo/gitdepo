// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"net/http"

	"forgejo.org/models/unit"
	"forgejo.org/modules/base"
	"forgejo.org/modules/util"
	"forgejo.org/services/accessreport"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

const tplAccess base.TplName = "repo/settings/access"

// Access shows who can access the repository, with what access, and through what.
func Access(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("access_report.title")
	ctx.Data["PageIsSettingsAccess"] = true

	rows, activity, err := accessreport.ForRepo(ctx, ctx.Repo.Repository, ctx.Doer.IsAdmin, ctx.Doer, accessreport.ParseFilter(ctx.FormString))
	if err != nil {
		ctx.ServerError("ForRepo", err)
		return
	}
	ctx.Data["ShowActivity"] = activity

	page := max(ctx.FormInt("page"), 1)
	limit := ctx.FormInt("limit")
	if limit <= 0 {
		limit = 50
	}
	ctx.Data["Rows"] = convert.ToAccessRows(ctx, util.PaginateSlice(rows, page, limit).([]*accessreport.Row), ctx.Doer)
	pager := context.NewPagination(len(rows), limit, page, 5)
	for _, k := range []string{"mode", "unit", "type", "external", "inactive_days", "limit"} {
		pager.AddParamString(k, ctx.FormString(k))
	}
	ctx.Data["Page"] = pager
	ctx.Data["Units"] = unit.Units
	ctx.Data["Filter"] = ctx.Req.URL.Query()
	ctx.HTML(http.StatusOK, tplAccess)
}
