// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"net/http"

	"forgejo.org/modules/base"
	"forgejo.org/services/accessreport"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

const tplUserAccess base.TplName = "admin/user/access"

// UserAccess shows everything that gives a user access.
func UserAccess(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("access_report.title")
	ctx.Data["PageIsAdminUsers"] = true
	u := prepareUserInfo(ctx)
	if ctx.Written() {
		return
	}
	ua, err := accessreport.ForUser(ctx, u, nil)
	if err != nil {
		ctx.ServerError("ForUser", err)
		return
	}
	ctx.Data["Access"] = convert.ToUserAccess(ctx, ua, ctx.Doer)
	ctx.HTML(http.StatusOK, tplUserAccess)
}
