// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"forgejo.org/modules/base"
	"forgejo.org/routers/web/shared"
	"forgejo.org/services/context"
)

const tplAccessReports base.TplName = "admin/access_reports"

// AccessReports shows who can access every repository, with what access, and through what.
func AccessReports(ctx *context.Context) {
	ctx.Data["PageIsAdminAccessReports"] = true
	shared.AccessReport(ctx, 0, tplAccessReports)
}
