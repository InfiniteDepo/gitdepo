// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"forgejo.org/modules/base"
	"forgejo.org/routers/web/shared"
	"forgejo.org/services/context"
)

const tplSettingsAccessReport base.TplName = "org/settings/access_report"

// AccessReport shows who can access the organization's repositories, with what access, and through what.
func AccessReport(ctx *context.Context) {
	ctx.Data["PageIsSettingsAccessReport"] = true
	shared.AccessReport(ctx, ctx.Org.Organization.ID, tplSettingsAccessReport)
}
