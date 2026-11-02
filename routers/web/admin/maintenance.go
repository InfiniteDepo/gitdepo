// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"net/http"
	"time"

	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	"forgejo.org/services/context"
	maintenance_service "forgejo.org/services/maintenance"
)

const tplMaintenance base.TplName = "admin/maintenance"

// Maintenance shows the maintenance mode settings
func Maintenance(ctx *context.Context) {
	s := setting.GetMaintenance(ctx)
	ctx.Data["Title"] = ctx.Tr("admin.maintenance")
	ctx.Data["PageIsAdminMaintenance"] = true
	ctx.Data["MaintenanceModes"] = setting.MaintenanceModes
	ctx.Data["State"] = s
	ctx.Data["until"] = formatAnnouncementTime(timeutil.TimeStamp(s.Until))
	ctx.Data["TimeZone"] = time.Now().In(setting.DefaultUILocation).Format("MST, UTC-07:00")
	ctx.HTML(http.StatusOK, tplMaintenance)
}

// MaintenancePost turns maintenance mode on or off
func MaintenancePost(ctx *context.Context) {
	link := setting.AppSubURL + "/admin/maintenance"
	until, err := parseAnnouncementTime(ctx.FormString("until"))
	if err != nil {
		ctx.Flash.Error(ctx.Tr("admin.maintenance.invalid_until"))
		ctx.Redirect(link)
		return
	}
	var t time.Time
	if until != 0 {
		t = until.AsTime()
	}
	err = maintenance_service.Set(ctx, ctx.Doer, ctx.FormString("mode"), ctx.FormString("message"), t)
	switch {
	case err == nil:
		ctx.Flash.Success(ctx.Tr("admin.maintenance.saved"))
	case errors.Is(err, maintenance_service.ErrSetByConfig):
		ctx.Flash.Error(ctx.Tr("admin.maintenance.from_config"))
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Flash.Error(err.Error())
	default:
		ctx.ServerError("Set", err)
		return
	}
	ctx.Redirect(link)
}
