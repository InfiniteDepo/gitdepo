// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"net/http"
	"strings"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/modules/base"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	shared_user "forgejo.org/routers/web/shared/user"
	"forgejo.org/services/context"
)

const tplSettingsActions base.TplName = "org/settings/actions"

// ActionsRetention shows the run retention of the organization. The route is for organization owners only.
func ActionsRetention(ctx *context.Context) {
	if err := shared_user.LoadHeaderCount(ctx); err != nil {
		ctx.ServerError("LoadHeaderCount", err)
		return
	}
	days, err := actions_model.GetOrgRunRetentionDays(ctx, ctx.Org.Organization.ID)
	if err != nil {
		ctx.ServerError("GetOrgRunRetentionDays", err)
		return
	}
	ctx.Data["Title"] = ctx.Tr("actions.settings.run_retention")
	ctx.Data["PageIsSharedSettingsRetention"] = true
	ctx.Data["PageType"] = "retention"
	ctx.Data["RunRetentionDays"] = days
	ctx.Data["InstanceRunRetentionDays"] = setting.Actions.RunRetentionDays
	ctx.Data["InstanceRunRetentionMaxDays"] = setting.Actions.RunRetentionMaxDays
	ctx.Data["MaxRunRetentionDays"] = actions_model.MaxRunRetentionDays
	ctx.HTML(http.StatusOK, tplSettingsActions)
}

// ActionsRetentionPost saves the number of days after which completed runs of the repositories of the organization
// are deleted. Repositories can only shorten it.
func ActionsRetentionPost(ctx *context.Context) {
	redirect := ctx.Org.OrgLink + "/settings/actions/retention"
	days, ok := actions_model.ParseRunRetentionDays(strings.TrimSpace(ctx.FormString("run_retention_days")))
	if !ok {
		ctx.Flash.Error(ctx.Tr("actions.settings.run_retention.invalid", actions_model.MaxRunRetentionDays))
		ctx.Redirect(redirect)
		return
	}
	if err := actions_model.SetOrgRunRetentionDays(ctx, ctx.Org.Organization.ID, days); err != nil {
		ctx.ServerError("SetOrgRunRetentionDays", err)
		return
	}
	log.Info("User %d set the run retention of organization %d to %d days", ctx.Doer.ID, ctx.Org.Organization.ID, days)
	ctx.Flash.Success(ctx.Tr("actions.settings.run_retention.saved"))
	ctx.Redirect(redirect)
}
