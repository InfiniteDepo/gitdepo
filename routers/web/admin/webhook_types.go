// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"net/http"

	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	"forgejo.org/services/context"
	webhook_service "forgejo.org/services/webhook"
)

const tplWebhookTypes base.TplName = "admin/webhook_types"

// WebhookTypes shows which webhook types can be added
func WebhookTypes(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.webhook_types")
	ctx.Data["PageIsAdminWebhookTypes"] = true
	ctx.Data["WebhookList"] = webhook_service.List()
	ctx.Data["Disabled"] = webhook_service.DisabledTypes(ctx)
	ctx.HTML(http.StatusOK, tplWebhookTypes)
}

// WebhookTypesPost stores the types that are not ticked as disabled
func WebhookTypesPost(ctx *context.Context) {
	var disabled []string
	for _, h := range webhook_service.List() {
		if !ctx.FormBool("enabled_" + h.Type()) {
			disabled = append(disabled, h.Type())
		}
	}
	err := webhook_service.SetDisabledTypes(ctx, ctx.Doer, disabled)
	if errors.Is(err, util.ErrInvalidArgument) {
		ctx.Error(http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		ctx.ServerError("SetDisabledTypes", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("admin.webhook_types.saved"))
	ctx.Redirect(setting.AppSubURL + "/admin/webhook-types")
}
