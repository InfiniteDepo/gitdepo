// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"html"
	"net/http"
	"strings"

	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	"forgejo.org/routers/common"
	"forgejo.org/services/context"
	logshipping_service "forgejo.org/services/logshipping"
)

const tplLogShipping base.TplName = "admin/log_shipping"

// logShippingAdmin is checked by every handler on top of the admin route group: this decides where logs are sent.
func logShippingAdmin(ctx *context.Context) bool {
	if !common.IsMaintenanceAdmin(ctx.Doer) {
		ctx.Error(http.StatusForbidden, "site administrators only")
		return false
	}
	return true
}

func renderLogShipping(ctx *context.Context, edit *logshipping_service.Destination) {
	list, err := logshipping_service.List(ctx)
	if err != nil {
		ctx.ServerError("List", err)
		return
	}
	ctx.Data["Title"] = ctx.Tr("admin.log_shipping")
	ctx.Data["PageIsAdminLogShipping"] = true
	ctx.Data["Destinations"] = list
	ctx.Data["LogTypes"] = append([]string{"all"}, setting.LogShippingLogTypes()...)
	ctx.Data["Levels"] = []string{"trace", "debug", "info", "warn", "error"}
	ctx.Data["Edit"] = edit
	selected := map[string]bool{}
	if edit != nil {
		for _, t := range edit.LogTypes {
			selected[t] = true
		}
		var headers []string
		for _, h := range edit.Headers {
			headers = append(headers, h.Name+":") // values are never shown; an empty value keeps the stored one
		}
		ctx.Data["HeaderLines"] = strings.Join(headers, "\n")
	}
	ctx.Data["SelectedTypes"] = selected
	ctx.HTML(http.StatusOK, tplLogShipping)
}

// LogShipping lists the log destinations and shows the form for a new one
func LogShipping(ctx *context.Context) {
	if !logShippingAdmin(ctx) {
		return
	}
	renderLogShipping(ctx, nil)
}

// EditLogShipping shows a destination
func EditLogShipping(ctx *context.Context) {
	if !logShippingAdmin(ctx) {
		return
	}
	d, err := logshipping_service.Get(ctx, ctx.Params("id"))
	if err != nil {
		logShippingError(ctx, err)
		return
	}
	renderLogShipping(ctx, &d)
}

func logShippingInput(ctx *context.Context) logshipping_service.Input {
	str := func(key string) *string { s := strings.TrimSpace(ctx.FormString(key)); return &s }
	in := logshipping_service.Input{
		Name: str("name"), Endpoint: str("endpoint"), Level: str("level"), Expression: str("expression"), Exclusion: str("exclusion"),
	}
	enabled, ndjson, types, headers := ctx.FormBool("enabled"), ctx.FormBool("ndjson"), ctx.FormStrings("log_types"), []logshipping_service.HeaderInput{}
	in.Enabled, in.NDJSON, in.LogTypes, in.Headers = &enabled, &ndjson, &types, &headers
	if key := ctx.FormString("key"); key != "" {
		in.Key = &key
	}
	if t := ctx.FormString("type"); t != "" {
		in.Type = &t
	}
	for line := range strings.SplitSeq(ctx.FormString("headers"), "\n") {
		if name, value, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(name) != "" {
			headers = append(headers, logshipping_service.HeaderInput{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
		}
	}
	return in
}

func logShippingError(ctx *context.Context, err error) {
	switch {
	case errors.Is(err, util.ErrNotExist):
		ctx.NotFound("LogShipping", err)
	case errors.Is(err, util.ErrInvalidArgument), errors.Is(err, logshipping_service.ErrRateLimited):
		// the flash renders HTML and the message can carry what the admin typed
		ctx.Flash.Error(html.EscapeString(err.Error()))
		ctx.Redirect(setting.AppSubURL + "/admin/log-shipping")
	default:
		ctx.ServerError("LogShipping", err)
	}
}

// LogShippingPost creates a destination, or saves the one in the path
func LogShippingPost(ctx *context.Context) {
	if !logShippingAdmin(ctx) {
		return
	}
	id := ctx.Params("id")
	d, err := logshipping_service.Save(ctx, ctx.Doer, id, logShippingInput(ctx))
	if err != nil {
		logShippingError(ctx, err)
		return
	}
	ctx.Flash.Success(ctx.Tr("admin.log_shipping.saved"))
	ctx.Redirect(setting.AppSubURL + "/admin/log-shipping/destinations/" + d.ID)
}

// LogShippingDelete deletes a destination
func LogShippingDelete(ctx *context.Context) {
	if !logShippingAdmin(ctx) {
		return
	}
	if err := logshipping_service.Remove(ctx, ctx.Doer, ctx.Params("id")); err != nil {
		logShippingError(ctx, err)
		return
	}
	ctx.Flash.Success(ctx.Tr("admin.log_shipping.deleted"))
	ctx.Redirect(setting.AppSubURL + "/admin/log-shipping")
}

// LogShippingTest sends a test event to a saved destination
func LogShippingTest(ctx *context.Context) {
	if !logShippingAdmin(ctx) {
		return
	}
	id := ctx.Params("id")
	ctx.Req.Body = http.MaxBytesReader(ctx.Resp, ctx.Req.Body, 1024) // the test takes no input
	res, err := logshipping_service.Test(ctx, id)
	if err != nil {
		logShippingError(ctx, err)
		return
	}
	if res.Error != "" {
		ctx.Flash.Error(ctx.Tr("admin.log_shipping.test_failed", res.Error))
	} else {
		ctx.Flash.Success(ctx.Tr("admin.log_shipping.test_ok", res.Status))
	}
	ctx.Redirect(setting.AppSubURL + "/admin/log-shipping/destinations/" + id)
}
