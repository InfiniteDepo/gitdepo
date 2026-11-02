// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	audit_service "forgejo.org/services/audit"
	"forgejo.org/services/context"
)

const tplAuditRetention base.TplName = "admin/audit_retention"

// auditRetentionLine is "Retention: 1 year" and, while a lowering waits, when it takes effect.
func auditRetentionLine(ctx *context.Context) string {
	s, now := setting.Config().AuditRetention.Value(ctx), time.Now()
	line := ctx.Locale.TrString("admin.audit.retention", ctx.Locale.TrString("admin.audit_retention.option."+strconv.Itoa(s.Effective(now))))
	if s.Pending(now) {
		line += " · " + ctx.Locale.TrString("admin.audit_retention.pending",
			ctx.Locale.TrString("admin.audit_retention.option."+strconv.Itoa(s.Target())), s.PendingUntil(now).UTC().Format("2006-01-02 15:04 UTC"))
	}
	return line
}

type auditRetentionOption struct {
	Days       int
	Projection string // "about N entries, S" at the current rate; "" while nothing was written
}

// AuditRetention shows the retention of the audit log, how much the log holds and would hold with each choice, and
// the form to change it.
func AuditRetention(ctx *context.Context) {
	now := time.Now()
	s := setting.Config().AuditRetention.Value(ctx)
	vol, err := audit_service.GetVolume(ctx, now)
	if err != nil {
		ctx.ServerError("GetVolume", err)
		return
	}
	options := make([]auditRetentionOption, 0, len(setting.AuditRetentionAllowed))
	for _, days := range setting.AuditRetentionAllowed {
		o := auditRetentionOption{Days: days}
		if n := vol.PerDay * int64(days); n > 0 {
			o.Projection = ctx.Locale.TrString("admin.audit_retention.projection", ctx.Locale.PrettyNumber(n), ctx.Locale.TrSize(n*audit_service.EntryBytes).String())
		}
		options = append(options, o)
	}
	ctx.Data["Title"] = ctx.Tr("admin.audit_retention")
	ctx.Data["PageIsAdminAudit"] = true
	ctx.Data["RetentionLine"] = auditRetentionLine(ctx)
	ctx.Data["Options"] = options
	ctx.Data["Current"] = s.Effective(now)
	ctx.Data["ShortRetention"] = s.Target() < setting.AuditRetentionDefault
	ctx.Data["VolumeLine"] = ctx.Locale.TrString("admin.audit_retention.volume", ctx.Locale.PrettyNumber(vol.Kept),
		ctx.Locale.TrSize(vol.Kept*audit_service.EntryBytes).String(), ctx.Locale.PrettyNumber(vol.PerDay))
	ctx.HTML(http.StatusOK, tplAuditRetention)
}

// AuditRetentionPost stores the chosen retention; only the number of days comes from the form.
func AuditRetentionPost(ctx *context.Context) {
	days, err := strconv.Atoi(ctx.FormString("days"))
	if err == nil {
		err = audit_service.SetRetention(ctx, days)
	}
	if errors.Is(err, util.ErrInvalidArgument) || errors.Is(err, strconv.ErrSyntax) || errors.Is(err, strconv.ErrRange) {
		ctx.Error(http.StatusBadRequest, "invalid retention")
		return
	}
	if err != nil {
		ctx.ServerError("SetRetention", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("admin.audit_retention.saved"))
	ctx.Redirect(setting.AppSubURL + "/admin/audit/retention")
}
