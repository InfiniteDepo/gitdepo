// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"net/http"

	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	shared_security "forgejo.org/routers/web/shared/security"
	"forgejo.org/services/context"
	secretscan_service "forgejo.org/services/secretscan"
)

const (
	tplSecretPatterns base.TplName = "admin/secret_patterns"

	secretPatternsLink = "/admin/security/patterns"
)

// SecretPatterns lists the site's custom secret patterns: site admins change them and read the rules, auditors read
// the names and keywords only.
func SecretPatterns(ctx *context.Context) { secretPatternsPage(ctx, http.StatusOK) }

func secretPatternsPage(ctx *context.Context, status int) {
	ctx.Data["Title"] = ctx.Tr("secret_pattern.title")
	ctx.Data["PageIsAdminSecretPatterns"] = true
	scope := secretscan_service.Scope{Doer: ctx.Doer, Admin: true}
	if err := shared_security.LoadPatterns(ctx, nil, scope, setting.AppSubURL+secretPatternsLink, setting.AppSubURL+secretAlertsLink, ctx.Doer.IsAdmin, ctx.Doer.IsAdmin); err != nil {
		ctx.ServerError("LoadPatterns", err)
		return
	}
	ctx.Data["SecretSiteOn"] = secretscan_service.SiteEnabled(ctx)
	ctx.HTML(status, tplSecretPatterns)
}

// SecretPatternAdd saves a site pattern; a refusal shows the page again with the reason.
func SecretPatternAdd(ctx *context.Context) {
	if !shared_security.PatternAdd(ctx, nil) {
		if !ctx.Written() {
			secretPatternsPage(ctx, http.StatusUnprocessableEntity)
		}
		return
	}
	ctx.Redirect(setting.AppSubURL + secretPatternsLink)
}

// SecretPatternAction renames, turns on, turns off or deletes a site pattern.
func SecretPatternAction(ctx *context.Context) {
	shared_security.PatternAction(ctx, nil, ctx.Params("action"), setting.AppSubURL+secretPatternsLink)
}
