// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"net/http"

	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/routers/common"
	shared_security "forgejo.org/routers/web/shared/security"
	"forgejo.org/services/auth"
	"forgejo.org/services/context"
	dependency_service "forgejo.org/services/dependency"
	secretscan_service "forgejo.org/services/secretscan"
)

const tplSecuritySearch base.TplName = "admin/security_search"

const tplSecretAlerts base.TplName = "admin/secret_alerts"

const secretAlertsLink = "/admin/security/secrets"

const securitySearchLink = "/admin/config/dependency-graph/"

// AuditExportReq lets a usable site admin, or an auditor reading with their own credential, post a download of what
// they may read; it runs after the sign-in check. An auditor changes nothing: the download is audited.
func AuditExportReq(ctx *context.Context) {
	if !common.UsableAuditReader(ctx.Doer) || !ctx.Doer.IsAdmin && !(ctx.Doer.IsAuditor && auth.IsHeldByUser(ctx.Authentication)) {
		ctx.Error(http.StatusForbidden)
	}
}

// SetSecuritySearchNav lets the admin menu show the two search pages only while they exist.
func SetSecuritySearchNav(ctx *context.Context) {
	ctx.Data["SecuritySearchEnabled"] = dependency_service.SiteEnabled(ctx)
}

// MustEnableSecuritySearch answers 404 to the search pages and downloads (after the access gate) while the dependency graph is
// off for the instance, so a download of nothing is never recorded.
func MustEnableSecuritySearch(ctx *context.Context) {
	if !dependency_service.SiteEnabled(ctx) {
		ctx.NotFound("MustEnableSecuritySearch", nil)
	}
}

func securitySearchScope(ctx *context.Context) dependency_service.SearchScope {
	return dependency_service.SearchScope{Doer: ctx.Doer, Admin: true}
}

// SecurityVulnerabilities searches the vulnerability alerts of every repository on the instance.
func SecurityVulnerabilities(ctx *context.Context) {
	securitySearch(ctx, shared_security.Vulnerabilities)
}

// SecurityDependencies searches the dependencies of every repository on the instance.
func SecurityDependencies(ctx *context.Context) { securitySearch(ctx, shared_security.Dependencies) }

func securitySearch(ctx *context.Context, kind string) {
	if !shared_security.Search(ctx, securitySearchScope(ctx), kind, setting.AppSubURL+securitySearchLink+kind) {
		return
	}
	if kind == shared_security.Vulnerabilities {
		ctx.Data["Title"] = ctx.Tr("security_search.vulnerabilities")
	} else {
		ctx.Data["Title"] = ctx.Tr("security_search.dependencies")
	}
	ctx.Data["PageIsAdminConfig"] = true
	ctx.Data["PageIsAdminConfigDependencyGraphVulnerabilities"] = kind == shared_security.Vulnerabilities
	ctx.Data["PageIsAdminConfigDependencyGraphDependencies"] = kind == shared_security.Dependencies
	ctx.HTML(http.StatusOK, tplSecuritySearch)
}

// SecurityVulnerabilitiesExport downloads the alert search as CSV or JSON.
func SecurityVulnerabilitiesExport(ctx *context.Context) {
	shared_security.Export(ctx, securitySearchScope(ctx), shared_security.Vulnerabilities, setting.AppSubURL+securitySearchLink+shared_security.Vulnerabilities)
}

// SecurityDependenciesExport downloads the dependency search as CSV or JSON.
func SecurityDependenciesExport(ctx *context.Context) {
	shared_security.Export(ctx, securitySearchScope(ctx), shared_security.Dependencies, setting.AppSubURL+securitySearchLink+shared_security.Dependencies)
}

// MustEnableSecretAlerts answers 404 to the download of the secret alert list (after the access gate) while secret
// scanning is off for the instance: its alerts are hidden then, and a download of nothing is never recorded.
func MustEnableSecretAlerts(ctx *context.Context) {
	if !secretscan_service.SiteEnabled(ctx) {
		ctx.NotFound("MustEnableSecretAlerts", nil)
	}
}

func secretAlertsScope(ctx *context.Context) secretscan_service.Scope {
	return secretscan_service.Scope{Doer: ctx.Doer, Admin: true}
}

// SecretAlerts lists the secret alerts of every repository on the instance, or says that secret scanning is off.
func SecretAlerts(ctx *context.Context) {
	if !secretscan_service.SiteEnabled(ctx) {
		ctx.Data["SecretsSiteOff"] = true
	} else if !shared_security.Secrets(ctx, secretAlertsScope(ctx), setting.AppSubURL+secretAlertsLink) {
		return
	}
	ctx.Data["Title"] = ctx.Tr("secret_search.title")
	ctx.Data["PageIsAdminSecretAlerts"] = true
	ctx.HTML(http.StatusOK, tplSecretAlerts)
}

// SecretAlertsExport downloads the secret alert list as CSV.
func SecretAlertsExport(ctx *context.Context) {
	shared_security.SecretsExport(ctx, secretAlertsScope(ctx), setting.AppSubURL+secretAlertsLink)
}
