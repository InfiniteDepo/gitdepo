// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"net/http"

	"forgejo.org/modules/base"
	shared_security "forgejo.org/routers/web/shared/security"
	shared_user "forgejo.org/routers/web/shared/user"
	"forgejo.org/services/context"
	dependency_service "forgejo.org/services/dependency"
	secretscan_service "forgejo.org/services/secretscan"
)

const (
	tplSecurity base.TplName = "org/security"
	tplSecrets  base.TplName = "org/security_secrets"

	tplSecretPatterns base.TplName = "org/security_patterns"
)

// MustEnableSecurity answers 404 (owners too) while the dependency graph is off for the site or the organization.
func MustEnableSecurity(ctx *context.Context) {
	if !dependency_service.OrgEnabled(ctx, ctx.Org.Organization.ID) {
		ctx.NotFound("MustEnableSecurity", nil)
	}
}

// SecurityIndex sends `/org/{org}/security` to its first tab.
func SecurityIndex(ctx *context.Context) {
	ctx.Redirect(ctx.Org.OrgLink + "/security/" + shared_security.Vulnerabilities)
}

func securityScope(ctx *context.Context) dependency_service.SearchScope {
	return dependency_service.SearchScope{Org: ctx.Org.Organization, Doer: ctx.Doer, Admin: ctx.IsUserSiteAdmin()}
}

// SecurityVulnerabilities searches the alerts of the organization's repositories, by advisory or package.
func SecurityVulnerabilities(ctx *context.Context) {
	securitySearch(ctx, shared_security.Vulnerabilities)
}

// SecurityDependencies searches the organization's dependencies by package.
func SecurityDependencies(ctx *context.Context) { securitySearch(ctx, shared_security.Dependencies) }

func securitySearch(ctx *context.Context, kind string) {
	if !shared_security.Search(ctx, securityScope(ctx), kind, ctx.Org.OrgLink+"/security/"+kind) {
		return
	}
	if err := shared_user.LoadHeaderCount(ctx); err != nil {
		ctx.ServerError("LoadHeaderCount", err)
		return
	}
	ctx.Data["Title"] = ctx.Tr("security_search.title")
	ctx.Data["PageIsOrgSecurity"] = true
	ctx.HTML(http.StatusOK, tplSecurity)
}

// SecurityVulnerabilitiesExport downloads the alert search as CSV or JSON.
func SecurityVulnerabilitiesExport(ctx *context.Context) {
	shared_security.Export(ctx, securityScope(ctx), shared_security.Vulnerabilities, ctx.Org.OrgLink+"/security/vulnerabilities")
}

// SecurityDependenciesExport downloads the dependency search as CSV or JSON.
func SecurityDependenciesExport(ctx *context.Context) {
	shared_security.Export(ctx, securityScope(ctx), shared_security.Dependencies, ctx.Org.OrgLink+"/security/dependencies")
}

// MustSeeSecretAlerts answers 404 to the list of secret alerts (and its download) for everyone it is not for: see
// context.Organization.SecretAlerts.
func MustSeeSecretAlerts(ctx *context.Context) {
	if !ctx.Org.SecretAlerts {
		ctx.NotFound("MustSeeSecretAlerts", nil)
	}
}

// secretScanningOff tells whether secret scanning is off for the organization's repositories, by the site or by the
// organization: their alerts are hidden then, so the list is a banner and there is nothing to download.
func secretScanningOff(ctx *context.Context) (site, org bool, err error) {
	if !secretscan_service.SiteEnabled(ctx) {
		return true, false, nil
	}
	sw, err := secretscan_service.GetOrgSwitch(ctx, ctx.Org.Organization.ID)
	return false, !sw.On, err
}

// secretScope is the list of the organization's secret alerts the viewer may see: every repository for owners, site
// admins and auditors, the ones with write access for a member.
func secretScope(ctx *context.Context) secretscan_service.Scope {
	narrow := ctx.Org.SecretAlertsNarrow
	return secretscan_service.Scope{
		Org: ctx.Org.Organization, Doer: ctx.Doer, Narrow: narrow,
		Admin: ctx.IsUserSiteAdmin() || (!narrow && !ctx.Org.IsOwner), // an auditor reads every repository
	}
}

// SecurityAlerts lists the secret alerts of the organization's repositories.
func SecurityAlerts(ctx *context.Context) {
	siteOff, orgOff, err := secretScanningOff(ctx)
	if err != nil {
		ctx.ServerError("secretScanningOff", err)
		return
	}
	if siteOff || orgOff {
		ctx.Data["SecretsSiteOff"], ctx.Data["SecretsOrgOff"] = siteOff, orgOff
	} else if !shared_security.Secrets(ctx, secretScope(ctx), ctx.Org.OrgLink+"/security/secrets") {
		return
	}
	if err := shared_user.LoadHeaderCount(ctx); err != nil {
		ctx.ServerError("LoadHeaderCount", err)
		return
	}
	if ctx.Org.IsOwner {
		ctx.Data["SecretOffListLink"] = ctx.Org.OrgLink + "/settings/code_security/secret_scanning/repos"
	}
	ctx.Data["Title"] = ctx.Tr("secret_search.title")
	ctx.Data["PageIsOrgSecurity"] = true
	ctx.HTML(http.StatusOK, tplSecrets)
}

// SecurityAlertsExport downloads the secret alert list as CSV; while scanning is off there is none (404).
func SecurityAlertsExport(ctx *context.Context) {
	siteOff, orgOff, err := secretScanningOff(ctx)
	if err != nil {
		ctx.ServerError("secretScanningOff", err)
		return
	}
	if siteOff || orgOff {
		ctx.NotFound("SecurityAlertsExport", nil)
		return
	}
	shared_security.SecretsExport(ctx, secretScope(ctx), ctx.Org.OrgLink+"/security/secrets")
}

// SecurityPatterns lists the organization's custom patterns and the site's, read-only: owners read the rules (and
// change them in the settings), everyone else the names and keywords.
func SecurityPatterns(ctx *context.Context) {
	scope := secretScope(ctx)
	org := ctx.Org.Organization.AsUser()
	if err := shared_security.LoadPatterns(ctx, org, scope, "", ctx.Org.OrgLink+"/security/secrets", false, ctx.Org.IsOwner); err != nil {
		ctx.ServerError("LoadPatterns", err)
		return
	}
	if err := shared_user.LoadHeaderCount(ctx); err != nil {
		ctx.ServerError("LoadHeaderCount", err)
		return
	}
	ctx.Data["Title"] = ctx.Tr("secret_pattern.title")
	ctx.Data["PageIsOrgSecurity"] = true
	ctx.Data["CanManagePatterns"] = ctx.Org.IsOwner // the acting owner, site admins included: the settings' rule
	ctx.HTML(http.StatusOK, tplSecretPatterns)
}
