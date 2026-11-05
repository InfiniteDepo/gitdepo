// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"errors"
	"net/http"
	"net/url"

	audit_model "forgejo.org/models/audit"
	org_model "forgejo.org/models/organization"
	"forgejo.org/modules/base"
	"forgejo.org/modules/util"
	"forgejo.org/services/context"
	org_service "forgejo.org/services/org"
)

const tplSettingsVerifiedDomains base.TplName = "org/settings/verified_domains"

// VerifiedDomains shows the verified domains of an organization, the DNS record for the domain in ?domain= and the
// member restriction.
func VerifiedDomains(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("org.settings.verified_domains")
	ctx.Data["PageIsSettingsVerifiedDomains"] = true
	org := ctx.Org.Organization

	domains, err := org_model.GetVerifiedDomains(ctx, org.ID)
	if err != nil {
		ctx.ServerError("GetVerifiedDomains", err)
		return
	}
	required, err := org_model.IsVerifiedDomainRequired(ctx, org.ID)
	if err != nil {
		ctx.ServerError("IsVerifiedDomainRequired", err)
		return
	}
	if required {
		ctx.Data["NonQualifying"], err = org_model.NonQualifyingMembers(ctx, org.ID)
		if err != nil {
			ctx.ServerError("NonQualifyingMembers", err)
			return
		}
	}
	ctx.Data["Domains"] = domains
	ctx.Data["Required"] = required
	ctx.Data["EmailConfirmationRequired"] = org_model.EmailConfirmationRequired()
	ctx.Data["MaxDomains"] = org_service.MaxVerifiedDomains
	ctx.Data["CanAdd"] = len(domains) < org_service.MaxVerifiedDomains

	if q := ctx.FormString("domain"); q != "" {
		domain, err := org_service.NormalizeDomain(q)
		if err != nil {
			ctx.Flash.Error(ctx.Tr("org.settings.verified_domains.err_invalid"), true)
		} else {
			ctx.Data["PendingDomain"] = domain
			ctx.Data["RecordName"] = org_service.DomainRecordName(domain)
			ctx.Data["RecordValue"] = org_service.DomainRecordValue(org.ID, domain)
		}
	}
	ctx.HTML(http.StatusOK, tplSettingsVerifiedDomains)
}

// VerifiedDomainsVerify verifies a domain by its DNS record, or for a site admin without DNS.
func VerifiedDomainsVerify(ctx *context.Context) {
	link := ctx.Org.OrgLink + "/settings/verified_domains"
	domain := ctx.FormString("domain")
	err := org_service.VerifyDomain(ctx, ctx.Org.Organization, ctx.Doer, domain, ctx.FormBool("without_dns"))
	switch {
	case err == nil:
		normalized, _ := org_service.NormalizeDomain(domain)
		ctx.Flash.Success(ctx.Tr("org.settings.verified_domains.verified", normalized))
	case errors.Is(err, util.ErrPermissionDenied):
		ctx.Error(http.StatusForbidden)
		return
	case errors.Is(err, org_service.ErrDomainRecordNotFound):
		ctx.Flash.Error(ctx.Tr("org.settings.verified_domains.err_not_found"))
		link += "?domain=" + url.QueryEscape(domain)
	case errors.Is(err, org_service.ErrInvalidDomain):
		ctx.Flash.Error(ctx.Tr("org.settings.verified_domains.err_invalid"))
	case errors.Is(err, org_service.ErrTooManyDomains):
		ctx.Flash.Error(ctx.Tr("org.settings.verified_domains.max", org_service.MaxVerifiedDomains))
	case errors.Is(err, org_model.ErrDomainVerifiedByOtherOrg):
		ctx.Flash.Error(ctx.Tr("org.settings.verified_domains.err_taken"))
	default:
		ctx.ServerError("VerifyDomain", err)
		return
	}
	ctx.Redirect(link)
}

// VerifiedDomainsRemove removes a verified domain.
func VerifiedDomainsRemove(ctx *context.Context) {
	domain := ctx.FormString("domain")
	if err := org_model.RemoveVerifiedDomain(ctx, ctx.Org.Organization.AsUser(), domain); err != nil {
		ctx.ServerError("RemoveVerifiedDomain", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("org.settings.verified_domains.removed", domain))
	ctx.Redirect(ctx.Org.OrgLink + "/settings/verified_domains")
}

// VerifiedDomainsRequire turns the member restriction on or off.
func VerifiedDomainsRequire(ctx *context.Context) {
	err := org_service.SetVerifiedDomainRequired(ctx, ctx.Org.Organization, ctx.FormBool("require"))
	switch {
	case err == nil:
		ctx.Flash.Success(ctx.Tr("org.settings.verified_domains.saved"))
	case errors.Is(err, org_service.ErrNoVerifiedDomains):
		ctx.Flash.Error(ctx.Tr("org.settings.verified_domains.require_no_domains"))
	case errors.Is(err, org_service.ErrEmailConfirmationOff):
		ctx.Flash.Error(ctx.Tr("org.settings.verified_domains.require_confirmation_off"))
	default:
		ctx.ServerError("SetVerifiedDomainRequired", err)
		return
	}
	ctx.Redirect(ctx.Org.OrgLink + "/settings/verified_domains")
}

// flashTeamAddRefusal flashes why a user can't join an organization that requires a verified email domain, or
// why a team whose members are part of deployment protection refused the request (audit_model.ErrNotOwnAct), and
// reports whether err was one of them.
func flashTeamAddRefusal(ctx *context.Context, err error, name string) bool {
	if errors.Is(err, audit_model.ErrNotOwnAct) { // a team whose members are part of deployment protection
		ctx.Flash.Error(ctx.Tr("org.teams.add_member_not_own_act"))
		return true
	}
	var e org_model.ErrUserNoVerifiedDomainEmail
	if !errors.As(err, &e) {
		return false
	}
	if e.ConfirmationOff {
		ctx.Flash.Error(ctx.Tr("org.settings.verified_domains.err_confirmation_off"))
	} else {
		ctx.Flash.Error(ctx.Tr("org.settings.verified_domains.err_member", name))
	}
	return true
}
