// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"errors"
	"net/http"

	"forgejo.org/models/db"
	secretscan_model "forgejo.org/models/secretscan"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	shared_security "forgejo.org/routers/web/shared/security"
	"forgejo.org/services/context"
	dependency_service "forgejo.org/services/dependency"
	secretscan_service "forgejo.org/services/secretscan"
)

const (
	tplSettingsCodeSecurity  base.TplName = "org/settings/code_security"
	tplSecretScanningOffList base.TplName = "org/settings/secret_scanning_off"
)

// CodeSecurity shows the organization's dependency graph switch.
func CodeSecurity(ctx *context.Context) { codeSecurityPage(ctx, http.StatusOK) }

// codeSecurityPage renders the page; a refused pattern is shown again with its status.
func codeSecurityPage(ctx *context.Context, status int) {
	ctx.Data["Title"] = ctx.Tr("org.settings.code_security")
	ctx.Data["PageIsOrgSettingsCodeSecurity"] = true
	sw, err := dependency_service.GetOrgSwitch(ctx, ctx.Org.Organization.ID)
	if err != nil {
		ctx.ServerError("GetOrgSwitch", err)
		return
	}
	ctx.Data["SiteEnabled"] = dependency_service.SiteEnabled(ctx)
	ctx.Data["CanChangeThere"] = ctx.Doer.IsAdmin // the site switch
	ctx.Data["Enabled"] = sw.On
	ctx.Data["Locked"] = sw.Locked
	if err := secretScanningBox(ctx); err != nil {
		ctx.ServerError("secretScanningBox", err)
		return
	}
	org := ctx.Org.Organization.AsUser()
	scope := secretscan_service.Scope{Org: ctx.Org.Organization, Doer: ctx.Doer, Admin: ctx.IsUserSiteAdmin()}
	if err := shared_security.LoadPatterns(ctx, org, scope, ctx.Org.OrgLink+"/settings/code_security/patterns", ctx.Org.OrgLink+"/security/secrets", true, true); err != nil {
		ctx.ServerError("LoadPatterns", err)
		return
	}
	ctx.HTML(status, tplSettingsCodeSecurity)
}

// secretScanningBox loads the organization's secret scanning switch and what the confirmations say: how many
// repositories there are, how many admins turned it off, and how many are scanned now.
func secretScanningBox(ctx *context.Context) error {
	sw, err := secretscan_service.GetOrgSwitch(ctx, ctx.Org.Organization.ID)
	if err != nil {
		return err
	}
	total, off, err := secretscan_model.CountOrgRepos(ctx, ctx.Org.Organization.ID)
	if err != nil {
		return err
	}
	scanned := total - off
	switch {
	case !sw.On:
		scanned = 0
	case sw.Locked:
		scanned = total
	}
	// what locking it on will turn on: every repository while the organization is off, else the ones that turned it off
	ctx.Data["SecretLockTurnsOn"] = off
	if !sw.On {
		ctx.Data["SecretLockTurnsOn"] = total
	}
	ctx.Data["SecretSiteOn"] = secretscan_service.SiteEnabled(ctx)
	ctx.Data["SecretOn"], ctx.Data["SecretLocked"] = sw.On, sw.Locked
	ctx.Data["SecretTotal"], ctx.Data["SecretOff"], ctx.Data["SecretScanned"] = total, off, scanned
	return nil
}

// SecretScanningPost stores the organization's secret scanning switch and lock (every owner may; a site administrator
// acts as one). Turning it off keeps the alerts; the lock applies the switch to every repository.
func SecretScanningPost(ctx *context.Context) {
	if err := secretscan_service.SetOrgSwitch(ctx, ctx.Org.Organization.AsUser(), ctx.FormBool("enabled"), ctx.FormBool("locked")); err != nil {
		ctx.ServerError("SetOrgSwitch", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("org.settings.secret_scanning.saved"))
	ctx.Redirect(ctx.Org.OrgLink + "/settings/code_security")
}

// secretOffRepo is a row of the list of repositories whose admins turned secret scanning off.
type secretOffRepo struct {
	FullName, Link string
	By             string // "" when the audit log has no entry (the setting was never changed through the page, or the entry is gone)
	At             timeutil.TimeStamp
}

// SecretScanningOff lists the repositories whose admins turned secret scanning off, with who and when.
func SecretScanningOff(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("org.settings.secret_scanning.off_list")
	ctx.Data["PageIsOrgSettingsCodeSecurity"] = true
	page := max(ctx.FormInt("page"), 1)
	repos, total, err := secretscan_model.FindOrgOffRepos(ctx, ctx.Org.Organization.ID, db.ListOptions{Page: page, PageSize: setting.UI.User.RepoPagingNum})
	if err != nil {
		ctx.ServerError("FindOrgOffRepos", err)
		return
	}
	rows := make([]secretOffRepo, 0, len(repos))
	changes := make([]*secretscan_service.SwitchChange, len(repos))
	var actorIDs []int64
	for i, repo := range repos { // one page at most: the audit log has no bulk read of this
		if changes[i], err = secretscan_service.LastSwitchChange(ctx, repo.ID); err != nil {
			ctx.ServerError("LastSwitchChange", err)
			return
		}
		if changes[i] != nil && !changes[i].On {
			actorIDs = append(actorIDs, changes[i].ActorID)
		}
	}
	actors, err := user_model.GetUsersByIDsWithBots(ctx, actorIDs) // one query for the page
	if err != nil {
		ctx.ServerError("GetUsersByIDsWithBots", err)
		return
	}
	for i, repo := range repos {
		row := secretOffRepo{FullName: repo.FullName(), Link: repo.Link() + "/settings/code_security"}
		if change := changes[i]; change != nil && !change.On {
			row.By, row.At = change.ActorName, change.CreatedUnix
			if u := actors[change.ActorID]; u != nil {
				row.By = u.GetDisplayName()
			}
		}
		rows = append(rows, row)
	}
	// the organization's own switch decides over these: the list must not claim a repository is off while it is scanned
	sw, err := secretscan_service.GetOrgSwitch(ctx, ctx.Org.Organization.ID)
	if err != nil {
		ctx.ServerError("GetOrgSwitch", err)
		return
	}
	ctx.Data["SecretOrgOn"], ctx.Data["SecretOrgLocked"] = sw.On, sw.Locked
	ctx.Data["SecretSiteOn"] = secretscan_service.SiteEnabled(ctx)
	ctx.Data["Rows"] = rows
	pager := context.NewPagination(int(total), setting.UI.User.RepoPagingNum, page, 5)
	ctx.Data["Page"] = pager
	ctx.HTML(http.StatusOK, tplSecretScanningOffList)
}

// CodeSecurityPost stores the switch; off deletes the stored package lists of every repository of the organization.
// While the site switch is off, the save is refused with a message on the settings page.
func CodeSecurityPost(ctx *context.Context) {
	err := dependency_service.SetOrgSwitch(ctx, ctx.Org.Organization.AsUser(), ctx.FormBool("enabled"), ctx.FormBool("locked"))
	switch {
	case errors.Is(err, dependency_service.ErrSwitchLocked):
		ctx.Flash.Error(ctx.Tr("repo.settings.dependency_graph.site_off"))
	case err != nil:
		ctx.ServerError("SetOrgSwitch", err)
		return
	default:
		ctx.Flash.Success(ctx.Tr("repo.settings.dependency_graph.saved"))
	}
	ctx.Redirect(ctx.Org.OrgLink + "/settings/code_security")
}

// SecretPatternAdd saves a custom pattern of the organization; a refusal shows the page again with the reason.
func SecretPatternAdd(ctx *context.Context) {
	if !shared_security.PatternAdd(ctx, ctx.Org.Organization.AsUser()) {
		if !ctx.Written() {
			codeSecurityPage(ctx, http.StatusUnprocessableEntity)
		}
		return
	}
	ctx.Redirect(ctx.Org.OrgLink + "/settings/code_security#custom-patterns")
}

// SecretPatternAction renames, turns on, turns off or deletes a pattern of the organization (the ID is looked up
// within it, so another owner's pattern is not found).
func SecretPatternAction(ctx *context.Context) {
	shared_security.PatternAction(ctx, ctx.Org.Organization.AsUser(), ctx.Params("action"), ctx.Org.OrgLink+"/settings/code_security#custom-patterns")
}
