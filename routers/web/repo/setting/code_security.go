// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"errors"
	"net/http"

	"forgejo.org/models/organization"
	secretscan_model "forgejo.org/models/secretscan"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/services/context"
	dependency_service "forgejo.org/services/dependency"
	secretscan_service "forgejo.org/services/secretscan"
)

const tplCodeSecurity base.TplName = "repo/settings/code_security"

// CodeSecurity shows the repository's dependency graph switch, and which level decides it: the site administrator
// and the organization's owners get a link to the page where they can change it.
func CodeSecurity(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("repo.settings.code_security")
	ctx.Data["PageIsSettingsCodeSecurity"] = true
	repo := ctx.Repo.Repository
	sw, err := dependency_service.GetRepoSwitch(ctx, repo)
	if err != nil {
		ctx.ServerError("GetRepoSwitch", err)
		return
	}
	ctx.Data["Switch"] = sw
	ctx.Data["CanChange"] = sw.CanChange()
	switch {
	case !sw.Site:
		ctx.Data["CanChangeThere"] = ctx.Doer.IsAdmin
	case !sw.CanChange():
		owner, err := organization.OrgFromUser(repo.Owner).IsActingOwner(ctx, ctx.Doer)
		if err != nil {
			ctx.ServerError("IsActingOwner", err)
			return
		}
		ctx.Data["CanChangeThere"] = owner
	}
	if err := secretScanningBox(ctx); err != nil {
		ctx.ServerError("secretScanningBox", err)
		return
	}
	ctx.HTML(http.StatusOK, tplCodeSecurity)
}

// secretScanningBox loads the secret scanning switch of the page: every level, and how many alerts turning it off
// keeps (an admin of the repository reads all of them).
func secretScanningBox(ctx *context.Context) error {
	sw, err := secretscan_service.GetRepoSwitch(ctx, ctx.Repo.Repository)
	if err != nil {
		return err
	}
	open, closed, err := secretscan_model.CountByState(ctx, ctx.Repo.Repository.ID, false)
	if err != nil {
		return err
	}
	ctx.Data["SecretSwitch"], ctx.Data["SecretCanChange"] = sw, sw.CanChange()
	ctx.Data["SecretOpen"], ctx.Data["SecretAlerts"] = open, open+closed
	if sw.Site && !sw.Own {
		change, err := secretscan_service.LastSwitchChange(ctx, ctx.Repo.Repository.ID)
		if err != nil {
			return err
		}
		if change != nil && !change.On {
			name := change.ActorName
			if u, err := user_model.GetUserByID(ctx, change.ActorID); err == nil {
				name = u.GetDisplayName()
			}
			ctx.Data["SecretOffBy"], ctx.Data["SecretOffAt"] = name, change.CreatedUnix
		}
	}
	return nil
}

// SecretScanningPost stores the repository's own secret scanning switch. Turning it off keeps the alerts. While the
// site or the organization decides, nothing is saved.
func SecretScanningPost(ctx *context.Context) {
	err := secretscan_service.SetRepoSwitch(ctx, ctx.Repo.Repository, ctx.FormBool("enabled"))
	switch {
	case errors.Is(err, secretscan_service.ErrSwitchLocked):
		ctx.Flash.Error(ctx.Tr("repo.settings.secret_scanning.locked"))
	case err != nil:
		ctx.ServerError("SetRepoSwitch", err)
		return
	default:
		ctx.Flash.Success(ctx.Tr("repo.settings.secret_scanning.saved"))
	}
	ctx.Redirect(ctx.Repo.RepoLink + "/settings/code_security")
}

// CodeSecurityPost stores the switch; off deletes the stored package list. While the site or the organization
// decides, the save is refused with a message on the settings page, which then shows who decides.
func CodeSecurityPost(ctx *context.Context) {
	err := dependency_service.SetRepoSwitch(ctx, ctx.Repo.Repository, ctx.FormBool("enabled"))
	switch {
	case errors.Is(err, dependency_service.ErrSwitchLocked):
		ctx.Flash.Error(ctx.Tr("repo.settings.dependency_graph.locked"))
	case err != nil:
		ctx.ServerError("SetRepoSwitch", err)
		return
	default:
		ctx.Flash.Success(ctx.Tr("repo.settings.dependency_graph.saved"))
	}
	ctx.Redirect(ctx.Repo.RepoLink + "/settings/code_security")
}
