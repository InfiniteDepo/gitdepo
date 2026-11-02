// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"errors"
	"net/http"
	"path"

	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/base"
	"forgejo.org/modules/util"
	"forgejo.org/services/context"
)

const tplSettingsRedirects base.TplName = "org/settings/redirects"

type redirectRow struct {
	ID         int64
	Project    bool
	OldPath    string
	Target     string // empty for a target the doer can't see, or one that is gone
	TargetLink string
}

// Redirects lists the live redirects of the organization's old repository and project paths; a redirect holds its
// name until an owner removes it here.
func Redirects(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("org.settings.redirects")
	ctx.Data["PageIsSettingsRedirects"] = true
	org := ctx.Org.Organization.AsUser()

	repoRedirects, groupRedirects, err := repo_model.FindRedirects(ctx, org.ID)
	if err != nil {
		ctx.ServerError("FindRedirects", err)
		return
	}
	groups, err := repo_model.GetRepoGroupsByOwnerIDs(ctx, []int64{org.ID})
	if err != nil {
		ctx.ServerError("GetRepoGroupsByOwnerIDs", err)
		return
	}
	groupByID := make(map[int64]*repo_model.RepoGroup, len(groups))
	for _, g := range groups {
		groupByID[g.ID] = g
	}
	repoIDs := make([]int64, 0, len(repoRedirects))
	for _, r := range repoRedirects {
		repoIDs = append(repoIDs, r.RedirectRepoID)
	}
	repos, err := repo_model.GetRepositoriesMapByIDs(ctx, repoIDs)
	if err != nil {
		ctx.ServerError("GetRepositoriesMapByIDs", err)
		return
	}

	rows := make([]redirectRow, 0, len(repoRedirects)+len(groupRedirects))
	for _, r := range groupRedirects {
		row := redirectRow{ID: r.ID, Project: true, OldPath: path.Join(org.Name, r.LowerName)}
		if g := groupByID[r.RedirectGroupID]; g != nil {
			row.Target, row.TargetLink = path.Join(org.Name, g.Name), g.Link(org.Name)
		}
		rows = append(rows, row)
	}
	for _, r := range repoRedirects {
		row := redirectRow{ID: r.ID, OldPath: path.Join(org.Name, r.LowerName)}
		if r.GroupID != 0 {
			if g := groupByID[r.GroupID]; g != nil {
				row.OldPath = path.Join(org.Name, g.Name, r.LowerName)
			}
		}
		// a repository transferred to another owner is shown only to those who can see it
		if repo := repos[r.RedirectRepoID]; repo != nil {
			perm, err := access_model.GetUserRepoPermission(ctx, repo, ctx.Doer)
			if err != nil {
				ctx.ServerError("GetUserRepoPermission", err)
				return
			}
			if perm.HasAccess() {
				row.Target, row.TargetLink = repo.FullName(), repo.Link()
			}
		}
		rows = append(rows, row)
	}
	ctx.Data["Redirects"] = rows
	ctx.HTML(http.StatusOK, tplSettingsRedirects)
}

// RedirectsDelete removes a redirect of the organization, which frees its name.
func RedirectsDelete(ctx *context.Context) {
	err := repo_model.DeleteOwnerRedirect(ctx, ctx.Org.Organization.ID, ctx.FormInt64("id"), ctx.FormString("kind") == "project")
	if errors.Is(err, util.ErrNotExist) {
		ctx.NotFound("DeleteOwnerRedirect", nil)
		return
	} else if err != nil {
		ctx.ServerError("DeleteOwnerRedirect", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("org.settings.redirects.removed"))
	ctx.Redirect(ctx.Org.OrgLink + "/settings/redirects")
}
