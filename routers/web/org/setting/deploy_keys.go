// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	asymkey_model "forgejo.org/models/asymkey"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/routers/web/shared/user"
	asymkey_service "forgejo.org/services/asymkey"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
)

const tplSettingsDeployKeys base.TplName = "org/settings/deploy_keys"

type orgDeployKeyRow struct {
	Key     *asymkey_model.OrgDeployKey
	Repos   []*repo_model.Repository // the selected repositories
	RepoIDs string                   // the selected live repositories, for the dropdown
}

// deployKeyLevel returns the project of the page (RepoGroupAssignment), 0 on the organization's own page, and the
// page's link.
func deployKeyLevel(ctx *context.Context) (groupID int64, link string) {
	if group, ok := ctx.Data["RepoGroup"].(*repo_model.RepoGroup); ok {
		return group.ID, group.Link(ctx.Org.Organization.Name) + "/-/settings/keys"
	}
	return 0, ctx.Org.OrgLink + "/settings/keys"
}

// ownedTokenLevel names the access tokens of the page: the organization's, or its project's.
func ownedTokenLevel(ctx *context.Context) user.OwnedTokenLevel {
	org := ctx.Org.Organization
	groupID, link := deployKeyLevel(ctx)
	level := user.OwnedTokenLevel{
		Opts:     auth_model.FindOwnedAccessTokensOptions{OwnerType: auth_model.AccessTokenOwnerOrg, OwnerID: org.ID},
		Link:     link,
		CloneURL: setting.AppURL + url.PathEscape(org.Name) + "/REPOSITORY.git",
		Owner:    org.AsUser(),
	}
	if groupID != 0 {
		level.Opts.OwnerType, level.Opts.GroupID = auth_model.AccessTokenOwnerProject, groupID
		level.CloneURL = setting.AppURL + url.PathEscape(org.Name) + "/" + url.PathEscape(ctx.Data["RepoGroup"].(*repo_model.RepoGroup).Name) + "/REPOSITORY.git"
	}
	return level
}

// loadDeployKeys sets the page data: the keys of the organization and its live repositories, or the keys of the
// project.
func loadDeployKeys(ctx *context.Context) bool {
	ctx.Data["Title"] = ctx.Tr("owned_token.keys_and_tokens")
	ctx.Data["PageIsSettingsDeployKeys"] = true
	ctx.Data["DisableSSH"] = setting.SSH.Disabled
	ctx.Data["ScopeAll"] = true
	user.SetExpiryFormData(ctx.Base, setting.DeployKeyExpiry)

	if !user.LoadOwnedTokens(ctx, ownedTokenLevel(ctx)) {
		return false
	}
	orgID := ctx.Org.Organization.ID
	groupID, link := deployKeyLevel(ctx)
	keys, err := asymkey_model.FindOrgDeployKeys(ctx, orgID, groupID)
	if err != nil {
		ctx.ServerError("FindOrgDeployKeys", err)
		return false
	}
	if groupID != 0 {
		if err := user.LoadHeaderCount(ctx); err != nil {
			ctx.ServerError("LoadHeaderCount", err)
			return false
		}
		ctx.Data["Title"] = ctx.Tr("owned_token.keys_and_tokens")
		ctx.Data["PageIsViewRepoGroups"] = true
		ctx.Data["RepoGroupLink"] = ctx.Data["RepoGroup"].(*repo_model.RepoGroup).Link(ctx.Org.Organization.Name)
		ctx.Data["Link"] = link
		rows := make([]*orgDeployKeyRow, 0, len(keys))
		for _, k := range keys {
			rows = append(rows, &orgDeployKeyRow{Key: k})
		}
		ctx.Data["DeployKeys"] = rows
		return true
	}
	repos, err := organization.GetOrgRepositories(ctx, orgID)
	if err != nil {
		ctx.ServerError("GetOrgRepositories", err)
		return false
	}
	slices.SortFunc(repos, func(a, b *repo_model.Repository) int { return strings.Compare(a.LowerName, b.LowerName) })
	byID := make(map[int64]*repo_model.Repository, len(repos))
	for _, r := range repos {
		byID[r.ID] = r
	}
	keyIDs := make([]int64, 0, len(keys))
	for _, k := range keys {
		keyIDs = append(keyIDs, k.ID)
	}
	selected, err := asymkey_model.GetOrgDeployKeyRepoIDs(ctx, keyIDs)
	if err != nil {
		ctx.ServerError("GetOrgDeployKeyRepoIDs", err)
		return false
	}
	rows := make([]*orgDeployKeyRow, 0, len(keys))
	for _, k := range keys {
		row := &orgDeployKeyRow{Key: k}
		var ids []string
		for _, id := range selected[k.ID] {
			if r := byID[id]; r != nil {
				row.Repos = append(row.Repos, r)
				if !r.IsTrashed() {
					ids = append(ids, strconv.FormatInt(r.ID, 10))
				}
			}
		}
		row.RepoIDs = strings.Join(ids, ",")
		rows = append(rows, row)
	}
	ctx.Data["DeployKeys"] = rows
	ctx.Data["Repos"] = slices.DeleteFunc(repos, (*repo_model.Repository).IsTrashed)
	return true
}

// deployKeyScope reads the repositories a key covers from the form: all, or the selected ones.
func deployKeyScope(ctx *context.Context) (includesAllRepos bool, repoIDs []int64) {
	if ctx.FormString("scope") == "all" {
		return true, nil
	}
	parts := slices.DeleteFunc(strings.Split(ctx.FormString("repo_ids"), ","), func(s string) bool { return strings.TrimSpace(s) == "" })
	repoIDs, _ = base.StringsToInt64s(parts) // anything unparsable selects nothing
	return false, repoIDs
}

// DeployKeys shows the deploy keys of the organization or of its project
func DeployKeys(ctx *context.Context) {
	if loadDeployKeys(ctx) {
		ctx.HTML(http.StatusOK, tplSettingsDeployKeys)
	}
}

// DeployKeysPost adds a deploy key to the organization or to its project
func DeployKeysPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.AddKeyForm)
	if !loadDeployKeys(ctx) {
		return
	}
	groupID, link := deployKeyLevel(ctx)
	// a refused form is shown again open, with what was entered
	includesAllRepos, repoIDs := deployKeyScope(ctx)
	if groupID != 0 { // a project key covers its project
		includesAllRepos, repoIDs = false, nil
	}
	ctx.Data["ScopeAll"], ctx.Data["ScopeRepoIDs"] = includesAllRepos, ctx.FormString("repo_ids")
	if ctx.HasError() {
		ctx.HTML(http.StatusOK, tplSettingsDeployKeys)
		return
	}

	content, err := asymkey_model.CheckPublicKeyString(form.Content)
	if err != nil {
		switch {
		case db.IsErrSSHDisabled(err):
			ctx.Flash.Info(ctx.Tr("settings.ssh_disabled"))
		case asymkey_model.IsErrKeyUnableVerify(err):
			ctx.Flash.Info(ctx.Tr("form.unable_verify_ssh_key"))
		case errors.Is(err, asymkey_model.ErrKeyIsPrivate):
			ctx.Flash.Error(ctx.Tr("form.must_use_public_key"))
		default:
			ctx.Flash.Error(ctx.Tr("form.invalid_ssh_key", err.Error()))
		}
		ctx.Redirect(link)
		return
	}

	ctx.Data["HasError"] = true // RenderWithErr below keeps the form open
	expires, expiryErr := user.ParseExpiryForm(ctx.Base, setting.DeployKeyExpiry, form.ExpiresAt)
	if has, msg := expiryErr.Get(); has {
		ctx.Data["Err_ExpiresAt"] = true
		ctx.RenderWithErr(template.HTML(template.HTMLEscapeString(msg)), tplSettingsDeployKeys, &form)
		return
	}
	if groupID == 0 && !includesAllRepos && len(repoIDs) == 0 {
		ctx.RenderWithErr(ctx.Tr("org.settings.deploy_key_no_repos"), tplSettingsDeployKeys, &form)
		return
	}

	key, err := asymkey_model.AddOrgDeployKey(ctx, ctx.Org.Organization.ID, groupID, strings.TrimSpace(form.Title), content, !form.IsWritable, includesAllRepos, repoIDs, expires)
	if err != nil {
		switch {
		case asymkey_model.IsErrDeployKeyAlreadyExist(err):
			ctx.Data["Err_Content"] = true
			ctx.RenderWithErr(ctx.Tr("repo.settings.key_been_used"), tplSettingsDeployKeys, &form)
		case asymkey_model.IsErrKeyAlreadyExist(err):
			ctx.Data["Err_Content"] = true
			ctx.RenderWithErr(ctx.Tr("settings.ssh_key_been_used"), tplSettingsDeployKeys, &form)
		case asymkey_model.IsErrDeployKeyNameAlreadyUsed(err):
			ctx.Data["Err_Title"] = true
			ctx.RenderWithErr(ctx.Tr("repo.settings.key_name_used"), tplSettingsDeployKeys, &form)
		case errors.Is(err, util.ErrInvalidArgument):
			ctx.RenderWithErr(ctx.Tr("org.settings.deploy_key_invalid_repos"), tplSettingsDeployKeys, &form)
		default:
			ctx.ServerError("AddOrgDeployKey", err)
		}
		return
	}

	ctx.Flash.Success(ctx.Tr("repo.settings.add_key_success", key.Name))
	ctx.Redirect(link)
}

// AccessTokenNew creates an access token of the organization or of its project and shows its value once
func AccessTokenNew(ctx *context.Context) {
	f := user.ReadOwnedTokenForm(ctx)
	includesAllRepos, repoIDs := deployKeyScope(ctx)
	ctx.Data["TokenScopeAll"], ctx.Data["TokenScopeRepoIDs"] = includesAllRepos, ctx.FormString("repo_ids")
	if user.CreateOwnedToken(ctx, ownedTokenLevel(ctx), f, includesAllRepos, repoIDs); ctx.Written() {
		return
	}
	if loadDeployKeys(ctx) {
		ctx.HTML(http.StatusOK, tplSettingsDeployKeys)
	}
}

// AccessTokenRotate gives an access token of the organization or of its project a new secret and shows it once
func AccessTokenRotate(ctx *context.Context) {
	if user.RotateOwnedToken(ctx, ownedTokenLevel(ctx)) && loadDeployKeys(ctx) {
		ctx.HTML(http.StatusOK, tplSettingsDeployKeys)
	}
}

// AccessTokenDelete revokes an access token of the organization or of its project
func AccessTokenDelete(ctx *context.Context) {
	user.DeleteOwnedToken(ctx, ownedTokenLevel(ctx))
}

// DeployKeyReposPost changes the repositories a deploy key of the organization covers
func DeployKeyReposPost(ctx *context.Context) {
	orgID := ctx.Org.Organization.ID
	key, err := asymkey_model.GetOrgDeployKey(ctx, orgID, 0, ctx.ParamsInt64(":id"))
	if err != nil {
		ctx.NotFoundOrServerError("GetOrgDeployKey", asymkey_model.IsErrDeployKeyNotExist, err)
		return
	}
	includesAllRepos, repoIDs := deployKeyScope(ctx)
	switch err := asymkey_service.SetOrgDeployKeyRepos(ctx, orgID, key.ID, includesAllRepos, repoIDs); {
	case err == nil:
		ctx.Flash.Success(ctx.Tr("org.settings.deploy_key_repos_saved", key.Name))
	case !includesAllRepos && len(repoIDs) == 0:
		ctx.Flash.Error(ctx.Tr("org.settings.deploy_key_no_repos"))
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Flash.Error(ctx.Tr("org.settings.deploy_key_invalid_repos"))
	default:
		ctx.ServerError("SetOrgDeployKeyRepos", err)
		return
	}
	ctx.Redirect(ctx.Org.OrgLink + "/settings/keys")
}

// DeleteDeployKey deletes a deploy key of the organization or of its project
func DeleteDeployKey(ctx *context.Context) {
	groupID, link := deployKeyLevel(ctx)
	if err := asymkey_service.DeleteOrgDeployKey(ctx, ctx.Org.Organization.ID, groupID, ctx.FormInt64("id")); err != nil {
		ctx.NotFoundOrServerError("DeleteOrgDeployKey", func(err error) bool {
			return asymkey_model.IsErrDeployKeyNotExist(err) || errors.Is(err, util.ErrNotExist)
		}, err)
		return
	}
	ctx.Flash.Success(ctx.Tr("repo.settings.deploy_key_deletion_success"))
	ctx.JSONRedirect(link)
}
