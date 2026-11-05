// Copyright 2014 The Gogs Authors. All rights reserved.
// Copyright 2018 The Gitea Authors. All rights reserved.
// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strings"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/container"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/routers/web/shared/user"
	"forgejo.org/services/authz"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"

	"xorm.io/builder"
)

const (
	tplAccessTokenEdit base.TplName = "user/settings/access_token_edit"
)

// errSelectedRepoNotFound is the one error for a missing, unreadable, malformed or duplicate selected repository.
var errSelectedRepoNotFound = errors.New("one or more of the repositories couldn't be found by owner & name")

// getSelectedRepos resolves the full names of the selected repositories. A missing, malformed or duplicate entry, or
// one the token owner can't read, gives errSelectedRepoNotFound, so that the response can't be used to probe for
// existence.
func getSelectedRepos(ctx *context.Context, owner *user_model.User, selectedReposRaw []string) ([]*repo_model.Repository, error) {
	selectedRepos := make([]*repo_model.Repository, 0, len(selectedReposRaw))
	seen := make(container.Set[int64], len(selectedReposRaw))
	for _, selected := range selectedReposRaw {
		repo, err := repo_model.GetRepositoryByFullName(ctx, selected)
		if repo_model.IsErrRepoNotExist(err) {
			return nil, errSelectedRepoNotFound
		} else if err != nil {
			return nil, err
		}
		permission, err := access_model.GetUserRepoPermission(ctx, repo, owner)
		if err != nil {
			return nil, err
		} else if !permission.HasAccess() || !seen.Add(repo.ID) {
			return nil, errSelectedRepoNotFound
		}
		selectedRepos = append(selectedRepos, repo)
	}
	// match sorting in loadAccessTokenCreateData for consistency
	slices.SortFunc(selectedRepos, func(a, b *repo_model.Repository) int {
		return strings.Compare(strings.ToLower(a.FullName()), strings.ToLower(b.FullName()))
	})
	return selectedRepos, nil
}

// loadAccessTokenCreateData fills the new token form for a token of owner, the doer or a user a site admin acts for.
func loadAccessTokenCreateData(ctx *context.Context, owner *user_model.User) {
	user.SetExpiryFormData(ctx.Base, setting.AccessTokenExpiry)
	ctx.Data["AccessTokenScopePublicOnly"] = string(auth_model.AccessTokenScopePublicOnly) // note: SliceUtils.Contains won't work in the template if this is a `auth_model.AccessTokenScope`, so it's cast to a string here

	categories := []string{
		"activitypub",
		"issue",
		"misc",
		"notification",
		"organization",
		"package",
		"repository",
		"user",
	}
	if owner.IsAdmin {
		categories = append(categories, "admin")
	}
	ctx.Data["TokenOwnerIsAdmin"] = owner.IsAdmin
	slices.Sort(categories)
	ctx.Data["Categories"] = categories

	allowed, err := authz.AllowedScopes(owner)
	if err != nil {
		ctx.ServerError("AllowedScopes", err)
		return
	}
	var disallowed []string
	if allowed != nil {
		for _, category := range categories {
			for _, scope := range []string{"read:" + category, "write:" + category} {
				if !slices.Contains(allowed, scope) {
					disallowed = append(disallowed, scope)
				}
			}
		}
	}
	ctx.Data["DisallowedScopes"] = disallowed

	// Awkward -- GET and POST use different form bindings for the reasons explained on NewAccessTokenGetForm -- and
	// this method can be called in both situations, on all GETs, and on some POSTs when validation errors occur.  So
	// both forms need to be handled here.
	getForm, isGet := web.GetForm(ctx).(*forms.NewAccessTokenGetForm)
	postForm, isPost := web.GetForm(ctx).(*forms.NewAccessTokenPostForm)

	if isGet {
		// Manage the result of adding or removing a repository before we do anything with `form.SelectedRepo`...
		changed := false
		if getForm.AddSelectedRepo != "" {
			getForm.SelectedRepo = append(getForm.SelectedRepo, getForm.AddSelectedRepo)
			changed = true
		}
		if getForm.RemoveSelectedRepo != "" {
			getForm.SelectedRepo = slices.DeleteFunc(
				getForm.SelectedRepo,
				func(r string) bool { return r == getForm.RemoveSelectedRepo },
			)
			changed = true
		}
		if changed {
			// We've changed getForm.SelectedRepo, but a reference to this slice was already present in `ctx.Data` (the
			// Bind middleware invokes AssignForm to put getForm values into `ctx.Data`).  Replace the reference:
			ctx.Data["selected_repo"] = getForm.SelectedRepo
		}
	}

	repoSearchText := ""
	if isGet {
		repoSearchText = getForm.RepoSearch
	}

	selectedReposRaw := []string{}
	if isGet {
		selectedReposRaw = getForm.SelectedRepo
	} else if isPost {
		selectedReposRaw = postForm.SelectedRepo
	}
	selectedRepos, err := getSelectedRepos(ctx, owner, selectedReposRaw)
	if err != nil {
		ctx.Error(http.StatusBadRequest, "getSelectedRepos")
		return
	}
	ctx.Data["SelectedRepos"] = selectedRepos

	page := 1
	if isGet {
		// Pagination on the repo search has form submit buttons that send the `set_page` param.  It's then encoded into
		// the page in the hidden input `page` which we fall back to, if anything else causes a form get (eg. adding or
		// removing a repo).
		if getForm.SetPage > 0 {
			page = getForm.SetPage
		} else if getForm.Page > 0 {
			page = getForm.Page
		}
	}
	pageSize := 10
	repoSearch := &repo_model.SearchRepoOptions{
		Actor:    owner,
		Keyword:  repoSearchText,
		Private:  true,
		Archived: optional.Some(false),

		// Restrict repositories to those owned by, or collaborated with, by the user.  Repo-specific access tokens
		// could theoretically be created on any public repository as well, but there wouldn't be much point to that and
		// it would really balloon the search results to an impractical number of repos.
		OwnerID: owner.ID,

		ListOptions: db.ListOptions{
			Page:     page,
			PageSize: pageSize,
		},
		OrderBy: db.SearchOrderByAlphabetically, // match sorting in getSelectedRepos for consistency
	}
	cond := repo_model.SearchRepositoryCondition(repoSearch)
	// Exclude all the repos that are currently in `form.SelectedRepo` from the search, by omitting them from the search
	// condition.  This prevents the UI from displaying the same repo on the left and right, and maintains the repo
	// search and page-size correctly.
	for _, selected := range selectedRepos {
		cond = cond.And(builder.Neq{"id": selected.ID})
	}
	repos, count, err := repo_model.SearchRepositoryByCondition(ctx, repoSearch, cond, false)
	if err != nil {
		log.Error("SearchRepository: %v", err)
		ctx.JSON(http.StatusInternalServerError, nil)
		return
	}
	// adding repositories shrinks the list, so the page the form remembers can be past its end: show the last one
	if len(repos) == 0 && page > 1 && count > 0 {
		page = (int(count) + pageSize - 1) / pageSize
		repoSearch.Page = page
		if repos, count, err = repo_model.SearchRepositoryByCondition(ctx, repoSearch, cond, false); err != nil {
			log.Error("SearchRepository: %v", err)
			ctx.JSON(http.StatusInternalServerError, nil)
			return
		}
	}
	ctx.Data["Repos"] = repos

	pager := context.NewPagination(int(count), pageSize, page, 3)
	pager.SetDefaultParams(ctx)
	ctx.Data["Page"] = pager

	autofocus := ""
	if isGet {
		switch {
		// Token name will be autofocused the first time the page is loaded -- if form.Scope is empty then that would be
		// a good sign it's the first load.
		case len(getForm.Scope) == 0:
			autofocus = "name"
		// After submitting a search, refocus the search text box.  Search invokes set_page=1 to reset the pagination
		// which we'll use to detect this case.
		case getForm.SetPage == 1:
			autofocus = "search"
		}
	}
	ctx.Data["Autofocus"] = autofocus
}

// AccessTokenCreate renders the new access token form
func AccessTokenCreate(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("settings.ssh_gpg_keys")
	ctx.Data["PageIsSettingsKeys"] = true
	AccessTokenCreateFor(ctx, ctx.Doer, tplAccessTokenEdit)
}

// AccessTokenCreateFor renders the new access token form for a token of owner.
func AccessTokenCreateFor(ctx *context.Context, owner *user_model.User, tpl base.TplName) {
	loadAccessTokenCreateData(ctx, owner)
	if ctx.Written() {
		return
	}
	// least privilege by default
	if r, _ := ctx.Data["resource"].(string); r == "" {
		ctx.Data["resource"] = "repo-specific"
	}

	ctx.HTML(http.StatusOK, tpl)
}

// AccessTokenCreatePost handles adding a user access token
func AccessTokenCreatePost(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("settings")
	ctx.Data["PageIsSettingsKeys"] = true
	AccessTokenCreatePostFor(ctx, ctx.Doer, tplAccessTokenEdit, setting.AppSubURL+"/user/settings/keys")
}

// AccessTokenCreatePostFor adds an access token of owner and redirects to redirect, where the flash shows its value.
func AccessTokenCreatePostFor(ctx *context.Context, owner *user_model.User, tpl base.TplName, redirect string) {
	form := web.GetForm(ctx).(*forms.NewAccessTokenPostForm)

	renderWithError := func(msg template.HTML) {
		loadAccessTokenCreateData(ctx, owner)
		if ctx.Written() {
			return
		}
		ctx.RenderWithErr(msg, tpl, form)
	}

	if ctx.HasError() {
		loadAccessTokenCreateData(ctx, owner)
		if ctx.Written() {
			return
		}
		ctx.HTML(http.StatusOK, tpl)
		return
	}

	scope, err := form.GetScope()
	if err != nil {
		ctx.ServerError("GetScope", err)
		return
	}
	if !scope.HasPermissionScope() {
		renderWithError(ctx.Tr("settings.at_least_one_permission"))
		return
	}

	expires, err := authz.ParseExpiryDate(form.ExpiresAt)
	if err != nil {
		renderWithError(template.HTML(template.HTMLEscapeString(user.TranslateExpiryError(ctx.Base, err, setting.AccessTokenExpiry).ValueOrZeroValue())))
		return
	}

	t := &auth_model.AccessToken{
		UID:         owner.ID,
		Name:        form.Name,
		Scope:       scope,
		ExpiresUnix: expires,
	}

	var resourceRepos []*auth_model.AccessTokenResourceRepo
	switch form.Resource {
	case "all":
		t.ResourceAllRepos = true
	case "public-only":
		t.ResourceAllRepos = true
		newScopeUnnormalized := fmt.Sprintf("%s,%s", scope, auth_model.AccessTokenScopePublicOnly)
		newScope, err := auth_model.AccessTokenScope(newScopeUnnormalized).Normalize()
		if err != nil {
			ctx.ServerError("AccessTokenScope.Normalize", err)
			return
		}
		t.Scope = newScope
	case "repo-specific":
		t.ResourceAllRepos = false
		selectedRepos, err := getSelectedRepos(ctx, owner, form.SelectedRepo)
		if err != nil {
			ctx.Error(http.StatusBadRequest, "getSelectedRepos")
			return
		}
		for _, repo := range selectedRepos {
			resourceRepos = append(resourceRepos, &auth_model.AccessTokenResourceRepo{RepoID: repo.ID})
		}
	}

	exist, err := auth_model.AccessTokenByNameExists(ctx, t)
	if err != nil {
		ctx.ServerError("AccessTokenByNameExists", err)
		return
	} else if exist {
		renderWithError(ctx.Tr("settings.generate_token_name_duplicate", t.Name))
		return
	}

	if err := authz.ValidateAccessToken(owner, t, resourceRepos); err != nil {
		s := user.TranslateAccessTokenValidationError(ctx.Base, err)
		if has, str := s.Get(); has {
			renderWithError(template.HTML(template.HTMLEscapeString(str)))
			return
		}
		ctx.ServerError("ValidateAccessToken", err)
		return
	}

	if err := auth_model.NewAccessToken(ctx, t, resourceRepos); errors.Is(err, util.ErrPermissionDenied) {
		renderWithError(ctx.Tr("settings.credential_not_own_act"))
		return
	} else if err != nil {
		ctx.ServerError("NewAccessToken", err)
		return
	}

	if ctx.Data["TokensForOtherUser"] == true {
		ctx.Flash.Success(ctx.Tr("admin.users.generate_token_success"))
	} else {
		ctx.Flash.Success(ctx.Tr("settings.generate_token_success"))
	}
	ctx.Flash.Info(t.Token)

	ctx.Redirect(redirect)
}

// DeleteAccessToken response for delete user access token
func DeleteAccessToken(ctx *context.Context) {
	if err := auth_model.DeleteAccessTokenByID(ctx, ctx.FormInt64("id"), ctx.Doer.ID); err != nil {
		ctx.Flash.Error("DeleteAccessTokenByID: " + err.Error())
	} else {
		ctx.Flash.Success(ctx.Tr("settings.delete_token_success"))
	}

	ctx.JSONRedirect(setting.AppSubURL + "/user/settings/keys")
}

// RegenerateAccessToken response for regenerating user access token
func RegenerateAccessToken(ctx *context.Context) {
	if t, err := auth_model.RegenerateAccessTokenByID(ctx, ctx.FormInt64("id"), ctx.Doer.ID); err != nil {
		if auth_model.IsErrAccessTokenNotExist(err) {
			ctx.Flash.Error(ctx.Tr("error.not_found"))
		} else {
			ctx.Flash.Error(ctx.Tr("error.server_internal"))
			log.Error("DeleteAccessTokenByID", err)
		}
	} else {
		ctx.Flash.Success(ctx.Tr("settings.regenerate_token_success"))
		ctx.Flash.Info(t.Token)
	}

	ctx.JSONRedirect(setting.AppSubURL + "/user/settings/keys")
}

type TokenWithResources struct {
	Token        *auth_model.AccessToken
	Repositories []*repo_model.Repository
}

func loadAccessTokensData(ctx *context.Context) {
	LoadAccessTokensFor(ctx, ctx.Doer, setting.AppSubURL+"/user/settings/keys/tokens")
}

// LoadAccessTokensFor lists the access tokens of owner, with the repositories owner can still read, for the
// keys_tokens template, whose links start with link.
func LoadAccessTokensFor(ctx *context.Context, owner *user_model.User, link string) {
	ctx.Data["AccessTokensLink"] = link
	tokens, err := db.Find[auth_model.AccessToken](ctx, auth_model.ListAccessTokensOptions{UserID: owner.ID})
	if err != nil {
		ctx.ServerError("ListAccessTokens", err)
		return
	}

	// Load all the AccessTokenResourceRepo for the tokens that we're returning:
	reposByTokenID, err := repo_model.BulkGetRepositoriesForAccessTokens(ctx, tokens,
		func(repo *repo_model.Repository) (bool, error) {
			// Repos associated with a repo-specific access token should already be visible to the token owner, but it's
			// possible that access has changed, such as a removed collaborator on a repo -- don't provide info on that
			// repo if so.
			permission, err := access_model.GetUserRepoPermission(ctx, repo, owner)
			if err != nil {
				return false, err
			}
			return permission.HasAccess(), nil
		})
	if err != nil {
		ctx.ServerError("BulkGetRepositoriesForAccessTokens", err)
		return
	}

	tokensWithResources := make([]*TokenWithResources, len(tokens))
	for i := range tokens {
		tokensWithResources[i] = &TokenWithResources{
			Token:        tokens[i],
			Repositories: reposByTokenID[tokens[i].ID],
		}
	}

	ctx.Data["TokensWithResources"] = tokensWithResources
}
