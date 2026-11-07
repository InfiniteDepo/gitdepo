// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package utils

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	auth_service "forgejo.org/services/auth"
	"forgejo.org/services/authz"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

// OwnedTokenOwner names the organization, project or repository whose access tokens a request manages.
type OwnedTokenOwner struct {
	Type    auth_model.AccessTokenOwnerType
	ID      int64  // the organization (also of a project), or the repository
	GroupID int64  // the project
	OrgName string // the organization, to find the selected repositories of an organization token
}

func (o OwnedTokenOwner) opts() auth_model.FindOwnedAccessTokensOptions {
	return auth_model.FindOwnedAccessTokensOptions{OwnerType: o.Type, OwnerID: o.ID, GroupID: o.GroupID}
}

// maxOwnedTokenRepos caps the repositories an organization token selects in one request.
const maxOwnedTokenRepos = 1000

// mayManageOwnedTokens refuses what must not manage credentials: a token of an organization, a project or a
// repository, the Actions user, a token limited to public resources, a credential another party holds for the user
// (an OAuth2 grant or an authorized integration), and an HTTP signature (an SSH key or certificate, whose expiry the
// request doesn't carry); these could otherwise mint a token that outlives them.
func mayManageOwnedTokens(ctx *context.APIContext) bool {
	if ctx.Doer().IsAccessTokenBot() || ctx.Doer().IsActions() || ctx.PublicOnly() || !auth_service.IsHeldByUser(ctx.Authentication()) ||
		ctx.Authentication().Credential().Type == audit_model.CredentialSSHKey {
		ctx.Error(http.StatusForbidden, "", "this credential can't manage access tokens")
		return false
	}
	return true
}

func toOwnedAccessToken(t *auth_model.AccessToken, names map[int64]string, repos []*repo_model.Repository) *api.AccessToken {
	name := func(id int64) string {
		if n, ok := names[id]; ok {
			return n
		}
		return user_model.NewGhostUser().Name
	}
	out := &api.AccessToken{
		ID:             t.ID,
		Name:           t.Name,
		Token:          t.Token,
		TokenLastEight: t.TokenLastEight,
		Scopes:         t.Scope.StringSlice(),
		Created:        t.CreatedUnix.AsTime(),
		Expires:        convert.OptionalTime(t.ExpiresUnix),
		Permission:     t.Mode.String(),
		CreatedBy:      name(t.CreatorID),
		Description:    t.Description,
		SelfRotate:     t.SelfRotate,
		LastUsedIP:     t.LastUsedIP,
		Rotated:        convert.OptionalTime(t.RotatedUnix),
		RotatedBySelf:  t.RotatedByID == user_model.AccessTokenBotID(t.ID),
	}
	if t.HasUsed {
		out.LastUsed = convert.OptionalTime(t.UpdatedUnix)
	}
	if t.RotatedUnix != 0 && !out.RotatedBySelf {
		out.RotatedBy = name(t.RotatedByID)
	}
	slices.SortFunc(repos, func(a, b *repo_model.Repository) int { return cmp.Compare(a.ID, b.ID) })
	for _, repo := range repos {
		out.Repositories = append(out.Repositories, &api.RepositoryMeta{
			ID:       repo.ID,
			Name:     repo.Name,
			Owner:    repo.OwnerName,
			FullName: repo.FullName(),
		})
	}
	return out
}

// ListOwnedAccessTokens lists the access tokens of an organization, a project or a repository, never their values.
func ListOwnedAccessTokens(ctx *context.APIContext, owner OwnedTokenOwner) {
	if !mayManageOwnedTokens(ctx) {
		return
	}
	opts := owner.opts()
	opts.ListOptions = GetListOptions(ctx)
	tokens, count, err := db.FindAndCount[auth_model.AccessToken](ctx, opts)
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	// the selections of an organization token are repositories of the organization: transfers drop them
	reposByTokenID, err := repo_model.BulkGetRepositoriesForAccessTokens(ctx, tokens, nil)
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	names, err := ownedTokenUserNames(ctx, tokens)
	if err != nil {
		ctx.InternalServerError(err)
		return
	}

	apiTokens := make([]*api.AccessToken, 0, len(tokens))
	for _, t := range tokens {
		t.Token = "" // never shown again
		apiTokens = append(apiTokens, toOwnedAccessToken(t, names, reposByTokenID[t.ID]))
	}
	ctx.SetTotalCountHeader(count)
	ctx.JSON(http.StatusOK, &apiTokens)
}

// ownedTokenUserNames returns the logins of who created and last rotated the tokens.
func ownedTokenUserNames(ctx *context.APIContext, tokens []*auth_model.AccessToken) (map[int64]string, error) {
	ids := make([]int64, 0, 2*len(tokens))
	for _, t := range tokens {
		ids = append(ids, t.CreatorID)
		if t.RotatedByID > 0 {
			ids = append(ids, t.RotatedByID)
		}
	}
	users, err := user_model.GetPossibleUserByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	names := make(map[int64]string, len(users))
	for _, u := range users {
		names[u.ID] = u.Name
	}
	return names, nil
}

// ownedTokenRepos resolves the repositories an organization token selects ("repo" or "project/repo"); a name outside
// the organization is refused.
func ownedTokenRepos(ctx *context.APIContext, orgName string, names []string) ([]*repo_model.Repository, bool) {
	if len(names) > maxOwnedTokenRepos {
		ctx.Error(http.StatusUnprocessableEntity, "", fmt.Sprintf("at most %d repositories", maxOwnedTokenRepos))
		return nil, false
	}
	repos := make([]*repo_model.Repository, 0, len(names))
	for _, name := range names {
		project, leaf, ok := strings.Cut(name, "/")
		if !ok {
			project, leaf = "", name
		}
		repo, err := repo_model.GetRepositoryByRef(ctx, orgName, project, leaf)
		if err != nil {
			if repo_model.IsErrRepoNotExist(err) {
				ctx.Error(http.StatusUnprocessableEntity, "", "repository not found in the organization: "+name)
			} else {
				ctx.Error(http.StatusInternalServerError, "GetRepositoryByRef", err)
			}
			return nil, false
		}
		if !slices.ContainsFunc(repos, func(r *repo_model.Repository) bool { return r.ID == repo.ID }) {
			repos = append(repos, repo)
		}
	}
	return repos, true
}

// CreateOwnedAccessToken creates an access token of an organization, a project or a repository. A token creating it
// must hold every scope it grants and must not expire before it; the new token's value is shown only in this answer.
func CreateOwnedAccessToken(ctx *context.APIContext, owner OwnedTokenOwner) {
	if !mayManageOwnedTokens(ctx) {
		return
	}
	form := web.GetForm(ctx).(*api.CreateOwnedAccessTokenOption)
	name := strings.TrimSpace(form.Name)
	if name == "" {
		ctx.Error(http.StatusUnprocessableEntity, "", "name is required")
		return
	}

	scope, err := auth_model.AccessTokenScope(strings.Join(form.Scopes, ",")).Normalize()
	if err != nil {
		ctx.Error(http.StatusUnprocessableEntity, "", fmt.Sprintf("invalid access token scope provided: %v", err))
		return
	}
	t := &auth_model.AccessToken{
		Name:             name,
		Description:      strings.TrimSpace(form.Description),
		SelfRotate:       form.SelfRotate,
		Scope:            scope,
		OwnerType:        owner.Type,
		OwnerID:          owner.ID,
		GroupID:          owner.GroupID,
		Mode:             perm.ParseAccessMode(form.Permission),
		CreatorID:        ctx.Doer().ID,
		ExpiresUnix:      ExpiryTimeStamp(form.ExpiresAt),
		ResourceAllRepos: true,
	}

	var repos []*repo_model.Repository
	if form.Repositories != nil {
		if owner.Type != auth_model.AccessTokenOwnerOrg {
			ctx.Error(http.StatusUnprocessableEntity, "", "only an organization token selects repositories")
			return
		}
		var ok bool
		if repos, ok = ownedTokenRepos(ctx, owner.OrgName, form.Repositories); !ok {
			return
		}
		t.ResourceAllRepos = false
	}

	if !mayGrant(ctx, scope, t.ExpiresUnix) {
		return
	}

	repoIDs := make([]int64, 0, len(repos))
	for _, repo := range repos {
		repoIDs = append(repoIDs, repo.ID)
	}
	if err := authz.CreateOwnedAccessToken(ctx, t, repoIDs); err != nil {
		if isOwnedTokenValidationError(err) {
			ctx.Error(http.StatusUnprocessableEntity, "", err.Error())
			return
		} else if errors.Is(err, util.ErrPermissionDenied) {
			ctx.Error(http.StatusForbidden, "", err.Error())
			return
		}
		ctx.InternalServerError(err)
		return
	}
	ctx.JSON(http.StatusCreated, toOwnedAccessToken(t, map[int64]string{ctx.Doer().ID: ctx.Doer().Name}, repos))
}

// mayGrant refuses a secret the request's credential couldn't have itself: a token creating or rotating another must
// hold every scope it grants and must not expire before it.
func mayGrant(ctx *context.APIContext, scope auth_model.AccessTokenScope, expires timeutil.TimeStamp) bool {
	// no scope, or one no such token may have, is refused later as invalid rather than as not held
	if has, reqScope := ctx.Authentication().Scope().Get(); has && scope != "" && auth_model.ValidateOwnedTokenScope(scope) == nil {
		var granted []auth_model.AccessTokenScope
		for _, s := range scope.StringSlice() {
			granted = append(granted, auth_model.AccessTokenScope(s))
		}
		if ok, err := reqScope.HasScope(granted...); err != nil {
			ctx.InternalServerError(err)
			return false
		} else if !ok {
			ctx.Error(http.StatusForbidden, "", "the token must hold every scope it grants")
			return false
		}
	}
	if has, credExpires := ctx.Authentication().ExpiresAt().Get(); has && (expires == 0 || expires > credExpires) {
		ctx.Error(http.StatusUnprocessableEntity, "", "the token must not expire after the credential that creates it")
		return false
	}
	return true
}

// isOwnedTokenValidationError reports whether err is a refusal of the token's settings by today's policies.
func isOwnedTokenValidationError(err error) bool {
	return errors.Is(err, authz.ErrOwnedTokenNameTaken) || errors.Is(err, authz.ErrOwnedTokenRepoNotInOrg) || IsExpiryError(err) || errors.Is(err, authz.ErrScopeNotAllowed) ||
		errors.Is(err, authz.ErrScopeNeedsRepoRestriction) || errors.Is(err, authz.ErrOwnedTokenNoScope) ||
		errors.Is(err, auth_model.ErrOwnedTokenScope) || errors.Is(err, auth_model.ErrOwnedTokenMode) || errors.Is(err, authz.ErrSpecifiedReposNone) ||
		errors.Is(err, authz.ErrSpecifiedReposNoPublicOnly) || errors.Is(err, authz.ErrSpecifiedReposInvalidScope)
}

// RotateOwnedAccessToken gives an access token of an organization, a project or a repository a new secret, shown only
// in this answer; an expired token may be rotated, a token of another owner is not found. Like creating one, a token
// rotating another must hold its scopes and must not expire before the new secret.
func RotateOwnedAccessToken(ctx *context.APIContext, owner OwnedTokenOwner, id int64) {
	if !mayManageOwnedTokens(ctx) {
		return
	}
	form := web.GetForm(ctx).(*api.RotateOwnedAccessTokenOption)
	t := &auth_model.AccessToken{}
	if has, err := db.GetEngine(ctx).Where(owner.opts().ToConds()).And("id = ?", id).Get(t); err != nil {
		ctx.InternalServerError(err)
		return
	} else if !has {
		ctx.NotFound()
		return
	}
	expires := optional.None[timeutil.TimeStamp]()
	if form.ExpiresAt != nil {
		expires = optional.Some(ExpiryTimeStamp(form.ExpiresAt))
	}
	newExpires := authz.RotationExpiry(setting.AccessTokenExpiry, t.ExpiresUnix != 0)
	if has, v := expires.Get(); has {
		newExpires = v
	}
	if !mayGrant(ctx, t.Scope, newExpires) {
		return
	}
	rotated, err := authz.RotateOwnedAccessToken(ctx, owner.opts(), id, t.TokenHash, optional.Some(newExpires), ctx.Doer().ID)
	writeRotated(ctx, rotated, err)
}

// RotateSelf gives the access token of an organization, a project or a repository that authenticated the request a
// new secret, if it may rotate itself; the old secret stops working.
func RotateSelf(ctx *context.APIContext) {
	cred := ctx.Authentication().Credential()
	bot := ctx.Doer()
	if !bot.IsAccessTokenBot() || cred.Type != audit_model.CredentialAccessToken || cred.ID != bot.BotToken.ID {
		ctx.Error(http.StatusForbidden, "", "only a token of an organization, a project or a repository can rotate itself")
		return
	}
	t := bot.BotToken
	if !t.SelfRotate {
		ctx.Error(http.StatusForbidden, "", "this token may not rotate itself")
		return
	}
	// the organization that owns the token, or the owner of the repository it belongs to
	ownerID := t.OwnerID
	if t.OwnerType == auth_model.AccessTokenOwnerRepo {
		repo, err := repo_model.GetRepositoryByID(ctx, t.OwnerID)
		if repo_model.IsErrRepoNotExist(err) {
			ctx.NotFound()
			return
		} else if err != nil {
			ctx.InternalServerError(err)
			return
		}
		ownerID = repo.OwnerID
	}
	owner, err := user_model.GetUserByID(ctx, ownerID)
	if user_model.IsErrUserNotExist(err) {
		ctx.NotFound()
		return
	} else if err != nil {
		ctx.InternalServerError(err)
		return
	}
	if context.IsArchivedOrgWrite(ctx.Req, owner, context.ArchivedOrgOpenRoutes...) {
		ctx.Error(http.StatusForbidden, "OrgArchived", "the organization is archived and read-only")
		return
	}
	opts := auth_model.FindOwnedAccessTokensOptions{OwnerType: t.OwnerType, OwnerID: t.OwnerID, GroupID: t.GroupID}
	rotated, err := authz.RotateOwnedAccessToken(ctx, opts, t.ID, t.TokenHash, optional.None[timeutil.TimeStamp](), bot.ID)
	writeRotated(ctx, rotated, err)
}

func writeRotated(ctx *context.APIContext, t *auth_model.AccessToken, err error) {
	if err != nil {
		switch {
		case auth_model.IsErrAccessTokenNotExist(err):
			ctx.NotFound()
		case isOwnedTokenValidationError(err):
			ctx.Error(http.StatusUnprocessableEntity, "", err.Error())
		case errors.Is(err, util.ErrPermissionDenied):
			ctx.Error(http.StatusForbidden, "", err.Error())
		default:
			ctx.InternalServerError(err)
		}
		return
	}
	reposByTokenID, err := repo_model.BulkGetRepositoriesForAccessTokens(ctx, []*auth_model.AccessToken{t}, nil)
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	names, err := ownedTokenUserNames(ctx, []*auth_model.AccessToken{t})
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	ctx.JSON(http.StatusOK, toOwnedAccessToken(t, names, reposByTokenID[t.ID]))
}

// DeleteOwnedAccessToken deletes (revokes) an access token of an organization, a project or a repository; a token of
// another owner is not found.
func DeleteOwnedAccessToken(ctx *context.APIContext, owner OwnedTokenOwner, id int64) {
	if !mayManageOwnedTokens(ctx) {
		return
	}
	if err := auth_model.DeleteOwnedAccessToken(ctx, owner.opts(), id, ctx.Doer().ID); err != nil {
		if auth_model.IsErrAccessTokenNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.InternalServerError(err)
		}
		return
	}
	ctx.Status(http.StatusNoContent)
}
