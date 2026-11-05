// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package user

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/secret"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	"forgejo.org/services/authz"
	"forgejo.org/services/context"
)

// ownedTokensPageSize is how many tokens the Keys and tokens page lists at once; above it the list pages and a
// name filter shows.
const ownedTokensPageSize = 20

// newOwnedTokenSessionKey prefixes the session key (see newOwnedTokenKey) that holds the encrypted
// "id:rotated:time:secret" of a token that was just created or rotated, from the POST to the page it redirects to;
// the page pops it, so a reload shows nothing and rotates nothing.
const newOwnedTokenSessionKey = "newOwnedToken"

// OwnedTokenRow is one token in the list of the Keys and tokens page.
type OwnedTokenRow struct {
	Token         *auth_model.AccessToken
	CreatedBy     *user_model.User
	RotatedBy     *user_model.User
	RotatedSelf   bool                     // last rotated by the token itself
	Repos         []*repo_model.Repository // the selected repositories of an organization token
	ExpiresSoon   bool                     // expires within 7 days
	ExpiresInDays int                      // days left, rounded up, when ExpiresSoon
	RotateExpires string                   // the expiry date a rotation gives it as the rows show dates, "" for none
}

// OwnedTokenLevel names the owner of the tokens a Keys and tokens page manages.
type OwnedTokenLevel struct {
	Opts     auth_model.FindOwnedAccessTokensOptions // OwnerType, OwnerID and GroupID
	Link     string                                  // the Keys and tokens page
	CloneURL string                                  // shown in the usage of a new token
	Owner    *user_model.User                        // the organization, or the owner of the repository
}

func newOwnedTokenRows(ctx *context.Context, tokens []*auth_model.AccessToken) ([]*OwnedTokenRow, error) {
	userIDs := make([]int64, 0, 2*len(tokens))
	for _, t := range tokens {
		userIDs = append(userIDs, t.CreatorID)
		if t.RotatedByID > 0 {
			userIDs = append(userIDs, t.RotatedByID)
		}
	}
	users, err := user_model.GetPossibleUserByIDs(ctx, userIDs)
	if err != nil {
		return nil, err
	}
	reposByToken, err := repo_model.BulkGetRepositoriesForAccessTokens(ctx, tokens, nil)
	if err != nil {
		return nil, err
	}
	userByID := func(id int64) *user_model.User {
		if i := slices.IndexFunc(users, func(u *user_model.User) bool { return u.ID == id }); i >= 0 {
			return users[i]
		}
		return user_model.NewGhostUser()
	}
	soon := timeutil.TimeStampNow().AddDuration(7 * 24 * time.Hour)
	rows := make([]*OwnedTokenRow, 0, len(tokens))
	for _, t := range tokens {
		row := &OwnedTokenRow{
			Token:       t,
			CreatedBy:   userByID(t.CreatorID),
			RotatedSelf: t.RotatedByID == user_model.AccessTokenBotID(t.ID),
			Repos:       reposByToken[t.ID],
			ExpiresSoon: t.ExpiresUnix != 0 && !t.IsExpired() && t.ExpiresUnix <= soon,
		}
		if !row.RotatedSelf {
			row.RotatedBy = userByID(t.RotatedByID)
		}
		if row.ExpiresSoon {
			row.ExpiresInDays = int((time.Duration(t.ExpiresUnix-timeutil.TimeStampNow())*time.Second + 24*time.Hour - 1) / (24 * time.Hour))
		}
		if expires := authz.RotationExpiry(setting.AccessTokenExpiry, t.ExpiresUnix != 0); expires != 0 {
			row.RotateExpires = expires.AsTime().Format("Jan 2, 2006") // what <absolute-date> shows the rows in English
		}
		slices.SortFunc(row.Repos, func(a, b *repo_model.Repository) int { return strings.Compare(a.FullName(), b.FullName()) })
		rows = append(rows, row)
	}
	return rows, nil
}

// LoadOwnedTokens sets the page data of the access tokens section: one page of the owner's tokens (newest first,
// filtered by the q parameter) and the create form's defaults.
func LoadOwnedTokens(ctx *context.Context, level OwnedTokenLevel) bool {
	opts := level.Opts
	opts.Keyword = strings.TrimSpace(ctx.FormString("q"))
	opts.ListOptions = db.ListOptions{Page: max(ctx.FormInt("page"), 1), PageSize: ownedTokensPageSize}
	tokens, count, err := db.FindAndCount[auth_model.AccessToken](ctx, opts)
	if err != nil {
		ctx.ServerError("FindOwnedAccessTokens", err)
		return false
	}
	rows, err := newOwnedTokenRows(ctx, tokens)
	if err != nil {
		ctx.ServerError("newOwnedTokenRows", err)
		return false
	}
	if !popNewOwnedToken(ctx, level) {
		return false
	}
	ctx.Data["Link"] = level.Link
	ctx.Data["OwnedTokens"] = rows
	ctx.Data["OwnedTokenCloneURL"] = level.CloneURL
	ctx.Data["OwnedTokensLink"] = level.Link + "/tokens"
	ctx.Data["OwnedTokensKeyword"] = opts.Keyword
	ctx.Data["OwnedTokenLevel"] = int(level.Opts.OwnerType)
	// an archived organization and a read-only instance refuse writes: tokens can only be revoked there
	ctx.Data["OwnedTokensArchived"] = level.Owner.IsOrganization() && level.Owner.IsArchived
	ctx.Data["OwnedTokensReadOnly"] = setting.GetMaintenance(ctx).ReadOnly()
	ctx.Data["OwnedTokenScopeCategories"] = auth_model.OwnedTokenScopeCategories
	if level.Opts.OwnerType != auth_model.AccessTokenOwnerOrg { // packages belong to the organization: only its tokens reach them
		ctx.Data["OwnedTokenScopeCategories"] = slices.DeleteFunc(slices.Clone(auth_model.OwnedTokenScopeCategories), func(c string) bool { return c == "package" })
	}
	if count > ownedTokensPageSize || opts.Keyword != "" {
		ctx.Data["OwnedTokensFilter"] = true
	}
	pager := context.NewPagination(int(count), ownedTokensPageSize, opts.Page, 5)
	pager.AddParamString("q", opts.Keyword)
	ctx.Data["Page"] = pager
	if _, ok := ctx.Data["token_permission"]; !ok { // the defaults of a new form
		ctx.Data["token_permission"] = "read"
		ctx.Data["token_scopes"] = []string{"read:repository"}
		ctx.Data["TokenScopeAll"] = true
	}
	ctx.Data["TokenExpiryRequired"] = setting.AccessTokenExpiry.Required || setting.AccessTokenExpiry.MaxLifetimeDays > 0
	ctx.Data["TokenExpiryMaxDate"] = authz.MaxExpiryDate(setting.AccessTokenExpiry)
	ctx.Data["TokenExpiryMaxDays"] = setting.AccessTokenExpiry.MaxLifetimeDays
	if v, _ := ctx.Data["token_expires_at"].(string); v == "" {
		ctx.Data["token_expires_at"] = authz.DefaultExpiryDate(setting.AccessTokenExpiry)
	}
	return true
}

// LoadCoveringTokens sets the organization and project tokens that cover the repository of the page, for the
// read-only list on its Keys and tokens page.
func LoadCoveringTokens(ctx *context.Context, repo *repo_model.Repository) bool {
	if !repo.Owner.IsOrganization() {
		return true
	}
	tokens, err := auth_model.FindOwnedAccessTokensCoveringRepo(ctx, repo.ID, repo.OwnerID, repo.GroupID)
	if err != nil {
		ctx.ServerError("FindOwnedAccessTokensCoveringRepo", err)
		return false
	}
	ctx.Data["CoveringTokens"] = tokens
	return true
}

// OwnedTokenForm is what the create form posted, kept to show it again after a refusal.
type OwnedTokenForm struct {
	Name        string
	Description string
	Permission  string
	Scopes      []string
	ExpiresAt   string
	SelfRotate  bool
}

// ReadOwnedTokenForm reads the create form and puts it back into the page data.
func ReadOwnedTokenForm(ctx *context.Context) OwnedTokenForm {
	f := OwnedTokenForm{
		Name:        strings.TrimSpace(ctx.FormString("token_name")),
		Description: strings.TrimSpace(ctx.FormString("token_description")),
		Permission:  ctx.FormString("token_permission"),
		Scopes:      slices.DeleteFunc(ctx.Req.Form["token_scopes"], func(s string) bool { return s == "" }),
		ExpiresAt:   ctx.FormString("token_expires_at"),
		SelfRotate:  ctx.FormBool("token_self_rotate"),
	}
	ctx.Data["token_name"] = f.Name
	ctx.Data["token_description"] = f.Description
	ctx.Data["token_self_rotate"] = f.SelfRotate
	ctx.Data["token_permission"] = f.Permission
	ctx.Data["token_scopes"] = f.Scopes
	ctx.Data["token_expires_at"] = f.ExpiresAt
	ctx.Data["HasTokenError"] = true // keeps the form open until it succeeds
	return f
}

// CreateOwnedToken creates the token the form describes for level, covering repoIDs for an organization token
// limited to selected repositories (allRepos false). On success it redirects to the page, which shows the secret
// once, and returns the token; on a refusal it sets TokenError and returns nil. Only the page's own owners reach it (the routes check).
func CreateOwnedToken(ctx *context.Context, level OwnedTokenLevel, f OwnedTokenForm, allRepos bool, repoIDs []int64) *auth_model.AccessToken {
	refuse := func(msg string) *auth_model.AccessToken {
		ctx.Data["TokenError"] = msg
		return nil
	}
	noScope := func() *auth_model.AccessToken { // shown under the Scopes field
		ctx.Data["Err_TokenScopes"] = true
		ctx.Data["TokenScopesError"] = ctx.Locale.TrString("owned_token.error.no_scope")
		return nil
	}
	if f.Name == "" || len(f.Name) > 255 {
		ctx.Data["Err_TokenName"] = true
		return refuse(ctx.Locale.TrString("owned_token.error.name"))
	}
	if len(f.Description) > 255 {
		return refuse(ctx.Locale.TrString("owned_token.error.description"))
	}
	mode := perm.ParseAccessMode(f.Permission)
	if f.Permission != "read" && f.Permission != "write" && f.Permission != "admin" {
		return refuse(ctx.Locale.TrString("owned_token.error.permission"))
	}
	scope, err := auth_model.AccessTokenScope(strings.Join(f.Scopes, ",")).Normalize()
	if err != nil || scope == "" {
		return noScope()
	}
	expires, expiryErr := ParseExpiryForm(ctx.Base, setting.AccessTokenExpiry, f.ExpiresAt)
	if has, msg := expiryErr.Get(); has {
		ctx.Data["Err_TokenExpiresAt"] = true
		return refuse(msg)
	}
	if level.Opts.OwnerType != auth_model.AccessTokenOwnerOrg {
		allRepos, repoIDs = true, nil
	}
	t := &auth_model.AccessToken{
		Name:             f.Name,
		Description:      f.Description,
		SelfRotate:       f.SelfRotate,
		Scope:            scope,
		OwnerType:        level.Opts.OwnerType,
		OwnerID:          level.Opts.OwnerID,
		GroupID:          level.Opts.GroupID,
		Mode:             mode,
		CreatorID:        ctx.Doer.ID,
		ExpiresUnix:      expires,
		ResourceAllRepos: allRepos,
	}
	if err := authz.CreateOwnedAccessToken(ctx, t, repoIDs); err != nil {
		switch {
		case errors.Is(err, authz.ErrOwnedTokenNameTaken):
			ctx.Data["Err_TokenName"] = true
			return refuse(ctx.Locale.TrString("owned_token.error.name_taken", f.Name))
		case errors.Is(err, authz.ErrOwnedTokenNoScope):
			return noScope()
		case errors.Is(err, auth_model.ErrOwnedTokenPackageScope):
			ctx.Data["Err_TokenScopes"] = true
			return refuse(ctx.Locale.TrString("owned_token.error.package_scope"))
		case errors.Is(err, auth_model.ErrOwnedTokenScope):
			ctx.Data["Err_TokenScopes"] = true
			return refuse(ctx.Locale.TrString("owned_token.error.scope"))
		case errors.Is(err, authz.ErrSpecifiedReposNone):
			return refuse(ctx.Locale.TrString("org.settings.deploy_key_no_repos"))
		case errors.Is(err, authz.ErrOwnedTokenRepoNotInOrg):
			return refuse(ctx.Locale.TrString("org.settings.deploy_key_invalid_repos"))
		}
		if has, msg := TranslateAccessTokenValidationError(ctx.Base, err).Get(); has {
			return refuse(msg)
		} else if errors.Is(err, util.ErrPermissionDenied) {
			return refuse(ctx.Locale.TrString("settings.credential_not_own_act"))
		}
		ctx.ServerError("CreateOwnedAccessToken", err)
		return nil
	}
	rememberNewOwnedToken(ctx, level, t, false)
	return t
}

// newOwnedTokenKey is the session key of the secret shown on the page of one owner (an organization, a project or a
// repository), so another owner's page never consumes it.
func newOwnedTokenKey(ownerType auth_model.AccessTokenOwnerType, ownerID, groupID int64) string {
	return fmt.Sprintf("%s:%d:%d:%d", newOwnedTokenSessionKey, ownerType, ownerID, groupID)
}

// newOwnedTokenMaxAge is how long a created or rotated secret waits in the session for its page.
const newOwnedTokenMaxAge = 5 * time.Minute

// rememberNewOwnedToken keeps the secret of a new or rotated token in the session, encrypted, and redirects to the
// page, which shows it once (popNewOwnedToken): the answer to the POST has no secret to repeat on a reload.
func rememberNewOwnedToken(ctx *context.Context, level OwnedTokenLevel, t *auth_model.AccessToken, rotated bool) {
	value, err := secret.EncryptSecret(setting.SecretKey, fmt.Sprintf("%d:%t:%d:%s", t.ID, rotated, time.Now().Unix(), t.Token))
	if err == nil {
		err = ctx.Session.Set(newOwnedTokenKey(t.OwnerType, t.OwnerID, t.GroupID), value)
	}
	if err != nil {
		ctx.ServerError("Session.Set", err)
		return
	}
	ctx.Redirect(level.Link+"#access-tokens", http.StatusSeeOther)
}

// popNewOwnedToken puts the token that rememberNewOwnedToken stored for level, if it is still fresh and its secret
// still the token's, into the page data and forgets it. It returns false when it answered with an error.
func popNewOwnedToken(ctx *context.Context, level OwnedTokenLevel) bool {
	if ctx.Session == nil { // unit-test contexts have none
		return true
	}
	key := newOwnedTokenKey(level.Opts.OwnerType, level.Opts.OwnerID, level.Opts.GroupID)
	v, ok := ctx.Session.Get(key).(string)
	if !ok {
		return true
	}
	if err := ctx.Session.Delete(key); err != nil {
		ctx.ServerError("Session.Delete", err)
		return false
	}
	plain, err := secret.DecryptSecret(setting.SecretKey, v)
	if err != nil {
		return true
	}
	idStr, rest, _ := strings.Cut(plain, ":")
	rotated, rest, _ := strings.Cut(rest, ":")
	createdStr, secretValue, _ := strings.Cut(rest, ":")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	created, _ := strconv.ParseInt(createdStr, 10, 64)
	if secretValue == "" || time.Since(time.Unix(created, 0)) > newOwnedTokenMaxAge {
		return true
	}
	t := &auth_model.AccessToken{}
	if has, err := db.GetEngine(ctx).Where(level.Opts.ToConds()).And("id = ?", id).Get(t); err != nil {
		ctx.ServerError("GetOwnedAccessToken", err)
		return false
	} else if !has || auth_model.HashToken(secretValue, t.TokenSalt) != t.TokenHash { // the token is gone or was rotated since
		return true
	}
	t.Token = secretValue
	ctx.Data["NewOwnedTokenRotated"] = rotated == "true"
	ctx.Resp.Header().Set("Cache-Control", "no-store")
	return showNewOwnedToken(ctx, t) != nil
}

// showNewOwnedToken puts a new or rotated token into the page data, so its secret shows once.
func showNewOwnedToken(ctx *context.Context, t *auth_model.AccessToken) *auth_model.AccessToken {
	reposByToken, err := repo_model.BulkGetRepositoriesForAccessTokens(ctx, []*auth_model.AccessToken{t}, nil)
	if err != nil {
		ctx.ServerError("BulkGetRepositoriesForAccessTokens", err)
		return nil
	}
	ctx.Data["NewOwnedToken"] = t
	ctx.Data["NewOwnedTokenRepos"] = reposByToken[t.ID]
	return t
}

// RotateOwnedToken gives the token of the form's id of level a new secret with the default lifetime and redirects to
// the page, which shows it once; a token of another owner is not found. It always answers, so it returns false.
func RotateOwnedToken(ctx *context.Context, level OwnedTokenLevel) bool {
	t, err := authz.RotateOwnedAccessToken(ctx, level.Opts, ctx.FormInt64("id"), "", optional.None[timeutil.TimeStamp](), ctx.Doer.ID)
	if err != nil {
		if auth_model.IsErrAccessTokenNotExist(err) {
			ctx.Flash.Error(ctx.Tr("error.not_found"))
		} else if errors.Is(err, auth_model.ErrOwnedTokenScope) || errors.Is(err, authz.ErrOwnedTokenNoScope) {
			ctx.Flash.Error(ctx.Tr("owned_token.error.scope"))
		} else if errors.Is(err, util.ErrPermissionDenied) {
			ctx.Flash.Error(ctx.Tr("settings.credential_not_own_act"))
		} else if has, msg := TranslateAccessTokenValidationError(ctx.Base, err).Get(); has {
			ctx.Flash.Error(html.EscapeString(msg)) // rendered as HTML
		} else {
			ctx.ServerError("RotateOwnedAccessToken", err)
			return false
		}
		ctx.Redirect(level.Link + "#access-tokens")
		return false
	}
	rememberNewOwnedToken(ctx, level, t, true)
	return false
}

// DeleteOwnedToken revokes the token of the form's id of level; a token of another owner is not found.
func DeleteOwnedToken(ctx *context.Context, level OwnedTokenLevel) {
	if err := auth_model.DeleteOwnedAccessToken(ctx, level.Opts, ctx.FormInt64("id"), ctx.Doer.ID); err != nil {
		if auth_model.IsErrAccessTokenNotExist(err) {
			ctx.Flash.Error(ctx.Tr("error.not_found"))
		} else {
			ctx.ServerError("DeleteOwnedAccessToken", err)
			return
		}
	} else {
		ctx.Flash.Success(ctx.Tr("owned_token.revoked"))
	}
	ctx.JSONRedirect(level.Link)
}
