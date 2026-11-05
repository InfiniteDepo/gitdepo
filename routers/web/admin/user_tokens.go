// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"fmt"

	auth_model "forgejo.org/models/auth"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	user_setting "forgejo.org/routers/web/user/setting"
	"forgejo.org/services/context"
)

const tplUserTokenNew base.TplName = "admin/user/access_token_new"

// tokenOwner returns the local individual account whose access tokens a site admin manages, or answers 404 for
// anything else (organizations, reserved, bot and remote users, external login sources, trashed or missing users).
func tokenOwner(ctx *context.Context) *user_model.User {
	u, err := user_model.GetUserByID(ctx, ctx.ParamsInt64(":userid"))
	if err != nil && !user_model.IsErrUserNotExist(err) {
		ctx.ServerError("GetUserByID", err)
		return nil
	}
	if u == nil || !u.IsIndividual() || !u.IsLocal() {
		ctx.NotFound("tokenOwner", nil)
		return nil
	}
	return u
}

func userEditLink(u *user_model.User) string {
	return fmt.Sprintf("%s/admin/users/%d/edit", setting.AppSubURL, u.ID)
}

func userTokensLink(u *user_model.User) string {
	return fmt.Sprintf("%s/admin/users/%d/tokens", setting.AppSubURL, u.ID)
}

// loadUserTokens shows the access tokens section on the user edit page for a local account.
func loadUserTokens(ctx *context.Context, u *user_model.User) {
	if !u.IsIndividual() || !u.IsLocal() {
		return
	}
	ctx.Data["ShowAccessTokens"] = true
	ctx.Data["TokensForOtherUser"] = true
	user_setting.LoadAccessTokensFor(ctx, u, userTokensLink(u))
}

// UserTokenNew renders the new access token form for a user.
func UserTokenNew(ctx *context.Context) {
	u := tokenOwner(ctx)
	if u == nil {
		return
	}
	ctx.Data["Title"] = ctx.Tr("settings.new_access_token")
	ctx.Data["PageIsAdminUsers"] = true
	ctx.Data["User"] = u
	user_setting.AccessTokenCreateFor(ctx, u, tplUserTokenNew)
}

// UserTokenNewPost creates an access token for a user.
func UserTokenNewPost(ctx *context.Context) {
	u := tokenOwner(ctx)
	if u == nil {
		return
	}
	ctx.Data["Title"] = ctx.Tr("settings.new_access_token")
	ctx.Data["PageIsAdminUsers"] = true
	ctx.Data["User"] = u
	ctx.Data["TokensForOtherUser"] = true
	user_setting.AccessTokenCreatePostFor(ctx, u, tplUserTokenNew, userEditLink(u))
}

// UserTokenDelete deletes an access token of a user; a token of another user is not found.
func UserTokenDelete(ctx *context.Context) {
	u := tokenOwner(ctx)
	if u == nil {
		return
	}
	if err := auth_model.DeleteAccessTokenByID(ctx, ctx.FormInt64("id"), u.ID); err != nil {
		if auth_model.IsErrAccessTokenNotExist(err) {
			ctx.NotFound("DeleteAccessTokenByID", nil)
		} else {
			ctx.ServerError("DeleteAccessTokenByID", err)
		}
		return
	}
	ctx.Flash.Success(ctx.Tr("admin.users.delete_token_success"))
	ctx.JSONRedirect(userEditLink(u))
}

// UserTokenRegenerate gives an access token of a user a new value, keeping its scopes, repositories and expiry.
func UserTokenRegenerate(ctx *context.Context) {
	u := tokenOwner(ctx)
	if u == nil {
		return
	}
	t, err := auth_model.RegenerateAccessTokenByID(ctx, ctx.FormInt64("id"), u.ID)
	if err != nil {
		if auth_model.IsErrAccessTokenNotExist(err) {
			ctx.NotFound("RegenerateAccessTokenByID", nil)
		} else if errors.Is(err, util.ErrPermissionDenied) {
			ctx.Flash.Error(ctx.Tr("settings.credential_not_own_act"))
			ctx.JSONRedirect(userEditLink(u))
		} else {
			ctx.ServerError("RegenerateAccessTokenByID", err)
		}
		return
	}
	ctx.Flash.Success(ctx.Tr("admin.users.regenerate_token_success"))
	ctx.Flash.Info(t.Token)
	ctx.JSONRedirect(userEditLink(u))
}
