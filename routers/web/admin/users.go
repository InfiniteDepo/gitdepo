// Copyright 2014 The Gogs Authors. All rights reserved.
// Copyright 2020 The Gitea Authors.
// SPDX-License-Identifier: MIT

package admin

import (
	"errors"
	"fmt"
	"html"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"forgejo.org/models"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/auth"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/auth/password"
	"forgejo.org/modules/base"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	"forgejo.org/modules/validation"
	"forgejo.org/modules/web"
	"forgejo.org/routers/web/explore"
	user_setting "forgejo.org/routers/web/user/setting"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
	"forgejo.org/services/mailer"
	user_service "forgejo.org/services/user"
)

const (
	tplUsers    base.TplName = "admin/user/list"
	tplUserNew  base.TplName = "admin/user/new"
	tplUserView base.TplName = "admin/user/view"
	tplUserEdit base.TplName = "admin/user/edit"
)

// UserSearchDefaultAdminSort is the default sort type for admin view
const UserSearchDefaultAdminSort = "alphabetically"

// Users show all the users
func Users(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.users")
	ctx.Data["PageIsAdminUsers"] = true

	extraParamStrings := map[string]string{}
	statusFilterKeys := []string{"is_active", "is_admin", "is_restricted", "is_2fa_enabled", "is_prohibit_login", "account_type"}
	statusFilterMap := map[string]string{}
	for _, filterKey := range statusFilterKeys {
		paramKey := "status_filter[" + filterKey + "]"
		paramVal := ctx.FormString(paramKey)
		statusFilterMap[filterKey] = paramVal
		if paramVal != "" {
			extraParamStrings[paramKey] = paramVal
		}
	}

	accountType := statusFilterMap["account_type"]
	accountTypeFilter := optional.None[user_model.UserType]()
	if accountType != "" {
		accountTypeInt, err := strconv.ParseInt(accountType, 10, 0)
		if err != nil {
			ctx.ServerError("account_type int", err)
			return
		}

		accountTypeFilter = optional.Some(user_model.UserType(accountTypeInt))
		extraParamStrings["account_type"] = accountType
	}

	sortType := ctx.FormString("sort")
	if sortType == "" {
		sortType = UserSearchDefaultAdminSort
		ctx.SetFormString("sort", sortType)
	}
	ctx.PageData["adminUserListSearchForm"] = map[string]any{
		"StatusFilterMap": statusFilterMap,
		"SortType":        sortType,
	}

	roleGroups, err := org_model.GetUsersGrantedRoleGroups(ctx, 0)
	if err != nil {
		ctx.ServerError("GetUsersGrantedRoleGroups", err)
		return
	}
	ctx.Data["RoleGroups"] = roleGroups

	explore.RenderUserSearch(ctx, &user_model.SearchUserOptions{
		Actor: ctx.Doer,
		Type:  user_model.UserTypeIndividual,
		ListOptions: db.ListOptions{
			PageSize: setting.UI.Admin.UserPagingNum,
		},
		SearchByEmail:      true,
		IsActive:           optional.ParseBool(statusFilterMap["is_active"]),
		IsAdmin:            optional.ParseBool(statusFilterMap["is_admin"]),
		IsRestricted:       optional.ParseBool(statusFilterMap["is_restricted"]),
		IsTwoFactorEnabled: optional.ParseBool(statusFilterMap["is_2fa_enabled"]),
		IsProhibitLogin:    optional.ParseBool(statusFilterMap["is_prohibit_login"]),
		AccountType:        accountTypeFilter,
		IncludeReserved:    true, // administrator needs to list all accounts include reserved, bot, remote ones
		Load2FAStatus:      true,
		LoadRepoUsage:      true,
		ExtraParamStrings:  extraParamStrings,
	}, tplUsers)
}

// NewUser render adding a new user page
func NewUser(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.users.new_account")
	ctx.Data["PageIsAdminUsers"] = true
	ctx.Data["DefaultUserVisibilityMode"] = setting.Service.DefaultUserVisibilityMode
	ctx.Data["AllowedUserVisibilityModes"] = setting.Service.AllowedUserVisibilityModesSlice.ToVisibleTypeSlice()

	ctx.Data["login_type"] = "0-0"

	sources, err := db.Find[auth.Source](ctx, auth.FindSourcesOptions{
		IsActive: optional.Some(true),
	})
	if err != nil {
		ctx.ServerError("auth.Sources", err)
		return
	}
	ctx.Data["Sources"] = sources

	ctx.Data["CanSendEmail"] = setting.MailService != nil
	ctx.HTML(http.StatusOK, tplUserNew)
}

// NewUserPost response for adding a new user
func NewUserPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.AdminCreateUserForm)
	ctx.Data["Title"] = ctx.Tr("admin.users.new_account")
	ctx.Data["PageIsAdminUsers"] = true
	ctx.Data["DefaultUserVisibilityMode"] = setting.Service.DefaultUserVisibilityMode
	ctx.Data["AllowedUserVisibilityModes"] = setting.Service.AllowedUserVisibilityModesSlice.ToVisibleTypeSlice()

	sources, err := db.Find[auth.Source](ctx, auth.FindSourcesOptions{
		IsActive: optional.Some(true),
	})
	if err != nil {
		ctx.ServerError("auth.Sources", err)
		return
	}
	ctx.Data["Sources"] = sources

	ctx.Data["CanSendEmail"] = setting.MailService != nil

	if ctx.HasError() {
		ctx.HTML(http.StatusOK, tplUserNew)
		return
	}

	u := &user_model.User{
		Name:      form.UserName,
		Email:     form.Email,
		Passwd:    form.Password,
		LoginType: auth.Plain,
	}

	overwriteDefault := &user_model.CreateUserOverwriteOptions{
		IsActive:   optional.Some(true),
		Visibility: &form.Visibility,
	}

	if len(form.LoginType) > 0 {
		fields := strings.Split(form.LoginType, "-")
		if len(fields) == 2 {
			lType, _ := strconv.ParseInt(fields[0], 10, 0)
			u.LoginType = auth.Type(lType)
			u.LoginSource, _ = strconv.ParseInt(fields[1], 10, 64)
			u.LoginName = form.LoginName
		}
	}
	if u.LoginType == auth.NoType || u.LoginType == auth.Plain {
		if len(form.Password) < setting.MinPasswordLength {
			ctx.Data["Err_Password"] = true
			ctx.RenderWithErr(ctx.Tr("auth.password_too_short", setting.MinPasswordLength), tplUserNew, &form)
			return
		}
		if !password.IsComplexEnough(form.Password) {
			ctx.Data["Err_Password"] = true
			ctx.RenderWithErr(password.BuildComplexityError(ctx.Locale), tplUserNew, &form)
			return
		}
		if err := password.IsPwned(ctx, form.Password); err != nil {
			ctx.Data["Err_Password"] = true
			errMsg := ctx.Tr("auth.password_pwned", "https://haveibeenpwned.com/Passwords")
			if password.IsErrIsPwnedRequest(err) {
				log.Error(err.Error())
				errMsg = ctx.Tr("auth.password_pwned_err")
			}
			ctx.RenderWithErr(errMsg, tplUserNew, &form)
			return
		}
		u.MustChangePassword = form.MustChangePassword
	}

	if err := user_model.AdminCreateUser(ctx, u, overwriteDefault); err != nil {
		switch {
		case user_model.IsErrUserAlreadyExist(err):
			ctx.Data["Err_UserName"] = true
			ctx.RenderWithErr(ctx.Tr("form.username_been_taken"), tplUserNew, &form)
		case user_model.IsErrEmailAlreadyUsed(err):
			ctx.Data["Err_Email"] = true
			ctx.RenderWithErr(ctx.Tr("form.email_been_used"), tplUserNew, &form)
		case validation.IsErrEmailInvalid(err):
			ctx.Data["Err_Email"] = true
			ctx.RenderWithErr(ctx.Tr("form.email_invalid"), tplUserNew, &form)
		case db.IsErrNameReserved(err):
			ctx.Data["Err_UserName"] = true
			ctx.RenderWithErr(ctx.Tr("user.form.name_reserved", err.(db.ErrNameReserved).Name), tplUserNew, &form)
		case db.IsErrNamePatternNotAllowed(err):
			ctx.Data["Err_UserName"] = true
			ctx.RenderWithErr(ctx.Tr("user.form.name_pattern_not_allowed", err.(db.ErrNamePatternNotAllowed).Pattern), tplUserNew, &form)
		case errors.Is(err, audit_model.ErrNotOwnAct):
			ctx.RenderWithErr(ctx.Tr("settings.credential_not_own_act"), tplUserNew, &form)
		default:
			ctx.ServerError("CreateUser", err)
		}
		return
	}

	if _, ok := validation.IsEmailDomainAllowed(u.Email); !ok {
		ctx.Flash.Warning(ctx.Tr("form.email_domain_is_not_allowed", u.Email))
	}

	log.Trace("Account created by admin (%s): %s", ctx.Doer.Name, u.Name)

	// Send email notification.
	if form.SendNotify {
		mailer.SendRegisterNotifyMail(u)
	}

	ctx.Flash.Success(ctx.Tr("admin.users.new_success", u.Name))
	ctx.Redirect(setting.AppSubURL + "/admin/users/" + strconv.FormatInt(u.ID, 10))
}

// personalRepoSizeLimitMiB is a custom size limit override of u as the edit form shows it, in MiB (at least 1); 0
// for the other modes.
func personalRepoSizeLimitMiB(u *user_model.User) int64 {
	if u.PersonalRepoSizeLimit > 0 {
		return max(u.PersonalRepoSizeLimit>>20, 1)
	}
	return 0
}

func prepareUserInfo(ctx *context.Context) *user_model.User {
	u, err := user_model.GetUserByID(ctx, ctx.ParamsInt64(":userid"))
	if err != nil {
		if user_model.IsErrUserNotExist(err) {
			ctx.Redirect(setting.AppSubURL + "/admin/users")
		} else {
			ctx.ServerError("GetUserByID", err)
		}
		return nil
	}
	if u.IsOrganization() { // changed in the organization's settings
		ctx.NotFound("prepareUserInfo", nil)
		return nil
	}

	ctx.Data["User"] = u
	ctx.Data["ContextUser"] = u
	if mib := personalRepoSizeLimitMiB(u); mib > 0 {
		ctx.Data["PersonalRepoSizeLimitMiB"] = mib
	}

	roleGroups, err := org_model.GetUsersGrantedRoleGroups(ctx, u.ID)
	if err != nil {
		ctx.ServerError("GetUsersGrantedRoleGroups", err)
		return nil
	}
	ctx.Data["RoleGroups"] = roleGroups[u.ID]

	if u.LoginSource > 0 {
		ctx.Data["LoginSource"], err = auth.GetSourceByID(ctx, u.LoginSource)
		if err != nil {
			ctx.ServerError("auth.GetSourceByID", err)
			return nil
		}
	} else {
		ctx.Data["LoginSource"] = &auth.Source{}
	}

	sources, err := db.Find[auth.Source](ctx, auth.FindSourcesOptions{})
	if err != nil {
		ctx.ServerError("auth.Sources", err)
		return nil
	}
	ctx.Data["Sources"] = sources

	hasTwoFactor, err := auth.HasTwoFactorByUID(ctx, u.ID)
	if err != nil {
		ctx.ServerError("HasTwoFactorByUID", err)
		return nil
	}
	ctx.Data["TwoFactorEnabled"] = hasTwoFactor

	return u
}

func ViewUser(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.users.details")
	ctx.Data["PageIsAdminUsers"] = true
	ctx.Data["DisableRegularOrgCreation"] = setting.Admin.DisableRegularOrgCreation
	ctx.Data["DisableMigrations"] = setting.Repository.DisableMigrations
	ctx.Data["AllowedUserVisibilityModes"] = setting.Service.AllowedUserVisibilityModesSlice.ToVisibleTypeSlice()

	u := prepareUserInfo(ctx)
	if ctx.Written() {
		return
	}

	repos, count, err := repo_model.SearchRepository(ctx, &repo_model.SearchRepoOptions{
		ListOptions: db.ListOptionsAll,
		OwnerID:     u.ID,
		OrderBy:     db.SearchOrderByAlphabetically,
		Private:     true,
		Collaborate: optional.Some(false),
	})
	if err != nil {
		ctx.ServerError("SearchRepository", err)
		return
	}

	ctx.Data["Repos"] = repos
	ctx.Data["ReposTotal"] = int(count)

	emails, err := user_model.GetEmailAddresses(ctx, u.ID)
	if err != nil {
		ctx.ServerError("GetEmailAddresses", err)
		return
	}
	ctx.Data["Emails"] = emails
	ctx.Data["EmailsTotal"] = len(emails)

	orgs, err := db.Find[org_model.Organization](ctx, org_model.FindOrgOptions{
		ListOptions:    db.ListOptionsAll,
		UserID:         u.ID,
		IncludePrivate: true,
	})
	if err != nil {
		ctx.ServerError("FindOrgs", err)
		return
	}

	ctx.Data["Users"] = orgs // needed to be able to use explore/user_list template
	ctx.Data["OrgsTotal"] = len(orgs)

	ctx.HTML(http.StatusOK, tplUserView)
}

func editUserCommon(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.users.edit_account")
	ctx.Data["PageIsAdminUsers"] = true
	ctx.Data["DisableRegularOrgCreation"] = setting.Admin.DisableRegularOrgCreation
	ctx.Data["DisableMigrations"] = setting.Repository.DisableMigrations
	ctx.Data["AllowedUserVisibilityModes"] = setting.Service.AllowedUserVisibilityModesSlice.ToVisibleTypeSlice()
	ctx.Data["DisableGravatar"] = setting.Config().Picture.DisableGravatar.Value(ctx)
	ctx.Data["MaxAvatarFileSize"] = setting.Avatar.MaxFileSize
	ctx.Data["MaxAvatarWidth"] = setting.Avatar.MaxWidth
	ctx.Data["MaxAvatarHeight"] = setting.Avatar.MaxHeight
}

// EditUser show editing user page
func EditUser(ctx *context.Context) {
	editUserCommon(ctx)
	u := prepareUserInfo(ctx)
	if ctx.Written() {
		return
	}
	loadUserTokens(ctx, u)
	if ctx.Written() {
		return
	}
	loadLastApproverWarnings(ctx, u)

	ctx.HTML(http.StatusOK, tplUserEdit)
}

// EditUserPost response for editing user
func EditUserPost(ctx *context.Context) {
	editUserCommon(ctx)
	u := prepareUserInfo(ctx)
	if ctx.Written() {
		return
	}
	loadUserTokens(ctx, u)
	if ctx.Written() {
		return
	}

	form := web.GetForm(ctx).(*forms.AdminEditUserForm)
	if ctx.HasError() {
		loadLastApproverWarnings(ctx, u)
		ctx.HTML(http.StatusOK, tplUserEdit)
		return
	}
	// the checks run only for a save that deactivates the user or suspends them, and before the update changes u
	var leaving []lastApproverRow
	if u.IsActive && !u.ProhibitLogin && (!form.Active || form.ProhibitLogin && ctx.Doer.ID != u.ID) {
		leaving = loadLastApproverWarnings(ctx, u)
	}
	sizeLimit := u.PersonalRepoSizeLimit // no mode sent: unchanged
	switch form.PersonalRepoSizeLimitMode {
	case "site":
		sizeLimit = 0
	case "unlimited":
		sizeLimit = -1
	case "custom":
		mib := form.PersonalRepoSizeLimit
		if mib < 1 || mib > math.MaxInt64>>20 {
			ctx.Data["Err_PersonalRepoSizeLimit"] = true
			ctx.RenderWithErr(ctx.Tr("admin.users.personal_repo_size_limit_invalid"), tplUserEdit, &form)
			return
		}
		// an unchanged value keeps an override set in bytes (API) that isn't whole MiB
		if u.PersonalRepoSizeLimit <= 0 || mib != personalRepoSizeLimitMiB(u) {
			sizeLimit = mib << 20
		}
	}
	authOpts := &user_service.UpdateAuthOptions{
		Password:  optional.FromNonDefault(form.Password),
		LoginName: optional.Some(form.LoginName),
	}

	// skip self Prohibit Login
	if ctx.Doer.ID == u.ID {
		authOpts.ProhibitLogin = optional.Some(false)
	} else {
		authOpts.ProhibitLogin = optional.Some(form.ProhibitLogin)
	}

	fields := strings.Split(form.LoginType, "-")
	if len(fields) == 2 {
		authSource, _ := strconv.ParseInt(fields[1], 10, 64)

		authOpts.LoginSource = optional.Some(authSource)
	}

	// refused before anything below is written
	if err := user_service.CheckEditIsOwnAct(ctx, u, authOpts, &user_service.UpdateOptions{IsAdmin: optional.Some(form.Admin)}, form.Email); err != nil {
		ctx.RenderWithErr(ctx.Tr("settings.credential_not_own_act"), tplUserEdit, &form)
		return
	}

	if form.UserName != "" {
		if err := user_service.AdminRenameUser(ctx, u, form.UserName); err != nil {
			switch {
			case user_model.IsErrUserIsNotLocal(err):
				ctx.Data["Err_UserName"] = true
				ctx.RenderWithErr(ctx.Tr("form.username_change_not_local_user"), tplUserEdit, &form)
			case user_model.IsErrUserAlreadyExist(err):
				ctx.Data["Err_UserName"] = true
				ctx.RenderWithErr(ctx.Tr("form.username_been_taken"), tplUserEdit, &form)
			case db.IsErrNameReserved(err):
				ctx.Data["Err_UserName"] = true
				ctx.RenderWithErr(ctx.Tr("user.form.name_reserved", form.UserName), tplUserEdit, &form)
			case db.IsErrNamePatternNotAllowed(err):
				ctx.Data["Err_UserName"] = true
				ctx.RenderWithErr(ctx.Tr("user.form.name_pattern_not_allowed", form.UserName), tplUserEdit, &form)
			case db.IsErrNameCharsNotAllowed(err):
				ctx.Data["Err_UserName"] = true
				ctx.RenderWithErr(ctx.Tr("user.form.name_chars_not_allowed", form.UserName), tplUserEdit, &form)
			case errors.Is(err, util.ErrPermissionDenied):
				ctx.Data["Err_UserName"] = true
				ctx.RenderWithErr(ctx.Tr("settings.credential_not_own_act"), tplUserEdit, &form)
			default:
				ctx.ServerError("RenameUser", err)
			}
			return
		}
	}

	if err := user_service.UpdateAuth(ctx, u, authOpts); err != nil {
		switch {
		case errors.Is(err, password.ErrMinLength):
			ctx.Data["Err_Password"] = true
			ctx.RenderWithErr(ctx.Tr("auth.password_too_short", setting.MinPasswordLength), tplUserEdit, &form)
		case errors.Is(err, password.ErrComplexity):
			ctx.Data["Err_Password"] = true
			ctx.RenderWithErr(password.BuildComplexityError(ctx.Locale), tplUserEdit, &form)
		case errors.Is(err, password.ErrIsPwned):
			ctx.Data["Err_Password"] = true
			ctx.RenderWithErr(ctx.Tr("auth.password_pwned", "https://haveibeenpwned.com/Passwords"), tplUserEdit, &form)
		case password.IsErrIsPwnedRequest(err):
			ctx.Data["Err_Password"] = true
			ctx.RenderWithErr(ctx.Tr("auth.password_pwned_err"), tplUserEdit, &form)
		case models.IsErrDeleteLastAdminUser(err):
			ctx.RenderWithErr(ctx.Tr("auth.last_admin"), tplUserEdit, &form)
		default:
			ctx.ServerError("UpdateUser", err)
		}
		return
	}

	if form.Email != "" {
		if err := user_service.AdminAddOrSetPrimaryEmailAddress(ctx, u, form.Email); err != nil {
			switch {
			case validation.IsErrEmailInvalid(err):
				ctx.Data["Err_Email"] = true
				ctx.RenderWithErr(ctx.Tr("form.email_invalid"), tplUserEdit, &form)
			case user_model.IsErrEmailAlreadyUsed(err):
				ctx.Data["Err_Email"] = true
				ctx.RenderWithErr(ctx.Tr("form.email_been_used"), tplUserEdit, &form)
			case errors.Is(err, util.ErrPermissionDenied):
				ctx.RenderWithErr(ctx.Tr("settings.credential_not_own_act"), tplUserEdit, &form)
			default:
				ctx.ServerError("AddOrSetPrimaryEmailAddress", err)
			}
			return
		}
		if _, ok := validation.IsEmailDomainAllowed(form.Email); !ok {
			ctx.Flash.Warning(ctx.Tr("form.email_domain_is_not_allowed", form.Email))
		}
	}

	opts := &user_service.UpdateOptions{
		FullName:                optional.Some(form.FullName),
		Website:                 optional.Some(form.Website),
		Location:                optional.Some(form.Location),
		Pronouns:                optional.Some(form.Pronouns),
		IsActive:                optional.Some(form.Active),
		IsAdmin:                 optional.Some(form.Admin),
		AllowGitHook:            optional.Some(form.AllowGitHook),
		AllowImportLocal:        optional.Some(form.AllowImportLocal),
		MaxRepoCreation:         optional.Some(form.MaxRepoCreation),
		PersonalRepoSizeLimit:   optional.Some(sizeLimit),
		AllowCreateOrganization: optional.Some(form.AllowCreateOrganization),
		IsRestricted:            optional.Some(form.Restricted),
		Visibility:              optional.Some(form.Visibility),
		Language:                optional.Some(form.Language),
		KeepEmailPrivate:        optional.Some(form.HideEmail),
	}

	oldSizeLimit := u.PersonalRepoSizeLimit
	if err := user_service.UpdateUser(ctx, u, opts); err != nil {
		if models.IsErrDeleteLastAdminUser(err) {
			ctx.RenderWithErr(ctx.Tr("auth.last_admin"), tplUserEdit, &form)
		} else {
			ctx.ServerError("UpdateUser", err)
		}
		return
	}
	log.Trace("Account profile updated by admin (%s): %s", ctx.Doer.Name, u.Name)
	if oldSizeLimit != u.PersonalRepoSizeLimit {
		log.Info("Personal repository size limit of %s changed from %d to %d by %s", u.Name, oldSizeLimit, u.PersonalRepoSizeLimit, ctx.Doer.Name)
	}

	if form.Reset2FA {
		tf, err := auth.GetTwoFactorByUID(ctx, u.ID)
		if err != nil && !auth.IsErrTwoFactorNotEnrolled(err) {
			ctx.ServerError("auth.GetTwoFactorByUID", err)
			return
		} else if tf != nil {
			if err := auth.DeleteTwoFactorByID(ctx, tf.ID, u.ID); err != nil {
				ctx.ServerError("auth.DeleteTwoFactorByID", err)
				return
			}
		}

		wn, err := auth.GetWebAuthnCredentialsByUID(ctx, u.ID)
		if err != nil {
			ctx.ServerError("auth.GetTwoFactorByUID", err)
			return
		}
		for _, cred := range wn {
			if _, err := auth.DeleteCredential(ctx, cred.ID, u.ID); err != nil {
				ctx.ServerError("auth.DeleteCredential", err)
				return
			}
		}
	}

	ctx.Flash.Success(ctx.Tr("admin.users.update_profile_success"))
	if len(leaving) > 0 {
		flashLastApproverWarnings(ctx, leaving)
	}
	ctx.Redirect(setting.AppSubURL + "/admin/users/" + url.PathEscape(ctx.Params(":userid")))
}

// DeleteUser response for deleting a user
func DeleteUser(ctx *context.Context) {
	u, err := user_model.GetUserByID(ctx, ctx.ParamsInt64(":userid"))
	if err != nil {
		ctx.ServerError("GetUserByID", err)
		return
	}

	// admin should not delete themself
	if u.ID == ctx.Doer.ID {
		ctx.Flash.Error(ctx.Tr("admin.users.cannot_delete_self"))
		ctx.Redirect(setting.AppSubURL + "/admin/users/" + url.PathEscape(ctx.Params(":userid")))
		return
	}

	if err = user_service.DeleteUser(ctx, u, ctx.FormBool("purge")); err != nil {
		switch {
		case models.IsErrUserOwnRepos(err):
			ctx.Flash.Error(ctx.Tr("admin.users.still_own_repo"))
			ctx.Redirect(setting.AppSubURL + "/admin/users/" + url.PathEscape(ctx.Params(":userid")))
		case models.IsErrUserHasOrgs(err):
			ctx.Flash.Error(ctx.Tr("admin.users.still_has_org"))
			ctx.Redirect(setting.AppSubURL + "/admin/users/" + url.PathEscape(ctx.Params(":userid")))
		case models.IsErrUserOwnPackages(err):
			ctx.Flash.Error(ctx.Tr("admin.users.still_own_packages"))
			ctx.Redirect(setting.AppSubURL + "/admin/users/" + url.PathEscape(ctx.Params(":userid")))
		case models.IsErrDeleteLastAdminUser(err):
			ctx.Flash.Error(ctx.Tr("auth.last_admin"))
			ctx.Redirect(setting.AppSubURL + "/admin/users/" + url.PathEscape(ctx.Params(":userid")))
		default:
			ctx.ServerError("DeleteUser", err)
		}
		return
	}
	log.Trace("Account deleted by admin (%s): %s", ctx.Doer.Name, u.Name)

	ctx.Flash.Success(ctx.Tr("admin.users.deletion_success"))
	ctx.Redirect(setting.AppSubURL + "/admin/users")
}

// AvatarPost response for change user's avatar request
func AvatarPost(ctx *context.Context) {
	u := prepareUserInfo(ctx)
	if ctx.Written() {
		return
	}

	form := web.GetForm(ctx).(*forms.AvatarForm)
	if err := user_setting.UpdateAvatarSetting(ctx, form, u); err != nil {
		ctx.Flash.Error(err.Error())
	} else {
		ctx.Flash.Success(ctx.Tr("settings.update_user_avatar_success"))
	}

	ctx.Redirect(setting.AppSubURL + "/admin/users/" + strconv.FormatInt(u.ID, 10))
}

// DeleteAvatar render delete avatar page
func DeleteAvatar(ctx *context.Context) {
	u := prepareUserInfo(ctx)
	if ctx.Written() {
		return
	}

	if err := user_service.DeleteAvatar(ctx, u); err != nil {
		ctx.Flash.Error(err.Error())
	}

	ctx.JSONRedirect(setting.AppSubURL + "/admin/users/" + strconv.FormatInt(u.ID, 10))
}

// Limits of the warnings: the edit page lists at most maxShownWarnings. The flash after a save travels in a cookie:
// its encoded size (after HTML escaping and the two rounds of URL encoding the flash and the cookie each apply), the
// warnings it lists and the length of one name are limited.
const (
	maxShownWarnings   = 50 // on the edit page
	maxFlashBytes      = 2048
	maxFlashedWarnings = 5
	maxFlashedName     = 80
)

// lastApproverRow is a warning of the edit page, in words.
type lastApproverRow struct{ Link, Text, Kind string }

// loadLastApproverWarnings lists on the edit page what deactivating the user or suspending them would break. Nothing
// is listed for a user who can't sign in already. It never blocks the save.
func loadLastApproverWarnings(ctx *context.Context, u *user_model.User) []lastApproverRow {
	if !u.IsActive || u.ProhibitLogin {
		return nil
	}
	warnings, err := user_service.LastApproverWarnings(ctx, []int64{u.ID})
	if err != nil {
		log.Error("LastApproverWarnings for user %d: %v", u.ID, err)
		return nil
	}
	rows := make([]lastApproverRow, len(warnings))
	for i, w := range warnings {
		rows[i] = lastApproverRow{
			Link: w.Link,
			Text: w.Name,
			Kind: lastApproverKind(ctx, w.Kind),
		}
		if !isLocalLink(rows[i].Link) {
			rows[i].Link = ""
		}
	}
	ctx.Data["LastApproverWarnings"] = rows[:min(len(rows), maxShownWarnings)]
	ctx.Data["LastApproverMore"] = max(len(rows)-maxShownWarnings, 0)
	return rows
}

// lastApproverKind is the label of a check's warning: its Kind is a locale key where one exists, else plain text
// (escaped when rendered).
func lastApproverKind(ctx *context.Context, kind string) string {
	switch kind { // literal keys, so that the locale lint sees them used
	case user_service.LastApproverRepoRule:
		return ctx.Locale.TrString("admin.users.last_approver.kind.repo_rule")
	case user_service.LastApproverProjectRule:
		return ctx.Locale.TrString("admin.users.last_approver.kind.project_rule")
	case user_service.LastApproverOrgRule:
		return ctx.Locale.TrString("admin.users.last_approver.kind.org_rule")
	}
	if ctx.Locale.HasKey(kind) { // another check's key
		return ctx.Locale.TrString(kind)
	}
	return kind
}

// isLocalLink is true for a path on this site: it starts with one slash, and has no second slash right after it,
// no backslash and no control character (C0, C1 or DEL), which browsers drop or read as a host.
func isLocalLink(link string) bool {
	if !strings.HasPrefix(link, "/") || strings.HasPrefix(link, "//") {
		return false
	}
	return !strings.ContainsFunc(link, func(r rune) bool { return r == '\\' || unicode.IsControl(r) })
}

func flashName(s string, limit int) string {
	if t := util.TruncateRunes(s, limit); t != s {
		return t + "…"
	}
	return s
}

// flashLastApproverWarnings tells the admin, after a save, what the user leaving would break: a short list of
// truncated names, as many as fit in maxFlashBytes once encoded for the cookie (fewer and shorter names for a name
// that escapes to a lot). Everything is escaped, and a link is used only if it is a path on this site.
func flashLastApproverWarnings(ctx *context.Context, rows []lastApproverRow) {
	render := func(shown, nameLen int) string {
		var b strings.Builder
		b.WriteString(html.EscapeString(ctx.Locale.TrString("admin.users.last_approver_flash")) + "<ul>")
		for _, r := range rows[:shown] {
			text := html.EscapeString(flashName(r.Text, nameLen))
			if isLocalLink(r.Link) {
				text = fmt.Sprintf(`<a href="%s">%s</a>`, html.EscapeString(r.Link), text)
			}
			b.WriteString("<li>" + text + " (" + html.EscapeString(flashName(r.Kind, nameLen)) + ")</li>")
		}
		if shown < len(rows) {
			b.WriteString("<li>" + html.EscapeString(ctx.Locale.TrString("admin.users.last_approver_more", len(rows)-shown)) + "</li>")
		}
		return b.String() + "</ul>"
	}
	for shown := min(len(rows), maxFlashedWarnings); shown >= 0; shown-- {
		for nameLen := maxFlashedName; nameLen >= maxFlashedName/2; nameLen /= 2 {
			if msg := render(shown, nameLen); len(url.QueryEscape(url.QueryEscape(msg))) <= maxFlashBytes {
				ctx.Flash.Warning(template.HTML(msg))
				return
			}
		}
	}
}
