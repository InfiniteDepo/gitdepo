// Copyright 2024 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package user

import (
	"context"
	"fmt"

	"forgejo.org/models"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	user_model "forgejo.org/models/user"
	password_module "forgejo.org/modules/auth/password"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/structs"
	"forgejo.org/services/mailer"
)

type UpdateOptions struct {
	KeepEmailPrivate             optional.Option[bool]
	FullName                     optional.Option[string]
	Website                      optional.Option[string]
	Location                     optional.Option[string]
	Description                  optional.Option[string]
	Pronouns                     optional.Option[string]
	AllowGitHook                 optional.Option[bool]
	AllowImportLocal             optional.Option[bool]
	MaxRepoCreation              optional.Option[int]
	PersonalRepoSizeLimit        optional.Option[int64]
	IsRestricted                 optional.Option[bool]
	Visibility                   optional.Option[structs.VisibleType]
	KeepActivityPrivate          optional.Option[bool]
	Language                     optional.Option[string]
	Theme                        optional.Option[string]
	DiffViewStyle                optional.Option[string]
	AllowCreateOrganization      optional.Option[bool]
	IsActive                     optional.Option[bool]
	IsAdmin                      optional.Option[bool]
	EmailNotificationsPreference optional.Option[string]
	SetLastLogin                 bool
	RepoAdminChangeTeamAccess    optional.Option[bool]
	RequireTwoFactor             optional.Option[bool]
	EnableRepoUnitHints          optional.Option[bool]
	KeepPronounsPrivate          optional.Option[bool]
	RestrictRepoVisibilityChange optional.Option[bool]
	PrivateForkPolicy            optional.Option[int]
	CategoryID                   optional.Option[int64]
}

// CheckEditIsOwnAct refuses, before anything is written, what UpdateAuth and UpdateUser would refuse because it is
// not a person's own act, so a handler that calls both changes nothing on a refusal.
func CheckEditIsOwnAct(ctx context.Context, u *user_model.User, authOpts *UpdateAuthOptions, opts *UpdateOptions) error {
	if err := checkPasswordIsOwnAct(ctx, u, authOpts.Password); err != nil {
		return err
	}
	return checkAdminFlagIsOwnAct(ctx, u, opts.IsAdmin)
}

// checkAdminFlagIsOwnAct: making someone a site admin is only a person's own act (a login source syncing the flag
// acts as the source).
func checkAdminFlagIsOwnAct(ctx context.Context, u *user_model.User, isAdmin optional.Option[bool]) error {
	if has, value := isAdmin.Get(); has && value && !u.IsAdmin {
		return audit_model.CheckOwnAct(ctx)
	}
	return nil
}

// checkPasswordIsOwnAct: a password is a credential of the user, so setting another user's is only a person's own
// act, as creating a token for them (auth_model.NewAccessToken).
func checkPasswordIsOwnAct(ctx context.Context, u *user_model.User, password optional.Option[string]) error {
	if password.Has() {
		return audit_model.CheckOwnActFor(ctx, u.ID)
	}
	return nil
}

func UpdateUser(ctx context.Context, u *user_model.User, opts *UpdateOptions) error {
	before := u.AuditFields()
	cols := make([]string, 0, 20)

	if has, value := opts.KeepEmailPrivate.Get(); has {
		u.KeepEmailPrivate = value
		cols = append(cols, "keep_email_private")
	}
	if has, value := opts.FullName.Get(); has {
		u.FullName = value
		cols = append(cols, "full_name")
	}
	if has, value := opts.Pronouns.Get(); has {
		u.Pronouns = value
		cols = append(cols, "pronouns")
	}
	if has, value := opts.Website.Get(); has {
		u.Website = value
		cols = append(cols, "website")
	}
	if has, value := opts.Location.Get(); has {
		u.Location = value
		cols = append(cols, "location")
	}
	if has, value := opts.Description.Get(); has {
		u.Description = value
		cols = append(cols, "description")
	}
	if has, value := opts.Language.Get(); has {
		u.Language = value
		cols = append(cols, "language")
	}
	if has, value := opts.Theme.Get(); has {
		u.Theme = value
		cols = append(cols, "theme")
	}
	if has, value := opts.DiffViewStyle.Get(); has {
		u.DiffViewStyle = value
		cols = append(cols, "diff_view_style")
	}
	if has, value := opts.EnableRepoUnitHints.Get(); has {
		u.EnableRepoUnitHints = value
		cols = append(cols, "enable_repo_unit_hints")
	}
	if has, value := opts.KeepPronounsPrivate.Get(); has {
		u.KeepPronounsPrivate = value
		cols = append(cols, "keep_pronouns_private")
	}
	if has, value := opts.AllowGitHook.Get(); has {
		u.AllowGitHook = value
		cols = append(cols, "allow_git_hook")
	}
	if has, value := opts.AllowImportLocal.Get(); has {
		u.AllowImportLocal = value
		cols = append(cols, "allow_import_local")
	}
	if has, value := opts.MaxRepoCreation.Get(); has {
		u.MaxRepoCreation = value
		cols = append(cols, "max_repo_creation")
	}
	if has, value := opts.PersonalRepoSizeLimit.Get(); has {
		u.PersonalRepoSizeLimit = value
		cols = append(cols, "personal_repo_size_limit")
	}
	if has, value := opts.IsActive.Get(); has {
		if !value && user_model.IsLastUsableAdmin(ctx, u) {
			return models.ErrDeleteLastAdminUser{UID: u.ID}
		}
		u.IsActive = value
		cols = append(cols, "is_active")
	}
	if has, value := opts.IsRestricted.Get(); has {
		u.IsRestricted = value
		cols = append(cols, "is_restricted")
	}
	if has, value := opts.IsAdmin.Get(); has {
		if !value && user_model.IsLastAdminUser(ctx, u) {
			return models.ErrDeleteLastAdminUser{UID: u.ID}
		}
		if err := checkAdminFlagIsOwnAct(ctx, u, opts.IsAdmin); err != nil {
			return err
		}
		u.IsAdmin = value
		cols = append(cols, "is_admin")
	}
	if has, value := opts.Visibility.Get(); has {
		if !u.IsOrganization() && !setting.Service.AllowedUserVisibilityModesSlice.IsAllowedVisibility(value) {
			return fmt.Errorf("visibility mode not allowed: %s", value.String())
		}
		u.Visibility = value
		cols = append(cols, "visibility")
	}
	if has, value := opts.KeepActivityPrivate.Get(); has {
		u.KeepActivityPrivate = value
		cols = append(cols, "keep_activity_private")
	}
	if has, value := opts.AllowCreateOrganization.Get(); has {
		u.AllowCreateOrganization = value
		cols = append(cols, "allow_create_organization")
	}
	if has, value := opts.RepoAdminChangeTeamAccess.Get(); has {
		u.RepoAdminChangeTeamAccess = value
		cols = append(cols, "repo_admin_change_team_access")
	}
	if has, value := opts.RequireTwoFactor.Get(); has {
		u.RequireTwoFactor = value
		cols = append(cols, "require_two_factor")
	}
	if has, value := opts.EmailNotificationsPreference.Get(); has {
		u.EmailNotificationsPreference = value
		cols = append(cols, "email_notifications_preference")
	}
	if has, value := opts.RestrictRepoVisibilityChange.Get(); has {
		u.RestrictRepoVisibilityChange = value
		cols = append(cols, "restrict_repo_visibility_change")
	}
	if has, value := opts.PrivateForkPolicy.Get(); has {
		u.PrivateForkPolicy = value
		cols = append(cols, "private_fork_policy")
	}
	if has, value := opts.CategoryID.Get(); has {
		u.CategoryID = value
		cols = append(cols, "category_id")
	}
	if opts.SetLastLogin {
		u.SetLastLogin()
		cols = append(cols, "last_login_unix")
	}

	return db.WithTx(ctx, func(ctx context.Context) error {
		stored, err := storedOrg(ctx, u)
		if err != nil {
			return err
		}
		if err := user_model.UpdateUserCols(ctx, u, cols...); err != nil {
			return err
		}
		if err := user_model.RecordOrgChange(ctx, stored, u); err != nil {
			return err
		}
		return user_model.RecordUserChange(ctx, before, u)
	})
}

// storedOrg reads the stored row of u when it is an organization, so that its audited change is taken from what the
// database held, not from u, which the caller already changed; nil for a user.
func storedOrg(ctx context.Context, u *user_model.User) (stored *user_model.User, err error) {
	if u.IsOrganization() {
		var has bool
		if stored, has, err = db.GetByID[user_model.User](ctx, u.ID); err == nil && !has {
			err = user_model.ErrUserNotExist{UID: u.ID}
		}
	}
	return stored, err
}

type UpdateAuthOptions struct {
	LoginSource        optional.Option[int64]
	LoginName          optional.Option[string]
	Password           optional.Option[string]
	MustChangePassword optional.Option[bool]
	ProhibitLogin      optional.Option[bool]
}

func UpdateAuth(ctx context.Context, u *user_model.User, opts *UpdateAuthOptions) error {
	if err := checkPasswordIsOwnAct(ctx, u, opts.Password); err != nil {
		return err
	}
	if opts.ProhibitLogin.ValueOrDefault(false) && user_model.IsLastUsableAdmin(ctx, u) {
		return models.ErrDeleteLastAdminUser{UID: u.ID}
	}
	before := u.AuditFields()
	passwordChanged := false
	if has, value := opts.LoginSource.Get(); has {
		source, err := auth_model.GetSourceByID(ctx, value)
		if err != nil {
			return err
		}

		u.LoginType = source.Type
		u.LoginSource = source.ID
	}
	if has, value := opts.LoginName.Get(); has {
		u.LoginName = value
	}

	if has, value := opts.Password.Get(); has && (u.IsLocal() || u.IsOAuth2()) {
		password := value

		if len(password) < setting.MinPasswordLength {
			return password_module.ErrMinLength
		}
		if !password_module.IsComplexEnough(password) {
			return password_module.ErrComplexity
		}
		if err := password_module.IsPwned(ctx, password); err != nil {
			return err
		}

		if err := u.SetPassword(password); err != nil {
			return err
		}
		passwordChanged = true
	}

	if has, value := opts.MustChangePassword.Get(); has {
		u.MustChangePassword = value
	}
	if has, value := opts.ProhibitLogin.Get(); has {
		u.ProhibitLogin = value
	}

	if err := db.WithTx(ctx, func(ctx context.Context) error {
		stored, err := storedOrg(ctx, u)
		if err != nil {
			return err
		}
		if err := user_model.UpdateUserCols(ctx, u, "login_type", "login_source", "login_name", "passwd", "passwd_hash_algo", "salt", "must_change_password", "prohibit_login"); err != nil {
			return err
		}
		if passwordChanged {
			if err := user_model.RecordUser(ctx, "account.user.password_changed", u, nil); err != nil {
				return err
			}
		}
		if err := user_model.RecordOrgChange(ctx, stored, u); err != nil {
			return err
		}
		return user_model.RecordUserChange(ctx, before, u)
	}); err != nil {
		return err
	}

	if opts.Password.Has() {
		return mailer.SendPasswordChange(u)
	}

	return nil
}

// UpdateUserFromSource is UpdateUser for changes synced from a login source. If they would remove
// the admin flag of the last usable admin, the flag is kept, a warning is logged and the other
// changes are applied. Like UpdateUser, only the other admins are counted, so an inactive or
// prohibited sole admin keeps the flag too. The check and the write are not atomic, as in UpdateUser.
func UpdateUserFromSource(ctx context.Context, u *user_model.User, opts *UpdateOptions, sourceName string) error {
	if has, isAdmin := opts.IsAdmin.Get(); has && !isAdmin && user_model.IsLastAdminUser(ctx, u) {
		log.Warn("login source %q would remove the admin flag of %s (id %d), the last usable admin: flag kept", sourceName, u.Name, u.ID)
		keep := *opts
		keep.IsAdmin = optional.None[bool]()
		opts = &keep
	}
	return UpdateUser(ctx, u, opts)
}
