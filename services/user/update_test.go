// Copyright 2024 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package user

import (
	"testing"
	"time"

	"forgejo.org/models"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	password_module "forgejo.org/modules/auth/password"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/structs"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
)

func TestUpdateUser(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})

	require.Error(t, UpdateUser(db.DefaultContext, admin, &UpdateOptions{
		IsAdmin: optional.Some(false),
	}))

	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 28})

	opts := &UpdateOptions{
		KeepEmailPrivate:             optional.Some(false),
		FullName:                     optional.Some("Changed Name"),
		Website:                      optional.Some("https://gitea.com/"),
		Location:                     optional.Some("location"),
		Description:                  optional.Some("description"),
		AllowGitHook:                 optional.Some(true),
		AllowImportLocal:             optional.Some(true),
		MaxRepoCreation:              optional.Some(10),
		IsRestricted:                 optional.Some(true),
		IsActive:                     optional.Some(false),
		IsAdmin:                      optional.Some(true),
		Visibility:                   optional.Some(structs.VisibleTypePrivate),
		KeepActivityPrivate:          optional.Some(true),
		Language:                     optional.Some("lang"),
		Theme:                        optional.Some("forgejo-dark"),
		DiffViewStyle:                optional.Some("split"),
		AllowCreateOrganization:      optional.Some(false),
		EmailNotificationsPreference: optional.Some("disabled"),
		SetLastLogin:                 true,
	}
	require.NoError(t, UpdateUser(ownCtx(), user, opts))

	assert.Equal(t, opts.KeepEmailPrivate.ValueOrZeroValue(), user.KeepEmailPrivate)
	assert.Equal(t, opts.FullName.ValueOrZeroValue(), user.FullName)
	assert.Equal(t, opts.Website.ValueOrZeroValue(), user.Website)
	assert.Equal(t, opts.Location.ValueOrZeroValue(), user.Location)
	assert.Equal(t, opts.Description.ValueOrZeroValue(), user.Description)
	assert.Equal(t, opts.AllowGitHook.ValueOrZeroValue(), user.AllowGitHook)
	assert.Equal(t, opts.AllowImportLocal.ValueOrZeroValue(), user.AllowImportLocal)
	assert.Equal(t, opts.MaxRepoCreation.ValueOrZeroValue(), user.MaxRepoCreation)
	assert.Equal(t, opts.IsRestricted.ValueOrZeroValue(), user.IsRestricted)
	assert.Equal(t, opts.IsActive.ValueOrZeroValue(), user.IsActive)
	assert.Equal(t, opts.IsAdmin.ValueOrZeroValue(), user.IsAdmin)
	assert.Equal(t, opts.Visibility.ValueOrZeroValue(), user.Visibility)
	assert.Equal(t, opts.KeepActivityPrivate.ValueOrZeroValue(), user.KeepActivityPrivate)
	assert.Equal(t, opts.Language.ValueOrZeroValue(), user.Language)
	assert.Equal(t, opts.Theme.ValueOrZeroValue(), user.Theme)
	assert.Equal(t, opts.DiffViewStyle.ValueOrZeroValue(), user.DiffViewStyle)
	assert.Equal(t, opts.AllowCreateOrganization.ValueOrZeroValue(), user.AllowCreateOrganization)
	assert.Equal(t, opts.EmailNotificationsPreference.ValueOrZeroValue(), user.EmailNotificationsPreference)

	user = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 28})
	assert.Equal(t, opts.KeepEmailPrivate.ValueOrZeroValue(), user.KeepEmailPrivate)
	assert.Equal(t, opts.FullName.ValueOrZeroValue(), user.FullName)
	assert.Equal(t, opts.Website.ValueOrZeroValue(), user.Website)
	assert.Equal(t, opts.Location.ValueOrZeroValue(), user.Location)
	assert.Equal(t, opts.Description.ValueOrZeroValue(), user.Description)
	assert.Equal(t, opts.AllowGitHook.ValueOrZeroValue(), user.AllowGitHook)
	assert.Equal(t, opts.AllowImportLocal.ValueOrZeroValue(), user.AllowImportLocal)
	assert.Equal(t, opts.MaxRepoCreation.ValueOrZeroValue(), user.MaxRepoCreation)
	assert.Equal(t, opts.IsRestricted.ValueOrZeroValue(), user.IsRestricted)
	assert.Equal(t, opts.IsActive.ValueOrZeroValue(), user.IsActive)
	assert.Equal(t, opts.IsAdmin.ValueOrZeroValue(), user.IsAdmin)
	assert.Equal(t, opts.Visibility.ValueOrZeroValue(), user.Visibility)
	assert.Equal(t, opts.KeepActivityPrivate.ValueOrZeroValue(), user.KeepActivityPrivate)
	assert.Equal(t, opts.Language.ValueOrZeroValue(), user.Language)
	assert.Equal(t, opts.Theme.ValueOrZeroValue(), user.Theme)
	assert.Equal(t, opts.DiffViewStyle.ValueOrZeroValue(), user.DiffViewStyle)
	assert.Equal(t, opts.AllowCreateOrganization.ValueOrZeroValue(), user.AllowCreateOrganization)
	assert.Equal(t, opts.EmailNotificationsPreference.ValueOrZeroValue(), user.EmailNotificationsPreference)
}

func TestUpdateAuth(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 28})
	userCopy := *user

	require.NoError(t, UpdateAuth(ownCtx(), user, &UpdateAuthOptions{
		LoginName: optional.Some("new-login"),
	}))
	assert.Equal(t, "new-login", user.LoginName)

	require.NoError(t, UpdateAuth(ownCtx(), user, &UpdateAuthOptions{
		Password:           optional.Some("%$DRZUVB576tfzgu"),
		MustChangePassword: optional.Some(true),
	}))
	assert.True(t, user.MustChangePassword)
	assert.NotEqual(t, userCopy.Passwd, user.Passwd)
	assert.NotEqual(t, userCopy.Salt, user.Salt)

	require.NoError(t, UpdateAuth(ownCtx(), user, &UpdateAuthOptions{
		ProhibitLogin: optional.Some(true),
	}))
	assert.True(t, user.ProhibitLogin)

	require.ErrorIs(t, UpdateAuth(ownCtx(), user, &UpdateAuthOptions{
		Password: optional.Some("aaaa"),
	}), password_module.ErrMinLength)
}

func TestUpdateLastUsableAdmin(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	deactivate := func(u *user_model.User) error {
		return UpdateUser(ctx, u, &UpdateOptions{IsActive: optional.Some(false)})
	}
	prohibit := func(u *user_model.User) error {
		return UpdateAuth(ctx, u, &UpdateAuthOptions{ProhibitLogin: optional.Some(true)})
	}
	load := func(id int64) *user_model.User {
		return unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: id})
	}

	// user 1 is the only usable admin
	for name, disable := range map[string]func(*user_model.User) error{"deactivate": deactivate, "prohibit": prohibit} {
		t.Run(name+" only admin", func(t *testing.T) {
			err := disable(load(1))
			assert.True(t, models.IsErrDeleteLastAdminUser(err), "%v", err)
			admin := load(1)
			assert.True(t, admin.IsActive)
			assert.False(t, admin.ProhibitLogin)
		})
	}
	t.Run("keep active", func(t *testing.T) {
		require.NoError(t, UpdateUser(ctx, load(1), &UpdateOptions{IsActive: optional.Some(true)}))
		require.NoError(t, UpdateAuth(ctx, load(1), &UpdateAuthOptions{ProhibitLogin: optional.Some(false)}))
	})
	t.Run("non-admin", func(t *testing.T) {
		require.NoError(t, prohibit(load(2)))
		require.NoError(t, deactivate(load(2)))
	})

	// user 2 is now a disabled admin: disabling it again is unaffected, user 1 is still the last usable one
	u2 := load(2)
	u2.IsAdmin = true
	require.NoError(t, user_model.UpdateUserCols(ctx, u2, "is_admin"))
	t.Run("disabled admin", func(t *testing.T) {
		require.NoError(t, deactivate(load(2)))
		require.NoError(t, prohibit(load(2)))
		require.Error(t, deactivate(load(1)))
	})

	// with two usable admins either can be disabled, then the other is the last one
	u2 = load(2)
	u2.IsActive, u2.ProhibitLogin = true, false
	require.NoError(t, user_model.UpdateUserCols(ctx, u2, "is_active", "prohibit_login"))
	require.NoError(t, prohibit(load(1)))
	assert.True(t, load(1).ProhibitLogin)
	require.Error(t, deactivate(load(2)))
	require.Error(t, prohibit(load(2)))

	u1 := load(1)
	u1.ProhibitLogin = false
	require.NoError(t, user_model.UpdateUserCols(ctx, u1, "prohibit_login"))
	require.NoError(t, deactivate(load(2)))
	assert.False(t, load(2).IsActive)
}

func TestUpdateUserFromSource(t *testing.T) {
	ctx := db.DefaultContext
	// user 1 is the only admin in the fixtures
	setFlags := func(t *testing.T, id int64, admin, active, prohibitLogin bool) *user_model.User {
		t.Helper()
		u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: id})
		u.IsAdmin, u.IsActive, u.ProhibitLogin = admin, active, prohibitLogin
		require.NoError(t, user_model.UpdateUserCols(ctx, u, "is_admin", "is_active", "prohibit_login"))
		return u
	}
	demote := func(t *testing.T, id int64) error {
		t.Helper()
		u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: id})
		return UpdateUserFromSource(ctx, u, &UpdateOptions{IsAdmin: optional.Some(false), IsRestricted: optional.Some(true)}, "test-source")
	}

	t.Run("sole admin keeps the flag", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		logChecker, cleanup := test.NewLogChecker(log.DEFAULT, log.WARN)
		defer cleanup()
		logChecker.Filter(`login source "test-source" would remove the admin flag of user1`).StopMark("flag kept")

		require.NoError(t, demote(t, 1))
		unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1, IsAdmin: true, IsRestricted: true})
		filtered, stopped := logChecker.Check(5 * time.Second)
		assert.True(t, stopped)
		assert.Equal(t, []bool{true}, filtered)

		// the admin UI and API paths still refuse
		admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		assert.True(t, models.IsErrDeleteLastAdminUser(UpdateUser(ctx, admin, &UpdateOptions{IsAdmin: optional.Some(false)})))
	})

	t.Run("another usable admin", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		setFlags(t, 8, true, true, false)
		require.NoError(t, demote(t, 1))
		unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1, IsAdmin: false, IsRestricted: true})
	})

	t.Run("two usable admins demoted in turn", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		setFlags(t, 8, true, true, false)
		require.NoError(t, demote(t, 1))
		require.NoError(t, demote(t, 8))
		assert.Equal(t, 1, unittest.GetCount(t, &user_model.User{}, builder.Eq{"is_admin": true}))
		unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8, IsAdmin: true})
	})

	for _, other := range []struct {
		name                  string
		id                    int64
		active, prohibitLogin bool
	}{{"other admin inactive", 8, false, false}, {"other admin prohibited", 8, true, true}, {"other admin is an organization", 3, true, false}} {
		t.Run(other.name, func(t *testing.T) {
			require.NoError(t, unittest.PrepareTestDatabase())
			setFlags(t, other.id, true, other.active, other.prohibitLogin)
			require.NoError(t, demote(t, 1))
			unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1, IsAdmin: true})
		})
	}

	t.Run("sole admin already inactive", func(t *testing.T) {
		// like UpdateUser, only the other admins are counted: the flag is kept
		require.NoError(t, unittest.PrepareTestDatabase())
		u := setFlags(t, 1, true, false, false)
		require.NoError(t, UpdateUserFromSource(ctx, u, &UpdateOptions{IsActive: optional.Some(true), IsAdmin: optional.Some(false)}, "test-source"))
		unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1, IsAdmin: true, IsActive: true})
	})

	t.Run("other errors are returned", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		defer test.MockVariableValue(&setting.Service.AllowedUserVisibilityModesSlice, []bool{true, false, false})()
		u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		err := UpdateUserFromSource(ctx, u, &UpdateOptions{IsAdmin: optional.Some(false), Visibility: optional.Some(structs.VisibleTypePrivate)}, "test-source")
		require.ErrorContains(t, err, "visibility mode not allowed")

		u = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		err = UpdateUserFromSource(ctx, u, &UpdateOptions{IsActive: optional.Some(false), IsAdmin: optional.Some(false)}, "test-source")
		assert.True(t, models.IsErrDeleteLastAdminUser(err), "%v", err)
		unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1, IsAdmin: true, IsActive: true})
	})
}

// Making someone a site admin or setting another user's password is only a person's own act; a login source syncing
// the flag and a user changing their own password are unchanged.
func TestUpdateUserOwnAct(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	grant := audit_model.WithActor(db.DefaultContext, &audit_model.Actor{Type: audit_model.ActorUser, ID: 1, Name: "user1", Credential: audit_model.Credential{Type: audit_model.CredentialOAuth2Grant}})
	u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 28})

	require.ErrorIs(t, UpdateUser(grant, u, &UpdateOptions{IsAdmin: optional.Some(true)}), audit_model.ErrNotOwnAct)
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 28}).IsAdmin)
	require.ErrorIs(t, UpdateAuth(grant, u, &UpdateAuthOptions{Password: optional.Some("%$DRZUVB576tfzgu")}), audit_model.ErrNotOwnAct)
	require.ErrorIs(t, CheckEditIsOwnAct(grant, u, &UpdateAuthOptions{}, &UpdateOptions{IsAdmin: optional.Some(true)}), audit_model.ErrNotOwnAct)
	require.NoError(t, UpdateUser(grant, u, &UpdateOptions{FullName: optional.Some("other fields")}))

	self := audit_model.WithActor(db.DefaultContext, &audit_model.Actor{Type: audit_model.ActorUser, ID: 28, Name: u.Name, Credential: audit_model.Credential{Type: audit_model.CredentialSession}})
	require.NoError(t, UpdateAuth(self, u, &UpdateAuthOptions{Password: optional.Some("%$DRZUVB576tfzgu")}))
	require.NoError(t, UpdateUserFromSource(audit_model.WithLoginSource(grant, 1, "ldap"), u, &UpdateOptions{IsAdmin: optional.Some(true)}, "ldap"))
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 28}).IsAdmin)
}
