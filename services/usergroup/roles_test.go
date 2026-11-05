// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package usergroup

import (
	"slices"
	"testing"

	"forgejo.org/models"
	org_model "forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	"forgejo.org/modules/test"
	user_service "forgejo.org/services/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRoleGroup(t *testing.T, name string, admin, createOrg bool) *org_model.UserGroup {
	t.Helper()
	g := &org_model.UserGroup{Name: name, GrantsSiteAdmin: admin, GrantsCreateOrganization: createOrg}
	require.NoError(t, org_model.InsertUserGroup(ownCtx(), g))
	return g
}

func assertRoles(t *testing.T, uid int64, admin, createOrg bool) {
	t.Helper()
	u := loadUser(t, uid)
	assert.Equal(t, admin, u.IsAdmin, "IsAdmin")
	assert.Equal(t, createOrg, u.AllowCreateOrganization, "AllowCreateOrganization")
}

func grantCount(t *testing.T, uid int64) int {
	t.Helper()
	return unittest.GetCount(t, &org_model.UserGroupRoleGrant{UID: uid})
}

func setUserFlags(t *testing.T, uid int64, admin, createOrg bool) {
	t.Helper()
	u := loadUser(t, uid)
	u.IsAdmin, u.AllowCreateOrganization = admin, createOrg
	require.NoError(t, user_model.UpdateUserCols(ownCtx(), u, "is_admin", "allow_create_organization"))
}

func TestRolesGrantAndRevoke(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()

	// user 5 is neither admin nor allowed to create organizations
	assertRoles(t, 5, false, false)
	group := newRoleGroup(t, "admins", true, true)

	require.NoError(t, AddMember(ctx, group, loadUser(t, 5)))
	assertRoles(t, 5, true, true)
	assert.Equal(t, 2, grantCount(t, 5))

	require.NoError(t, RemoveMember(ctx, group, 5))
	assertRoles(t, 5, false, false)
	assert.Equal(t, 0, grantCount(t, 5))
}

func TestRolesManualFlagIsKept(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()

	setUserFlags(t, 5, true, true)
	group := newRoleGroup(t, "admins", true, true)

	require.NoError(t, AddMember(ctx, group, loadUser(t, 5)))
	assert.Equal(t, 0, grantCount(t, 5), "a flag set by hand is not recorded as granted")

	require.NoError(t, RemoveMember(ctx, group, 5))
	assertRoles(t, 5, true, true)
}

func TestRolesSeveralGroups(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()

	a, b := newRoleGroup(t, "admins-a", true, false), newRoleGroup(t, "admins-b", true, false)
	require.NoError(t, AddMember(ctx, a, loadUser(t, 5)))
	require.NoError(t, AddMember(ctx, b, loadUser(t, 5)))
	assertRoles(t, 5, true, false)
	assert.Equal(t, 1, grantCount(t, 5))

	require.NoError(t, RemoveMember(ctx, a, 5))
	assertRoles(t, 5, true, false)

	require.NoError(t, RemoveMember(ctx, b, 5))
	assertRoles(t, 5, false, false)
	assert.Equal(t, 0, grantCount(t, 5))
}

func TestRolesChangeAndDeleteGroup(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()

	group := newRoleGroup(t, "staff", false, false)
	require.NoError(t, AddMember(ctx, group, loadUser(t, 5)))
	assertRoles(t, 5, false, false)

	group.GrantsCreateOrganization = true
	require.NoError(t, UpdateGroup(ctx, group))
	assertRoles(t, 5, false, true)

	group.GrantsCreateOrganization, group.GrantsSiteAdmin = false, true
	require.NoError(t, UpdateGroup(ctx, group))
	assertRoles(t, 5, true, false)

	require.NoError(t, DeleteGroup(ctx, group))
	assertRoles(t, 5, false, false)
	assert.Equal(t, 0, grantCount(t, 5))
}

func TestRolesLastAdminGuard(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()

	group := newRoleGroup(t, "admins", true, false)
	require.NoError(t, AddMember(ctx, group, loadUser(t, 5)))
	// user 1 is the only other admin: user 5 becomes the last one
	setUserFlags(t, 1, false, true)

	err := RemoveMember(ctx, group, 5)
	assert.True(t, models.IsErrDeleteLastAdminUser(err), "%v", err)
	unittest.AssertExistsAndLoadBean(t, &org_model.UserGroupUser{GroupID: group.ID, UID: 5})

	group.GrantsSiteAdmin = false
	err = UpdateGroup(ctx, group)
	assert.True(t, models.IsErrDeleteLastAdminUser(err), "%v", err)
	unittest.AssertExistsAndLoadBean(t, &org_model.UserGroup{ID: group.ID, GrantsSiteAdmin: true})

	err = DeleteGroup(ctx, group)
	assert.True(t, models.IsErrDeleteLastAdminUser(err), "%v", err)
	unittest.AssertExistsAndLoadBean(t, &org_model.UserGroup{ID: group.ID})

	assertRoles(t, 5, true, false)
	assert.Equal(t, 1, grantCount(t, 5))

	// with another admin around, the change goes through
	setUserFlags(t, 1, true, true)
	require.NoError(t, RemoveMember(ctx, group, 5))
	assertRoles(t, 5, false, false)
}

func TestRolesLastUsableAdminGuard(t *testing.T) {
	ctx := ownCtx()
	for _, col := range []string{"is_active", "prohibit_login"} {
		t.Run(col, func(t *testing.T) {
			require.NoError(t, unittest.PrepareTestDatabase())
			group := newRoleGroup(t, "admins", true, false)
			require.NoError(t, AddMember(ctx, group, loadUser(t, 5)))
			// user 1 stays an admin but cannot sign in: user 5 is the last usable one
			admin := loadUser(t, 1)
			admin.IsActive, admin.ProhibitLogin = col != "is_active", col == "prohibit_login"
			require.NoError(t, user_model.UpdateUserCols(ctx, admin, "is_active", "prohibit_login"))

			err := RemoveMember(ctx, group, 5)
			assert.True(t, models.IsErrDeleteLastAdminUser(err), "%v", err)
			assertRoles(t, 5, true, false)

			// the disabled admin loses a group grant while user 5 remains usable
			setUserFlags(t, 1, false, false)
			disabled := newRoleGroup(t, "disabled-admins", true, false)
			require.NoError(t, AddMember(ctx, disabled, loadUser(t, 1)))
			require.NoError(t, RemoveMember(ctx, disabled, 1))
			assertRoles(t, 1, false, false)
		})
	}
}

func TestRolesLastAdminGuardSameTransaction(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()

	// users 1 and 5 are the only admins, both through the same group
	setUserFlags(t, 1, false, false)
	group := newRoleGroup(t, "admins", true, false)
	require.NoError(t, AddMember(ctx, group, loadUser(t, 1)))
	require.NoError(t, AddMember(ctx, group, loadUser(t, 5)))

	err := DeleteGroup(ctx, group)
	assert.True(t, models.IsErrDeleteLastAdminUser(err), "%v", err)
	unittest.AssertExistsAndLoadBean(t, &org_model.UserGroup{ID: group.ID})
	assertRoles(t, 1, true, false)
	assertRoles(t, 5, true, false)
}

func TestRolesUserDeletionRemovesGrants(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()

	group := newRoleGroup(t, "admins", true, false)
	require.NoError(t, AddMember(ctx, group, loadUser(t, 9)))
	assert.Equal(t, 1, grantCount(t, 9))

	require.NoError(t, user_service.DeleteUser(ctx, loadUser(t, 9), false))
	assert.Equal(t, 0, grantCount(t, 9))
}

func TestDirectoryAdmin(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()

	check := func(uid int64, directoryIsAdmin, expected bool) {
		t.Helper()
		isAdmin, err := DirectoryAdmin(ctx, loadUser(t, uid), directoryIsAdmin)
		require.NoError(t, err)
		assert.Equal(t, expected, isAdmin)
	}

	// without a group, the directory decides
	check(1, false, false)
	check(5, true, true)

	group := newRoleGroup(t, "admins", true, false)
	require.NoError(t, AddMember(ctx, group, loadUser(t, 5)))
	// the group grant wins over the directory
	check(5, false, true)
	check(5, true, true)
}

func TestDirectoryAdminWithoutGrantRow(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()

	// user 2 is already an admin through the directory when they join the group,
	// so the group records no grant
	setUserFlags(t, 2, true, true)
	group := newRoleGroup(t, "admins", true, false)
	require.NoError(t, AddMember(ctx, group, loadUser(t, 2)))
	assert.Equal(t, 0, grantCount(t, 2))

	// the directory drops the admin attribute: the group still keeps them admin
	isAdmin, err := DirectoryAdmin(ctx, loadUser(t, 2), false)
	require.NoError(t, err)
	assert.True(t, isAdmin)
}

func TestRolesAuditor(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()

	group := &org_model.UserGroup{Name: "auditors", GrantsAuditor: true}
	require.NoError(t, org_model.InsertUserGroup(ctx, group))
	user := loadUser(t, 5)
	assert.False(t, user.IsAuditor)

	require.NoError(t, AddMember(ctx, group, user))
	assert.True(t, loadUser(t, 5).IsAuditor)
	assertRoles(t, 5, false, false)
	assert.Equal(t, 1, grantCount(t, 5))

	require.NoError(t, RemoveMember(ctx, group, 5))
	assert.False(t, loadUser(t, 5).IsAuditor)
	assert.Equal(t, 0, grantCount(t, 5))

	const sourceID = 7
	mapping := map[string]container.Set[string]{"cn=auditors": container.SetOf("auditors")}
	require.NoError(t, SyncDirectoryGroups(ctx, user, sourceID, container.SetOf("cn=auditors"), mapping, true))
	assert.True(t, loadUser(t, 5).IsAuditor)
	require.NoError(t, SyncDirectoryGroups(ctx, user, sourceID, container.SetOf[string](), mapping, true))
	assert.False(t, loadUser(t, 5).IsAuditor)
}

func TestRolesUnknownRole(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&org_model.UserGroupRoles, append(slices.Clone(org_model.UserGroupRoles), "unknown"))()

	require.Error(t, syncRoles(ownCtx(), 0, 5))
	assertRoles(t, 5, false, false)
}
