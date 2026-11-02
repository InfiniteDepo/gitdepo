// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package organization_test

import (
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserGroupCRUD(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	g := &organization.UserGroup{Name: " Platform-Devs ", Description: "Platform developers"}
	require.NoError(t, organization.InsertUserGroup(ctx, g))
	assert.Equal(t, "Platform-Devs", g.Name)
	assert.Equal(t, "platform-devs", g.LowerName)

	err := organization.InsertUserGroup(ctx, &organization.UserGroup{Name: "PLATFORM-devs"})
	require.True(t, organization.IsErrUserGroupAlreadyExist(err), "unexpected error: %v", err)

	got, err := organization.GetUserGroupByName(ctx, "platform-DEVS")
	require.NoError(t, err)
	assert.Equal(t, g.ID, got.ID)
	assert.Equal(t, "Platform developers", got.Description)

	_, err = organization.GetUserGroupByName(ctx, "missing")
	require.True(t, organization.IsErrUserGroupNotExist(err))
	_, err = organization.GetUserGroupByID(ctx, 9999)
	require.True(t, organization.IsErrUserGroupNotExist(err))

	other := &organization.UserGroup{Name: "qa"}
	require.NoError(t, organization.InsertUserGroup(ctx, other))
	other.Name = "Platform-devs"
	err = organization.UpdateUserGroup(ctx, other)
	require.True(t, organization.IsErrUserGroupAlreadyExist(err), "unexpected error: %v", err)

	other.Name = "quality"
	other.Description = "QA engineers"
	require.NoError(t, organization.UpdateUserGroup(ctx, other))
	got, err = organization.GetUserGroupByID(ctx, other.ID)
	require.NoError(t, err)
	assert.Equal(t, "quality", got.LowerName)
	assert.Equal(t, "QA engineers", got.Description)

	groups, count, err := organization.SearchUserGroups(ctx, &organization.SearchUserGroupOptions{Keyword: "PLAT"})
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
	require.Len(t, groups, 1)
	assert.Equal(t, g.ID, groups[0].ID)

	groups, count, err = organization.SearchUserGroups(ctx, &organization.SearchUserGroupOptions{})
	require.NoError(t, err)
	assert.EqualValues(t, 2, count)
	assert.Equal(t, []string{"platform-devs", "quality"}, []string{groups[0].LowerName, groups[1].LowerName})
}

func TestUserGroupMembersAndTeams(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	g := &organization.UserGroup{Name: "devs"}
	require.NoError(t, organization.InsertUserGroup(ctx, g))
	require.NoError(t, organization.InsertUserGroupMember(ctx, g.ID, 5, 0))
	require.NoError(t, organization.InsertUserGroupMember(ctx, g.ID, 4, 0))

	members, err := organization.GetUserGroupMembers(ctx, g.ID, db.ListOptions{})
	require.NoError(t, err)
	require.Len(t, members, 2)
	assert.Equal(t, "user4", members[0].Name)
	assert.Equal(t, "user5", members[1].Name)

	isMember, err := organization.IsUserGroupMember(ctx, g.ID, 5)
	require.NoError(t, err)
	assert.True(t, isMember)

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	viaGroup, err := organization.IsTeamMemberViaUserGroup(ctx, team.ID, 5)
	require.NoError(t, err)
	assert.False(t, viaGroup)

	require.NoError(t, organization.InsertUserGroupTeam(ctx, g.ID, team, organization.LinkManual))
	unittest.AssertExistsAndLoadBean(t, &organization.UserGroupTeam{GroupID: g.ID, TeamID: team.ID, OrgID: team.OrgID})

	viaGroup, err = organization.IsTeamMemberViaUserGroup(ctx, team.ID, 5)
	require.NoError(t, err)
	assert.True(t, viaGroup)
	viaGroup, err = organization.IsTeamMemberViaUserGroup(ctx, team.ID, 8)
	require.NoError(t, err)
	assert.False(t, viaGroup)

	linkable, _, err := organization.SearchUserGroups(ctx, &organization.SearchUserGroupOptions{NotLinkedToTeamID: team.ID})
	require.NoError(t, err)
	assert.Empty(t, linkable)
	linkable, _, err = organization.SearchUserGroups(ctx, &organization.SearchUserGroupOptions{NotLinkedToTeamID: 1})
	require.NoError(t, err)
	assert.Len(t, linkable, 1)

	groups, err := organization.GetTeamUserGroups(ctx, team.ID)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, g.ID, groups[0].ID)

	require.NoError(t, g.LoadCounts(ctx))
	assert.Equal(t, 2, g.NumMembers)
	assert.Equal(t, 1, g.NumTeams)

	require.NoError(t, organization.DeleteUserGroupMember(ctx, g.ID, 5))
	require.NoError(t, organization.DeleteUserGroupTeam(ctx, g.ID, team.ID))
	require.NoError(t, g.LoadCounts(ctx))
	assert.Equal(t, 1, g.NumMembers)
	assert.Equal(t, 0, g.NumTeams)
}

func TestUserGroupTeamCounts(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	a := &organization.UserGroup{Name: "platform-devs"}
	b := &organization.UserGroup{Name: "release-managers"}
	empty := &organization.UserGroup{Name: "empty"}
	for _, g := range []*organization.UserGroup{a, b, empty} {
		require.NoError(t, organization.InsertUserGroup(ctx, g))
	}
	for _, uid := range []int64{2, 4, 5} {
		require.NoError(t, organization.InsertUserGroupMember(ctx, a.ID, uid, 0))
	}
	require.NoError(t, organization.InsertUserGroupMember(ctx, b.ID, 5, 0))
	require.NoError(t, organization.InsertUserGroupMember(ctx, b.ID, 8, 0))

	team2 := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	team11 := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 11})
	team1 := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 1})
	for _, g := range []*organization.UserGroup{a, b, empty} {
		require.NoError(t, organization.InsertUserGroupTeam(ctx, g.ID, team2, organization.LinkManual))
	}
	require.NoError(t, organization.InsertUserGroupTeam(ctx, b.ID, team11, organization.LinkManual))

	groups := []*organization.UserGroup{a, b, empty}
	require.NoError(t, organization.LoadUserGroupsNumMembers(ctx, groups))
	assert.Equal(t, []int{3, 2, 0}, []int{a.NumMembers, b.NumMembers, empty.NumMembers})

	teams := []*organization.Team{team1, team2, team11}
	require.NoError(t, organization.LoadTeamsNumUserGroups(ctx, teams))
	assert.Equal(t, []int{0, 3, 1}, []int{team1.NumUserGroups, team2.NumUserGroups, team11.NumUserGroups})

	byUser, err := organization.GetTeamMembersUserGroups(ctx, team2.ID, []int64{2, 5, 8, 9})
	require.NoError(t, err)
	names := func(uid int64) (n []string) {
		for _, g := range byUser[uid] {
			n = append(n, g.Name)
		}
		return n
	}
	assert.Equal(t, []string{"platform-devs"}, names(2))
	assert.Equal(t, []string{"platform-devs", "release-managers"}, names(5))
	assert.Equal(t, []string{"release-managers"}, names(8))
	assert.Empty(t, names(9))
	assert.NotContains(t, byUser, int64(4), "user 4 was not asked for")

	byUser, err = organization.GetTeamMembersUserGroups(ctx, team11.ID, []int64{2, 5})
	require.NoError(t, err)
	assert.Equal(t, []string{"release-managers"}, names(5))
	assert.Empty(t, names(2))
}

func TestCountUserGroupRoleLosses(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	group := &organization.UserGroup{Name: "admins", GrantsSiteAdmin: true, GrantsCreateOrganization: true}
	require.NoError(t, organization.InsertUserGroup(ctx, group))
	other := &organization.UserGroup{Name: "other-admins", GrantsSiteAdmin: true, GrantsCreateOrganization: true}
	require.NoError(t, organization.InsertUserGroup(ctx, other))

	setFlags := func(uid int64, admin, createOrg bool, roles ...organization.UserGroupRole) {
		_, err := db.GetEngine(ctx).ID(uid).Cols("is_admin", "allow_create_organization").
			Update(&user_model.User{IsAdmin: admin, AllowCreateOrganization: createOrg})
		require.NoError(t, err)
		for _, role := range roles {
			require.NoError(t, db.Insert(ctx, &organization.UserGroupRoleGrant{UID: uid, Role: role}))
		}
	}
	both := []organization.UserGroupRole{organization.UserGroupRoleSiteAdmin, organization.UserGroupRoleCreateOrganization}
	// user2 has both roles only through this group: counted.
	setFlags(2, true, true, both...)
	// user4 has both roles through this group and another group: not counted.
	setFlags(4, true, true, both...)
	require.NoError(t, organization.InsertUserGroupMember(ctx, other.ID, 4, 0))
	// user1 has both flags set by hand, without a grant row: not counted.
	// user5 has grant rows but both flags are already off: not counted.
	setFlags(5, false, false, both...)
	for _, uid := range []int64{1, 2, 4, 5} {
		require.NoError(t, organization.InsertUserGroupMember(ctx, group.ID, uid, 0))
	}

	counts, err := organization.CountUserGroupRoleLosses(ctx, group.ID, both...)
	require.NoError(t, err)
	assert.Equal(t, map[organization.UserGroupRole]int{
		organization.UserGroupRoleSiteAdmin:          1,
		organization.UserGroupRoleCreateOrganization: 1,
	}, counts)

	counts, err = organization.CountUserGroupRoleLosses(ctx, group.ID, organization.UserGroupRoleSiteAdmin)
	require.NoError(t, err)
	assert.Equal(t, map[organization.UserGroupRole]int{organization.UserGroupRoleSiteAdmin: 1}, counts)

	counts, err = organization.CountUserGroupRoleLosses(ctx, group.ID)
	require.NoError(t, err)
	assert.Empty(t, counts)
}

func TestCountUserGroupRoleLossesAuditor(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	auditor := organization.UserGroupRoleAuditor

	group := &organization.UserGroup{Name: "auditors", GrantsAuditor: true}
	require.NoError(t, organization.InsertUserGroup(ctx, group))
	other := &organization.UserGroup{Name: "other-auditors", GrantsAuditor: true}
	require.NoError(t, organization.InsertUserGroup(ctx, other))

	setAuditor := func(uid int64, flag, grant bool) {
		_, err := db.GetEngine(ctx).ID(uid).Cols("is_auditor").Update(&user_model.User{IsAuditor: flag})
		require.NoError(t, err)
		if grant {
			require.NoError(t, db.Insert(ctx, &organization.UserGroupRoleGrant{UID: uid, Role: auditor}))
		}
		require.NoError(t, organization.InsertUserGroupMember(ctx, group.ID, uid, 0))
	}
	// user2 and user3 have auditor only through this group: counted.
	setAuditor(2, true, true)
	setAuditor(3, true, true)
	// user4 also gets it from another group: not counted.
	setAuditor(4, true, true)
	require.NoError(t, organization.InsertUserGroupMember(ctx, other.ID, 4, 0))
	// user1 has the flag set by hand, without a grant row: not counted.
	setAuditor(1, true, false)
	// user5 has a grant row but the flag is already off: not counted.
	setAuditor(5, false, true)

	counts, err := organization.CountUserGroupRoleLosses(ctx, group.ID, auditor, organization.UserGroupRoleSiteAdmin)
	require.NoError(t, err)
	assert.Equal(t, map[organization.UserGroupRole]int{auditor: 2}, counts)

	// a role list without auditor leaves it out
	counts, err = organization.CountUserGroupRoleLosses(ctx, group.ID, organization.UserGroupRoleSiteAdmin)
	require.NoError(t, err)
	assert.Empty(t, counts)
}

func TestGetUserGroupTeamsTrashedOrg(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	g := &organization.UserGroup{Name: "devs"}
	require.NoError(t, organization.InsertUserGroup(ctx, g))
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	require.NoError(t, organization.InsertUserGroupTeam(ctx, g.ID, team, organization.LinkManual))
	_, err := db.GetEngine(ctx).ID(team.OrgID).Cols("trashed_unix").Update(&user_model.User{TrashedUnix: 1})
	require.NoError(t, err)

	linked, err := organization.GetUserGroupTeams(ctx, g.ID)
	require.NoError(t, err)
	require.Len(t, linked, 1)
	assert.Equal(t, team.OrgID, linked[0].Org.ID)
	assert.NotZero(t, linked[0].Org.TrashedUnix)
}
