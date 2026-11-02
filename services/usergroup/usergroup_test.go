// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package usergroup

import (
	"testing"

	"forgejo.org/models"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	unittest.MainTest(m)
}

func newGroup(t *testing.T, name string) *org_model.UserGroup {
	t.Helper()
	g := &org_model.UserGroup{Name: name}
	require.NoError(t, org_model.InsertUserGroup(db.DefaultContext, g))
	return g
}

func loadTeam(t *testing.T, id int64) *org_model.Team {
	t.Helper()
	return unittest.AssertExistsAndLoadBean(t, &org_model.Team{ID: id})
}

func loadUser(t *testing.T, id int64) *user_model.User {
	t.Helper()
	return unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: id})
}

func assertTeamMember(t *testing.T, team *org_model.Team, uid int64, reason org_model.MembershipReason) {
	t.Helper()
	tu := unittest.AssertExistsAndLoadBean(t, &org_model.TeamUser{TeamID: team.ID, UID: uid})
	assert.Equal(t, reason, tu.Reason)
	unittest.AssertExistsAndLoadBean(t, &org_model.OrgUser{OrgID: team.OrgID, UID: uid})
}

func assertNotTeamMember(t *testing.T, team *org_model.Team, uid int64) {
	t.Helper()
	unittest.AssertNotExistsBean(t, &org_model.TeamUser{TeamID: team.ID, UID: uid})
}

func TestLinkTeamAcrossOrganizations(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	// team 2 belongs to org 3 and gives write access to repo 3; team 11 belongs to org 26.
	team2, team11 := loadTeam(t, 2), loadTeam(t, 11)
	user5 := loadUser(t, 5)
	group := newGroup(t, "platform-devs")
	require.NoError(t, AddMember(ctx, group, user5))

	repo3 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	mode, err := access_model.AccessLevel(ctx, user5, repo3)
	require.NoError(t, err)
	assert.Less(t, mode, team2.AccessMode)

	require.NoError(t, LinkTeam(ctx, group, team2))
	require.NoError(t, LinkTeam(ctx, group, team11))

	assertTeamMember(t, team2, 5, org_model.MembershipReasonAddedByUserGroup)
	assertTeamMember(t, team11, 5, org_model.MembershipReasonAddedByUserGroup)
	assert.Equal(t, 3, loadTeam(t, 2).NumMembers)
	assert.Equal(t, 1, loadTeam(t, 11).NumMembers)

	// the membership grants the team's access to its repositories
	mode, err = access_model.AccessLevel(ctx, user5, repo3)
	require.NoError(t, err)
	assert.Equal(t, team2.AccessMode, mode)

	linked, err := org_model.GetUserGroupTeams(ctx, group.ID)
	require.NoError(t, err)
	require.Len(t, linked, 2)
	assert.Equal(t, "org3", linked[0].Org.Name)
	assert.Equal(t, "org26", linked[1].Org.Name)

	require.ErrorIs(t, LinkTeam(ctx, group, team2), ErrAlreadyLinked)
}

func TestUnlinkTeamKeepsDirectMembers(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	team2, team11 := loadTeam(t, 2), loadTeam(t, 11)
	group := newGroup(t, "platform-devs")
	// user 4 is already a direct member of team 2
	require.NoError(t, AddMember(ctx, group, loadUser(t, 4)))
	require.NoError(t, AddMember(ctx, group, loadUser(t, 5)))
	require.NoError(t, LinkTeam(ctx, group, team2))
	require.NoError(t, LinkTeam(ctx, group, team11))

	directReason := unittest.AssertExistsAndLoadBean(t, &org_model.TeamUser{TeamID: 2, UID: 4}).Reason
	assert.NotEqual(t, org_model.MembershipReasonAddedByUserGroup, directReason)

	require.NoError(t, UnlinkTeam(ctx, group, team2))

	assertNotTeamMember(t, team2, 5)
	unittest.AssertNotExistsBean(t, &org_model.OrgUser{OrgID: 3, UID: 5})
	assertTeamMember(t, team2, 4, directReason)
	assertTeamMember(t, team11, 5, org_model.MembershipReasonAddedByUserGroup)
	unittest.AssertNotExistsBean(t, &org_model.UserGroupTeam{GroupID: group.ID, TeamID: team2.ID})
}

func TestMembershipChangesPropagateToLinkedTeams(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	team2, team11 := loadTeam(t, 2), loadTeam(t, 11)
	group := newGroup(t, "platform-devs")
	require.NoError(t, LinkTeam(ctx, group, team2))
	require.NoError(t, LinkTeam(ctx, group, team11))

	require.NoError(t, AddMember(ctx, group, loadUser(t, 8)))
	assertTeamMember(t, team2, 8, org_model.MembershipReasonAddedByUserGroup)
	assertTeamMember(t, team11, 8, org_model.MembershipReasonAddedByUserGroup)

	require.ErrorIs(t, AddMember(ctx, group, loadUser(t, 8)), ErrAlreadyMember)

	require.NoError(t, RemoveMember(ctx, group, 8))
	assertNotTeamMember(t, team2, 8)
	assertNotTeamMember(t, team11, 8)
	unittest.AssertNotExistsBean(t, &org_model.OrgUser{OrgID: 26, UID: 8})

	// removing a direct member from a group does not remove the direct membership
	require.NoError(t, AddMember(ctx, group, loadUser(t, 4)))
	require.NoError(t, RemoveMember(ctx, group, 4))
	unittest.AssertExistsAndLoadBean(t, &org_model.TeamUser{TeamID: 2, UID: 4})
}

func TestUserInSeveralGroupsLinkedToSameTeam(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	team2 := loadTeam(t, 2)
	user5 := loadUser(t, 5)
	groupA, groupB := newGroup(t, "group-a"), newGroup(t, "group-b")
	for _, g := range []*org_model.UserGroup{groupA, groupB} {
		require.NoError(t, AddMember(ctx, g, user5))
		require.NoError(t, LinkTeam(ctx, g, team2))
	}

	require.NoError(t, RemoveMember(ctx, groupA, user5.ID))
	assertTeamMember(t, team2, 5, org_model.MembershipReasonAddedByUserGroup)

	require.NoError(t, UnlinkTeam(ctx, groupB, team2))
	assertNotTeamMember(t, team2, 5)
}

func TestDeleteGroup(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	team2, team11 := loadTeam(t, 2), loadTeam(t, 11)
	group := newGroup(t, "platform-devs")
	require.NoError(t, AddMember(ctx, group, loadUser(t, 5)))
	require.NoError(t, LinkTeam(ctx, group, team2))
	require.NoError(t, LinkTeam(ctx, group, team11))

	require.NoError(t, DeleteGroup(ctx, group))

	unittest.AssertNotExistsBean(t, &org_model.UserGroup{ID: group.ID})
	unittest.AssertNotExistsBean(t, &org_model.UserGroupUser{GroupID: group.ID})
	unittest.AssertNotExistsBean(t, &org_model.UserGroupTeam{GroupID: group.ID})
	assertNotTeamMember(t, team2, 5)
	assertNotTeamMember(t, team11, 5)
}

func TestLastOwnerViaGroupCannotBeRemoved(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	// team 15 is the owners team of org 22 and has no members
	owners := loadTeam(t, 15)
	require.Zero(t, owners.NumMembers)
	group := newGroup(t, "org22-owners")
	require.NoError(t, AddMember(ctx, group, loadUser(t, 5)))
	require.NoError(t, LinkTeam(ctx, group, owners))
	assertTeamMember(t, owners, 5, org_model.MembershipReasonAddedByUserGroup)

	err := RemoveMember(ctx, group, 5)
	require.True(t, org_model.IsErrLastOrgOwner(err), "unexpected error: %v", err)

	// the whole change was rolled back
	unittest.AssertExistsAndLoadBean(t, &org_model.UserGroupUser{GroupID: group.ID, UID: 5})
	assertTeamMember(t, owners, 5, org_model.MembershipReasonAddedByUserGroup)

	err = DeleteGroup(ctx, group)
	require.True(t, org_model.IsErrLastOrgOwner(err), "unexpected error: %v", err)
	unittest.AssertExistsAndLoadBean(t, &org_model.UserGroup{ID: group.ID})
}

func TestOrganizationCannotBeMember(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	group := newGroup(t, "platform-devs")
	require.ErrorIs(t, AddMember(db.DefaultContext, group, loadUser(t, 3)), ErrOrganizationCannotBeMember)
	unittest.AssertNotExistsBean(t, &org_model.UserGroupUser{GroupID: group.ID})
}

func TestDeletingTeamRemovesLink(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	team11 := loadTeam(t, 11)
	group := newGroup(t, "platform-devs")
	require.NoError(t, AddMember(ctx, group, loadUser(t, 5)))
	require.NoError(t, LinkTeam(ctx, group, team11))

	require.NoError(t, models.DeleteTeam(ctx, team11))

	unittest.AssertNotExistsBean(t, &org_model.UserGroupTeam{TeamID: team11.ID})
	unittest.AssertExistsAndLoadBean(t, &org_model.UserGroupUser{GroupID: group.ID, UID: 5})
}
