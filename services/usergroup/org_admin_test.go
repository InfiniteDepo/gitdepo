// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package usergroup

import (
	"testing"

	"forgejo.org/models"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/container"
	"forgejo.org/modules/optional"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// users without any team membership in the fixtures
const (
	userA = 8
	userB = 10
)

// ownerTeams returns the Owners team of every organization.
func ownerTeams(t *testing.T) []*org_model.Team {
	t.Helper()
	teams := make([]*org_model.Team, 0, 20)
	require.NoError(t, db.GetEngine(ownCtx()).Where("name=?", org_model.OwnerTeamName).Find(&teams))
	require.NotEmpty(t, teams)
	return teams
}

// withOrg22Owner gives the organizations whose Owners team is empty in the
// fixtures (org 22 among them) a manual owner.
func withOrg22Owner(t *testing.T) {
	t.Helper()
	for _, team := range ownerTeams(t) {
		if team.NumMembers > 0 {
			continue
		}
		_, err := models.InsertTeamMember(audit_model.WithSystem(ownCtx(), "test"), loadTeam(t, team.ID), 2, org_model.MembershipReasonAddedByUser, optional.None[int64](), optional.None[int64]())
		require.NoError(t, err)
	}
}

func newOrgAdminGroup(t *testing.T, name string, uids ...int64) *org_model.UserGroup {
	t.Helper()
	g := &org_model.UserGroup{Name: name}
	require.NoError(t, org_model.InsertUserGroup(ownCtx(), g))
	for _, uid := range uids {
		require.NoError(t, AddMember(ownCtx(), g, loadUser(t, uid)))
	}
	return g
}

func setOrgAdmin(t *testing.T, g *org_model.UserGroup, on bool) error {
	t.Helper()
	g.GrantsOrgAdmin = on
	return UpdateGroup(ownCtx(), g)
}

func linkManaged(t *testing.T, g *org_model.UserGroup, team *org_model.Team) int {
	t.Helper()
	l := &org_model.UserGroupTeam{GroupID: g.ID, TeamID: team.ID}
	has, err := db.GetEngine(ownCtx()).Get(l)
	require.NoError(t, err)
	if !has {
		return -1
	}
	return l.Managed
}

// AC2, AC4, AC6 (no user flag), AC10: the role links the group to every Owners team; members follow the links.
func TestOrgAdminRoleLinksAllOrgs(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	withOrg22Owner(t)
	ctx := ownCtx()
	owners := ownerTeams(t)
	g := newOrgAdminGroup(t, "platform-admins", userA)

	require.NoError(t, setOrgAdmin(t, g, true))
	for _, team := range owners {
		assert.Equal(t, org_model.LinkManaged, linkManaged(t, g, team), "org %d", team.OrgID)
		isOwner, err := org_model.IsOrganizationOwner(ctx, team.OrgID, userA)
		require.NoError(t, err)
		assert.True(t, isOwner, "org %d", team.OrgID)
	}
	assert.False(t, loadUser(t, userA).IsAdmin)

	// a member added later becomes owner too
	require.NoError(t, AddMember(ctx, g, loadUser(t, userB)))
	for _, team := range owners {
		assertTeamMember(t, loadTeam(t, team.ID), userB, org_model.MembershipReasonAddedByUserGroup)
	}

	// removing the member removes only what the group created
	require.NoError(t, RemoveMember(ctx, g, userB))
	for _, team := range owners {
		assertNotTeamMember(t, loadTeam(t, team.ID), userB)
	}
}

// AC4: a membership the user holds another way stays.
func TestOrgAdminRoleKeepsOtherMemberships(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	withOrg22Owner(t)
	ctx := ownCtx()
	org3 := loadTeam(t, 1)
	// user 2 is a member of org 3's Owners team by hand (fixture); add user 5 by group
	g1 := newOrgAdminGroup(t, "g1", userA)
	g2 := newOrgAdminGroup(t, "g2", userA)
	require.NoError(t, setOrgAdmin(t, g1, true))
	require.NoError(t, setOrgAdmin(t, g2, true))

	require.NoError(t, RemoveMember(ctx, g1, userA))
	assertTeamMember(t, org3, userA, org_model.MembershipReasonAddedByUserGroup) // still via g2
	require.NoError(t, RemoveMember(ctx, g2, userA))
	assertNotTeamMember(t, org3, userA)

	// a manual membership survives the policy
	manual := newOrgAdminGroup(t, "g3", userB)
	assertTeamMember(t, loadTeam(t, 1), 2, org_model.MembershipReasonUnknown)
	require.NoError(t, setOrgAdmin(t, manual, true))
	require.NoError(t, RemoveMember(ctx, manual, userB))
	assertTeamMember(t, loadTeam(t, 1), 2, org_model.MembershipReasonUnknown)
}

// AC5, AC7: taking the role off removes managed links and their memberships; a manual link stays, as manual.
func TestOrgAdminRoleOff(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	withOrg22Owner(t)
	ctx := ownCtx()
	owners := ownerTeams(t)
	org3 := loadTeam(t, 1)
	g := newOrgAdminGroup(t, "platform-admins", userA)
	require.NoError(t, LinkTeam(ctx, g, org3)) // manual link first

	require.NoError(t, setOrgAdmin(t, g, true))
	assert.Equal(t, org_model.LinkManualManaged, linkManaged(t, g, org3))

	require.NoError(t, setOrgAdmin(t, g, false))
	assert.Equal(t, org_model.LinkManual, linkManaged(t, g, org3))
	assertTeamMember(t, loadTeam(t, org3.ID), userA, org_model.MembershipReasonAddedByUserGroup)
	for _, team := range owners {
		if team.ID == org3.ID {
			continue
		}
		assert.Equal(t, -1, linkManaged(t, g, team), "org %d", team.OrgID)
		assertNotTeamMember(t, loadTeam(t, team.ID), userA)
	}
}

// AC5, AC10: role removal that would orphan an organization is refused and nothing is applied.
func TestOrgAdminRoleOffLastOwnerRefused(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	// org 22's Owners team (15) has no members: the group is its only owner
	g := newOrgAdminGroup(t, "platform-admins", userA)
	require.NoError(t, setOrgAdmin(t, g, true))
	assertTeamMember(t, loadTeam(t, 15), userA, org_model.MembershipReasonAddedByUserGroup)

	err := setOrgAdmin(t, g, false)
	require.True(t, org_model.IsErrLastOrgOwner(err), "unexpected error: %v", err)
	assert.Equal(t, int64(22), err.(org_model.ErrLastOrgOwner).OrgID)

	// nothing was partly applied
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &org_model.UserGroup{ID: g.ID}).GrantsOrgAdmin)
	for _, team := range ownerTeams(t) {
		assert.Equal(t, org_model.LinkManaged, linkManaged(t, g, team), "org %d", team.OrgID)
		assertTeamMember(t, loadTeam(t, team.ID), userA, org_model.MembershipReasonAddedByUserGroup)
	}
}

// AC8, AC10: an excluded org gets no link; removing the exclusion creates it.
func TestOrgAdminExclusions(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	withOrg22Owner(t)
	ctx := ownCtx()
	org3 := loadTeam(t, 1)
	g := newOrgAdminGroup(t, "platform-admins", userA)
	require.NoError(t, setOrgAdmin(t, g, true))

	require.NoError(t, SetOrgAdminExclusions(ctx, []int64{3}))
	assert.Equal(t, -1, linkManaged(t, g, org3))
	assertNotTeamMember(t, org3, userA)
	ids, err := org_model.GetOrgAdminExclusionOrgIDs(ctx)
	require.NoError(t, err)
	assert.Equal(t, container.SetOf(int64(3)), ids)

	require.NoError(t, SetOrgAdminExclusions(ctx, nil))
	assert.Equal(t, org_model.LinkManaged, linkManaged(t, g, org3))
	assertTeamMember(t, loadTeam(t, org3.ID), userA, org_model.MembershipReasonAddedByUserGroup)
}

// AC5, AC10, S4: an exclusion that would orphan an organization is refused as a whole.
// The organization has two owners through two groups, so a stale member count would let the second removal through.
func TestOrgAdminExclusionLastOwnerRefused(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()
	a := newOrgAdminGroup(t, "g-a", userA)
	b := newOrgAdminGroup(t, "g-b", userB)
	require.NoError(t, setOrgAdmin(t, a, true))
	require.NoError(t, setOrgAdmin(t, b, true))
	require.Equal(t, 2, loadTeam(t, 15).NumMembers)

	err := SetOrgAdminExclusions(ctx, []int64{22})
	require.True(t, org_model.IsErrLastOrgOwner(err), "unexpected error: %v", err)

	ids, err := org_model.GetOrgAdminExclusionOrgIDs(ctx)
	require.NoError(t, err)
	assert.Empty(t, ids)
	assert.Equal(t, 2, loadTeam(t, 15).NumMembers)
	assertTeamMember(t, loadTeam(t, 15), userA, org_model.MembershipReasonAddedByUserGroup)
	assertTeamMember(t, loadTeam(t, 15), userB, org_model.MembershipReasonAddedByUserGroup)
	assert.Equal(t, org_model.LinkManaged, linkManaged(t, a, loadTeam(t, 15)))
	assert.Equal(t, org_model.LinkManaged, linkManaged(t, b, loadTeam(t, 15)))
}

// An org without an Owners team is skipped instead of failing the whole change.
func TestOrgAdminSkipsOrgWithoutOwnersTeam(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	_, err := db.GetEngine(ownCtx()).Exec("UPDATE team SET name='Boss', lower_name='boss' WHERE id=?", 1)
	require.NoError(t, err)
	g := newOrgAdminGroup(t, "platform-admins", userA)
	require.NoError(t, setOrgAdmin(t, g, true))
	assertTeamMember(t, loadTeam(t, 3), userA, org_model.MembershipReasonAddedByUserGroup)
}

// Deleting an organization drops its exclusion and its links.
func TestOrgAdminOrgDeletion(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()
	g := newOrgAdminGroup(t, "platform-admins")
	require.NoError(t, setOrgAdmin(t, g, true))
	require.NoError(t, SetOrgAdminExclusions(ctx, []int64{22}))
	require.NoError(t, SetOrgAdminExclusions(ctx, []int64{22, 23}))

	org := unittest.AssertExistsAndLoadBean(t, &org_model.Organization{ID: 23})
	require.NoError(t, org_model.DeleteOrganization(ctx, org))
	unittest.AssertNotExistsBean(t, &org_model.OrgAdminExclusion{OrgID: 23})
	unittest.AssertExistsAndLoadBean(t, &org_model.OrgAdminExclusion{OrgID: 22})
	unittest.AssertNotExistsBean(t, &org_model.UserGroupTeam{OrgID: 23})
}
