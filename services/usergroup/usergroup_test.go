// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package usergroup

import (
	"context"
	"testing"

	"forgejo.org/models"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	unittest.MainTest(m)
}

func newGroup(t *testing.T, name string) *org_model.UserGroup {
	t.Helper()
	g := &org_model.UserGroup{Name: name}
	require.NoError(t, org_model.InsertUserGroup(ownCtx(), g))
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
	ctx := ownCtx()

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
	ctx := ownCtx()

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
	ctx := ownCtx()

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
	ctx := ownCtx()

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
	ctx := ownCtx()

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
	ctx := ownCtx()

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
	require.ErrorIs(t, AddMember(ownCtx(), group, loadUser(t, 3)), ErrOrganizationCannotBeMember)
	unittest.AssertNotExistsBean(t, &org_model.UserGroupUser{GroupID: group.ID})
}

func TestDeletingTeamRemovesLink(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()

	team11 := loadTeam(t, 11)
	group := newGroup(t, "platform-devs")
	require.NoError(t, AddMember(ctx, group, loadUser(t, 5)))
	require.NoError(t, LinkTeam(ctx, group, team11))

	require.NoError(t, models.DeleteTeam(ctx, team11))

	unittest.AssertNotExistsBean(t, &org_model.UserGroupTeam{TeamID: team11.ID})
	unittest.AssertExistsAndLoadBean(t, &org_model.UserGroupUser{GroupID: group.ID, UID: 5})
}

// ownCtx is a request of the site admin with a credential of their own (audit_model.IsOwnAct): the group writes that
// add team members refuse delegated credentials.
func ownCtx() context.Context {
	return audit_model.WithActor(db.DefaultContext, &audit_model.Actor{Type: audit_model.ActorUser, ID: 1, Name: "user1", Credential: audit_model.Credential{Type: audit_model.CredentialSession}})
}

// A request that links a group to the Owners team or a reviewer team, adds a member to a group, makes a group grant
// the org-admin role or lifts an exclusion adds team members, so it is only the doer's own act; the sync that follows
// such a change, and the sync of a login source, still adds to a protected team.
func TestGroupWritesThatAddTeamMembersAreOwnActs(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	grant := audit_model.WithActor(db.DefaultContext, &audit_model.Actor{Type: audit_model.ActorUser, ID: 1, Name: "user1", Credential: audit_model.Credential{Type: audit_model.CredentialOAuth2Grant}})
	owners, reviewers, unrelated := loadTeam(t, 1), loadTeam(t, 2), loadTeam(t, 7)
	_, err := db.GetEngine(db.DefaultContext).Exec("INSERT INTO action_environment_reviewer (environment_id, user_id, team_id) VALUES (1, 0, ?)", reviewers.ID)
	require.NoError(t, err)

	group := newGroup(t, "deployers")
	require.NoError(t, AddMember(ownCtx(), group, loadUser(t, 8)))
	for _, team := range []*org_model.Team{owners, reviewers} {
		require.ErrorIs(t, LinkTeam(grant, group, team), audit_model.ErrNotOwnAct)
		assertNotTeamMember(t, team, 8)
	}
	require.NoError(t, LinkTeam(grant, group, unrelated), "another team")
	assertTeamMember(t, unrelated, 8, org_model.MembershipReasonAddedByUserGroup)

	require.ErrorIs(t, AddMember(grant, group, loadUser(t, 10)), audit_model.ErrNotOwnAct)
	require.ErrorIs(t, CreateGroup(grant, &org_model.UserGroup{Name: "org-admins", GrantsOrgAdmin: true}), audit_model.ErrNotOwnAct)
	unittest.AssertNotExistsBean(t, &org_model.UserGroup{LowerName: "org-admins"})
	group.GrantsOrgAdmin = true
	require.ErrorIs(t, UpdateGroup(grant, group), audit_model.ErrNotOwnAct)
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &org_model.UserGroup{ID: group.ID}).GrantsOrgAdmin)
	group.GrantsOrgAdmin = false
	// so are the site admin and auditor roles
	require.ErrorIs(t, CreateGroup(grant, &org_model.UserGroup{Name: "site-admins", GrantsSiteAdmin: true}), audit_model.ErrNotOwnAct)
	require.ErrorIs(t, CreateGroup(grant, &org_model.UserGroup{Name: "auditors", GrantsAuditor: true}), audit_model.ErrNotOwnAct)
	group.GrantsSiteAdmin = true
	require.ErrorIs(t, UpdateGroup(grant, group), audit_model.ErrNotOwnAct)
	group.GrantsSiteAdmin, group.GrantsAuditor = false, true
	require.ErrorIs(t, UpdateGroup(grant, group), audit_model.ErrNotOwnAct)
	group.GrantsAuditor = false
	stored := unittest.AssertExistsAndLoadBean(t, &org_model.UserGroup{ID: group.ID})
	assert.False(t, stored.GrantsSiteAdmin || stored.GrantsAuditor)

	// a new name retargets the login sources that map to it
	group.Name = "staff"
	require.ErrorIs(t, UpdateGroup(grant, group), audit_model.ErrNotOwnAct)
	assert.Equal(t, "deployers", unittest.AssertExistsAndLoadBean(t, &org_model.UserGroup{ID: group.ID}).Name)
	group.Name, group.Description = " Deployers ", "a description" // same name, other fields
	require.NoError(t, UpdateGroup(grant, group))
	group.Name = "staff"
	require.NoError(t, UpdateGroup(ownCtx(), group), "the admin's own rename")
	group.Name = "deployers"
	require.NoError(t, UpdateGroup(ownCtx(), group))

	// adding an exclusion only removes owners, lifting one adds them
	require.NoError(t, SetOrgAdminExclusions(grant, []int64{3}))
	require.ErrorIs(t, SetOrgAdminExclusions(grant, nil), audit_model.ErrNotOwnAct)
	excluded, err := org_model.GetOrgAdminExclusionOrgIDs(db.DefaultContext)
	require.NoError(t, err)
	assert.True(t, excluded.Contains(3))
	require.NoError(t, SetOrgAdminExclusions(ownCtx(), nil))

	// the person's own link, then a login source sync adds a group member to the reviewer team
	require.NoError(t, LinkTeam(ownCtx(), group, reviewers))
	assertTeamMember(t, reviewers, 8, org_model.MembershipReasonAddedByUserGroup)
	sync := audit_model.WithLoginSource(grant, 1, "ldap")
	require.NoError(t, SyncDirectoryGroups(sync, loadUser(t, 10), 0, container.SetOf("cn=deployers"), map[string]container.Set[string]{"cn=deployers": container.SetOf("deployers")}, false))
	assertTeamMember(t, reviewers, 10, org_model.MembershipReasonAddedByUserGroup)
	// and a system actor (a cron task or the Bitbucket import) links
	require.NoError(t, UnlinkTeam(ownCtx(), group, owners))
	require.NoError(t, LinkTeam(audit_model.WithSystem(db.DefaultContext, "test"), group, owners))
	assertTeamMember(t, owners, 8, org_model.MembershipReasonAddedByUserGroup)
}
