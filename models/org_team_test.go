// Copyright 2017 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package models

import (
	"context"
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTeam_RemoveMember(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	testSuccess := func(teamID, userID int64) {
		team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: teamID})
		require.NoError(t, RemoveTeamMember(db.DefaultContext, team, userID))
		unittest.AssertNotExistsBean(t, &organization.TeamUser{UID: userID, TeamID: teamID})
		unittest.CheckConsistencyFor(t, &organization.Team{ID: teamID})
	}
	testSuccess(1, 4)
	testSuccess(2, 2)
	testSuccess(3, 2)
	testSuccess(3, unittest.NonexistentID)

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 1})
	err := RemoveTeamMember(db.DefaultContext, team, 2)
	assert.True(t, organization.IsErrLastOrgOwner(err))
}

func TestIsUsableTeamName(t *testing.T) {
	require.NoError(t, organization.IsUsableTeamName("usable"))
	assert.True(t, db.IsErrNameReserved(organization.IsUsableTeamName("new")))
}

func TestNewTeam(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	const teamName = "newTeamName"
	team := &organization.Team{Name: teamName, OrgID: 3}
	require.NoError(t, NewTeam(db.DefaultContext, team))
	unittest.AssertExistsAndLoadBean(t, &organization.Team{Name: teamName})
	unittest.CheckConsistencyFor(t, &organization.Team{}, &user_model.User{ID: team.OrgID})
}

func TestUpdateTeam(t *testing.T) {
	// successful update
	require.NoError(t, unittest.PrepareTestDatabase())

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	team.LowerName = "newname"
	team.Name = "newName"
	team.Description = strings.Repeat("A long description!", 100)
	team.AccessMode = perm.AccessModeAdmin
	require.NoError(t, UpdateTeam(db.DefaultContext, team, true, false))

	team = unittest.AssertExistsAndLoadBean(t, &organization.Team{Name: "newName"})
	assert.True(t, strings.HasPrefix(team.Description, "A long description!"))

	access := unittest.AssertExistsAndLoadBean(t, &access_model.Access{UserID: 4, RepoID: 3})
	assert.Equal(t, perm.AccessModeAdmin, access.Mode)

	unittest.CheckConsistencyFor(t, &organization.Team{ID: team.ID})
}

func TestUpdateTeam2(t *testing.T) {
	// update to already-existing team
	require.NoError(t, unittest.PrepareTestDatabase())

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	team.LowerName = "owners"
	team.Name = "Owners"
	team.Description = strings.Repeat("A long description!", 100)
	err := UpdateTeam(db.DefaultContext, team, true, false)
	assert.True(t, organization.IsErrTeamAlreadyExist(err))

	unittest.CheckConsistencyFor(t, &organization.Team{ID: team.ID})
}

func TestDeleteTeam(t *testing.T) {
	defer unittest.OverrideFixtures("models/fixtures/TestDeleteTeam")()
	require.NoError(t, unittest.PrepareTestDatabase())

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	require.NoError(t, DeleteTeam(db.DefaultContext, team))
	unittest.AssertNotExistsBean(t, &organization.Team{ID: team.ID})
	unittest.AssertNotExistsBean(t, &organization.TeamRepo{TeamID: team.ID})
	unittest.AssertNotExistsBean(t, &organization.TeamUser{TeamID: team.ID})

	// check that team members don't have "leftover" access to repos
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	accessMode, err := access_model.AccessLevel(db.DefaultContext, user, repo)
	require.NoError(t, err)
	assert.Less(t, accessMode, perm.AccessModeWrite)

	// Delete a team that is set `includes_all_repositories: true`, which should still cleanup any access that was
	// granted by this team.  First assert that the permission we're expecting to cleanup exists:
	user = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 33})
	repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 61})
	unittest.AssertExistsAndLoadBean(t, &access_model.Access{UserID: user.ID, RepoID: repo.ID, Mode: perm.AccessModeWrite})
	// Delete team 100, which includes all repos:
	team = unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 100})
	require.NoError(t, DeleteTeam(db.DefaultContext, team))
	// Validate TeamRepo & Access are removed:
	unittest.AssertNotExistsBean(t, &organization.TeamRepo{TeamID: team.ID})
	unittest.AssertNotExistsBean(t, &access_model.Access{UserID: user.ID, RepoID: repo.ID, Mode: perm.AccessModeWrite})
}

func TestAddTeamMemberByCooptation(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	testCases := []struct {
		name      string
		teamID    int64
		userID    int64
		inviterID int64
	}{
		{"user already in team", 1, 2, 5},
		{"user not yet in team", 1, 4, 5},
		{"adding a user to a non-owners team", 3, 2, 5},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: testCase.teamID})
			require.NoError(t, AddTeamMemberByCooptation(ownCtx(), team, testCase.userID, testCase.inviterID))
			if testCase.userID == 4 {
				unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{UID: testCase.userID, TeamID: testCase.teamID, Reason: organization.MembershipReasonAddedByUser, CreatedByUserID: optional.Some(testCase.inviterID)})
			} else {
				unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{UID: testCase.userID, TeamID: testCase.teamID})
			}
			unittest.CheckConsistencyFor(t, &organization.Team{ID: testCase.teamID}, &user_model.User{ID: team.OrgID})
		})
	}
}

func TestAddTeamMemberByLoginSource(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	loginSource := auth_model.Source{ID: 1}
	_, err := db.GetEngine(db.DefaultContext).Insert(loginSource)
	require.NoError(t, err)

	testCases := []struct {
		name   string
		teamID int64
		userID int64
	}{
		{"user already in team", 1, 2},
		{"user not yet in team", 1, 4},
		{"adding a user to a non-owners team", 3, 2},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: testCase.teamID})
			require.NoError(t, AddTeamMemberByLoginSource(audit_model.WithLoginSource(db.DefaultContext, loginSource.ID, "source"), team, testCase.userID, loginSource.ID))
			unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{UID: testCase.userID, TeamID: testCase.teamID})
			unittest.CheckConsistencyFor(t, &organization.Team{ID: testCase.teamID}, &user_model.User{ID: team.OrgID})
		})
	}
}

func TestTeam_AddAndReturnTeamMember(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	for _, testCase := range []struct {
		name          string
		alreadyMember bool
		teamID        int64
		userID        int64
		inviterID     int64
	}{
		{
			name:          "Already member of a team with repositories",
			alreadyMember: true,
			teamID:        1,
			userID:        2,
			inviterID:     28,
		},
		{
			name:      "New member of a team with repositories",
			teamID:    1,
			userID:    4,
			inviterID: 1,
		},
		{
			name:      "New member of a team with no repositories",
			teamID:    3,
			userID:    2,
			inviterID: 4,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: testCase.teamID})
			teamUser, err := InsertTeamMember(ownCtx(), team, testCase.userID, organization.MembershipReasonAddedByUser, optional.Some(testCase.inviterID), optional.None[int64]())
			require.NoError(t, err)
			if testCase.alreadyMember {
				assert.Nil(t, teamUser)
			} else {
				require.NotNil(t, teamUser)
				assert.Equal(t, testCase.teamID, teamUser.TeamID)
				assert.Equal(t, testCase.userID, teamUser.UID)
				unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{UID: testCase.userID, TeamID: testCase.teamID, Reason: organization.MembershipReasonAddedByUser, CreatedByUserID: optional.Some(testCase.inviterID)})
			}
			unittest.CheckConsistencyFor(t, &organization.Team{ID: testCase.teamID}, &user_model.User{ID: team.OrgID})
		})
	}
}

func TestTeam_AddTeamRepository(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	for _, testCase := range []struct {
		name   string
		teamID int64
		repoID int64
	}{
		{
			name:   "AddAndReturnTeamRepository",
			teamID: 8,
			repoID: 23,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: testCase.teamID})
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: testCase.repoID})
			teamRepo, err := InsertTeamRepository(t.Context(), team, repo)
			require.NoError(t, err)
			require.NotNil(t, teamRepo)
			assert.Equal(t, testCase.teamID, teamRepo.TeamID)
			assert.Equal(t, testCase.repoID, teamRepo.RepoID)
			unittest.AssertExistsAndLoadBean(t, &organization.TeamRepo{RepoID: testCase.repoID, TeamID: testCase.teamID})
		})
	}

	for _, testCase := range []struct {
		name   string
		teamID int64
		repoID int64
	}{
		{
			name:   "AddTeamRepository",
			teamID: 9,
			repoID: 23,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: testCase.teamID})
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: testCase.repoID})
			err := AddRepository(t.Context(), team, repo)
			require.NoError(t, err)
			unittest.AssertExistsAndLoadBean(t, &organization.TeamRepo{RepoID: testCase.repoID, TeamID: testCase.teamID})
		})
	}
}

func TestRemoveTeamMember(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	testSuccess := func(teamID, userID int64) {
		team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: teamID})
		require.NoError(t, RemoveTeamMember(db.DefaultContext, team, userID))
		unittest.AssertNotExistsBean(t, &organization.TeamUser{UID: userID, TeamID: teamID})
		unittest.CheckConsistencyFor(t, &organization.Team{ID: teamID})
	}
	testSuccess(1, 4)
	testSuccess(2, 2)
	testSuccess(3, 2)
	testSuccess(3, unittest.NonexistentID)

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 1})
	err := RemoveTeamMember(db.DefaultContext, team, 2)
	assert.True(t, organization.IsErrLastOrgOwner(err))
}

func TestRepository_RecalculateAccesses3(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	team5 := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 5})
	user29 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 29})

	has, err := db.GetEngine(db.DefaultContext).Get(&access_model.Access{UserID: 29, RepoID: 23})
	require.NoError(t, err)
	assert.False(t, has)

	// adding user29 to team5 should add an explicit access row for repo 23
	// even though repo 23 is public
	require.NoError(t, AddTeamMemberByCooptation(ownCtx(), team5, user29.ID, 1))

	has, err = db.GetEngine(db.DefaultContext).Get(&access_model.Access{UserID: 29, RepoID: 23})
	require.NoError(t, err)
	assert.True(t, has)
}

// ownCtx is a request of user 1 with a credential of their own (audit_model.IsOwnAct).
func ownCtx() context.Context {
	return audit_model.WithActor(db.DefaultContext, &audit_model.Actor{Type: audit_model.ActorUser, ID: 1, Name: "user1", Credential: audit_model.Credential{Type: audit_model.CredentialAccessToken}})
}

// Adding a member to the Owners team or to a team listed as an environment's reviewer is only a person's own act;
// other teams, removals and the user group sync are not affected.
func TestAddTeamMemberOwnAct(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	grant := audit_model.WithActor(db.DefaultContext, &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, Name: "user2", Credential: audit_model.Credential{Type: audit_model.CredentialOAuth2Grant}})
	integration := audit_model.WithActor(db.DefaultContext, &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, Name: "user2", Credential: audit_model.Credential{Type: audit_model.CredentialAuthorizedIntegration}})
	sudoActor := &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, Name: "user2", Credential: audit_model.Credential{Type: audit_model.CredentialAccessToken}}
	sudoActor.SetSudo(1, "user1")
	sudo := audit_model.WithActor(db.DefaultContext, sudoActor)

	owners := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 1})
	reviewers := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	unrelated := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 7})
	_, err := db.GetEngine(db.DefaultContext).Exec("INSERT INTO action_environment_reviewer (environment_id, user_id, team_id) VALUES (1, 0, ?)", reviewers.ID)
	require.NoError(t, err)

	for name, ctx := range map[string]context.Context{"OAuth2 grant": grant, "authorized integration": integration, "sudo": sudo, "no actor": db.DefaultContext} {
		for _, team := range []*organization.Team{owners, reviewers} {
			require.ErrorIs(t, AddTeamMemberByCooptation(ctx, team, 5, 2), audit_model.ErrNotOwnAct, name)
			assert.False(t, unittest.BeanExists(t, &organization.TeamUser{UID: 5, TeamID: team.ID}), name)
			_, err := organization.CreateTeamInviteForUser(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5}), team)
			require.ErrorIs(t, err, audit_model.ErrNotOwnAct, name)
			_, err = organization.CreateTeamInviteByEmail(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), team, "someone@example.com")
			require.ErrorIs(t, err, audit_model.ErrNotOwnAct, name)
		}
		require.NoError(t, AddTeamMemberByCooptation(ctx, owners, 2, 2), "already a member: nothing to add")
	}
	assert.Zero(t, unittest.GetCount(t, &organization.TeamInvite{TeamID: owners.ID}))
	assert.Zero(t, unittest.GetCount(t, &organization.TeamInvite{TeamID: reviewers.ID}))

	require.NoError(t, AddTeamMemberByCooptation(grant, unrelated, 5, 2), "another team")
	unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{UID: 5, TeamID: unrelated.ID})
	require.NoError(t, RemoveTeamMember(grant, reviewers, 4), "a removal")

	// a user group sync adds what the group's links say, whoever changed the group
	_, err = InsertTeamMember(grant, reviewers, 5, organization.MembershipReasonAddedByUserGroup, optional.None[int64](), optional.None[int64]())
	require.NoError(t, err)
	// a login source sync acts as the login source
	_, err = db.GetEngine(db.DefaultContext).Insert(auth_model.Source{ID: 1})
	require.NoError(t, err)
	require.NoError(t, AddTeamMemberByLoginSource(audit_model.WithLoginSource(grant, 1, "ldap"), owners, 5, 1))
	// the person's own credential
	require.NoError(t, AddTeamMemberByCooptation(ownCtx(), reviewers, 10, 2))
	unittest.CheckConsistencyFor(t, &organization.Team{ID: owners.ID}, &organization.Team{ID: reviewers.ID}, &user_model.User{ID: 3})
}
