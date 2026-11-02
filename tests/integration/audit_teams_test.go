// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"forgejo.org/models"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"
	user_service "forgejo.org/services/user"
	usergroup_service "forgejo.org/services/usergroup"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditTeam(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)

	since := auditMaxID(t)
	resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/teams", &api.CreateTeamOption{
		Name: "audit-team", Permission: "write", Units: []string{"repo.code", "repo.issues"},
	}).AddTokenAuth(token), http.StatusCreated)
	var created api.Team
	DecodeJSON(t, resp, &created)
	e := orgOne(t, since, "org.team.created")
	assert.EqualValues(t, 2, e.ActorID)
	assert.EqualValues(t, 3, e.OwnerID)
	assert.Equal(t, "team", e.TargetType)
	assert.Equal(t, created.ID, e.TargetID)
	data := auditData(t, e)
	assert.Equal(t, []any{"code:write", "issues:write"}, data["units"])
	assert.Equal(t, "write", data["access_mode"])

	// the "before" is the stored team, units included
	teamURL := fmt.Sprintf("/api/v1/teams/%d", created.ID)
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", teamURL, &api.EditTeamOption{
		Name: "audit-team", UnitsMap: map[string]string{"repo.code": "read", "repo.issues": "write"},
	}).AddTokenAuth(token), http.StatusOK)
	data = auditData(t, orgOne(t, since, "org.team.updated"))
	assert.Equal(t, map[string]any{"units": []any{"code:write", "issues:write"}}, data["before"])
	assert.Equal(t, map[string]any{"units": []any{"code:read", "issues:write"}}, data["after"])
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", teamURL, &api.EditTeamOption{
		Name: "audit-team", Description: new("only text"), UnitsMap: map[string]string{"repo.code": "read", "repo.issues": "write"},
	}).AddTokenAuth(token), http.StatusOK)
	assert.Empty(t, auditActions(t, since, "org.team.updated"), "an unchanged save records nothing")

	// members
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "PUT", teamURL+"/members/user5").AddTokenAuth(token), http.StatusNoContent)
	e = orgOne(t, since, "org.team.member_added")
	assert.EqualValues(t, 5, e.SubjectUserID)
	assert.Equal(t, map[string]any{"user_id": float64(5), "reason": "added_by_user", "inviter_id": float64(2)}, auditData(t, e))
	MakeRequest(t, NewRequest(t, "PUT", teamURL+"/members/user5").AddTokenAuth(token), http.StatusNoContent)
	assert.Len(t, auditActions(t, since, "org.team.member_added"), 1, "adding a member again records nothing")
	MakeRequest(t, NewRequest(t, "DELETE", teamURL+"/members/user5").AddTokenAuth(token), http.StatusNoContent)
	assert.EqualValues(t, 5, orgOne(t, since, "org.team.member_removed").SubjectUserID)

	// repositories: the org team API and the repository's own team API
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "PUT", teamURL+"/repos/org3/repo3").AddTokenAuth(token), http.StatusNoContent)
	e = orgOne(t, since, "org.team.repo_added")
	assert.EqualValues(t, 3, e.RepoID)
	assert.Equal(t, "org3/repo3", auditData(t, e)["repo_name"])
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/org3/repo3/teams/audit-team").AddTokenAuth(token), http.StatusNoContent)
	assert.EqualValues(t, 3, orgOne(t, since, "org.team.repo_removed").RepoID)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/org3/repo3/teams/audit-team").AddTokenAuth(token), http.StatusUnprocessableEntity)
	assert.Len(t, auditActions(t, since, "org.team.repo_removed"), 1)
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/repos/org3/repo5/teams/audit-team").AddTokenAuth(token), http.StatusNoContent)
	assert.Len(t, auditActions(t, since, "org.team.repo_added"), 2)
	// the repository's collaboration page
	MakeRequest(t, NewRequest(t, "PUT", teamURL+"/repos/org3/repo3").AddTokenAuth(token), http.StatusNoContent)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/repo3/settings/collaboration/team/delete", map[string]string{"id": fmt.Sprint(created.ID)}), http.StatusOK)
	assert.Len(t, auditActions(t, since, "org.team.repo_removed"), 2)

	ctx := asActor(t, 2, "user2")
	team := unittest.AssertExistsAndLoadBean(t, &org_model.Team{ID: created.ID})
	since = auditMaxID(t)
	require.NoError(t, models.AddAllRepositories(ctx, team))
	all := auditData(t, orgOne(t, since, "org.team.repos_added_all"))["counts"].(map[string]any)["repos"].(float64)
	assert.Positive(t, all)
	require.NoError(t, models.AddAllRepositories(ctx, team))
	assert.Len(t, auditActions(t, since, "org.team.repos_added_all"), 1, "nothing to add records nothing")
	require.NoError(t, models.RemoveAllRepositories(ctx, team))
	assert.InDelta(t, all+1, auditData(t, orgOne(t, since, "org.team.repos_removed_all"))["counts"].(map[string]any)["repos"], 0)

	// delete counts what goes with it
	MakeRequest(t, NewRequest(t, "PUT", teamURL+"/members/user5").AddTokenAuth(token), http.StatusNoContent)
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", teamURL).AddTokenAuth(token), http.StatusNoContent)
	e = orgOne(t, since, "org.team.deleted")
	assert.Equal(t, "audit-team", e.TargetName)
	assert.EqualValues(t, 1, auditData(t, e)["counts"].(map[string]any)["members"])
}

// TestAuditTeamMemberRemovalPaths checks that every path that takes a user out of a team records it.
func TestAuditTeamMemberRemovalPaths(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := asActor(t, 2, "user2")
	team1 := unittest.AssertExistsAndLoadBean(t, &org_model.Team{ID: 2}) // org3, members user2 and user4

	// leaving through the team page
	since := auditMaxID(t)
	loginUser(t, "user4").MakeRequest(t, NewRequest(t, "POST", "/org/org3/teams/team1/action/leave"), NoExpectedStatus)
	e := orgOne(t, since, "org.team.member_removed")
	assert.EqualValues(t, 4, e.ActorID)
	assert.EqualValues(t, 4, e.SubjectUserID)

	// removed by an owner on the team page
	require.NoError(t, models.AddTeamMemberByCooptation(ctx, team1, 5, 2))
	since = auditMaxID(t)
	loginUser(t, "user2").MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/teams/team1/action/remove", map[string]string{"uid": "5"}), NoExpectedStatus)
	assert.EqualValues(t, 5, orgOne(t, since, "org.team.member_removed").SubjectUserID)

	// removed from the organization
	require.NoError(t, models.AddTeamMemberByCooptation(ctx, team1, 5, 2))
	since = auditMaxID(t)
	require.NoError(t, models.RemoveOrgUser(ctx, 3, 5))
	assert.EqualValues(t, 5, orgOne(t, since, "org.team.member_removed").SubjectUserID)

	// archiving the organization without its members
	require.NoError(t, models.AddTeamMemberByCooptation(ctx, team1, 5, 2))
	since = auditMaxID(t)
	require.NoError(t, org_service.ArchiveOrganization(ctx, unittest.AssertExistsAndLoadBean(t, &org_model.Organization{ID: 3}), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), true))
	removed := container.Set[int64]{}
	for _, e := range auditActions(t, since, "org.team.member_removed") {
		removed.Add(e.SubjectUserID)
	}
	assert.True(t, removed.Contains(5), "every member but the owners goes")
	assert.False(t, removed.Contains(2))
	require.NoError(t, org_service.UnarchiveOrganization(ctx, unittest.AssertExistsAndLoadBean(t, &org_model.Organization{ID: 3})))

	// purging the user
	require.NoError(t, models.AddTeamMemberByCooptation(ctx, team1, 8, 2))
	since = auditMaxID(t)
	require.NoError(t, user_service.DeleteUser(asActor(t, 1, "user1"), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8}), true))
	assert.EqualValues(t, 8, orgOne(t, since, "org.team.member_removed").SubjectUserID)
}

// TestAuditTrashedOrgMemberRemoved checks that purging a user records leaving the teams of an organization in the trash.
func TestAuditTrashedOrgMemberRemoved(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	token := getUserToken(t, "user8", auth_model.AccessTokenScopeAll)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "audit-trashed"}).AddTokenAuth(token), http.StatusCreated)
	org := unittest.AssertExistsAndLoadBean(t, &org_model.Organization{LowerName: "audit-trashed"})
	ctx := asActor(t, 1, "user1")
	user1 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	require.NoError(t, org_service.TrashOrganization(ctx, user1, org))

	since := auditMaxID(t)
	require.NoError(t, user_service.DeleteUser(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8}), true))
	e := orgOne(t, since, "org.team.member_removed")
	assert.EqualValues(t, 8, e.SubjectUserID)
	assert.Equal(t, org.ID, e.OwnerID)
}

func TestAuditTeamFailClosed(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error {
		return errors.New("audit down")
	})()
	ctx := asActor(t, 2, "user2")
	team1 := unittest.AssertExistsAndLoadBean(t, &org_model.Team{ID: 2})

	require.Error(t, models.AddTeamMemberByCooptation(ctx, team1, 5, 2))
	unittest.AssertNotExistsBean(t, &org_model.OrgUser{OrgID: 3, UID: 5})
	unittest.AssertNotExistsBean(t, &org_model.TeamUser{TeamID: 2, UID: 5})
	require.Error(t, models.RemoveTeamMember(ctx, team1, 4))
	unittest.AssertExistsAndLoadBean(t, &org_model.TeamUser{TeamID: 2, UID: 4})
}

func TestAuditTeamTransferAndProject(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := asActor(t, 2, "user2")
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	org3 := unittest.AssertExistsAndLoadBean(t, &org_model.Organization{ID: 3})
	team1 := unittest.AssertExistsAndLoadBean(t, &org_model.Team{ID: 2})

	// a transfer adds the chosen teams
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}) // user2/repo1
	since := auditMaxID(t)
	require.NoError(t, repo_service.TransferOwnership(ctx, user2, org3.AsUser(), repo, []*org_model.Team{team1}))
	e := orgOne(t, since, "org.team.repo_added")
	assert.Equal(t, team1.ID, e.TargetID)
	assert.EqualValues(t, 1, e.RepoID)

	// a project link gives the team the project's repositories
	group, err := repo_model.CreateRepoGroup(ctx, org3.AsUser(), "audit-project", "")
	require.NoError(t, err)
	since = auditMaxID(t)
	require.NoError(t, repo_service.LinkTeamToRepoGroup(ctx, user2, org3, team1.ID, group.ID))
	e = orgOne(t, since, "org.team.project_linked")
	assert.Equal(t, group.ID, e.GroupID)
	assert.EqualValues(t, group.ID, auditData(t, e)["group_id"])
	require.NoError(t, repo_service.UnlinkTeamFromRepoGroup(ctx, user2, org3, team1.ID, group.ID))
	assert.Equal(t, group.ID, orgOne(t, since, "org.team.project_unlinked").GroupID)
}

func TestAuditTeamInvite(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := asActor(t, 2, "user2")
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	team1 := unittest.AssertExistsAndLoadBean(t, &org_model.Team{ID: 2})

	since := auditMaxID(t)
	byMail, err := org_model.CreateTeamInviteByEmail(ctx, user2, team1, "audit-invite@example.com")
	require.NoError(t, err)
	e := orgOne(t, since, "org.team.invite_created")
	assert.Equal(t, map[string]any{"email": "audit-invite@example.com"}, auditData(t, e))
	assert.Zero(t, e.SubjectUserID)

	// revoked by an owner
	require.NoError(t, org_model.RemoveInviteByID(ctx, byMail.ID, team1.ID))
	require.NoError(t, org_model.RemoveInviteByID(ctx, byMail.ID, team1.ID))
	assert.Equal(t, "audit-invite@example.com", auditData(t, orgOne(t, since, "org.team.invite_removed"))["email"])

	// an expired invite is removed when the user is invited again
	since = auditMaxID(t)
	invite, err := org_model.CreateTeamInviteForUser(ctx, user2, user5, team1)
	require.NoError(t, err)
	_, err = db.Exec(t.Context(), "UPDATE team_invite SET expiry_unix = 1 WHERE id = ?", invite.ID)
	require.NoError(t, err)
	invite, err = org_model.CreateTeamInviteForUser(ctx, user2, user5, team1)
	require.NoError(t, err)
	e = orgOne(t, since, "org.team.invite_removed")
	assert.Equal(t, map[string]any{"user_id": float64(5), "reason": "expired"}, auditData(t, e), "a user's invite keeps no email")
	assert.EqualValues(t, 5, e.SubjectUserID)
	assert.Len(t, auditActions(t, since, "org.team.invite_created"), 2)

	// accepted: a member added by the inviter, and the invite goes
	since = auditMaxID(t)
	require.NoError(t, org_service.AcceptInvite(asActor(t, 5, "user5"), team1, invite, user5, false))
	e = orgOne(t, since, "org.team.member_added")
	assert.EqualValues(t, 5, e.ActorID)
	assert.EqualValues(t, 2, auditData(t, e)["inviter_id"])
	orgOne(t, since, "org.team.invite_removed")

	var invites []*org_model.TeamInvite
	require.NoError(t, db.GetEngine(t.Context()).Find(&invites))
	tokens := []string{}
	for _, i := range invites {
		tokens = append(tokens, i.Token)
	}
	tokens = append(tokens, byMail.Token, invite.Token)
	assertNoSecretIn(t, 0, tokens...)
}

// TestAuditTeamMemberReason keeps a directory-removed last owner in the Owners team, as added by a user.
func TestAuditTeamMemberReason(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := asActor(t, 1, "user1")
	user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	org := &org_model.Organization{Name: "audit-reason-org"}
	require.NoError(t, org_model.CreateOrganization(ctx, org, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})))
	owners, err := org_model.GetOwnerTeam(t.Context(), org.ID)
	require.NoError(t, err)

	group := &org_model.UserGroup{Name: "audit-reason-group"}
	require.NoError(t, usergroup_service.CreateGroup(ctx, group))
	require.NoError(t, usergroup_service.LinkTeam(ctx, group, owners))
	sync := audit_model.WithLoginSource(ctx, 77, "audit-source")
	mapping := map[string]container.Set[string]{"devs": container.SetOf("audit-reason-group")}
	require.NoError(t, usergroup_service.SyncDirectoryGroups(sync, user4, 77, container.SetOf("devs"), mapping, true))
	owners, err = org_model.GetOwnerTeam(t.Context(), org.ID)
	require.NoError(t, err)
	require.NoError(t, models.RemoveTeamMember(ctx, owners, 2))

	since := auditMaxID(t)
	require.NoError(t, usergroup_service.SyncDirectoryGroups(sync, user4, 77, container.Set[string]{}, mapping, true))
	e := orgOne(t, since, "org.team.member_reason_changed")
	assert.EqualValues(t, 4, e.SubjectUserID)
	assert.Equal(t, audit_model.ActorLoginSource, e.ActorType)
	data := auditData(t, e)
	assert.Equal(t, map[string]any{"reason": "added_by_user_group"}, data["before"])
	assert.Equal(t, map[string]any{"reason": "added_by_user"}, data["after"])
	assert.Empty(t, auditActions(t, since, "org.team.member_removed"))
}
