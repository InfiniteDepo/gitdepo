// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"

	"forgejo.org/models"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const orgAdminMember = "user8" // ID 8: no organizations in the fixtures

func orgAdminOwnerTeams(t *testing.T) []*organization.Team {
	t.Helper()
	teams := make([]*organization.Team, 0, 20)
	require.NoError(t, db.GetEngine(db.DefaultContext).Where("name=?", organization.OwnerTeamName).Find(&teams))
	require.NotEmpty(t, teams)
	return teams
}

// fillEmptyOwnerTeams gives the organizations whose Owners team is empty in the fixtures (22 and 23) a manual owner.
func fillEmptyOwnerTeams(t *testing.T) {
	t.Helper()
	for _, team := range orgAdminOwnerTeams(t) {
		if team.NumMembers == 0 {
			_, err := models.InsertTeamMember(db.DefaultContext, team, 2, organization.MembershipReasonAddedByUser, optional.None[int64](), optional.None[int64]())
			require.NoError(t, err)
		}
	}
}

func orgAdminLink(t *testing.T, groupID, teamID int64) int {
	t.Helper()
	l := &organization.UserGroupTeam{GroupID: groupID, TeamID: teamID}
	has, err := db.GetEngine(db.DefaultContext).Get(l)
	require.NoError(t, err)
	if !has {
		return -1
	}
	return l.Managed
}

func assertOrgAdminOwnerEverywhere(t *testing.T, uid int64, owner bool) {
	t.Helper()
	for _, team := range orgAdminOwnerTeams(t) {
		isOwner, err := organization.IsOrganizationOwner(db.DefaultContext, team.OrgID, uid)
		require.NoError(t, err)
		assert.Equal(t, owner, isOwner, "org %d", team.OrgID)
		if owner {
			tu := unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{TeamID: team.ID, UID: uid})
			assert.Equal(t, organization.MembershipReasonAddedByUserGroup, tu.Reason, "org %d", team.OrgID)
		}
	}
}

func createOrgAdminGroupAPI(t *testing.T, token, name string, role bool) *api.UserGroup {
	t.Helper()
	resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/groups", &api.CreateUserGroupOption{Name: name, GrantsOrgAdmin: role}).AddTokenAuth(token), http.StatusCreated)
	var group api.UserGroup
	DecodeJSON(t, resp, &group)
	return &group
}

func patchOrgAdminRole(t *testing.T, token, name string, role bool, status int) {
	t.Helper()
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/admin/groups/"+name, &api.EditUserGroupOption{GrantsOrgAdmin: &role}).AddTokenAuth(token), status)
}

// AC1: the role is set and removed through the group form and the admin API, and shown again.
func TestOrgAdminRoleAC1SetAndRemove(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	admin := loginUser(t, "user1")
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)

	// web
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/groups/new", map[string]string{"name": "web-admins", "grants_org_admin": "on"}), http.StatusSeeOther)
	group := unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{LowerName: "web-admins"})
	assert.True(t, group.GrantsOrgAdmin)
	groupURL := fmt.Sprintf("/admin/groups/%d", group.ID)
	NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", groupURL), http.StatusOK).Body).AssertElement(t, `input[name="grants_org_admin"][checked]`, true)
	for _, team := range orgAdminOwnerTeams(t) {
		assert.Equal(t, organization.LinkManaged, orgAdminLink(t, group.ID, team.ID), "a new group is linked right away")
	}
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", groupURL+"/edit", map[string]string{"name": "web-admins"}), http.StatusSeeOther)
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{ID: group.ID}).GrantsOrgAdmin)
	NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", groupURL), http.StatusOK).Body).AssertElement(t, `input[name="grants_org_admin"][checked]`, false)
	assert.Equal(t, -1, orgAdminLink(t, group.ID, 1))

	// API
	created := createOrgAdminGroupAPI(t, token, "api-admins", true)
	assert.True(t, created.GrantsOrgAdmin)
	assert.Equal(t, organization.LinkManaged, orgAdminLink(t, created.ID, 1))
	patchOrgAdminRole(t, token, "api-admins", false, http.StatusOK)
	resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/groups/api-admins").AddTokenAuth(token), http.StatusOK)
	DecodeJSON(t, resp, created)
	assert.False(t, created.GrantsOrgAdmin)
	assert.Equal(t, -1, orgAdminLink(t, created.ID, 1))
	patchOrgAdminRole(t, token, "api-admins", true, http.StatusOK)
	assert.Equal(t, organization.LinkManaged, orgAdminLink(t, created.ID, 1))
}

// AC2, AC3, AC4, AC6, AC7, AC8 in one flow.
func TestOrgAdminRoleFlow(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	fillEmptyOwnerTeams(t)
	admin := loginUser(t, "user1")
	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin, auth_model.AccessTokenScopeWriteOrganization)
	org3Owner := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization)
	group := createOrgAdminGroupAPI(t, adminToken, "platform-admins", true)
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/admin/groups/platform-admins/members/"+orgAdminMember).AddTokenAuth(adminToken), http.StatusNoContent)
	member := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: orgAdminMember})

	// AC2: owner of every existing organization, through a system-managed link
	assertOrgAdminOwnerEverywhere(t, member.ID, true)
	for _, team := range orgAdminOwnerTeams(t) {
		assert.Equal(t, organization.LinkManaged, orgAdminLink(t, group.ID, team.ID), "org %d", team.OrgID)
	}

	// AC6: not a site administrator
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: member.ID}).IsAdmin)
	memberSession := loginUser(t, orgAdminMember)
	memberSession.MakeRequest(t, NewRequest(t, "GET", "/admin"), http.StatusForbidden)
	memberSession.MakeRequest(t, NewRequest(t, "GET", "/admin/roles/org-admin"), http.StatusForbidden)
	memberToken := getUserToken(t, orgAdminMember, auth_model.AccessTokenScopeWriteAdmin)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/users").AddTokenAuth(memberToken), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/roles/org-admin/exclusions").AddTokenAuth(memberToken), http.StatusForbidden)

	// AC3: organizations created afterwards, through the web and the API
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/create", map[string]string{"org_name": "weborg"}), http.StatusSeeOther)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "apiorg"}).AddTokenAuth(adminToken), http.StatusCreated)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/users/user1/orgs", &api.CreateOrgOption{UserName: "adminapiorg"}).AddTokenAuth(adminToken), http.StatusCreated)
	for _, name := range []string{"weborg", "apiorg", "adminapiorg"} {
		org := unittest.AssertExistsAndLoadBean(t, &user_model.User{LowerName: name})
		owners, err := organization.GetOwnerTeam(db.DefaultContext, org.ID)
		require.NoError(t, err)
		assert.Equal(t, organization.LinkManaged, orgAdminLink(t, group.ID, owners.ID), name)
		isOwner, err := organization.IsOrganizationOwner(db.DefaultContext, org.ID, member.ID)
		require.NoError(t, err)
		assert.True(t, isOwner, name)
	}

	// AC7: the Owners team page shows the link, and an owner cannot unlink it
	page := NewHTMLParser(t, loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org/org3/teams/owners"), http.StatusOK).Body)
	assert.Contains(t, page.Find("#team-user-groups").Parent().Text(), "Linked by instance policy (Organization administrators)")
	page.AssertElement(t, `form[action$="/teams/owners/action/group/unlink"]`, false)
	user2 := loginUser(t, "user2")
	user2.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/teams/owners/action/group/unlink", map[string]string{"group_id": fmt.Sprint(group.ID)}), http.StatusSeeOther)
	assert.Equal(t, organization.LinkManaged, orgAdminLink(t, group.ID, 1))
	assert.Contains(t, user2.MakeRequest(t, NewRequest(t, "GET", "/org/org3/teams/owners"), http.StatusOK).Body.String(), "set by the instance policy")
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/teams/1/groups/platform-admins").AddTokenAuth(org3Owner), http.StatusUnprocessableEntity)
	assert.Equal(t, organization.LinkManaged, orgAdminLink(t, group.ID, 1))

	// S1: the Owners team can be neither deleted nor renamed
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/teams/1").AddTokenAuth(org3Owner), http.StatusUnprocessableEntity)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/teams/1", &api.EditTeamOption{Name: "Bosses"}).AddTokenAuth(org3Owner), http.StatusUnprocessableEntity)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/teams/1", &api.EditTeamOption{Name: "owners"}).AddTokenAuth(org3Owner), http.StatusUnprocessableEntity)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/teams/1", &api.EditTeamOption{Name: "Owners"}).AddTokenAuth(org3Owner), http.StatusOK)
	user2.MakeRequest(t, NewRequest(t, "POST", "/org/org3/teams/owners/delete"), http.StatusOK)
	unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 1, Name: "Owners"})

	// S2: an org owner cannot remove a user who is a member through a linked group
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/orgs/org3/members/"+orgAdminMember).AddTokenAuth(org3Owner), http.StatusConflict)
	user2.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/members/action/remove", map[string]string{"uid": fmt.Sprint(member.ID)}), http.StatusOK)
	unittest.AssertExistsAndLoadBean(t, &organization.OrgUser{OrgID: 3, UID: member.ID})

	// AC8: exclusions, API and web page
	MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/admin/roles/org-admin/exclusions", &api.SetOrgAdminExclusionsOption{Orgs: []string{"org3", "org3"}}).AddTokenAuth(adminToken), http.StatusNoContent)
	assert.Equal(t, -1, orgAdminLink(t, group.ID, 1))
	isOwner, err := organization.IsOrganizationOwner(db.DefaultContext, 3, member.ID)
	require.NoError(t, err)
	assert.False(t, isOwner)
	assert.Equal(t, organization.LinkManaged, orgAdminLink(t, group.ID, 3)) // other orgs untouched
	var excluded []api.Organization
	DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/roles/org-admin/exclusions").AddTokenAuth(adminToken), http.StatusOK), &excluded)
	require.Len(t, excluded, 1)
	assert.Equal(t, "org3", excluded[0].Name)
	rolesPage := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/roles/org-admin"), http.StatusOK)
	// the navbar group holding the Roles link is open on this page
	_, open := NewHTMLParser(t, bytes.NewBuffer(rolesPage.Body.Bytes())).doc.Find(`a[href$="/admin/roles/org-admin"]`).Closest("details").Attr("open")
	assert.True(t, open, "Identity & access is open on the Roles page")
	body := rolesPage.Body.String()
	assert.Contains(t, body, "platform-admins")
	assert.Contains(t, body, orgAdminMember)
	assert.Contains(t, body, "org3")
	// bad input changes nothing
	MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/admin/roles/org-admin/exclusions", &api.SetOrgAdminExclusionsOption{Orgs: []string{"org6", "nosuchorg"}}).AddTokenAuth(adminToken), http.StatusNotFound)
	MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/admin/roles/org-admin/exclusions", &api.SetOrgAdminExclusionsOption{Orgs: []string{"org6", "user2"}}).AddTokenAuth(adminToken), http.StatusUnprocessableEntity)
	assert.Equal(t, organization.LinkManaged, orgAdminLink(t, group.ID, 3))
	MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/admin/roles/org-admin/exclusions", &api.SetOrgAdminExclusionsOption{Orgs: []string{"org3"}}).AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeWriteAdmin)), http.StatusForbidden)
	// web
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/roles/org-admin/exclusions", map[string]string{"orgs": "org6\norg7\norg6"}), http.StatusSeeOther)
	assert.Equal(t, organization.LinkManaged, orgAdminLink(t, group.ID, 1)) // org3 included again
	assert.Equal(t, -1, orgAdminLink(t, group.ID, 3))
	assert.Equal(t, -1, orgAdminLink(t, group.ID, 4))
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/roles/org-admin/exclusions", map[string]string{"orgs": ""}), http.StatusSeeOther)
	assertOrgAdminOwnerEverywhere(t, member.ID, true)

	// AC4: leaving the group removes the memberships the links created
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/groups/platform-admins/members/"+orgAdminMember).AddTokenAuth(adminToken), http.StatusNoContent)
	assertOrgAdminOwnerEverywhere(t, member.ID, false)
}

// AC4, AC5, AC7, AC10: removing the role removes only what the policy created.
func TestOrgAdminRoleRemoval(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	fillEmptyOwnerTeams(t)
	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	org3Owner := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization)
	group := createOrgAdminGroupAPI(t, adminToken, "platform-admins", false)
	other := createOrgAdminGroupAPI(t, adminToken, "other-admins", true)
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/admin/groups/platform-admins/members/"+orgAdminMember).AddTokenAuth(adminToken), http.StatusNoContent)
	// org 3 adds user10 to its Owners team by hand before the group adds them, and links the group by hand
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/1/members/user10").AddTokenAuth(org3Owner), http.StatusNoContent)
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/admin/groups/other-admins/members/user10").AddTokenAuth(adminToken), http.StatusNoContent)
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/1/groups/platform-admins").AddTokenAuth(org3Owner), http.StatusNoContent)

	patchOrgAdminRole(t, adminToken, "platform-admins", true, http.StatusOK)
	assert.Equal(t, organization.LinkManualManaged, orgAdminLink(t, group.ID, 1), "a manual link the policy also covers")
	assert.Equal(t, organization.LinkManaged, orgAdminLink(t, group.ID, 3))
	// unlinking a manual+managed link is refused too
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/teams/1/groups/platform-admins").AddTokenAuth(org3Owner), http.StatusUnprocessableEntity)

	patchOrgAdminRole(t, adminToken, "platform-admins", false, http.StatusOK)
	assert.Equal(t, organization.LinkManual, orgAdminLink(t, group.ID, 1), "the manual link stays, as manual")
	assert.Equal(t, -1, orgAdminLink(t, group.ID, 3))
	member := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: orgAdminMember})
	isOwner, err := organization.IsOrganizationOwner(db.DefaultContext, 3, member.ID)
	require.NoError(t, err)
	assert.True(t, isOwner, "the manual link keeps the membership")
	isOwner, err = organization.IsOrganizationOwner(db.DefaultContext, 6, member.ID)
	require.NoError(t, err)
	assert.False(t, isOwner)
	// the other group is untouched
	assert.Equal(t, organization.LinkManaged, orgAdminLink(t, other.ID, 3))
	// and the manual link can now be removed
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/teams/1/groups/platform-admins").AddTokenAuth(org3Owner), http.StatusNoContent)
	isOwner, err = organization.IsOrganizationOwner(db.DefaultContext, 3, member.ID)
	require.NoError(t, err)
	assert.False(t, isOwner)

	// a membership held another way stays: user10 is also an owner by hand
	user10 := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "user10"})
	tu := unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{TeamID: 1, UID: user10.ID})
	assert.NotEqual(t, organization.MembershipReasonAddedByUserGroup, tu.Reason)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/groups/other-admins/members/user10").AddTokenAuth(adminToken), http.StatusNoContent)
	unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{TeamID: 1, UID: user10.ID})
	isOwner, err = organization.IsOrganizationOwner(db.DefaultContext, 6, user10.ID)
	require.NoError(t, err)
	assert.False(t, isOwner)
}

// AC5: a role removal or an exclusion that would leave an organization without an owner is refused as a whole.
func TestOrgAdminRoleLastOwnerRefused(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	admin := loginUser(t, "user1")
	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	// organizations 22 and 23 have no owner but the group
	group := createOrgAdminGroupAPI(t, adminToken, "platform-admins", true)
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/admin/groups/platform-admins/members/"+orgAdminMember).AddTokenAuth(adminToken), http.StatusNoContent)
	member := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: orgAdminMember})
	assertOrgAdminOwnerEverywhere(t, member.ID, true)

	nothingChanged := func() {
		t.Helper()
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{ID: group.ID}).GrantsOrgAdmin)
		excluded, err := organization.GetOrgAdminExclusionOrgIDs(db.DefaultContext)
		require.NoError(t, err)
		assert.Empty(t, excluded)
		for _, team := range orgAdminOwnerTeams(t) {
			assert.Equal(t, organization.LinkManaged, orgAdminLink(t, group.ID, team.ID), "org %d", team.OrgID)
		}
		assertOrgAdminOwnerEverywhere(t, member.ID, true)
	}

	patchOrgAdminRole(t, adminToken, "platform-admins", false, http.StatusConflict)
	nothingChanged()
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/admin/groups/%d/edit", group.ID), map[string]string{"name": "platform-admins"}), http.StatusSeeOther)
	nothingChanged()
	assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/admin/groups/%d", group.ID)), http.StatusOK).Body.String(), "last owner of the organization")

	MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/admin/roles/org-admin/exclusions", &api.SetOrgAdminExclusionsOption{Orgs: []string{"org3", "limited_org"}}).AddTokenAuth(adminToken), http.StatusConflict)
	nothingChanged()
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/roles/org-admin/exclusions", map[string]string{"orgs": "org3 limited_org"}), http.StatusSeeOther)
	nothingChanged()
	assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/roles/org-admin"), http.StatusOK).Body.String(), "limited_org")
}

// The Owners team is found by its lower-case name: a case-renamed team is still protected.
func TestOrgAdminRoleCaseRenamedOwnersTeam(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin, auth_model.AccessTokenScopeWriteOrganization)
	// organization 22 has no owner but the group; its Owners team (15) is renamed in the database
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE team SET name='owners', lower_name='owners' WHERE id=15")
	require.NoError(t, err)
	group := createOrgAdminGroupAPI(t, adminToken, "platform-admins", true)
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/admin/groups/platform-admins/members/"+orgAdminMember).AddTokenAuth(adminToken), http.StatusNoContent)
	assert.Equal(t, organization.LinkManaged, orgAdminLink(t, group.ID, 15))

	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/teams/15").AddTokenAuth(adminToken), http.StatusUnprocessableEntity)
	unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 15})
	patchOrgAdminRole(t, adminToken, "platform-admins", false, http.StatusConflict)
	MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/admin/roles/org-admin/exclusions", &api.SetOrgAdminExclusionsOption{Orgs: []string{"limited_org"}}).AddTokenAuth(adminToken), http.StatusConflict)
	assert.Equal(t, organization.LinkManaged, orgAdminLink(t, group.ID, 15))
}
