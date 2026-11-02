// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIAdminUserGroups(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	token := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)

	// only site administrators can manage groups
	userToken := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteAdmin)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/groups").AddTokenAuth(userToken), http.StatusForbidden)
	readOnlyToken := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/groups", &api.CreateUserGroupOption{Name: "nope"}).AddTokenAuth(readOnlyToken), http.StatusForbidden)

	// create
	resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/groups", &api.CreateUserGroupOption{
		Name:        "api-group",
		Description: "Created through the API",
	}).AddTokenAuth(token), http.StatusCreated)
	var group api.UserGroup
	DecodeJSON(t, resp, &group)
	assert.Positive(t, group.ID)
	assert.Equal(t, "api-group", group.Name)
	assert.Equal(t, "Created through the API", group.Description)
	assert.Zero(t, group.MembersCount)
	assert.False(t, group.Created.IsZero())

	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/groups", &api.CreateUserGroupOption{Name: "API-Group"}).AddTokenAuth(token), http.StatusConflict)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/groups", &api.CreateUserGroupOption{Name: "not valid!"}).AddTokenAuth(token), http.StatusUnprocessableEntity)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/groups", &api.CreateUserGroupOption{Name: "other-group"}).AddTokenAuth(token), http.StatusCreated)

	// list and get
	resp = MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/groups?q=api").AddTokenAuth(token), http.StatusOK)
	var groups []api.UserGroup
	DecodeJSON(t, resp, &groups)
	require.Len(t, groups, 1)
	assert.Equal(t, group.ID, groups[0].ID)
	assert.Equal(t, "1", resp.Header().Get("X-Total-Count"))

	resp = MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/groups?limit=1").AddTokenAuth(token), http.StatusOK)
	DecodeJSON(t, resp, &groups)
	assert.Len(t, groups, 1)
	assert.Equal(t, "2", resp.Header().Get("X-Total-Count"))

	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/groups/API-GROUP").AddTokenAuth(token), http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/groups/missing").AddTokenAuth(token), http.StatusNotFound)

	// edit
	newName, newDescription, taken, empty, invalid := "api-group-renamed", "Renamed", "other-group", "", "not valid!"
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/admin/groups/api-group", &api.EditUserGroupOption{Name: &invalid}).AddTokenAuth(token), http.StatusUnprocessableEntity)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/admin/groups/api-group", &api.EditUserGroupOption{Name: &taken}).AddTokenAuth(token), http.StatusConflict)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/admin/groups/api-group", &api.EditUserGroupOption{Name: &empty}).AddTokenAuth(token), http.StatusUnprocessableEntity)
	resp = MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/admin/groups/api-group", &api.EditUserGroupOption{
		Name:        &newName,
		Description: &newDescription,
	}).AddTokenAuth(token), http.StatusOK)
	DecodeJSON(t, resp, &group)
	assert.Equal(t, newName, group.Name)
	assert.Equal(t, newDescription, group.Description)
	groupURL := "/api/v1/admin/groups/" + newName

	// members
	MakeRequest(t, NewRequest(t, "PUT", groupURL+"/members/user5").AddTokenAuth(token), http.StatusNoContent)
	MakeRequest(t, NewRequest(t, "PUT", groupURL+"/members/user5").AddTokenAuth(token), http.StatusNoContent)
	MakeRequest(t, NewRequest(t, "PUT", groupURL+"/members/org3").AddTokenAuth(token), http.StatusUnprocessableEntity)
	MakeRequest(t, NewRequest(t, "PUT", groupURL+"/members/nobody").AddTokenAuth(token), http.StatusNotFound)

	resp = MakeRequest(t, NewRequest(t, "GET", groupURL+"/members").AddTokenAuth(token), http.StatusOK)
	var members []api.User
	DecodeJSON(t, resp, &members)
	require.Len(t, members, 1)
	assert.Equal(t, "user5", members[0].UserName)
	assert.Equal(t, "1", resp.Header().Get("X-Total-Count"))

	resp = MakeRequest(t, NewRequest(t, "GET", groupURL).AddTokenAuth(token), http.StatusOK)
	DecodeJSON(t, resp, &group)
	assert.Equal(t, 1, group.MembersCount)

	resp = MakeRequest(t, NewRequest(t, "GET", groupURL+"/teams").AddTokenAuth(token), http.StatusOK)
	var teams []api.Team
	DecodeJSON(t, resp, &teams)
	assert.Empty(t, teams)

	MakeRequest(t, NewRequest(t, "DELETE", groupURL+"/members/user5").AddTokenAuth(token), http.StatusNoContent)
	MakeRequest(t, NewRequest(t, "DELETE", groupURL+"/members/user5").AddTokenAuth(token), http.StatusNotFound)

	// delete
	MakeRequest(t, NewRequest(t, "DELETE", groupURL).AddTokenAuth(token), http.StatusNoContent)
	MakeRequest(t, NewRequest(t, "GET", groupURL).AddTokenAuth(token), http.StatusNotFound)
	unittest.AssertNotExistsBean(t, &organization.UserGroup{ID: group.ID})
}

func TestAPITeamUserGroups(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin, auth_model.AccessTokenScopeWriteOrganization)
	ownerToken := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization)  // owner of org3
	memberToken := getUserToken(t, "user4", auth_model.AccessTokenScopeWriteOrganization) // member of org3/team1, not an owner

	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/groups", &api.CreateUserGroupOption{Name: "release-managers"}).AddTokenAuth(adminToken), http.StatusCreated)
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/admin/groups/release-managers/members/user5").AddTokenAuth(adminToken), http.StatusNoContent)

	// team 2 is org3/team1
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/2/groups/release-managers").AddTokenAuth(memberToken), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/2/groups/missing").AddTokenAuth(ownerToken), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/2/groups/release-managers").AddTokenAuth(ownerToken), http.StatusNoContent)
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/2/groups/release-managers").AddTokenAuth(ownerToken), http.StatusNoContent)

	tu := unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{TeamID: 2, UID: 5})
	assert.Equal(t, organization.MembershipReasonAddedByUserGroup, tu.Reason)

	// organization members can see the linked groups
	resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/teams/2/groups").AddTokenAuth(memberToken), http.StatusOK)
	var groups []api.UserGroup
	DecodeJSON(t, resp, &groups)
	require.Len(t, groups, 1)
	assert.Equal(t, "release-managers", groups[0].Name)
	assert.Equal(t, 1, groups[0].MembersCount)
	assert.Equal(t, 1, groups[0].TeamsCount)

	// the group lists the team with its organization
	resp = MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/groups/release-managers/teams").AddTokenAuth(adminToken), http.StatusOK)
	var teams []api.Team
	DecodeJSON(t, resp, &teams)
	require.Len(t, teams, 1)
	assert.Equal(t, "team1", teams[0].Name)
	require.NotNil(t, teams[0].Organization)
	assert.Equal(t, "org3", teams[0].Organization.UserName)

	// a member coming from a linked group cannot be removed from the team directly
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/teams/2/members/user5").AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
	unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{TeamID: 2, UID: 5})

	// unlinking removes the membership
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/teams/2/groups/release-managers").AddTokenAuth(memberToken), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/teams/2/groups/release-managers").AddTokenAuth(ownerToken), http.StatusNoContent)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/teams/2/groups/release-managers").AddTokenAuth(ownerToken), http.StatusNotFound)
	unittest.AssertNotExistsBean(t, &organization.TeamUser{TeamID: 2, UID: 5})

	// changes that would remove the last owner of an organization are refused:
	// team 15 is the owners team of org22, which has no other owner
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/15/groups/release-managers").AddTokenAuth(adminToken), http.StatusNoContent)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/groups/release-managers/members/user5").AddTokenAuth(adminToken), http.StatusConflict)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/teams/15/groups/release-managers").AddTokenAuth(adminToken), http.StatusConflict)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/groups/release-managers").AddTokenAuth(adminToken), http.StatusConflict)
	unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{TeamID: 15, UID: 5})
}
