// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"net/http"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPITeamInviteInTeam(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 1})
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})

	invite, err := organization.CreateTeamInviteForUser(ownActCtx(t), user2, user5, team)
	require.NoError(t, err)

	t.Run("Not org owner PoV", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()

		session := loginUser(t, user5.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadOrganization)
		req := NewRequestf(t, "GET", "/api/v1/teams/%d/invitations", team.ID).
			AddTokenAuth(token)
		MakeRequest(t, req, http.StatusNotFound)

		req = NewRequestf(t, "GET", "/api/v1/teams/%d/invitations/%d", team.ID, invite.ID).
			AddTokenAuth(token)
		MakeRequest(t, req, http.StatusNotFound)

		token = getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteOrganization)
		req = NewRequestf(t, "DELETE", "/api/v1/teams/%d/invitations/%d", team.ID, invite.ID).
			AddTokenAuth(token)
		MakeRequest(t, req, http.StatusNotFound)
	})

	t.Run("Org owner PoV", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()

		session := loginUser(t, user2.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadOrganization)
		req := NewRequestf(t, "GET", "/api/v1/teams/%d/invitations", team.ID).
			AddTokenAuth(token)
		resp := MakeRequest(t, req, http.StatusOK)
		assert.Equal(t, "1", resp.Header().Get("x-total-count"))

		var apiTeamInvites []*api.TeamInvite
		DecodeJSON(t, resp, &apiTeamInvites)
		assert.Len(t, apiTeamInvites, 1)
		assert.Equal(t, invite.ID, apiTeamInvites[0].ID)
		assert.Equal(t, team.ID, apiTeamInvites[0].TeamID)
		assert.Equal(t, user2.Name, apiTeamInvites[0].Inviter.UserName)

		req = NewRequestf(t, "GET", "/api/v1/teams/%d/invitations/%d", team.ID, invite.ID).
			AddTokenAuth(token)
		resp = MakeRequest(t, req, http.StatusOK)
		var apiTeamInvite *api.TeamInvite
		DecodeJSON(t, resp, &apiTeamInvite)
		assert.Equal(t, invite.ID, apiTeamInvite.ID)
		assert.Equal(t, team.ID, apiTeamInvite.TeamID)
		assert.Equal(t, user2.Name, apiTeamInvite.Inviter.UserName)

		token = getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteOrganization)
		req = NewRequestf(t, "DELETE", "/api/v1/teams/%d/invitations/%d", team.ID, invite.ID).
			AddTokenAuth(token)
		MakeRequest(t, req, http.StatusNoContent)

		unittest.AssertNotExistsBean(t, invite)
	})
}

func TestAPIMyTeamInvites(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 1})
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	user8 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8})

	invite, err := organization.CreateTeamInviteForUser(ownActCtx(t), user2, user5, team)
	require.NoError(t, err)
	invite8, err := organization.CreateTeamInviteForUser(ownActCtx(t), user2, user8, team)
	require.NoError(t, err)

	t.Run("Different user PoV", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()

		session := loginUser(t, user2.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadUser)
		req := NewRequestf(t, "GET", "/api/v1/user/team_invitations/%d", invite.ID).
			AddTokenAuth(token)
		MakeRequest(t, req, http.StatusNotFound)

		token = getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteUser)
		req = NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/user/team_invitations/%d/accept", invite.ID), &api.AcceptTeamInviteOptions{}).
			AddTokenAuth(token)
		MakeRequest(t, req, http.StatusNotFound)

		req = NewRequest(t, "POST", fmt.Sprintf("/api/v1/user/team_invitations/%d/decline", invite.ID)).
			AddTokenAuth(token)
		MakeRequest(t, req, http.StatusNotFound)
	})

	t.Run("Invited user PoV", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()

		session := loginUser(t, user5.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadUser)
		req := NewRequestf(t, "GET", "/api/v1/user/team_invitations").
			AddTokenAuth(token)
		resp := MakeRequest(t, req, http.StatusOK)
		assert.Equal(t, "1", resp.Header().Get("x-total-count"))

		var apiTeamInvites []*api.TeamInvite
		DecodeJSON(t, resp, &apiTeamInvites)
		assert.Len(t, apiTeamInvites, 1)
		assert.Equal(t, invite.ID, apiTeamInvites[0].ID)
		assert.Equal(t, team.ID, apiTeamInvites[0].TeamID)
		assert.Equal(t, user2.Name, apiTeamInvites[0].Inviter.UserName)
		assert.Equal(t, invite.Token, apiTeamInvites[0].Token)

		req = NewRequestf(t, "GET", "/api/v1/user/team_invitations/%d", invite.ID).
			AddTokenAuth(token)
		resp = MakeRequest(t, req, http.StatusOK)
		var apiTeamInvite *api.TeamInvite
		DecodeJSON(t, resp, &apiTeamInvite)
		assert.Equal(t, invite.ID, apiTeamInvite.ID)
		assert.Equal(t, team.ID, apiTeamInvite.TeamID)
		assert.Equal(t, user2.Name, apiTeamInvite.Inviter.UserName)
		assert.Equal(t, invite.Token, apiTeamInvite.Token)

		token = getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteUser)
		req = NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/user/team_invitations/%d/accept", invite.ID), &api.AcceptTeamInviteOptions{}).
			AddTokenAuth(token)
		MakeRequest(t, req, http.StatusNoContent)

		unittest.AssertNotExistsBean(t, invite)
		isMember, err := organization.IsTeamMember(db.DefaultContext, team.OrgID, team.ID, user5.ID)
		require.NoError(t, err)
		assert.True(t, isMember)
	})

	t.Run("Decline an invitation", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()

		session := loginUser(t, user8.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteUser)
		req := NewRequest(t, "POST", fmt.Sprintf("/api/v1/user/team_invitations/%d/decline", invite8.ID)).
			AddTokenAuth(token)
		MakeRequest(t, req, http.StatusNoContent)

		unittest.AssertNotExistsBean(t, invite8)
		isMember, err := organization.IsTeamMember(db.DefaultContext, team.OrgID, team.ID, user8.ID)
		require.NoError(t, err)
		assert.False(t, isMember)
	})
}
