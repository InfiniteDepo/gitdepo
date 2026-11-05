// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	usergroup_service "forgejo.org/services/usergroup"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ownActCtx is a request of user 2 with a credential of their own, for test setup that adds team members or invites
// directly (org_model.CheckMemberAddIsOwnAct).
func ownActCtx(t *testing.T) context.Context {
	return audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, Name: "user2", Credential: audit_model.Credential{Type: audit_model.CredentialAccessToken}})
}

// A member of the Owners team changes the rules of environments and a member of a team listed as an environment's
// reviewer approves deployments, so adding one (or inviting one) is only a person's own act: an OAuth2 grant, an
// authorized integration or sudo gets a 403 and nothing is written. Other teams, removals, the user group sync and
// creating an organization are not affected.
func TestOrgTeamMemberAddOwnAct(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		ownerToken := getUserToken(t, user2.Name, auth_model.AccessTokenScopeWriteOrganization)
		owners := unittest.AssertExistsAndLoadBean(t, &org_model.Team{ID: 1})
		reviewers := unittest.AssertExistsAndLoadBean(t, &org_model.Team{ID: 2})
		unrelated := unittest.AssertExistsAndLoadBean(t, &org_model.Team{ID: 7})
		require.Equal(t, owners.OrgID, reviewers.OrgID)
		_, err := db.GetEngine(t.Context()).Exec("INSERT INTO action_environment_reviewer (environment_id, user_id, team_id) VALUES (1, 0, ?)", reviewers.ID)
		require.NoError(t, err)

		memberURL := func(team *org_model.Team, name string) string {
			return fmt.Sprintf("/api/v1/teams/%d/members/%s", team.ID, name)
		}
		added := func() int {
			return unittest.GetCount(t, &audit_model.Entry{Action: "org.team.member_added"})
		}

		ait := newAITester(t)
		defer ait.close()
		sudoToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteAdmin)
		credentials := map[string]func(*RequestWrapper) *RequestWrapper{
			"authorized integration": func(r *RequestWrapper) *RequestWrapper { return r.AddTokenAuth(ait.signedJWT()) },
			"OAuth2 grant": func(r *RequestWrapper) *RequestWrapper {
				return r.AddTokenAuth(createOAuth2Token(t, loginUser(t, user2.Name), []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteOrganization}))
			},
			"sudo": func(r *RequestWrapper) *RequestWrapper {
				return r.AddTokenAuth(sudoToken).SetHeader("Sudo", user2.Name)
			},
		}
		for name, auth := range credentials {
			t.Run(name, func(t *testing.T) {
				before := added()
				for _, team := range []*org_model.Team{owners, reviewers} {
					MakeRequest(t, auth(NewRequest(t, "PUT", memberURL(team, "user5"))), http.StatusForbidden)
					assert.False(t, unittest.BeanExists(t, &org_model.TeamUser{TeamID: team.ID, UID: 5}))
				}
				assert.Equal(t, before, added(), "a refusal records nothing")

				// invitations are created by the same request
				defer test.MockVariableValue(&setting.Service.AddMembersByInvitations, true)()
				for _, team := range []*org_model.Team{owners, reviewers} {
					MakeRequest(t, auth(NewRequest(t, "PUT", memberURL(team, "user5"))), http.StatusForbidden)
					assert.Zero(t, unittest.GetCount(t, &org_model.TeamInvite{TeamID: team.ID}))
				}
				setting.Service.AddMembersByInvitations = false

				MakeRequest(t, auth(NewRequest(t, "PUT", memberURL(unrelated, "user5"))), http.StatusNoContent)
				unittest.AssertExistsAndLoadBean(t, &org_model.TeamUser{TeamID: unrelated.ID, UID: 5})
				MakeRequest(t, auth(NewRequest(t, "DELETE", memberURL(unrelated, "user5"))), http.StatusNoContent)
			})
		}

		t.Run("a removal is allowed", func(t *testing.T) {
			MakeRequest(t, credentials["OAuth2 grant"](NewRequest(t, "DELETE", memberURL(reviewers, "user4"))), http.StatusNoContent)
			assert.False(t, unittest.BeanExists(t, &org_model.TeamUser{TeamID: reviewers.ID, UID: 4}))
		})

		t.Run("the owner's own token and session", func(t *testing.T) {
			MakeRequest(t, NewRequest(t, "PUT", memberURL(owners, "user5")).AddTokenAuth(ownerToken), http.StatusNoContent)
			MakeRequest(t, NewRequest(t, "PUT", memberURL(reviewers, "user4")).AddTokenAuth(ownerToken), http.StatusNoContent)
			unittest.AssertExistsAndLoadBean(t, &org_model.TeamUser{TeamID: owners.ID, UID: 5})
			unittest.AssertExistsAndLoadBean(t, &org_model.TeamUser{TeamID: reviewers.ID, UID: 4})

			session := loginUser(t, user2.Name)
			org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: reviewers.OrgID})
			session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/org/%s/teams/%s/action/add", org.Name, url.PathEscape(reviewers.LowerName)),
				map[string]string{"uname": "user10"}), http.StatusSeeOther)
			unittest.AssertExistsAndLoadBean(t, &org_model.TeamUser{TeamID: reviewers.ID, UID: 10})
		})

		t.Run("linking a user group is checked, the sync that follows is not", func(t *testing.T) {
			admin := audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorUser, ID: 1, Name: "user1", Credential: audit_model.Credential{Type: audit_model.CredentialSession}})
			group := &org_model.UserGroup{Name: "deployers"}
			require.NoError(t, usergroup_service.CreateGroup(admin, group))
			require.NoError(t, usergroup_service.AddMember(admin, group, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8})))
			linkURL := fmt.Sprintf("/api/v1/teams/%d/groups/%s", reviewers.ID, group.Name)
			for name, auth := range credentials {
				MakeRequest(t, auth(NewRequest(t, "PUT", linkURL)), http.StatusForbidden)
				assert.False(t, unittest.BeanExists(t, &org_model.TeamUser{TeamID: reviewers.ID, UID: 8}), name)
				MakeRequest(t, auth(NewRequest(t, "PUT", fmt.Sprintf("/api/v1/teams/%d/groups/%s", owners.ID, group.Name))), http.StatusForbidden)
			}
			// an admin's delegated credential can't add a member to a group (it would join the linked teams)
			adminGrant := createOAuth2Token(t, loginUser(t, "user1"), []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteAdmin})
			MakeRequest(t, NewRequest(t, "PUT", "/api/v1/admin/groups/deployers/members/user10").AddTokenAuth(adminGrant), http.StatusForbidden)
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/admin/groups/deployers", &api.EditUserGroupOption{GrantsOrgAdmin: new(true)}).AddTokenAuth(adminGrant), http.StatusForbidden)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/admin/roles/org-admin/exclusions", &api.SetOrgAdminExclusionsOption{Orgs: []string{}}).AddTokenAuth(adminGrant), http.StatusForbidden)

			MakeRequest(t, NewRequest(t, "PUT", linkURL).AddTokenAuth(ownerToken), http.StatusNoContent)
			unittest.AssertExistsAndLoadBean(t, &org_model.TeamUser{TeamID: reviewers.ID, UID: 8, Reason: org_model.MembershipReasonAddedByUserGroup})
			// a login source sync adds a new group member to the linked reviewer team
			sync := audit_model.WithLoginSource(t.Context(), 1, "directory")
			require.NoError(t, usergroup_service.SyncDirectoryGroups(sync, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 12}), 0,
				container.SetOf("cn=deployers"), map[string]container.Set[string]{"cn=deployers": container.SetOf("deployers")}, false))
			unittest.AssertExistsAndLoadBean(t, &org_model.TeamUser{TeamID: reviewers.ID, UID: 12, Reason: org_model.MembershipReasonAddedByUserGroup})
		})

		t.Run("accepting an invitation is the invitee's own act", func(t *testing.T) {
			defer test.MockVariableValue(&setting.Service.AddMembersByInvitations, true)()
			MakeRequest(t, NewRequest(t, "PUT", memberURL(owners, "user11")).AddTokenAuth(ownerToken), http.StatusNoContent)
			invite := unittest.AssertExistsAndLoadBean(t, &org_model.TeamInvite{TeamID: owners.ID})
			acceptURL := fmt.Sprintf("/api/v1/user/team_invitations/%d/accept", invite.ID)
			grant := createOAuth2Token(t, loginUser(t, "user11"), []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteUser})
			MakeRequest(t, NewRequestWithJSON(t, "POST", acceptURL, &api.AcceptTeamInviteOptions{}).AddTokenAuth(grant), http.StatusForbidden)
			assert.False(t, unittest.BeanExists(t, &org_model.TeamUser{TeamID: owners.ID, UID: 11}))
			own := getUserToken(t, "user11", auth_model.AccessTokenScopeWriteUser)
			MakeRequest(t, NewRequestWithJSON(t, "POST", acceptURL, &api.AcceptTeamInviteOptions{}).AddTokenAuth(own), http.StatusNoContent)
			unittest.AssertExistsAndLoadBean(t, &org_model.TeamUser{TeamID: owners.ID, UID: 11})
		})

		t.Run("creating an organization with a delegated credential", func(t *testing.T) {
			MakeRequest(t, credentials["OAuth2 grant"](NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "own-act-org"})), http.StatusCreated)
			org := unittest.AssertExistsAndLoadBean(t, &user_model.User{LowerName: "own-act-org"})
			team, err := org_model.GetOwnerTeam(t.Context(), org.ID)
			require.NoError(t, err)
			unittest.AssertExistsAndLoadBean(t, &org_model.TeamUser{TeamID: team.ID, UID: user2.ID})
		})
	})
}
