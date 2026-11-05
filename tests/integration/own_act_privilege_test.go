// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	api "forgejo.org/modules/structs"
	repo_service "forgejo.org/services/repository"
	user_service "forgejo.org/services/user"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Acts that grant a privilege need the person's own act: a token or password for someone else, a rename, a
// repository transfer (started or accepted), the site admin and auditor roles, and an organization owned by someone
// else. An OAuth2 grant, an authorized integration and sudo get a 403 and nothing changes; the person's own token
// is allowed, and login source syncs and system paths keep working.
func TestPrivilegeGrantsAreOwnActs(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	// user 8 is a second site admin, so that sudo reaches the admin routes
	admin8 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8})
	admin8.IsAdmin = true
	require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, admin8, "is_admin"))

	adminScopes := []auth_model.AccessTokenScope{
		auth_model.AccessTokenScopeWriteAdmin, auth_model.AccessTokenScopeWriteUser,
		auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository,
	}
	adminToken := getUserToken(t, "user1", adminScopes...)
	ait := newAITester(t, func(ai *auth_model.AuthorizedIntegration) { ai.UserID = 1 })
	defer ait.close()
	grant := createOAuth2Token(t, loginUser(t, "user1"), adminScopes)
	credentials := map[string]func(*RequestWrapper) *RequestWrapper{
		"OAuth2 grant":           func(r *RequestWrapper) *RequestWrapper { return r.AddTokenAuth(grant) },
		"authorized integration": func(r *RequestWrapper) *RequestWrapper { return r.AddTokenAuth(ait.signedJWT()) },
		"sudo": func(r *RequestWrapper) *RequestWrapper {
			return r.AddTokenAuth(adminToken).SetHeader("Sudo", admin8.Name)
		},
	}
	own := func(r *RequestWrapper) *RequestWrapper { return r.AddTokenAuth(adminToken) }
	refused := func(t *testing.T, req func() *RequestWrapper) {
		t.Helper()
		for name, auth := range credentials {
			resp := MakeRequest(t, auth(req()), http.StatusForbidden)
			assert.Contains(t, resp.Body.String(), "credential of their own", name)
		}
	}

	t.Run("a token for another user", func(t *testing.T) {
		create := func() *RequestWrapper {
			return NewRequestWithJSON(t, "POST", "/api/v1/admin/users/user5/tokens", &api.CreateAccessTokenOption{Name: "minted", Scopes: []string{"read:user"}})
		}
		created := func() int { return unittest.GetCount(t, &audit_model.Entry{Action: "credential.access_token.created"}) }
		before := created()
		refused(t, create)
		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{UID: 5, Name: "minted"})
		assert.Equal(t, before, created(), "a refusal records nothing")
		MakeRequest(t, own(create()), http.StatusCreated)
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 5, Name: "minted"})
	})

	t.Run("an organization token under sudo", func(t *testing.T) {
		create := NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/tokens", &api.CreateOwnedAccessTokenOption{Name: "org-minted", Scopes: []string{"read:repository"}, Permission: "read"})
		assert.Contains(t, MakeRequest(t, create.AddTokenAuth(adminToken).SetHeader("Sudo", "user2"), http.StatusForbidden).Body.String(), "credential of their own")
		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{OwnerID: 3, Name: "org-minted"})
		owner := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/tokens", &api.CreateOwnedAccessTokenOption{Name: "org-minted", Scopes: []string{"read:repository"}, Permission: "read"}).AddTokenAuth(owner), http.StatusCreated)
	})

	t.Run("renaming a user", func(t *testing.T) {
		rename := func() *RequestWrapper {
			return NewRequestWithJSON(t, "POST", "/api/v1/admin/users/user5/rename", &api.RenameUserOption{NewName: "user5-renamed"})
		}
		refused(t, rename)
		unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5, Name: "user5"})
		MakeRequest(t, own(rename()), http.StatusNoContent)
		unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5, Name: "user5-renamed"})
		MakeRequest(t, own(NewRequestWithJSON(t, "POST", "/api/v1/admin/users/user5-renamed/rename", &api.RenameUserOption{NewName: "user5"})), http.StatusNoContent)
	})

	t.Run("the site admin flag and another user's password", func(t *testing.T) {
		before := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
		edit := func(opts api.EditUserOption) func() *RequestWrapper {
			return func() *RequestWrapper { return NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/user5", &opts) }
		}
		refused(t, edit(api.EditUserOption{Admin: new(true)}))
		refused(t, edit(api.EditUserOption{Password: "an-own-act-is-needed-1A!", FullName: new("changed")}))
		after := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
		assert.False(t, after.IsAdmin)
		assert.Equal(t, before.Passwd, after.Passwd, "nothing is written")
		assert.Equal(t, before.FullName, after.FullName, "nothing is written")

		MakeRequest(t, own(edit(api.EditUserOption{Admin: new(true)})()), http.StatusOK)
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5}).IsAdmin)
		MakeRequest(t, own(edit(api.EditUserOption{Admin: new(false)})()), http.StatusOK)

		// a login source syncing the flag acts as the source
		u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
		require.NoError(t, user_service.UpdateUserFromSource(audit_model.WithLoginSource(t.Context(), 1, "ldap"), u, &user_service.UpdateOptions{IsAdmin: optional.Some(true)}, "ldap"))
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5}).IsAdmin)
		require.NoError(t, user_service.UpdateUser(ownActCtx(t), u, &user_service.UpdateOptions{IsAdmin: optional.Some(false)}))
	})

	t.Run("the site admin and auditor roles of a user group", func(t *testing.T) {
		MakeRequest(t, own(NewRequestWithJSON(t, "POST", "/api/v1/admin/groups", &api.CreateUserGroupOption{Name: "roles"})), http.StatusCreated)
		for _, opts := range []api.EditUserGroupOption{{GrantsSiteAdmin: new(true)}, {GrantsAuditor: new(true)}} {
			refused(t, func() *RequestWrapper { return NewRequestWithJSON(t, "PATCH", "/api/v1/admin/groups/roles", &opts) })
		}
		group := unittest.AssertExistsAndLoadBean(t, &org_model.UserGroup{LowerName: "roles"})
		assert.False(t, group.GrantsSiteAdmin || group.GrantsAuditor)
		refused(t, func() *RequestWrapper {
			return NewRequestWithJSON(t, "POST", "/api/v1/admin/groups", &api.CreateUserGroupOption{Name: "admins", GrantsSiteAdmin: true})
		})
		// adding a member to any group stays strict
		refused(t, func() *RequestWrapper { return NewRequest(t, "PUT", "/api/v1/admin/groups/roles/members/user5") })
		MakeRequest(t, own(NewRequestWithJSON(t, "PATCH", "/api/v1/admin/groups/roles", &api.EditUserGroupOption{GrantsSiteAdmin: new(true)})), http.StatusOK)
	})

	t.Run("an organization owned by another user", func(t *testing.T) {
		create := func() *RequestWrapper {
			return NewRequestWithJSON(t, "POST", "/api/v1/admin/users/user2/orgs", &api.CreateOrgOption{UserName: "org-for-user2"})
		}
		refused(t, create)
		unittest.AssertNotExistsBean(t, &user_model.User{LowerName: "org-for-user2"})
		MakeRequest(t, own(create()), http.StatusCreated)

		// an owner who may not create organizations (user 5) is a 403, not a 500
		require.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5}).AllowCreateOrganization)
		MakeRequest(t, own(NewRequestWithJSON(t, "POST", "/api/v1/admin/users/user5/orgs", &api.CreateOrgOption{UserName: "org-for-user5"})), http.StatusForbidden)
	})

	t.Run("a repository transfer", func(t *testing.T) {
		transfer := func(repo string) func() *RequestWrapper {
			return func() *RequestWrapper {
				return NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/"+repo+"/transfer", &api.TransferRepoOption{NewOwner: "user5"})
			}
		}
		refused(t, transfer("repo1"))
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1, OwnerID: 2})
		MakeRequest(t, own(transfer("repo1")()), http.StatusAccepted) // an admin's transfer is immediate
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1, OwnerID: 5})

		// accepting is the recipient's own act
		owner := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		MakeRequest(t, transfer("repo2")().AddTokenAuth(owner), http.StatusCreated)
		accept := func() *RequestWrapper { return NewRequest(t, "POST", "/api/v1/repos/user2/repo2/transfer/accept") }
		recipientGrant := createOAuth2Token(t, loginUser(t, "user5"), []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteRepository})
		assert.Contains(t, MakeRequest(t, accept().AddTokenAuth(recipientGrant), http.StatusForbidden).Body.String(), "credential of their own")
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2, OwnerID: 2})
		MakeRequest(t, accept().AddTokenAuth(getUserToken(t, "user5", auth_model.AccessTokenScopeWriteRepository)), http.StatusAccepted)
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2, OwnerID: 5})

		// a system path keeps working
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		require.NoError(t, repo_service.TransferOwnership(audit_model.WithSystem(t.Context(), "test"), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}),
			unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), repo, nil))
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1, OwnerID: 2})
	})
}
