// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	asymkey_model "forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	app_context "forgejo.org/services/context"
	repo_service "forgejo.org/services/repository"
	user_service "forgejo.org/services/user"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Acts that grant a privilege need the person's own act: a token, password or email for someone else, a rename, a
// repository transfer (started, accepted or a trash restore to a new owner), the site admin and auditor roles, and an
// organization owned by someone else. An OAuth2 grant, an authorized integration and sudo get a 403 and nothing changes; the person's own token
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

	t.Run("another user's primary email", func(t *testing.T) {
		edit := func() *RequestWrapper {
			return NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/user5", &api.EditUserOption{Email: new("taken-over@example.com"), FullName: new("changed")})
		}
		before := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
		refused(t, edit)
		after := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
		assert.Equal(t, before.Email, after.Email)
		assert.Equal(t, before.FullName, after.FullName, "nothing is written")
		unittest.AssertNotExistsBean(t, &user_model.EmailAddress{LowerEmail: "taken-over@example.com"})
		MakeRequest(t, own(edit()), http.StatusOK)
		unittest.AssertExistsAndLoadBean(t, &user_model.EmailAddress{UID: 5, LowerEmail: "taken-over@example.com", IsPrimary: true, IsActivated: true})
	})

	t.Run("a trash restore to a new owner", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Trash.RetentionDays, 365)()
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 16, OwnerID: 2})
		require.NoError(t, repo_service.DeleteRepository(ownActCtx(t), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}), repo, false))
		restore := func() *RequestWrapper {
			return NewRequestWithJSON(t, "POST", "/api/v1/admin/trash/repo/16/restore", &api.RestoreTrashOption{NewOwner: "user5"})
		}
		refused(t, restore)
		repo = trashRepoByID(t, 16)
		assert.True(t, repo.IsTrashed())
		assert.EqualValues(t, 2, repo.OwnerID)
		MakeRequest(t, own(restore()), http.StatusNoContent)
		repo = trashRepoByID(t, 16)
		assert.False(t, repo.IsTrashed())
		assert.EqualValues(t, 5, repo.OwnerID)
	})

	t.Run("sudo as the user is the admin's act", func(t *testing.T) {
		// the sudoer is the real actor, so this is no act of the user's own
		defer test.MockVariableValue(&setting.Service.RegisterEmailConfirm, false)() // an added address is activated
		addEmail := func() *RequestWrapper {
			return NewRequestWithJSON(t, "POST", "/api/v1/user/emails", &api.CreateEmailOption{Emails: []string{"sudo-added@example.com"}})
		}
		resp := MakeRequest(t, addEmail().AddTokenAuth(adminToken).SetHeader("Sudo", "user2"), http.StatusForbidden)
		assert.Contains(t, resp.Body.String(), "credential of their own")
		unittest.AssertNotExistsBean(t, &user_model.EmailAddress{LowerEmail: "sudo-added@example.com"})
		MakeRequest(t, addEmail().AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeWriteUser)), http.StatusCreated)
		unittest.AssertExistsAndLoadBean(t, &user_model.EmailAddress{UID: 2, LowerEmail: "sudo-added@example.com", IsActivated: true})

		createToken := func() *RequestWrapper {
			return NewRequestWithJSON(t, "POST", "/api/v1/users/user2/tokens", &api.CreateAccessTokenOption{Name: "sudo-minted", Scopes: []string{"read:user"}})
		}
		resp = MakeRequest(t, createToken().AddBasicAuth("user1").SetHeader("Sudo", "user2"), http.StatusForbidden)
		assert.Contains(t, resp.Body.String(), "credential of their own")
		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{UID: 2, Name: "sudo-minted"})
		MakeRequest(t, createToken().AddBasicAuth("user2"), http.StatusCreated)
	})

	t.Run("a delegated credential for its own user", func(t *testing.T) {
		// a grant or an integration must not give its user a credential that passes every own-act check
		delegated := map[string]func(*RequestWrapper) *RequestWrapper{
			"OAuth2 grant":           credentials["OAuth2 grant"],
			"authorized integration": credentials["authorized integration"],
		}
		before := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		for name, auth := range delegated {
			for _, req := range []*RequestWrapper{
				NewRequestWithJSON(t, "POST", "/api/v1/admin/users/user1/tokens", &api.CreateAccessTokenOption{Name: "self-minted", Scopes: []string{"read:user"}}),
				NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/user1", &api.EditUserOption{Password: "an-own-act-is-needed-1A!"}),
				NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/user1", &api.EditUserOption{Email: new("self-taken@example.com")}),
			} {
				resp := MakeRequest(t, auth(req), http.StatusForbidden)
				assert.Contains(t, resp.Body.String(), "credential of their own", name)
			}
		}
		resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/emails", &api.CreateEmailOption{Emails: []string{"self-added@example.com"}}).AddTokenAuth(grant), http.StatusForbidden)
		assert.Contains(t, resp.Body.String(), "credential of their own")

		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{UID: 1, Name: "self-minted"})
		after := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		assert.Equal(t, before.Passwd, after.Passwd)
		assert.Equal(t, before.Email, after.Email)
		unittest.AssertNotExistsBean(t, &user_model.EmailAddress{LowerEmail: "self-taken@example.com"})
		unittest.AssertNotExistsBean(t, &user_model.EmailAddress{LowerEmail: "self-added@example.com"})
	})

	t.Run("another user's login source and login name", func(t *testing.T) {
		edit := func() *RequestWrapper {
			return NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/user5", &api.EditUserOption{SourceID: new(int64(0)), LoginName: new("user5-elsewhere")})
		}
		before := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
		refused(t, edit)
		assert.Equal(t, before.LoginName, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5}).LoginName)
		MakeRequest(t, own(edit()), http.StatusOK)
		assert.Equal(t, "user5-elsewhere", unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5}).LoginName)
	})

	t.Run("an SSH key", func(t *testing.T) {
		// a key signs in as its user (SSH, HTTP signatures), so it is a credential like a token
		const key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4cn+iXnA4KvcQYSV88vGn0Yi91vG47t1P7okprVmhNTkipNRIHWr6WdCO4VDr/cvsRkuVJAsLO2enwjGWWueOO6BodiBgyAOZ/5t5nJNMCNuLGT5UIo/RI1b0WRQwxEZTRjt6mFNw6lH14wRd8ulsr9toSWBPMOGWoYs1PDeDL0JuTjL+tr1SZi/EyxCngpYszKdXllJEHyI79KQgeD0Vt3pTrkbNVTOEcCNqZePSVmUH8X8Vhugz3bnE0/iE9Pb5fkWO9c4AnM1FgI/8Bvp27Fw2ShryIXuR6kKvUqhVMTuOSDHwu6A8jLE5Owt3GAYugDpDYuwTVNGrHLXKpPzrGGPE/jPmaLCMZcsdkec95dYeU3zKODEm8UQZFhmJmDeWVJ36nGrGZHL4J5aTTaeFUJmmXDaJYiJ+K2/ioKgXqnXvltu0A9R8/LGy4nrTJRr4JMLuJFoUXvGm1gXQ70w2LSpk6yl71RNC0hCtsBe8BP8IhYCM0EP5jh7eCMQZNvM= nocomment"
		add := func(path string) func() *RequestWrapper {
			return func() *RequestWrapper {
				return NewRequestWithJSON(t, "POST", path, &api.CreateKeyOption{Title: "own-act-key", Key: key})
			}
		}
		refused(t, add("/api/v1/admin/users/user5/keys")) // for another user
		refused(t, add("/api/v1/user/keys"))              // for the credential's own user (sudo: the sudo'd admin)
		unittest.AssertNotExistsBean(t, &asymkey_model.PublicKey{Name: "own-act-key"})
		MakeRequest(t, own(add("/api/v1/admin/users/user5/keys")()), http.StatusCreated)
		unittest.AssertExistsAndLoadBean(t, &asymkey_model.PublicKey{OwnerID: 5, Name: "own-act-key"})

		// a login source syncing keys acts as the source
		_, err := asymkey_model.AddPrincipalKey(audit_model.WithLoginSource(t.Context(), 1, "ldap"), 5, "own-act-principal", 1)
		require.NoError(t, err)
		_, err = asymkey_model.AddPrincipalKey(audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorUser, ID: 5, Credential: audit_model.Credential{Type: audit_model.CredentialOAuth2Grant}}), 5, "grant-principal", 0)
		require.ErrorIs(t, err, audit_model.ErrNotOwnAct)
	})

	t.Run("a restricted access token", func(t *testing.T) {
		// a token limited to public data or to some repositories is no own act; a full-scope token of the user is
		addEmail := func(email string) *RequestWrapper {
			return NewRequestWithJSON(t, "POST", "/api/v1/user/emails", &api.CreateEmailOption{Emails: []string{email}})
		}
		publicOnly := getUserToken(t, "user2", auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeWriteUser)
		repoLimited := createFineGrainedRepoAccessToken(t, "user2", []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteUser}, []int64{1})
		for name, token := range map[string]string{"public-only": publicOnly, "repository-limited": repoLimited} {
			resp := MakeRequest(t, addEmail("restricted@example.com").AddTokenAuth(token), http.StatusForbidden)
			assert.Contains(t, resp.Body.String(), "credential of their own", name)
		}
		unittest.AssertNotExistsBean(t, &user_model.EmailAddress{LowerEmail: "restricted@example.com"})
		MakeRequest(t, addEmail("restricted@example.com").AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeWriteUser)), http.StatusCreated)
	})
}

// trashRestoreFlash restores repository id from the trash to newOwner on the web admin page and returns the flash.
func trashRestoreFlash(t *testing.T, id int64, newOwner string) string {
	t.Helper()
	session := loginUser(t, "user1")
	session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/admin/trash/%d/restore", id), map[string]string{"new_owner": newOwner}), http.StatusSeeOther)
	cookie := session.GetCookie(app_context.CookieNameFlash)
	require.NotNil(t, cookie)
	flash, err := url.QueryUnescape(cookie.Value) // the cookie value, then the encoded flash values
	require.NoError(t, err)
	flash, err = url.QueryUnescape(flash)
	require.NoError(t, err)
	assert.NotContains(t, flash, "own credentials")
	return flash
}
