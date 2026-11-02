// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	perm_model "forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	"forgejo.org/tests"

	"github.com/42wim/httpsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestOwnedAccessTokenAPI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	owner := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteIssue)

	create := func(t *testing.T, path, token string, opts api.CreateOwnedAccessTokenOption, status int) *api.AccessToken {
		t.Helper()
		resp := MakeRequest(t, NewRequestWithJSON(t, "POST", path, opts).AddTokenAuth(token), status)
		if status != http.StatusCreated {
			return nil
		}
		var out api.AccessToken
		DecodeJSON(t, resp, &out)
		return &out
	}
	use := func(t *testing.T, path, token string) int {
		t.Helper()
		return MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), NoExpectedStatus).Code
	}
	name := func() string { return fmt.Sprintf("api-token-%d", tokenCounter.Add(1)) }

	t.Run("repository token", func(t *testing.T) {
		since := auditMaxID(t)
		n := name()
		tok := create(t, "/api/v1/repos/org3/repo3/tokens", owner,
			api.CreateOwnedAccessTokenOption{Name: n, Scopes: []string{"read:repository"}, Permission: "read"}, http.StatusCreated)
		assert.NotEmpty(t, tok.Token)
		assert.Equal(t, "read", tok.Permission)
		assert.Equal(t, "user2", tok.CreatedBy)
		e := auditOne(t, since, "credential.access_token.created")
		assert.Equal(t, tok.ID, e.TargetID)
		assert.EqualValues(t, 3, e.RepoID)

		assert.Equal(t, http.StatusOK, use(t, "/api/v1/repos/org3/repo3", tok.Token))
		assert.Equal(t, http.StatusNotFound, use(t, "/api/v1/repos/org3/repo5", tok.Token))

		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3/tokens").AddTokenAuth(owner), http.StatusOK)
		var list []*api.AccessToken
		DecodeJSON(t, resp, &list)
		require.NotEmpty(t, list)
		assert.Equal(t, n, list[0].Name)
		assert.Empty(t, list[0].Token)
		assert.Equal(t, "user2", list[0].CreatedBy)

		// the same name again, and a token of another owner by ID
		create(t, "/api/v1/repos/org3/repo3/tokens", owner,
			api.CreateOwnedAccessTokenOption{Name: n, Scopes: []string{"read:repository"}, Permission: "read"}, http.StatusUnprocessableEntity)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/repos/org3/repo5/tokens/%d", tok.ID)).AddTokenAuth(owner), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/orgs/org3/tokens/%d", tok.ID)).AddTokenAuth(owner), http.StatusNotFound)

		since = auditMaxID(t)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/repos/org3/repo3/tokens/%d", tok.ID)).AddTokenAuth(owner), http.StatusNoContent)
		assert.Equal(t, tok.ID, auditOne(t, since, "credential.access_token.deleted").TargetID)
		assert.Equal(t, http.StatusUnauthorized, use(t, "/api/v1/repos/org3/repo3", tok.Token))
	})

	t.Run("refusals", func(t *testing.T) {
		path := "/api/v1/repos/org3/repo3/tokens"
		for _, c := range []struct {
			name   string
			opts   api.CreateOwnedAccessTokenOption
			status int
		}{
			{"no scope", api.CreateOwnedAccessTokenOption{Name: name(), Permission: "read"}, http.StatusUnprocessableEntity},
			{"user scope", api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"write:user"}, Permission: "read"}, http.StatusUnprocessableEntity},
			{"empty permission", api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}}, http.StatusUnprocessableEntity},
			{"none permission", api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "none"}, http.StatusUnprocessableEntity},
			{"blank name", api.CreateOwnedAccessTokenOption{Name: "  ", Scopes: []string{"read:repository"}, Permission: "read"}, http.StatusUnprocessableEntity},
			{"long name", api.CreateOwnedAccessTokenOption{Name: strings.Repeat("n", 300), Scopes: []string{"read:repository"}, Permission: "read"}, http.StatusUnprocessableEntity},
			{"owner permission", api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "owner"}, http.StatusUnprocessableEntity},
			{"repositories", api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read", Repositories: []string{"repo3"}}, http.StatusUnprocessableEntity},
			{"scope the creator lacks", api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"write:package"}, Permission: "write"}, http.StatusForbidden},
		} {
			t.Run(c.name, func(t *testing.T) {
				create(t, path, owner, c.opts, c.status)
			})
		}

		t.Run("not a repository admin", func(t *testing.T) {
			create(t, path, getUserToken(t, "user4", auth_model.AccessTokenScopeWriteRepository),
				api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read"}, http.StatusForbidden)
		})

		t.Run("a token of a repository can't create tokens", func(t *testing.T) {
			bot := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, 3, 0, perm_model.AccessModeAdmin, "write:repository")
			create(t, path, bot.Token,
				api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read"}, http.StatusForbidden)
			MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(bot.Token), http.StatusForbidden)
			MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", path, bot.ID)).AddTokenAuth(bot.Token), http.StatusForbidden)
		})

		t.Run("an OAuth2 grant can't manage tokens", func(t *testing.T) {
			oauth := createOAuth2Token(t, loginUser(t, "user2"), []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteRepository})
			create(t, path, oauth,
				api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read"}, http.StatusForbidden)
			MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(oauth), http.StatusForbidden)
		})

		t.Run("an HTTP signature can't manage tokens", func(t *testing.T) {
			defer test.MockVariableValue(&setting.SSH.MinimumKeySizeCheck, false)()
			keyToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteUser)
			sshSigner, err := ssh.ParsePrivateKey([]byte(httpsigPrivateKey))
			require.NoError(t, err)
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/keys", api.CreateKeyOption{
				Title: "owned-token-httpsig", Key: string(ssh.MarshalAuthorizedKey(sshSigner.PublicKey())),
			}).AddTokenAuth(keyToken), http.StatusCreated)

			body, err := json.Marshal(api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read"})
			require.NoError(t, err)
			req := NewRequestWithBody(t, "POST", path, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			signer, _, err := httpsig.NewSSHSigner(sshSigner, httpsig.DigestSha512, []string{httpsig.RequestTarget, "(created)", "(expires)"}, httpsig.Signature, 10)
			require.NoError(t, err)
			require.NoError(t, signer.SignRequest(ssh.FingerprintSHA256(sshSigner.PublicKey()), req.Request, body))
			MakeRequest(t, req, http.StatusForbidden)
		})

		t.Run("not after the creating token's expiry", func(t *testing.T) {
			user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			short := &auth_model.AccessToken{
				UID: user2.ID, Name: name(), Scope: "write:repository", ResourceAllRepos: true,
				ExpiresUnix: timeutil.TimeStamp(time.Now().Add(24 * time.Hour).Unix()),
			}
			require.NoError(t, auth_model.NewAccessToken(audit_model.WithSystem(db.DefaultContext, "test"), short, nil))
			create(t, path, short.Token,
				api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read"}, http.StatusUnprocessableEntity)
			later := time.Now().Add(48 * time.Hour)
			create(t, path, short.Token,
				api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read", ExpiresAt: &later}, http.StatusUnprocessableEntity)
			sooner := time.Now().Add(time.Hour)
			create(t, path, short.Token,
				api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read", ExpiresAt: &sooner}, http.StatusCreated)
		})
	})

	t.Run("organization token", func(t *testing.T) {
		path := "/api/v1/orgs/org3/tokens"
		tok := create(t, path, owner, api.CreateOwnedAccessTokenOption{
			Name: name(), Scopes: []string{"read:repository"}, Permission: "read", Repositories: []string{"repo3", "REPO3"},
		}, http.StatusCreated)
		require.Len(t, tok.Repositories, 1)
		assert.Equal(t, "org3/repo3", tok.Repositories[0].FullName)
		assert.Equal(t, http.StatusOK, use(t, "/api/v1/repos/org3/repo3", tok.Token))
		assert.Equal(t, http.StatusNotFound, use(t, "/api/v1/repos/org3/repo5", tok.Token))

		create(t, path, owner, api.CreateOwnedAccessTokenOption{
			Name: name(), Scopes: []string{"read:repository"}, Permission: "read", Repositories: []string{"repo1"},
		}, http.StatusUnprocessableEntity)
		create(t, path, owner, api.CreateOwnedAccessTokenOption{
			Name: name(), Scopes: []string{"read:repository"}, Permission: "read", Repositories: []string{},
		}, http.StatusUnprocessableEntity)

		all := create(t, path, owner, api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read"}, http.StatusCreated)
		assert.Empty(t, all.Repositories)
		assert.Equal(t, http.StatusOK, use(t, "/api/v1/repos/org3/repo5", all.Token))

		resp := MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(owner), http.StatusOK)
		var list []*api.AccessToken
		DecodeJSON(t, resp, &list)
		assert.Len(t, list, 2)

		// a member who isn't an owner, and a token limited to specific repositories
		create(t, path, getUserToken(t, "user4", auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository),
			api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read"}, http.StatusForbidden)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		limited := &auth_model.AccessToken{UID: user2.ID, Name: name(), Scope: "write:repository,write:organization"}
		require.NoError(t, auth_model.NewAccessToken(audit_model.WithSystem(db.DefaultContext, "test"), limited,
			[]*auth_model.AccessTokenResourceRepo{{RepoID: 3}}))
		create(t, path, limited.Token,
			api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read"}, http.StatusForbidden)
	})

	t.Run("project token", func(t *testing.T) {
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		group, err := repo_model.CreateRepoGroup(audit_model.WithSystem(db.DefaultContext, "test"), org3, "tokens-api", "")
		require.NoError(t, err)
		path := fmt.Sprintf("/api/v1/orgs/org3/projects/%d/tokens", group.ID)
		tok := create(t, path, owner, api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "write"}, http.StatusCreated)
		assert.Equal(t, "write", tok.Permission)
		create(t, path, owner, api.CreateOwnedAccessTokenOption{
			Name: name(), Scopes: []string{"read:repository"}, Permission: "read", Repositories: []string{"repo3"},
		}, http.StatusUnprocessableEntity)
		create(t, "/api/v1/orgs/org3/projects/999999/tokens", owner,
			api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read"}, http.StatusNotFound)

		resp := MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(owner), http.StatusOK)
		var list []*api.AccessToken
		DecodeJSON(t, resp, &list)
		require.Len(t, list, 1)
		assert.Equal(t, tok.ID, list[0].ID)

		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", path, tok.ID)).AddTokenAuth(owner), http.StatusNoContent)
	})

	t.Run("rotate", func(t *testing.T) {
		path := "/api/v1/repos/org3/repo3/tokens"
		tok := create(t, path, owner, api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read", Description: " release job "}, http.StatusCreated)
		assert.Equal(t, "release job", tok.Description)
		rotate := func(t *testing.T, path, token string, status int) *api.AccessToken {
			t.Helper()
			resp := MakeRequest(t, NewRequestWithJSON(t, "POST", path, api.RotateOwnedAccessTokenOption{}).AddTokenAuth(token), status)
			if status != http.StatusOK {
				return nil
			}
			var out api.AccessToken
			DecodeJSON(t, resp, &out)
			return &out
		}

		// another owner's route doesn't find it, and the token itself can't rotate others
		rotate(t, fmt.Sprintf("/api/v1/repos/org3/repo5/tokens/%d/rotate", tok.ID), owner, http.StatusNotFound)
		rotate(t, fmt.Sprintf("/api/v1/orgs/org3/tokens/%d/rotate", tok.ID), owner, http.StatusNotFound)
		rotate(t, fmt.Sprintf("%s/%d/rotate", path, tok.ID), tok.Token, http.StatusForbidden)

		// an expired token can be rotated, and comes back with the same settings
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE access_token SET expires_unix = ? WHERE id = ?", timeutil.TimeStampNow().AddDuration(-time.Hour), tok.ID)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, use(t, "/api/v1/repos/org3/repo3", tok.Token))
		since := auditMaxID(t)
		rotated := rotate(t, fmt.Sprintf("%s/%d/rotate", path, tok.ID), owner, http.StatusOK)
		assert.Equal(t, tok.ID, rotated.ID)
		assert.NotEqual(t, tok.Token, rotated.Token)
		assert.Equal(t, "read", rotated.Permission)
		assert.Equal(t, "user2", rotated.RotatedBy)
		assert.False(t, rotated.RotatedBySelf)
		assert.Equal(t, http.StatusOK, use(t, "/api/v1/repos/org3/repo3", rotated.Token))
		assert.Equal(t, http.StatusUnauthorized, use(t, "/api/v1/repos/org3/repo3", tok.Token))
		e := auditOne(t, since, "credential.access_token.rotated")
		assert.Equal(t, tok.ID, e.TargetID)
		assert.NotContains(t, e.Data, rotated.Token)

		// self-rotate needs the setting, and only a token of an organization, a project or a repository has it
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/tokens/self/rotate").AddTokenAuth(rotated.Token), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/tokens/self/rotate").AddTokenAuth(owner), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/tokens/self/rotate"), http.StatusUnauthorized)

		self := create(t, path, owner, api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read", SelfRotate: true}, http.StatusCreated)
		assert.True(t, self.SelfRotate)
		resp := MakeRequest(t, NewRequest(t, "POST", "/api/v1/tokens/self/rotate").AddTokenAuth(self.Token), http.StatusOK)
		var selfRotated api.AccessToken
		DecodeJSON(t, resp, &selfRotated)
		assert.Equal(t, self.ID, selfRotated.ID)
		assert.True(t, selfRotated.RotatedBySelf)
		assert.Empty(t, selfRotated.RotatedBy)
		assert.Equal(t, http.StatusUnauthorized, use(t, "/api/v1/repos/org3/repo3", self.Token), "the old secret stops working")
		assert.Equal(t, http.StatusOK, use(t, "/api/v1/repos/org3/repo3", selfRotated.Token))
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/tokens/self/rotate").AddTokenAuth(self.Token), http.StatusUnauthorized)

		// a revoked token can't be rotated back
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", path, self.ID)).AddTokenAuth(owner), http.StatusNoContent)
		rotate(t, fmt.Sprintf("%s/%d/rotate", path, self.ID), owner, http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/tokens/self/rotate").AddTokenAuth(selfRotated.Token), http.StatusUnauthorized)
		resp = MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(owner), http.StatusOK)
		var list []*api.AccessToken
		DecodeJSON(t, resp, &list)
		for _, l := range list {
			assert.NotEqual(t, self.ID, l.ID, "a revoked token isn't listed")
		}
	})
}
