// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	auth_service "forgejo.org/services/auth"
	"forgejo.org/services/authz"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testScopePolicy = setting.AccessTokenScopePolicy{
	Allowed:                []string{"write:repository", "read:user"},
	RequireRepoRestriction: []string{"write:repository"},
}

func TestAccessTokenScopePolicyAPI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	// A token created before the policy keeps working (no change to existing tokens).
	existing := getUserToken(t, "user2", auth_model.AccessTokenScopeReadIssue, auth_model.AccessTokenScopeReadUser)
	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	defer test.MockVariableValue(&setting.AccessTokenScopes, testScopePolicy)()

	create := func(t *testing.T, url, user, token string, opt api.CreateAccessTokenOption, status int) string {
		t.Helper()
		opt.Name = fmt.Sprintf("scope-policy-%d", tokenCounter.Add(1))
		req := NewRequestWithJSON(t, "POST", url, opt)
		if token != "" {
			req.AddTokenAuth(token)
		} else {
			req.AddBasicAuth(user)
		}
		return MakeRequest(t, req, status).Body.String()
	}
	repo1 := []*api.RepoTargetOption{{Owner: "user2", Name: "repo1"}}

	t.Run("non-admin", func(t *testing.T) {
		body := create(t, "/api/v1/users/user2/tokens", "user2", "", api.CreateAccessTokenOption{Scopes: []string{"read:issue"}}, http.StatusUnprocessableEntity)
		assert.Contains(t, body, "read:issue")
		assert.Contains(t, body, "allowed scopes: read:repository, write:repository, read:user")

		create(t, "/api/v1/users/user2/tokens", "user2", "", api.CreateAccessTokenOption{Scopes: []string{"all"}}, http.StatusUnprocessableEntity)
		body = create(t, "/api/v1/users/user2/tokens", "user2", "", api.CreateAccessTokenOption{Scopes: []string{"write:repository"}}, http.StatusUnprocessableEntity)
		assert.Contains(t, body, "write:repository")
		create(t, "/api/v1/users/user2/tokens", "user2", "", api.CreateAccessTokenOption{Scopes: []string{"read:user"}}, http.StatusCreated)
		create(t, "/api/v1/users/user2/tokens", "user2", "", api.CreateAccessTokenOption{Scopes: []string{"read:repository"}, Repositories: repo1}, http.StatusCreated)
		create(t, "/api/v1/users/user2/tokens", "user2", "", api.CreateAccessTokenOption{Scopes: []string{"public-only", "read:user"}}, http.StatusCreated)
	})

	t.Run("existing token still works", func(t *testing.T) {
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/issues/search").AddTokenAuth(existing), http.StatusOK)
	})

	t.Run("site admin is exempt", func(t *testing.T) {
		create(t, "/api/v1/users/user1/tokens", "user1", "", api.CreateAccessTokenOption{Scopes: []string{"all"}}, http.StatusCreated)
	})

	t.Run("admin API: the target user's admin flag decides", func(t *testing.T) {
		create(t, "/api/v1/admin/users/user2/tokens", "", adminToken, api.CreateAccessTokenOption{Scopes: []string{"all"}}, http.StatusUnprocessableEntity)
		create(t, "/api/v1/admin/users/user2/tokens", "", adminToken, api.CreateAccessTokenOption{Scopes: []string{"read:user"}}, http.StatusCreated)

		user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
		user4.IsAdmin = true
		require.NoError(t, user_model.UpdateUserCols(t.Context(), user4, "is_admin"))
		defer func() {
			user4.IsAdmin = false
			require.NoError(t, user_model.UpdateUserCols(t.Context(), user4, "is_admin"))
		}()
		create(t, "/api/v1/admin/users/user4/tokens", "", adminToken, api.CreateAccessTokenOption{Scopes: []string{"all"}}, http.StatusCreated)

		// A site admin who can't log in is not exempt.
		user4.ProhibitLogin = true
		require.NoError(t, user_model.UpdateUserCols(t.Context(), user4, "prohibit_login"))
		defer func() {
			user4.ProhibitLogin = false
			require.NoError(t, user_model.UpdateUserCols(t.Context(), user4, "prohibit_login"))
		}()
		create(t, "/api/v1/admin/users/user4/tokens", "", adminToken, api.CreateAccessTokenOption{Scopes: []string{"all"}}, http.StatusUnprocessableEntity)
	})
}

func TestAccessTokenScopePolicyWeb(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.AccessTokenScopes, testScopePolicy)()

	post := func(t *testing.T, session *TestSession, name, resource string, status int, scopes ...string) string {
		t.Helper()
		values := url.Values{"name": {name}, "resource": {resource}, "scope": scopes}
		if resource == "repo-specific" {
			values.Set("selected_repo", "user2/repo1")
		}
		return session.MakeRequest(t, NewRequestWithURLValues(t, "POST", "/user/settings/keys/tokens/new", values), status).Body.String()
	}

	t.Run("non-admin", func(t *testing.T) {
		session := loginUser(t, "user2")

		resp := session.MakeRequest(t, NewRequest(t, "GET", "/user/settings/keys/tokens/new"), http.StatusOK)
		doc := NewHTMLParser(t, resp.Body)
		assert.True(t, doc.Find(`#access-token-scope-issue option[value="read:issue"]`).Is("[disabled]"))
		assert.True(t, doc.Find(`#access-token-scope-user option[value="write:user"]`).Is("[disabled]"))
		assert.False(t, doc.Find(`#access-token-scope-user option[value="read:user"]`).Is("[disabled]"))
		assert.False(t, doc.Find(`#access-token-scope-repository option[value="write:repository"]`).Is("[disabled]"))

		body := post(t, session, "web-disallowed", "all", http.StatusOK, "read:issue")
		assert.Contains(t, body, "The scope read:issue is not allowed.")
		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{UID: 2, Name: "web-disallowed"})

		body = post(t, session, "web-unrestricted", "all", http.StatusOK, "write:repository")
		assert.Contains(t, body, "Access tokens with the write:repository scope must be limited to specified repositories.")
		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{UID: 2, Name: "web-unrestricted"})

		post(t, session, "web-restricted", "repo-specific", http.StatusSeeOther, "write:repository")
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 2, Name: "web-restricted", ResourceAllRepos: false})
		post(t, session, "web-allowed", "all", http.StatusSeeOther, "read:user")
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 2, Name: "web-allowed"})
	})

	t.Run("regenerate is not checked", func(t *testing.T) {
		// A token that breaks the policy, created before it was set.
		old := &auth_model.AccessToken{UID: 2, Name: "pre-policy", Scope: auth_model.AccessTokenScopeReadIssue, ResourceAllRepos: true}
		require.NoError(t, auth_model.NewAccessToken(t.Context(), old, nil))

		session := loginUser(t, "user2")
		req := NewRequestWithValues(t, "POST", "/user/settings/keys/tokens/regenerate", map[string]string{"id": fmt.Sprint(old.ID)})
		session.MakeRequest(t, req, http.StatusOK)
		regenerated := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: old.ID, Scope: auth_model.AccessTokenScopeReadIssue})
		assert.NotEqual(t, old.TokenHash, regenerated.TokenHash)
	})

	t.Run("site admin is exempt", func(t *testing.T) {
		session := loginUser(t, "user1")

		resp := session.MakeRequest(t, NewRequest(t, "GET", "/user/settings/keys/tokens/new"), http.StatusOK)
		assert.Equal(t, 0, NewHTMLParser(t, resp.Body).Find(".access-token-select option[disabled]").Length())

		post(t, session, "web-admin", "all", http.StatusSeeOther, "write:admin", "write:issue")
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 1, Name: "web-admin"})
	})
}

func TestAccessTokenScopePolicyAuthorizedIntegrationWeb(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.AccessTokenScopes, testScopePolicy)()
	session := loginUser(t, "user2")

	post := func(t *testing.T, name, scope string, status int) string {
		t.Helper()
		req := NewRequestWithValues(t, "POST", "/user/settings/authorized-integrations/forgejo-actions-local/new", map[string]string{
			"name": name, "resource": "all", "scope": scope, "source_repo": "user2/repo1",
		})
		return session.MakeRequest(t, req, status).Body.String()
	}

	body := post(t, "ai-disallowed", "read:issue", http.StatusOK)
	assert.Contains(t, body, "The scope read:issue is not allowed.")
	unittest.AssertNotExistsBean(t, &auth_model.AuthorizedIntegration{UserID: 2, Name: "ai-disallowed"})

	body = post(t, "ai-unrestricted", "write:repository", http.StatusOK)
	assert.Contains(t, body, "Access tokens with the write:repository scope must be limited to specified repositories.")
	unittest.AssertNotExistsBean(t, &auth_model.AuthorizedIntegration{UserID: 2, Name: "ai-unrestricted"})

	post(t, "ai-allowed", "read:user", http.StatusSeeOther)
	unittest.AssertExistsAndLoadBean(t, &auth_model.AuthorizedIntegration{UserID: 2, Name: "ai-allowed"})
}

func TestAccessTokenScopePolicyAuthorizedIntegrationUpdate(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	// An integration that breaks the policy, created before it was set.
	ait := newAITester(t, func(ai *auth_model.AuthorizedIntegration) {
		ai.Scope = auth_model.AccessTokenScopeReadIssue
	})
	defer ait.close()
	defer test.MockVariableValue(&setting.AccessTokenScopes, testScopePolicy)()

	// Editing it re-checks the policy, even when the edit doesn't touch the scope.
	ai := ait.authorizedIntegration
	ai.Name = "renamed"
	require.ErrorIs(t, auth_service.UpdateAuthorizedIntegration(t.Context(), ai, nil), authz.ErrScopeNotAllowed)
	unittest.AssertNotExistsBean(t, &auth_model.AuthorizedIntegration{ID: ai.ID, Name: "renamed"})

	// It keeps working.
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/issues/search").AddTokenAuth(ait.signedJWT()), http.StatusOK)
}

func TestAccessTokenScopePolicyCLIAuthorizedIntegration(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	// The CLI runs in another process: give it the policy through its config file.
	conf, err := os.ReadFile(setting.CustomConf)
	require.NoError(t, err)
	confPath := filepath.Join(t.TempDir(), "app.ini")
	conf = append(conf, "\n[security]\nACCESS_TOKEN_ALLOWED_SCOPES = read:user\n"...)
	require.NoError(t, os.WriteFile(confPath, conf, 0o600))
	defer test.MockVariableValue(&setting.CustomConf, confPath)()

	_, err = runMainApp("admin", "user", "create-authorized-integration", "--username", "user2", "--name", "cli-disallowed",
		"--issuer", "https://issuer.example.org", "--scope", "read:issue")
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Contains(t, string(exitErr.Stderr), "access token scope not allowed: read:issue")
	unittest.AssertNotExistsBean(t, &auth_model.AuthorizedIntegration{UserID: 2, Name: "cli-disallowed"})
}

func TestAccessTokenScopePolicyEnforced(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	// Tokens created before the policy existed.
	broad := getUserToken(t, "user2", auth_model.AccessTokenScopeReadIssue, auth_model.AccessTokenScopeReadUser)
	unrestricted := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
	allowed := getUserToken(t, "user2", auth_model.AccessTokenScopeReadUser)
	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	ait := newAITester(t, func(ai *auth_model.AuthorizedIntegration) {
		ai.Scope = auth_model.AccessTokenScopeReadIssue
	})
	defer ait.close()
	task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
	task.GenerateToken()
	require.NoError(t, actions_model.UpdateTask(t.Context(), task))

	policy := testScopePolicy
	policy.EnforceAfter = "2030-01-02"
	defer test.MockVariableValue(&setting.AccessTokenScopes, policy)()
	date := time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC)
	defer timeutil.MockUnset()

	apiGet := func(t *testing.T, url, token string, status int) *httptest.ResponseRecorder {
		t.Helper()
		return MakeRequest(t, NewRequest(t, "GET", url).AddTokenAuth(token), status)
	}

	t.Run("before the date", func(t *testing.T) {
		timeutil.MockSet(date.Add(-time.Minute))
		apiGet(t, "/api/v1/user", broad, http.StatusOK)
		apiGet(t, "/api/v1/repos/user2/repo1", unrestricted, http.StatusOK)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/issues/search").AddTokenAuth(ait.signedJWT()), http.StatusOK)
	})

	timeutil.MockSet(date.Add(time.Minute))

	t.Run("API", func(t *testing.T) {
		resp := apiGet(t, "/api/v1/user", broad, http.StatusUnauthorized)
		assert.Contains(t, resp.Body.String(), "access token breaks the access token scope policy: access token scope not allowed: read:issue; allowed scopes: read:repository, write:repository, read:user; replace it with a token that follows the policy")
		resp = apiGet(t, "/api/v1/repos/user2/repo1", unrestricted, http.StatusUnauthorized)
		assert.Contains(t, resp.Body.String(), "access token scope must be limited to specified repositories: write:repository")
		apiGet(t, "/api/v1/user", allowed, http.StatusOK)
		apiGet(t, "/api/v1/admin/users", adminToken, http.StatusOK)
	})

	t.Run("every way to send the token", func(t *testing.T) {
		// None falls through to anonymous access: /api/v1/user answers 401 without a user anyway, so use a public page.
		url := "/api/v1/repos/user2/repo1"
		MakeRequest(t, NewRequest(t, "GET", url).SetHeader("Authorization", "token "+broad), http.StatusUnauthorized)
		MakeRequest(t, NewRequest(t, "GET", url).SetHeader("Authorization", "Bearer "+broad), http.StatusUnauthorized)
		defer test.MockVariableValue(&setting.DisableQueryAuthToken, false)()
		MakeRequest(t, NewRequest(t, "GET", url+"?token="+broad), http.StatusUnauthorized)
		MakeRequest(t, NewRequest(t, "GET", url+"?access_token="+broad), http.StatusUnauthorized)
		req := NewRequest(t, "GET", url)
		req.SetBasicAuth("user2", broad)
		MakeRequest(t, req, http.StatusUnauthorized)
		req = NewRequest(t, "GET", url)
		req.SetBasicAuth(broad, "x-oauth-basic")
		MakeRequest(t, req, http.StatusUnauthorized)
		MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK)
	})

	// The admin token works above; once its owner is no longer a usable admin it is enforced.
	for _, col := range []string{"is_admin", "prohibit_login", "is_active"} {
		t.Run("admin token after changing "+col, func(t *testing.T) {
			admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
			restore := *admin
			admin.IsAdmin, admin.ProhibitLogin, admin.IsActive = col != "is_admin", col == "prohibit_login", col != "is_active"
			require.NoError(t, user_model.UpdateUserCols(t.Context(), admin, col))
			defer func() { require.NoError(t, user_model.UpdateUserCols(t.Context(), &restore, col)) }()
			apiGet(t, "/api/v1/admin/users", adminToken, http.StatusUnauthorized)
		})
	}
	apiGet(t, "/api/v1/admin/users", adminToken, http.StatusOK)

	t.Run("last used is not updated", func(t *testing.T) {
		apiGet(t, "/api/v1/user", broad, http.StatusUnauthorized)
		token, err := auth_model.GetAccessTokenBySHA(t.Context(), broad)
		require.NoError(t, err)
		assert.Less(t, token.UpdatedUnix.AsTime(), date)
	})

	t.Run("git HTTP", func(t *testing.T) {
		req := NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack")
		req.SetBasicAuth("user2", broad)
		MakeRequest(t, req, http.StatusUnauthorized)
	})

	t.Run("nuget", func(t *testing.T) {
		for _, token := range []string{broad, unrestricted} {
			req := NewRequest(t, "GET", "/api/packages/user2/nuget/index.json").SetHeader("X-NuGet-ApiKey", token)
			MakeRequest(t, req, http.StatusUnauthorized)
		}
		req := NewRequest(t, "GET", "/api/packages/user2/nuget/index.json").SetHeader("X-NuGet-ApiKey", allowed)
		MakeRequest(t, req, http.StatusOK)
	})

	t.Run("authorized integration", func(t *testing.T) {
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/issues/search").AddTokenAuth(ait.signedJWT()), http.StatusUnauthorized)
		assert.Contains(t, resp.Body.String(), "edit the integration's scopes")
		// Last used is not updated: the use before the date set it to a minute before.
		ai := unittest.AssertExistsAndLoadBean(t, &auth_model.AuthorizedIntegration{ID: ait.authorizedIntegration.ID})
		assert.Less(t, ai.UpdatedUnix.AsTime(), date)
	})

	t.Run("Actions job token is not checked", func(t *testing.T) {
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user5/repo4").AddTokenAuth(task.Token), http.StatusOK)
	})
}
