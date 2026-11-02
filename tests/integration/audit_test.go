// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/routers"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"
	trash_service "forgejo.org/services/trash"
	user_service "forgejo.org/services/user"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func auditMaxID(t *testing.T) int64 {
	t.Helper()
	var id int64
	_, err := db.GetEngine(t.Context()).Table("audit_event").Select("COALESCE(MAX(id), 0)").Get(&id)
	require.NoError(t, err)
	return id
}

// auditOne returns the one entry of action written after the id since; there must be no other entry since then,
// apart from sign-in, credential and request activity (categories auth and activity), which every request may add.
func auditOne(t *testing.T, since int64, action string) *audit_model.Entry {
	t.Helper()
	var entries []*audit_model.Entry
	require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND category NOT IN (?, ?) AND action <> ?", since, audit_model.CategoryAuth, audit_model.CategoryActivity, "audit.chain.started").OrderBy("id").Find(&entries))
	require.Len(t, entries, 1)
	require.Equal(t, action, entries[0].Action)
	return entries[0]
}

func auditData(t *testing.T, e *audit_model.Entry) map[string]any {
	t.Helper()
	data := map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(e.Data), &data))
	return data
}

func TestAuditAccessTokenWeb(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")

	assertActor := func(t *testing.T, e *audit_model.Entry, token *auth_model.AccessToken) {
		t.Helper()
		assert.Equal(t, audit_model.ActorUser, e.ActorType)
		assert.EqualValues(t, 2, e.ActorID)
		assert.Equal(t, "user2", e.ActorName)
		assert.Zero(t, e.SudoByID)
		assert.Equal(t, audit_model.CredentialSession, e.CredentialType)
		assert.EqualValues(t, 2, e.CredentialOwnerID)
		assert.Equal(t, "203.0.113.9", e.IP)
		assert.Equal(t, "audit-agent", e.UserAgent)
		assert.Len(t, e.RequestID, 22)
		assert.NotEqual(t, "client-request-id", e.RequestID)
		assert.EqualValues(t, 2, e.SubjectUserID)
		assert.EqualValues(t, 2, e.OwnerID)
		assert.Equal(t, "access_token", e.TargetType)
		assert.Equal(t, token.ID, e.TargetID)
		assert.Equal(t, "audit-web", e.TargetName)
		assert.Equal(t, audit_model.CategoryCredential, e.Category)
		assert.Equal(t, audit_model.ResultSuccess, e.Result)
	}
	client := func(rw *RequestWrapper) *RequestWrapper {
		return from("203.0.113.9", rw).SetHeader("User-Agent", "audit-agent").SetHeader("X-Request-ID", "client-request-id")
	}

	since := auditMaxID(t)
	session.MakeRequest(t, client(NewRequestWithValues(t, "POST", "/user/settings/keys/tokens/new", map[string]string{
		"name": "audit-web", "scope": "read:user", "resource": "all",
	})), http.StatusSeeOther)
	token := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 2, Name: "audit-web"})
	e := auditOne(t, since, "credential.access_token.created")
	assertActor(t, e, token)
	assert.Equal(t, map[string]any{"after": map[string]any{
		"name": "audit-web", "scopes": "read:user", "expires": 0.0, "resource_all_repos": true, "repo_ids": []any{},
	}}, auditData(t, e))
	assert.NotContains(t, e.Data, token.TokenHash)

	since = auditMaxID(t)
	session.MakeRequest(t, client(NewRequestWithValues(t, "POST", "/user/settings/keys/tokens/regenerate", map[string]string{"id": fmt.Sprint(token.ID)})), http.StatusOK)
	assertActor(t, auditOne(t, since, "credential.access_token.regenerated"), token)

	since = auditMaxID(t)
	session.MakeRequest(t, client(NewRequestWithValues(t, "POST", "/user/settings/keys/tokens/delete", map[string]string{"id": fmt.Sprint(token.ID)})), http.StatusOK)
	e = auditOne(t, since, "credential.access_token.deleted")
	assertActor(t, e, token)
	assert.Equal(t, "audit-web", auditData(t, e)["before"].(map[string]any)["name"])
}

func TestAuditAccessTokenAPI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	create := func(t *testing.T, rw *RequestWrapper) *api.AccessToken {
		t.Helper()
		token := &api.AccessToken{}
		DecodeJSON(t, MakeRequest(t, rw, http.StatusCreated), token)
		return token
	}
	newToken := func(url, name string) *RequestWrapper {
		return NewRequestWithJSON(t, "POST", url, &api.CreateAccessTokenOption{
			Name:         name,
			Scopes:       []string{"read:repository"},
			Repositories: []*api.RepoTargetOption{{Owner: "user2", Name: "repo1"}},
		})
	}

	t.Run("own token with a password", func(t *testing.T) {
		since := auditMaxID(t)
		token := create(t, newToken("/api/v1/users/user2/tokens", "audit-api").AddBasicAuth("user2"))
		e := auditOne(t, since, "credential.access_token.created")
		assert.EqualValues(t, 2, e.ActorID)
		assert.Equal(t, audit_model.CredentialPassword, e.CredentialType)
		assert.EqualValues(t, 2, e.CredentialOwnerID)
		assert.EqualValues(t, 2, e.SubjectUserID)
		assert.Equal(t, token.ID, e.TargetID)
		after := auditData(t, e)["after"].(map[string]any)
		assert.Equal(t, []any{1.0}, after["repo_ids"])
		assert.Equal(t, false, after["resource_all_repos"])

		since = auditMaxID(t)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/users/user2/tokens/%d", token.ID)).AddBasicAuth("user2"), http.StatusNoContent)
		e = auditOne(t, since, "credential.access_token.deleted")
		assert.EqualValues(t, 2, e.ActorID)
		assert.Equal(t, []any{1.0}, auditData(t, e)["before"].(map[string]any)["repo_ids"])
	})

	t.Run("admin for another user", func(t *testing.T) {
		adminToken := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeWriteAdmin)
		adminTokenRow := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{TokenLastEight: adminToken[len(adminToken)-8:]})

		assertAdmin := func(t *testing.T, e *audit_model.Entry) {
			t.Helper()
			assert.EqualValues(t, 1, e.ActorID)
			assert.Zero(t, e.SudoByID)
			assert.Equal(t, audit_model.CredentialAccessToken, e.CredentialType)
			assert.Equal(t, adminTokenRow.ID, e.CredentialID)
			assert.Equal(t, adminTokenRow.Name, e.CredentialName)
			assert.EqualValues(t, 1, e.CredentialOwnerID)
			assert.EqualValues(t, 2, e.SubjectUserID, "the subject is the token's owner, not the doer")
		}

		since := auditMaxID(t)
		token := create(t, newToken("/api/v1/admin/users/user2/tokens", "audit-admin").AddTokenAuth(adminToken))
		assertAdmin(t, auditOne(t, since, "credential.access_token.created"))

		since = auditMaxID(t)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/admin/users/user2/tokens/%d", token.ID)).AddTokenAuth(adminToken), http.StatusNoContent)
		assertAdmin(t, auditOne(t, since, "credential.access_token.deleted"))
	})

	t.Run("sudo", func(t *testing.T) {
		assertSudo := func(t *testing.T, e *audit_model.Entry) {
			t.Helper()
			assert.Equal(t, audit_model.ActorUser, e.ActorType)
			assert.EqualValues(t, 2, e.ActorID, "the actor is the user acted as")
			assert.Equal(t, "user2", e.ActorName)
			assert.EqualValues(t, 1, e.SudoByID, "the admin is kept")
			assert.Equal(t, audit_model.CredentialPassword, e.CredentialType)
			assert.EqualValues(t, 1, e.CredentialOwnerID, "the credential is the admin's")
			assert.EqualValues(t, 2, e.SubjectUserID)
		}

		since := auditMaxID(t)
		token := create(t, newToken("/api/v1/users/user2/tokens", "audit-sudo").AddBasicAuth("user1").SetHeader("Sudo", "user2"))
		assertSudo(t, auditOne(t, since, "credential.access_token.created"))

		since = auditMaxID(t)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/users/user2/tokens/%d?sudo=user2", token.ID)).AddBasicAuth("user1"), http.StatusNoContent)
		assertSudo(t, auditOne(t, since, "credential.access_token.deleted"))
	})
}

func TestAuditFailClosed(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	old := &auth_model.AccessToken{UID: 2, Name: "audit-keep", Scope: auth_model.AccessTokenScopeReadUser, ResourceAllRepos: true}
	require.NoError(t, auth_model.NewAccessToken(audit_model.WithSystem(t.Context(), "test"), old, nil))

	defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error {
		return errors.New("audit store down")
	})()
	since := auditMaxID(t)

	t.Run("create", func(t *testing.T) {
		repoRows := unittest.GetCount(t, &auth_model.AccessTokenResourceRepo{})
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/users/user2/tokens", &api.CreateAccessTokenOption{
			Name: "audit-refused", Scopes: []string{"read:repository"},
			Repositories: []*api.RepoTargetOption{{Owner: "user2", Name: "repo1"}},
		}).AddBasicAuth("user2"), http.StatusInternalServerError)
		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{UID: 2, Name: "audit-refused"})
		assert.Equal(t, repoRows, unittest.GetCount(t, &auth_model.AccessTokenResourceRepo{}), "no repository rows are left")
	})

	t.Run("regenerate", func(t *testing.T) {
		session := loginUser(t, "user2")
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/settings/keys/tokens/regenerate", map[string]string{"id": fmt.Sprint(old.ID)}), http.StatusOK)
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: old.ID, TokenHash: old.TokenHash})
	})

	t.Run("delete", func(t *testing.T) {
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/users/user2/tokens/%d", old.ID)).AddBasicAuth("user2"), http.StatusInternalServerError)
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: old.ID})
	})

	assert.Equal(t, since, auditMaxID(t))
}

func TestAuditClientIP(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	createFrom := func(t *testing.T, remoteAddr, xff, realIP string) *audit_model.Entry {
		t.Helper()
		since := auditMaxID(t)
		req := NewRequestWithJSON(t, "POST", "/api/v1/users/user2/tokens", &api.CreateAccessTokenOption{Name: remoteAddr + xff + realIP, Scopes: []string{"read:user"}}).AddBasicAuth("user2")
		req.RemoteAddr = remoteAddr
		if xff != "" {
			req.SetHeader("X-Forwarded-For", xff)
		}
		if realIP != "" {
			req.SetHeader("X-Real-IP", realIP)
		}
		MakeRequest(t, req, http.StatusCreated)
		return auditOne(t, since, "credential.access_token.created")
	}

	t.Run("client X-Forwarded-For, proxy X-Real-IP", func(t *testing.T) {
		e := createFrom(t, "127.0.0.1:1234", "198.51.100.7", "203.0.113.5")
		assert.Equal(t, "127.0.0.1", e.IP, "the trusted peer, never a header value")
		data := auditData(t, e)
		assert.Equal(t, true, data["ip_ambiguous"])
		assert.Equal(t, []any{"203.0.113.5", "198.51.100.7"}, data["ip_candidates"])
	})

	t.Run("proxy X-Forwarded-For, client X-Real-IP", func(t *testing.T) {
		e := createFrom(t, "127.0.0.1:1234", "203.0.113.5, 198.51.100.8", "not-an-ip")
		assert.Equal(t, "127.0.0.1", e.IP)
		data := auditData(t, e)
		assert.Equal(t, true, data["ip_ambiguous"])
		assert.Equal(t, []any{"198.51.100.8"}, data["ip_candidates"], "only values that parse as IPs")
	})

	t.Run("trusted proxy", func(t *testing.T) {
		e := createFrom(t, "127.0.0.1:1234", "198.51.100.9", "")
		assert.Equal(t, "198.51.100.9", e.IP)
		assert.NotContains(t, e.Data, "ip_ambiguous")
	})

	t.Run("unix socket", func(t *testing.T) {
		// with trusted proxies configured, the proxy middleware reads a unix socket peer as 127.0.0.1 (auditPeer
		// stores "unix" without them, see TestAuditPeer)
		e := createFrom(t, "@", "", "")
		assert.Equal(t, "127.0.0.1", e.IP)
	})
}

func TestAuditCLI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	since := auditMaxID(t)
	_, err := runMainApp("admin", "user", "generate-access-token", "--username", "user2", "--token-name", "audit-cli", "--scopes", "read:user")
	require.NoError(t, err)
	e := auditOne(t, since, "credential.access_token.created")
	assert.Equal(t, audit_model.ActorCLI, e.ActorType)
	assert.Equal(t, audit_model.CredentialCLI, e.CredentialType)
	assert.Empty(t, e.ActorName)
	assert.EqualValues(t, 2, e.SubjectUserID)
}

func TestAuditInstanceStarted(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	conf := filepath.Join(t.TempDir(), "app.ini")
	defer test.MockVariableValue(&setting.CustomConf, conf)()

	started := func(t *testing.T, content string) string {
		t.Helper()
		require.NoError(t, os.WriteFile(conf, []byte(content), 0o600))
		since := auditMaxID(t)
		require.NoError(t, routers.RecordInstanceStarted(t.Context()))
		e := auditOne(t, since, "audit.instance.started")
		assert.Equal(t, audit_model.ActorSystem, e.ActorType)
		assert.Equal(t, "instance", e.ActorName)
		data := auditData(t, e)
		assert.Equal(t, setting.AppVer, data["version"])
		sum := sha256.Sum256([]byte(content))
		assert.Equal(t, hex.EncodeToString(sum[:]), data["config_sha256"])
		return data["config_sha256"].(string)
	}
	assert.NotEqual(t, started(t, "[server]\n"), started(t, "[server]\nDOMAIN = example.org\n"))

	t.Run("insert failure stops the start", func(t *testing.T) {
		defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error {
			return errors.New("audit store down")
		})()
		require.ErrorContains(t, routers.RecordInstanceStarted(t.Context()), "audit store down")
	})
}

func TestAuditRowsOutliveDeletes(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := audit_model.WithSystem(t.Context(), "test")
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	user8 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8})
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

	org := &org_model.Organization{Name: "audit-org"}
	require.NoError(t, org_model.CreateOrganization(ctx, org, user2))
	repo, err := repo_service.CreateRepository(ctx, user2, user2, repo_service.CreateRepoOptions{Name: "audit-repo"})
	require.NoError(t, err)

	since := auditMaxID(t)
	for _, ev := range []audit_model.Event{
		{Action: "audit.exported", SubjectUserID: user8.ID, OwnerID: user8.ID},
		{Action: "audit.exported", OwnerID: org.ID},
		{Action: "audit.exported", OwnerID: user2.ID, RepoID: repo.ID},
	} {
		require.NoError(t, audit_model.Record(ctx, ev))
	}

	require.NoError(t, user_service.DeleteUser(ctx, user8, false))
	require.NoError(t, repo_service.DeleteRepository(ctx, admin, repo, false))
	require.NoError(t, org_service.TrashOrganization(ctx, admin, org))
	require.NoError(t, trash_service.PurgeOrg(ctx, admin, org.ID))
	unittest.AssertNotExistsBean(t, &user_model.User{ID: org.ID})
	unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: repo.ID})

	count, err := db.GetEngine(t.Context()).Where("id > ? AND action = 'audit.exported' AND actor_name = 'test'", since).Count(new(audit_model.Entry))
	require.NoError(t, err)
	assert.EqualValues(t, 3, count)
}
