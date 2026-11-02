// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	actions_service "forgejo.org/services/actions"
	auth_service "forgejo.org/services/auth"
	"forgejo.org/tests"

	runnerv1 "code.forgejo.org/forgejo/actions-proto/runner/v1"
	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditSince returns every entry written after since, except sign-in, credential and request activity.
func auditSince(t *testing.T, since int64) []*audit_model.Entry {
	t.Helper()
	var entries []*audit_model.Entry
	require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND category NOT IN (?, ?) AND action <> ?", since, audit_model.CategoryAuth, audit_model.CategoryActivity, "audit.chain.started").OrderBy("id").Find(&entries))
	return entries
}

// assertNoSecretIn fails when one of the secrets appears in any text column of an entry written after since.
func assertNoSecretIn(t *testing.T, since int64, secrets ...string) {
	t.Helper()
	var entries []*audit_model.Entry
	require.NoError(t, db.GetEngine(t.Context()).Where("id > ?", since).Find(&entries))
	for _, e := range entries {
		for _, s := range secrets {
			for _, v := range []string{e.Data, e.ActorName, e.CredentialName, e.TargetName, e.UserAgent} {
				assert.NotContains(t, v, s, e.Action)
			}
		}
	}
}

func TestAuditOAuth2App(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	admin := loginUser(t, "user1")

	// web, a user's own app: created + the first secret
	since := auditMaxID(t)
	values := appForm("audit-app")
	values["redirect_uris"] = "https://u:p@example.com/cb?code=x#frag\nhttp://localhost:8080/a/b"
	resp := admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/settings/applications/oauth2", values), http.StatusOK)
	app := unittest.AssertExistsAndLoadBean(t, &auth_model.OAuth2Application{Name: "audit-app"})
	entries := auditSince(t, since)
	require.Len(t, entries, 2)
	assert.Equal(t, "credential.oauth2_app.created", entries[0].Action)
	assert.Equal(t, "credential.oauth2_app.secret_regenerated", entries[1].Action)
	e := entries[0]
	assertSubject(t, e, 1, 1)
	assert.Equal(t, "oauth2_app", e.TargetType)
	assert.Equal(t, app.ID, e.TargetID)
	assert.Equal(t, "audit-app", e.TargetName)
	data := auditData(t, e)
	assert.Equal(t, []any{"https://example.com/cb", "http://localhost:8080/a/b"}, data["redirect_uris"])
	assert.Equal(t, true, data["confidential"])
	assert.NotContains(t, data, "on_behalf")
	secret := NewHTMLParser(t, resp.Body).Find("#client-secret").AttrOr("value", "")
	require.NotEmpty(t, secret)
	assertNoSecretIn(t, since, secret, app.ClientSecret)

	// edit: before/after; a no-op edit records nothing
	edit := fmt.Sprintf("/user/settings/applications/oauth2/%d", app.ID)
	values = appForm("audit-app-renamed")
	since = auditMaxID(t)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", edit, values), http.StatusSeeOther)
	e = auditOne(t, since, "credential.oauth2_app.updated")
	data = auditData(t, e)
	assert.Equal(t, map[string]any{"name": "audit-app", "redirect_uris": []any{"https://example.com/cb", "http://localhost:8080/a/b"}}, data["before"])
	assert.Equal(t, map[string]any{"name": "audit-app-renamed", "redirect_uris": []any{"https://example.com/cb"}}, data["after"])
	since = auditMaxID(t)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", edit, values), http.StatusSeeOther)
	assert.Empty(t, auditSince(t, since))

	// regenerate
	since = auditMaxID(t)
	admin.MakeRequest(t, NewRequest(t, "POST", edit+"/regenerate_secret"), http.StatusOK)
	assert.Contains(t, auditData(t, auditOne(t, since, "credential.oauth2_app.secret_regenerated")), "secret_expires")

	// delete with one grant
	_, err := (&auth_model.OAuth2Application{ID: app.ID}).CreateGrant(asActor(t, 4, "user4"), 4, "openid")
	require.NoError(t, err)
	since = auditMaxID(t)
	admin.MakeRequest(t, NewRequest(t, "POST", edit+"/delete"), http.StatusOK)
	e = auditOne(t, since, "credential.oauth2_app.deleted")
	assert.Equal(t, map[string]any{"grants": float64(1)}, auditData(t, e)["counts"])

	// an organization's app: owner = the org, no subject
	since = auditMaxID(t)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/applications/oauth2", appForm("audit-org-app")), http.StatusOK)
	e = auditActions(t, since, "credential.oauth2_app.created")[0]
	assert.EqualValues(t, 1, e.ActorID)
	assert.EqualValues(t, 3, e.OwnerID)
	assert.Zero(t, e.SubjectUserID)

	// an instance app: no owner
	since = auditMaxID(t)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/applications/oauth2", appForm("audit-instance-app")), http.StatusOK)
	e = auditActions(t, since, "credential.oauth2_app.created")[0]
	assert.Zero(t, e.OwnerID)
	assert.Zero(t, e.SubjectUserID)

	// API
	token := getTokenForLoggedInUser(t, admin, auth_model.AccessTokenScopeWriteUser)
	since = auditMaxID(t)
	var created api.OAuth2Application
	DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/applications/oauth2", &api.CreateOAuth2ApplicationOptions{
		Name: "audit-api-app", RedirectURIs: []string{"https://example.com/api"}, ConfidentialClient: true,
	}).AddTokenAuth(token), http.StatusCreated), &created)
	assert.Len(t, auditActions(t, since, "credential.oauth2_app.created"), 1)
	assert.Len(t, auditActions(t, since, "credential.oauth2_app.secret_regenerated"), 1)
	assertNoSecretIn(t, since, created.ClientSecret)
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/user/applications/oauth2/%d", created.ID), &api.CreateOAuth2ApplicationOptions{
		Name: "audit-api-app2", RedirectURIs: []string{"https://example.com/api"}, ConfidentialClient: true,
	}).AddTokenAuth(token), http.StatusOK)
	assert.Len(t, auditActions(t, since, "credential.oauth2_app.updated"), 1)
	since = auditMaxID(t)
	MakeRequest(t, NewRequestf(t, "DELETE", "/api/v1/user/applications/oauth2/%d", created.ID).AddTokenAuth(token), http.StatusNoContent)
	assert.Equal(t, created.ID, auditOne(t, since, "credential.oauth2_app.deleted").TargetID)
}

func TestAuditOAuth2Grant(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user4")

	since := auditMaxID(t)
	session.MakeRequest(t, NewRequest(t, "GET", "/login/oauth/authorize?client_id=da7da3ba-9a13-4167-856f-3899de0b0138&redirect_uri=a&response_type=code&state=s&scope=openid"), http.StatusOK)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/login/oauth/grant", map[string]string{
		"client_id": "da7da3ba-9a13-4167-856f-3899de0b0138", "redirect_uri": "a", "state": "s", "scope": "openid", "granted": "true",
	}), http.StatusSeeOther)
	e := credentialOne(t, since, "credential.oauth2_grant.created")
	assertSubject(t, e, 4, 4)
	assert.Equal(t, "Test", e.TargetName)
	data := auditData(t, e)
	assert.EqualValues(t, 1, data["app_id"])
	assert.Equal(t, "Test", data["app_name"])
	assert.Equal(t, "openid", data["scopes"])

	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestf(t, "POST", "/user/settings/applications/oauth2/1/revoke/%d", e.TargetID), http.StatusOK)
	assertSubject(t, credentialOne(t, since, "credential.oauth2_grant.revoked"), 4, 4)
	unittest.AssertNotExistsBean(t, &auth_model.OAuth2Grant{ID: e.TargetID})

	// another user's grant: nothing found, nothing recorded
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequest(t, "POST", "/user/settings/applications/oauth2/1/revoke/1"), http.StatusOK)
	assert.Empty(t, auditSince(t, since))
	unittest.AssertExistsAndLoadBean(t, &auth_model.OAuth2Grant{ID: 1})
}

func newAuditIntegration(name string) *auth_model.AuthorizedIntegration {
	ii, _ := auth_service.GetInternalIssuerByURLSuffix("api/actions")
	return &auth_model.AuthorizedIntegration{
		UserID: 2, Name: name, Scope: auth_model.AccessTokenScopeReadRepository, Issuer: ii.IssuerPlaceholder(),
		UI: auth_model.AuthorizedIntegrationUIGeneric,
		ClaimRules: &auth_model.ClaimRules{Rules: []auth_model.ClaimRule{
			{Claim: "repository", Comparison: auth_model.ClaimEqual, Value: "secret-rule-value"},
		}},
	}
}

func TestAuditAuthorizedIntegration(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := asActor(t, 2, "user2")

	since := auditMaxID(t)
	ai := newAuditIntegration("audit-ai")
	require.NoError(t, auth_service.InsertAuthorizedIntegration(ctx, ai, []*auth_model.AuthorizedIntegResourceRepo{{RepoID: 1}}))
	e := credentialOne(t, since, "credential.authorized_integration.created")
	assertSubject(t, e, 2, 2)
	assert.Equal(t, ai.ID, e.TargetID)
	data := auditData(t, e)
	assert.Equal(t, []any{float64(1)}, data["repo_ids"])
	assert.Equal(t, "read:repository", data["scopes"])
	assert.Equal(t, "generic", data["ui"])
	assert.NotContains(t, e.Data, "secret-rule-value")

	since = auditMaxID(t)
	ai.Name = "audit-ai-renamed"
	ai.ClaimRules.Rules[0].Value = "other-rule-value"
	require.NoError(t, auth_service.UpdateAuthorizedIntegration(ctx, ai, []*auth_model.AuthorizedIntegResourceRepo{{RepoID: 1}}))
	e = credentialOne(t, since, "credential.authorized_integration.updated")
	data = auditData(t, e)
	assert.Equal(t, map[string]any{"name": "audit-ai"}, data["before"])
	assert.Equal(t, map[string]any{"name": "audit-ai-renamed"}, data["after"])
	assert.Equal(t, true, data["claim_rules_changed"])
	assert.NotContains(t, e.Data, "rule-value")

	since = auditMaxID(t)
	require.NoError(t, auth_model.DeleteAuthorizedIntegrationByID(ctx, ai.ID, 2))
	assertSubject(t, credentialOne(t, since, "credential.authorized_integration.deleted"), 2, 2)

	// the CLI
	since = auditMaxID(t)
	_, err := runMainApp("admin", "user", "create-authorized-integration", "--username", "user2", "--name", "cli-ai",
		"--issuer", newAuditIntegration("").Issuer, "--scope", "read:user")
	require.NoError(t, err)
	e = credentialOne(t, since, "credential.authorized_integration.created")
	assert.Equal(t, audit_model.ActorCLI, e.ActorType)
	assert.EqualValues(t, 2, e.SubjectUserID)
}

func TestAuditRunnerWeb(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	base := "/user2/repo1/settings/actions/runners"

	since := auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/new", map[string]string{"runner_name": "audit-runner"}), http.StatusOK)
	runner := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunner{Name: "audit-runner"})
	e := credentialOne(t, since, "credential.runner.registered")
	assert.EqualValues(t, 2, e.ActorID)
	assert.EqualValues(t, 2, e.OwnerID)
	assert.EqualValues(t, 1, e.RepoID)
	assert.Zero(t, e.SubjectUserID)
	assert.Equal(t, "runner", e.TargetType)
	assert.Equal(t, runner.ID, e.TargetID)
	assert.Equal(t, "repo", auditData(t, e)["level"])

	edit := fmt.Sprintf("%s/%d/edit", base, runner.ID)
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", edit, map[string]string{"runner_name": "audit-runner2"}), http.StatusSeeOther)
	data := auditData(t, credentialOne(t, since, "credential.runner.updated"))
	assert.Equal(t, map[string]any{"name": "audit-runner"}, data["before"])
	assert.Equal(t, map[string]any{"name": "audit-runner2"}, data["after"])

	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", edit, map[string]string{"runner_name": "audit-runner2", "runner_description": "only text"}), http.StatusSeeOther)
	assert.Empty(t, auditSince(t, since))

	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", edit, map[string]string{"runner_name": "audit-runner2", "regenerate_token": "true"}), http.StatusOK)
	assert.Equal(t, true, auditData(t, credentialOne(t, since, "credential.runner.updated"))["token_reset"])

	since = auditMaxID(t)
	session.MakeRequest(t, NewRequest(t, "GET", base+"/reset_registration_token"), http.StatusSeeOther)
	e = credentialOne(t, since, "credential.runner_token.reset")
	assert.Equal(t, "runner_token", e.TargetType)
	assert.Empty(t, e.TargetName)
	assert.EqualValues(t, 1, e.RepoID)
	token, err := actions_model.GetLatestRunnerToken(t.Context(), optional.None[int64](), optional.Some[int64](1))
	require.NoError(t, err)
	assert.Equal(t, token.ID, e.TargetID)
	assertNoSecretIn(t, since, token.Token)

	// a view while a token is active issues none (Q2)
	apiToken := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/actions/runners/registration-token").AddTokenAuth(apiToken), http.StatusOK)
	assert.Empty(t, auditSince(t, since))

	since = auditMaxID(t)
	session.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("%s/%d/delete", base, runner.ID)), http.StatusOK)
	assert.Equal(t, runner.ID, credentialOne(t, since, "credential.runner.deleted").TargetID)
}

func TestAuditRunnerAPIAndPrivate(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)

	// a repository in a project: the scope comes from the repository row
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	group, err := repo_model.CreateRepoGroup(t.Context(), org, "audit-runner-project", "")
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Exec("UPDATE repository SET group_id = ? WHERE id = 3", group.ID)
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &repo_model.RepoUnit{RepoID: 3, Type: unit.TypeActions}))
	since := auditMaxID(t)
	var inProject api.RegisterRunnerResponse
	DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repositories/3/actions/runners", &api.RegisterRunnerOptions{Name: "in-project"}).
		AddTokenAuth(token), http.StatusCreated), &inProject)
	e := credentialOne(t, since, "credential.runner.registered")
	assert.EqualValues(t, 3, e.OwnerID)
	assert.Equal(t, group.ID, e.GroupID)
	assert.EqualValues(t, 3, e.RepoID)

	since = auditMaxID(t)
	var created api.RegisterRunnerResponse
	DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/actions/runners", &api.RegisterRunnerOptions{Name: "api-runner"}).
		AddTokenAuth(token), http.StatusCreated), &created)
	e = credentialOne(t, since, "credential.runner.registered")
	assert.EqualValues(t, 2, e.ActorID)
	assert.EqualValues(t, 1, e.RepoID)
	assertNoSecretIn(t, since, created.Token)
	since = auditMaxID(t)
	MakeRequest(t, NewRequestf(t, "DELETE", "/api/v1/repos/user2/repo1/actions/runners/%d", created.ID).AddTokenAuth(token), http.StatusNoContent)
	assert.Equal(t, created.ID, credentialOne(t, since, "credential.runner.deleted").TargetID)

	// the private route keeps the system actor (forgejo actions generate-runner-token)
	_, err = db.GetEngine(t.Context()).Exec("UPDATE action_runner_token SET is_active = ?", false)
	require.NoError(t, err)
	since = auditMaxID(t)
	text, extra := private.GenerateActionsRunnerToken(t.Context(), "user2")
	require.NoError(t, extra.Error)
	e = credentialOne(t, since, "credential.runner_token.reset")
	assert.Equal(t, audit_model.ActorSystem, e.ActorType)
	assert.EqualValues(t, 2, e.OwnerID)
	assert.Equal(t, "user", auditData(t, e)["level"])
	assertNoSecretIn(t, since, text.Text)
}

func TestAuditRunnerRPC(t *testing.T) {
	if !setting.Database.Type.IsSQLite3() {
		t.Skip()
	}
	defer unittest.OverrideFixtures("tests/integration/fixtures/TestEphemeralRunner")()
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		session := loginUser(t, "user2")
		apiToken := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		registrationToken := func(t *testing.T) (*actions_model.ActionRunnerToken, string) {
			var resp struct {
				Token string `json:"token"`
			}
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/actions/runners/registration-token").AddTokenAuth(apiToken), http.StatusOK), &resp)
			row, err := actions_model.GetRunnerToken(t.Context(), resp.Token)
			require.NoError(t, err)
			return row, resp.Token
		}

		t.Run("register", func(t *testing.T) {
			row, regToken := registrationToken(t)
			since := auditMaxID(t)
			runner := newMockRunner()
			runner.doRegister(t, "rpc-runner", regToken, []string{"ubuntu", "docker"})
			e := credentialOne(t, since, "credential.runner.registered")
			assert.Equal(t, audit_model.ActorAnonymous, e.ActorType)
			assert.Equal(t, "runner_token", e.CredentialType)
			assert.Equal(t, row.ID, e.CredentialID)
			assert.EqualValues(t, 2, e.CredentialOwnerID)
			assert.Empty(t, e.CredentialName)
			assert.EqualValues(t, 2, e.OwnerID)
			assert.EqualValues(t, 1, e.RepoID)
			assert.Equal(t, []any{"ubuntu", "docker"}, auditData(t, e)["labels"])
			assertNoSecretIn(t, since, regToken, runner.token)

			// labels and version a runner reports are not recorded (S5)
			since = auditMaxID(t)
			_, err := runner.client.runnerServiceClient.Declare(t.Context(), connect.NewRequest(&runnerv1.DeclareRequest{Version: "v2", Labels: []string{"other"}}))
			require.NoError(t, err)
			assert.Empty(t, auditSince(t, since))
		})

		t.Run("ambiguous client IP", func(t *testing.T) {
			_, regToken := registrationToken(t)
			since := auditMaxID(t)
			req := connect.NewRequest(&runnerv1.RegisterRequest{Name: "ambiguous", Token: regToken})
			req.Header().Set("X-Forwarded-For", "198.51.100.7")
			req.Header().Set("X-Real-IP", "203.0.113.5")
			_, err := newMockRunnerClient("", "").runnerServiceClient.Register(t.Context(), req)
			require.NoError(t, err)
			e := credentialOne(t, since, "credential.runner.registered")
			assert.Equal(t, "127.0.0.1", e.IP)
			assert.Equal(t, true, auditData(t, e)["ip_ambiguous"])
		})

		t.Run("bad token", func(t *testing.T) {
			since := auditMaxID(t)
			_, err := newMockRunnerClient("", "").runnerServiceClient.Register(t.Context(),
				connect.NewRequest(&runnerv1.RegisterRequest{Name: "bad", Token: "not-a-token"}))
			require.Error(t, err)
			assert.Empty(t, auditSince(t, since))
		})

		t.Run("ephemeral runner finishing its task", func(t *testing.T) {
			runner, err := actions_model.GetRunnerByID(t.Context(), 10000008)
			require.NoError(t, err)
			since := auditMaxID(t)
			// the token is in models/fixtures/action_runner.yml, id 10000008
			_, err = newMockRunnerClient(runner.UUID, "mysuuupersecrettoekn").runnerServiceClient.UpdateTask(t.Context(),
				connect.NewRequest(&runnerv1.UpdateTaskRequest{State: &runnerv1.TaskState{Id: 10054, Result: runnerv1.Result_RESULT_SUCCESS}}))
			require.NoError(t, err)
			e := credentialOne(t, since, "credential.runner.deleted")
			assert.Equal(t, "runner", e.ActorType)
			assert.Equal(t, runner.ID, e.ActorID)
			assert.Equal(t, "runner", e.CredentialType)
			assert.Equal(t, "ephemeral", auditData(t, e)["reason"])
			assertNoSecretIn(t, since, "mysuuupersecrettoekn")
		})

		t.Run("owner in the trash", func(t *testing.T) {
			token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteOrganization)
			var created api.RegisterRunnerResponse
			DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/actions/runners", &api.RegisterRunnerOptions{Name: "org-runner"}).
				AddTokenAuth(token), http.StatusCreated), &created)
			_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET trashed_unix = 1 WHERE id = 3")
			require.NoError(t, err)
			defer func() {
				_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET trashed_unix = 0 WHERE id = 3")
				require.NoError(t, err)
			}()
			since := auditMaxID(t)
			_, err = newMockRunnerClient(created.UUID, created.Token).runnerServiceClient.UpdateTask(t.Context(),
				connect.NewRequest(&runnerv1.UpdateTaskRequest{State: &runnerv1.TaskState{Id: 10054}}))
			assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
			var n int64
			n, err = db.GetEngine(t.Context()).Where("id > ? AND actor_type = ?", since, "runner").Count(new(audit_model.Entry))
			require.NoError(t, err)
			assert.Zero(t, n)
		})
	})
}

func TestAuditRunnerCleanup(t *testing.T) {
	defer unittest.OverrideFixtures("tests/integration/fixtures/TestEphemeralRunner")()
	defer tests.PrepareTestEnv(t)()
	ctx := audit_model.WithSystem(t.Context(), "cron:cleanup_offline_runners")

	var offline []int64
	require.NoError(t, db.GetEngine(t.Context()).Table("action_runner").Where("last_online > 0 AND last_online < ?", 1716104432).Cols("id").Find(&offline))
	require.NotEmpty(t, offline)
	since := auditMaxID(t)
	require.NoError(t, actions_service.CleanupOfflineRunners(ctx, actions_model.RunnerOfflineTime, false))
	entries := auditActions(t, since, "credential.runner.deleted")
	ids := make([]int64, 0, len(entries))
	for _, e := range entries {
		assert.Equal(t, audit_model.ActorSystem, e.ActorType)
		assert.Equal(t, "offline", auditData(t, e)["reason"])
		ids = append(ids, e.TargetID)
	}
	assert.Subset(t, ids, offline)

	// an ephemeral runner whose task is done
	_, err := db.GetEngine(t.Context()).Exec("UPDATE action_task SET status = ? WHERE id = 10054", actions_model.StatusSuccess)
	require.NoError(t, err)
	since = auditMaxID(t)
	require.NoError(t, actions_service.CleanupEphemeralRunners(audit_model.WithSystem(t.Context(), "cron:cleanup_ephemeral_runners")))
	e := credentialOne(t, since, "credential.runner.deleted")
	assert.EqualValues(t, 10000008, e.TargetID)
	assert.Equal(t, "ephemeral", auditData(t, e)["reason"])

	// an organization's ephemeral runner that picked a task of a deleted repository (Q6)
	_, err = db.GetEngine(t.Context()).Exec("UPDATE action_task SET runner_id = 10000013 WHERE id = 10055")
	require.NoError(t, err)
	since = auditMaxID(t)
	require.NoError(t, actions_service.CleanupEphemeralRunnersByPickedTaskOfRepo(asActor(t, 2, "user2"), 64))
	var org *audit_model.Entry
	for _, e := range auditActions(t, since, "credential.runner.deleted") {
		if e.TargetID == 10000013 {
			org = e
		}
	}
	require.NotNil(t, org)
	assert.EqualValues(t, 3, org.OwnerID)
	data := auditData(t, org)
	assert.Equal(t, "ephemeral", data["reason"])
	assert.Equal(t, "org", data["level"])
	unittest.AssertNotExistsBean(t, &actions_model.ActionRunner{ID: 10000013})
}

func TestAuditOAuthRunnerFailClosed(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := asActor(t, 2, "user2")
	defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error {
		return errors.New("audit down")
	})()

	_, err := auth_model.CreateOAuth2Application(ctx, auth_model.CreateOAuth2ApplicationOptions{Name: "fail-app", UserID: 2, RedirectURIs: []string{"https://example.com"}})
	require.Error(t, err)
	unittest.AssertNotExistsBean(t, &auth_model.OAuth2Application{Name: "fail-app"})

	require.Error(t, auth_model.RevokeOAuth2Grant(ctx, 1, 1))
	unittest.AssertExistsAndLoadBean(t, &auth_model.OAuth2Grant{ID: 1})

	require.Error(t, auth_service.InsertAuthorizedIntegration(ctx, newAuditIntegration("fail-ai"), nil))
	unittest.AssertNotExistsBean(t, &auth_model.AuthorizedIntegration{Name: "fail-ai"})

	runner := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunner{ID: 12345678})
	require.Error(t, actions_model.DeleteRunner(ctx, runner))
	unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunner{ID: 12345678, UUID: "37653537-3765-3537-3765-353737653537"})

	before := unittest.GetCount(t, &actions_model.ActionRunnerToken{})
	_, err = actions_model.NewRunnerToken(ctx, optional.Some[int64](2), optional.None[int64]())
	require.Error(t, err)
	assert.Equal(t, before, unittest.GetCount(t, &actions_model.ActionRunnerToken{}))
}
