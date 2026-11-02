// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	actions_model "forgejo.org/models/actions"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	webhook_model "forgejo.org/models/webhook"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	webhook_module "forgejo.org/modules/webhook"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The /orgs/{org}/projects/{id} branch protection, hook, secret and variable APIs. org3 is owned by user2.
func TestAPIProjectSettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := t.Context()
	pay, web := createProjectForKeys(t, 3, "pay"), createProjectForKeys(t, 3, "web")
	foreign := createProjectForKeys(t, 17, "foreign")
	writeScope := []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteOrganization}
	owner := getUserToken(t, "user2", writeScope...)
	admin := getUserToken(t, "user1", writeScope...)
	const orgBase = "/api/v1/orgs/org3"
	projectBase := func(id int64) string { return fmt.Sprintf("%s/projects/%d", orgBase, id) }
	payBase := projectBase(pay.ID)

	do := func(t *testing.T, method, url, token string, body any, status int) *httptest.ResponseRecorder {
		t.Helper()
		var req *RequestWrapper
		if body == nil {
			req = NewRequest(t, method, url)
		} else {
			req = NewRequestWithJSON(t, method, url, body)
		}
		return MakeRequest(t, req.AddTokenAuth(token), status)
	}

	// one row of each kind on the organization, on pay and on web, all with the same names
	for _, base := range []string{orgBase, payBase, projectBase(web.ID)} {
		do(t, "POST", base+"/branch_protections", owner, api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "main"}}, http.StatusCreated)
		do(t, "POST", base+"/hooks", owner, api.CreateHookOption{Type: "forgejo", Config: api.CreateHookOptionConfig{"url": "http://example.com" + strings.TrimPrefix(base, orgBase), "content_type": "json"}, Active: true}, http.StatusCreated)
		do(t, "PUT", base+"/actions/secrets/TOKEN", owner, api.CreateOrUpdateSecretOption{Data: "s3cr3t-value"}, http.StatusCreated)
		do(t, "POST", base+"/actions/variables/COLOR", owner, api.CreateVariableOption{Value: "blue" + strings.TrimPrefix(base, orgBase)}, http.StatusNoContent)
	}
	payRule := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{OrgID: 3, GroupID: pay.ID, RuleName: "main"})
	orgRule := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{OrgID: 3, GroupID: 0, RepoID: 0, RuleName: "main"})
	payHook := unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{OwnerID: 3, GroupID: pay.ID})
	webHook := unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{OwnerID: 3, GroupID: web.ID})
	orgHook := unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{OwnerID: 3, GroupID: 0, URL: "http://example.com"})
	unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{OwnerID: 3, GroupID: pay.ID, Name: "TOKEN"})
	unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{OwnerID: 3, GroupID: pay.ID, Name: "COLOR"})

	t.Run("each level sees only its own rows", func(t *testing.T) {
		var rules []*api.OrgBranchProtection
		DecodeJSON(t, do(t, "GET", orgBase+"/branch_protections", owner, nil, http.StatusOK), &rules)
		require.Len(t, rules, 1)
		DecodeJSON(t, do(t, "GET", payBase+"/branch_protections", owner, nil, http.StatusOK), &rules)
		require.Len(t, rules, 1)
		assert.Equal(t, "main", rules[0].RuleName)

		var hooks []*api.Hook
		DecodeJSON(t, do(t, "GET", orgBase+"/hooks", owner, nil, http.StatusOK), &hooks)
		ids := make([]int64, 0, len(hooks))
		for _, h := range hooks {
			ids = append(ids, h.ID)
		}
		assert.Contains(t, ids, orgHook.ID)
		assert.NotContains(t, ids, payHook.ID)
		assert.NotContains(t, ids, webHook.ID)
		DecodeJSON(t, do(t, "GET", payBase+"/hooks", owner, nil, http.StatusOK), &hooks)
		require.Len(t, hooks, 1)
		assert.Equal(t, payHook.ID, hooks[0].ID)

		var variable api.ActionVariable
		DecodeJSON(t, do(t, "GET", payBase+"/actions/variables/COLOR", owner, nil, http.StatusOK), &variable)
		assert.Equal(t, "blue/projects/"+fmt.Sprint(pay.ID), variable.Data)
		DecodeJSON(t, do(t, "GET", orgBase+"/actions/variables/COLOR", owner, nil, http.StatusOK), &variable)
		assert.Equal(t, "blue", variable.Data)
		var variables []*api.ActionVariable
		DecodeJSON(t, do(t, "GET", payBase+"/actions/variables", owner, nil, http.StatusOK), &variables)
		require.Len(t, variables, 1)
		assert.Equal(t, "blue/projects/"+fmt.Sprint(pay.ID), variables[0].Data)
		DecodeJSON(t, do(t, "GET", orgBase+"/actions/variables", owner, nil, http.StatusOK), &variables)
		require.Len(t, variables, 1)
		assert.Equal(t, "blue", variables[0].Data)

		var secrets []*api.Secret
		DecodeJSON(t, do(t, "GET", payBase+"/actions/secrets", owner, nil, http.StatusOK), &secrets)
		require.Len(t, secrets, 1)
		DecodeJSON(t, do(t, "GET", orgBase+"/actions/secrets", owner, nil, http.StatusOK), &secrets)
		require.Len(t, secrets, 1)
	})

	t.Run("hooks of another level are not found", func(t *testing.T) {
		for _, id := range []int64{orgHook.ID, webHook.ID} {
			url := fmt.Sprintf("%s/hooks/%d", payBase, id)
			do(t, "GET", url, owner, nil, http.StatusNotFound)
			do(t, "PATCH", url, owner, api.EditHookOption{Config: map[string]string{"url": "http://evil.example.com"}}, http.StatusNotFound)
			do(t, "DELETE", url, owner, nil, http.StatusNotFound)
		}
		url := fmt.Sprintf("%s/hooks/%d", orgBase, payHook.ID)
		do(t, "GET", url, owner, nil, http.StatusNotFound)
		do(t, "PATCH", url, owner, api.EditHookOption{Config: map[string]string{"url": "http://evil.example.com"}}, http.StatusNotFound)
		do(t, "DELETE", url, owner, nil, http.StatusNotFound)
		assert.Equal(t, "http://example.com", unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: orgHook.ID}).URL)
		assert.Equal(t, webHook.URL, unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: webHook.ID}).URL)
		assert.Equal(t, payHook.URL, unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: payHook.ID}).URL)

		var hook api.Hook
		DecodeJSON(t, do(t, "PATCH", fmt.Sprintf("%s/hooks/%d", payBase, payHook.ID), owner, api.EditHookOption{Config: map[string]string{"url": "http://pay.example.com"}, Events: []string{"push"}}, http.StatusOK), &hook)
		assert.Equal(t, "http://pay.example.com", hook.URL)
		assert.Equal(t, pay.ID, unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: payHook.ID}).GroupID)
		do(t, "POST", payBase+"/hooks", owner, api.CreateHookOption{Type: "forgejo", Config: api.CreateHookOptionConfig{"url": "not a url", "content_type": "json"}}, http.StatusUnprocessableEntity)
	})

	t.Run("rules of another level are not touched", func(t *testing.T) {
		edit := api.EditOrgBranchProtectionOption{EditBranchProtectionOption: api.EditBranchProtectionOption{EnablePush: new(true)}}
		do(t, "PATCH", payBase+"/branch_protections/main", owner, edit, http.StatusOK)
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: payRule.ID}).CanPush)
		assert.False(t, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: orgRule.ID}).CanPush)
		assert.False(t, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{OrgID: 3, GroupID: web.ID, RuleName: "main"}).CanPush)

		do(t, "GET", payBase+"/branch_protections/other", owner, nil, http.StatusNotFound)
		do(t, "DELETE", payBase+"/branch_protections/other", owner, nil, http.StatusNotFound)
		// a project rule covers the whole project
		selected := api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "release"}, ApplyToSelectedRepos: true, Repos: []string{"repo3"}}
		do(t, "POST", payBase+"/branch_protections", owner, selected, http.StatusUnprocessableEntity)
		do(t, "POST", payBase+"/branch_protections", owner, api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "main"}}, http.StatusForbidden)
		unittest.AssertNotExistsBean(t, &git_model.ProtectedBranch{OrgID: 3, GroupID: pay.ID, RuleName: "release"})
	})

	t.Run("secrets and variables of another level are not touched", func(t *testing.T) {
		do(t, "PUT", payBase+"/actions/secrets/TOKEN", owner, api.CreateOrUpdateSecretOption{Data: "n3w-value"}, http.StatusNoContent)
		do(t, "PUT", payBase+"/actions/variables/COLOR", owner, api.UpdateVariableOption{Value: "red"}, http.StatusNoContent)
		assert.Equal(t, "red", unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{OwnerID: 3, GroupID: pay.ID, Name: "COLOR"}).Data)
		assert.Equal(t, "blue", unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{OwnerID: 3, GroupID: 0, RepoID: 0, Name: "COLOR"}).Data)
		do(t, "POST", payBase+"/actions/variables/COLOR", owner, api.CreateVariableOption{Value: "green"}, http.StatusConflict)

		// writes on the organization never reach the project's row of the same name
		paySecret := unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{OwnerID: 3, GroupID: pay.ID, Name: "TOKEN"})
		do(t, "PUT", orgBase+"/actions/secrets/TOKEN", owner, api.CreateOrUpdateSecretOption{Data: "org-value"}, http.StatusNoContent)
		do(t, "PUT", orgBase+"/actions/variables/COLOR", owner, api.UpdateVariableOption{Value: "orange"}, http.StatusNoContent)
		assert.Equal(t, paySecret.Data, unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{ID: paySecret.ID}).Data)
		assert.Equal(t, "red", unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{OwnerID: 3, GroupID: pay.ID, Name: "COLOR"}).Data)
		assert.Equal(t, "orange", unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{OwnerID: 3, GroupID: 0, RepoID: 0, Name: "COLOR"}).Data)

		do(t, "DELETE", payBase+"/actions/secrets/NONE", owner, nil, http.StatusNotFound)
		do(t, "DELETE", payBase+"/actions/variables/NONE", owner, nil, http.StatusNotFound)
		do(t, "GET", payBase+"/actions/variables/NONE", owner, nil, http.StatusNotFound)
	})

	t.Run("secret values are never in a response", func(t *testing.T) {
		for _, resp := range []*httptest.ResponseRecorder{
			do(t, "PUT", payBase+"/actions/secrets/NEW", owner, api.CreateOrUpdateSecretOption{Data: "s3cr3t-value"}, http.StatusCreated),
			do(t, "PUT", payBase+"/actions/secrets/NEW", owner, api.CreateOrUpdateSecretOption{Data: "n3w-value"}, http.StatusNoContent),
			do(t, "GET", payBase+"/actions/secrets", owner, nil, http.StatusOK),
		} {
			assert.NotContains(t, resp.Body.String(), "s3cr3t-value")
			assert.NotContains(t, resp.Body.String(), "n3w-value")
		}
		do(t, "DELETE", payBase+"/actions/secrets/NEW", owner, nil, http.StatusNoContent)
	})

	urls := func(base string) map[string][2]string {
		return map[string][2]string{
			"rules":     {"GET", base + "/branch_protections"},
			"rule":      {"DELETE", base + "/branch_protections/main"},
			"hooks":     {"GET", base + "/hooks"},
			"hook":      {"DELETE", fmt.Sprintf("%s/hooks/%d", base, payHook.ID)},
			"secrets":   {"GET", base + "/actions/secrets"},
			"secret":    {"DELETE", base + "/actions/secrets/TOKEN"},
			"variables": {"GET", base + "/actions/variables"},
			"variable":  {"DELETE", base + "/actions/variables/COLOR"},
		}
	}
	check := func(t *testing.T, who, token, base string, status int) {
		t.Helper()
		for name, u := range urls(base) {
			resp := MakeRequest(t, NewRequest(t, u[0], u[1]).AddTokenAuth(token), NoExpectedStatus)
			assert.Equal(t, status, resp.Code, "%s %s", who, name)
		}
	}
	rowsLeft := func(t *testing.T) {
		t.Helper()
		unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: payRule.ID})
		unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: payHook.ID})
		unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{OwnerID: 3, GroupID: pay.ID, Name: "TOKEN"})
		unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{OwnerID: 3, GroupID: pay.ID, Name: "COLOR"})
	}

	t.Run("permissions", func(t *testing.T) {
		check(t, "member", getUserToken(t, "user4", writeScope...), payBase, http.StatusForbidden)
		check(t, "other organization's owner", getUserToken(t, "user15", writeScope...), payBase, http.StatusForbidden)
		check(t, "outsider", getUserToken(t, "user8", writeScope...), payBase, http.StatusForbidden)
		check(t, "anonymous", "", payBase, http.StatusUnauthorized)
		check(t, "repo-only token", createFineGrainedRepoAccessToken(t, "user2", writeScope, []int64{3}), payBase, http.StatusForbidden)
		check(t, "public-only token", getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopePublicOnly), payBase, http.StatusForbidden)
		check(t, "no organization scope", getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository), payBase, http.StatusForbidden)
		rowsLeft(t)

		for name, u := range urls(payBase) {
			if u[0] == "GET" {
				assert.Equal(t, http.StatusOK, MakeRequest(t, NewRequest(t, "GET", u[1]).AddTokenAuth(admin), NoExpectedStatus).Code, "site admin %s", name)
			}
		}

		// a token that can't be used on projects is refused before the project is looked up
		for id, status := range map[int64]int{pay.ID: http.StatusForbidden, 999999: http.StatusForbidden} {
			check(t, "public-only token", getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopePublicOnly), projectBase(id), status)
			check(t, "repo-only token", createFineGrainedRepoAccessToken(t, "user2", writeScope, []int64{3}), projectBase(id), status)
			check(t, "non-owner", getUserToken(t, "user4", writeScope...), projectBase(id), status)
		}
		rowsLeft(t)
	})

	t.Run("site admin writes", func(t *testing.T) {
		rule := api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "admin"}}
		do(t, "POST", payBase+"/branch_protections", admin, rule, http.StatusCreated)
		do(t, "PATCH", payBase+"/branch_protections/admin", admin, api.EditOrgBranchProtectionOption{EditBranchProtectionOption: api.EditBranchProtectionOption{EnablePush: new(true)}}, http.StatusOK)
		do(t, "DELETE", payBase+"/branch_protections/admin", admin, nil, http.StatusNoContent)

		var hook api.Hook
		DecodeJSON(t, do(t, "POST", payBase+"/hooks", admin, api.CreateHookOption{Type: "forgejo", Config: api.CreateHookOptionConfig{"url": "http://admin.example.com", "content_type": "json"}}, http.StatusCreated), &hook)
		assert.Equal(t, pay.ID, unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: hook.ID}).GroupID)
		do(t, "PATCH", fmt.Sprintf("%s/hooks/%d", payBase, hook.ID), admin, api.EditHookOption{Events: []string{"push"}}, http.StatusOK)
		do(t, "DELETE", fmt.Sprintf("%s/hooks/%d", payBase, hook.ID), admin, nil, http.StatusNoContent)

		do(t, "PUT", payBase+"/actions/secrets/ADMIN", admin, api.CreateOrUpdateSecretOption{Data: "x"}, http.StatusCreated)
		do(t, "DELETE", payBase+"/actions/secrets/ADMIN", admin, nil, http.StatusNoContent)
		do(t, "POST", payBase+"/actions/variables/ADMIN", admin, api.CreateVariableOption{Value: "x"}, http.StatusNoContent)
		do(t, "PUT", payBase+"/actions/variables/ADMIN", admin, api.UpdateVariableOption{Value: "y"}, http.StatusNoContent)
		assert.Equal(t, "y", unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{OwnerID: 3, GroupID: pay.ID, Name: "ADMIN"}).Data)
		do(t, "DELETE", payBase+"/actions/variables/ADMIN", admin, nil, http.StatusNoContent)
		rowsLeft(t)
	})

	t.Run("an owner blocked by the two-factor requirement", func(t *testing.T) {
		_, err := db.Exec(ctx, "UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
		require.NoError(t, err)
		defer func() {
			_, err := db.Exec(ctx, "UPDATE `user` SET require_two_factor = ? WHERE id = 3", false)
			require.NoError(t, err)
		}()
		check(t, "blocked owner", owner, payBase, http.StatusForbidden)
		rowsLeft(t)
	})

	t.Run("another organization's project or a repository ID is not found", func(t *testing.T) {
		// a repository of org3 whose ID is no project's
		repoID := int64(32)
		require.False(t, unittest.BeanExists(t, &repo_model.RepoGroup{ID: repoID}))
		for _, id := range []int64{foreign.ID, repoID, 999999} {
			check(t, "owner", owner, projectBase(id), http.StatusNotFound)
		}
		rowsLeft(t)
	})

	t.Run("a project whose ID is a repository's", func(t *testing.T) {
		// give a new project the ID of an org3 repository that has its own rule, hook, secret and variable
		var repo *repo_model.Repository
		for _, id := range []int64{3, 5, 32} {
			if !unittest.BeanExists(t, &repo_model.RepoGroup{ID: id}) {
				repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: id, OwnerID: 3})
				break
			}
		}
		require.NotNil(t, repo)
		collide := createProjectForKeys(t, 3, "collide")
		_, err := db.Exec(ctx, "UPDATE repo_group SET id = ? WHERE id = ?", repo.ID, collide.ID)
		require.NoError(t, err)
		require.NoError(t, db.Insert(ctx, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "repo-rule"}))
		repoHook := &webhook_model.Webhook{RepoID: repo.ID, URL: "http://repo.example.com", ContentType: webhook_model.ContentTypeJSON, HookEvent: &webhook_module.HookEvent{PushOnly: true}, IsActive: true, Type: "forgejo"}
		require.NoError(t, webhook_model.CreateWebhook(ctx, repoHook, ""))
		repoSecret, err := secret_model.InsertEncryptedSecret(ctx, 0, 0, repo.ID, "REPO_TOKEN", "x")
		require.NoError(t, err)
		require.NoError(t, db.Insert(ctx, &actions_model.ActionVariable{RepoID: repo.ID, Name: "REPO_VAR", Data: "x"}))

		base := projectBase(repo.ID)
		for _, path := range []string{"/branch_protections", "/hooks", "/actions/secrets", "/actions/variables"} {
			assert.JSONEq(t, "[]", do(t, "GET", base+path, owner, nil, http.StatusOK).Body.String(), path)
		}
		do(t, "GET", base+"/branch_protections/repo-rule", owner, nil, http.StatusNotFound)
		do(t, "DELETE", base+"/branch_protections/repo-rule", owner, nil, http.StatusNotFound)
		do(t, "GET", fmt.Sprintf("%s/hooks/%d", base, repoHook.ID), owner, nil, http.StatusNotFound)
		do(t, "DELETE", fmt.Sprintf("%s/hooks/%d", base, repoHook.ID), owner, nil, http.StatusNotFound)
		do(t, "DELETE", base+"/actions/secrets/REPO_TOKEN", owner, nil, http.StatusNotFound)
		do(t, "GET", base+"/actions/variables/REPO_VAR", owner, nil, http.StatusNotFound)
		do(t, "DELETE", base+"/actions/variables/REPO_VAR", owner, nil, http.StatusNotFound)

		// a write lands on the project, never on the repository
		do(t, "PUT", base+"/actions/secrets/REPO_TOKEN", owner, api.CreateOrUpdateSecretOption{Data: "y"}, http.StatusCreated)
		unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{OwnerID: 3, GroupID: repo.ID, RepoID: 0, Name: "REPO_TOKEN"})
		assert.Equal(t, repoSecret.Data, unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{ID: repoSecret.ID}).Data)
		unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "repo-rule"})
		unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: repoHook.ID})
		unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{RepoID: repo.ID, Name: "REPO_VAR"})
	})

	t.Run("Actions hidden for the organization", func(t *testing.T) {
		require.NoError(t, db.Insert(ctx, &repo_model.OrgUnit{OrgID: 3, Type: unit_model.TypeActions, Disabled: true}))
		defer func() {
			_, err := db.DeleteByBean(ctx, &repo_model.OrgUnit{OrgID: 3, Type: unit_model.TypeActions})
			require.NoError(t, err)
		}()
		for _, path := range []string{"/actions/secrets", "/actions/variables"} {
			orgCode := do(t, "GET", orgBase+path, owner, nil, NoExpectedStatus).Code
			assert.Equal(t, http.StatusNotFound, orgCode)
			assert.Equal(t, orgCode, do(t, "GET", payBase+path, owner, nil, NoExpectedStatus).Code)
		}
		do(t, "PUT", payBase+"/actions/secrets/HIDDEN", owner, api.CreateOrUpdateSecretOption{Data: "x"}, http.StatusNotFound)
		unittest.AssertNotExistsBean(t, &secret_model.Secret{OwnerID: 3, GroupID: pay.ID, Name: "HIDDEN"})
	})

	t.Run("webhooks disabled", func(t *testing.T) {
		defer test.MockVariableValue(&setting.DisableWebhooks, true)()
		do(t, "GET", orgBase+"/hooks", owner, nil, http.StatusForbidden)
		do(t, "GET", payBase+"/hooks", owner, nil, http.StatusForbidden)
		do(t, "POST", payBase+"/hooks", owner, api.CreateHookOption{Type: "forgejo", Config: api.CreateHookOptionConfig{"url": "http://off.example.com", "content_type": "json"}}, http.StatusForbidden)
	})

	t.Run("project delete removes the rows", func(t *testing.T) {
		do(t, "DELETE", payBase, owner, nil, http.StatusNoContent)
		unittest.AssertNotExistsBean(t, &git_model.ProtectedBranch{ID: payRule.ID})
		unittest.AssertNotExistsBean(t, &webhook_model.Webhook{ID: payHook.ID})
		unittest.AssertNotExistsBean(t, &secret_model.Secret{OwnerID: 3, GroupID: pay.ID})
		unittest.AssertNotExistsBean(t, &actions_model.ActionVariable{OwnerID: 3, GroupID: pay.ID})
		unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: orgRule.ID})
		unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: webHook.ID})
		do(t, "GET", payBase+"/hooks", owner, nil, http.StatusNotFound)
	})
}
