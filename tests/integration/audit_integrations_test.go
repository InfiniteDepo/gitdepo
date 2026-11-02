// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	webhook_model "forgejo.org/models/webhook"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	webhook_module "forgejo.org/modules/webhook"
	actions_service "forgejo.org/services/actions"
	migrations_allowlist "forgejo.org/services/migrations/allowlist"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scopedOne returns the one entry of action written after since, and checks its category and owner/project scope.
func scopedOne(t *testing.T, since int64, action, category string, ownerID, groupID int64) *audit_model.Entry {
	t.Helper()
	entries := auditActions(t, since, action)
	require.Len(t, entries, 1, action)
	assert.Equal(t, category, entries[0].Category, action)
	assert.Equal(t, ownerID, entries[0].OwnerID, action)
	assert.Equal(t, groupID, entries[0].GroupID, action)
	return entries[0]
}

// assertNoSecrets checks that no column of any entry written after since holds one of secrets.
func assertNoSecrets(t *testing.T, since int64, secrets ...string) {
	t.Helper()
	var entries []*audit_model.Entry
	require.NoError(t, db.GetEngine(t.Context()).Where("id > ?", since).Find(&entries))
	require.NotEmpty(t, entries)
	for _, e := range entries {
		row, err := json.Marshal(e)
		require.NoError(t, err)
		for _, s := range secrets {
			assert.NotContains(t, string(row), s, e.Action)
		}
	}
}

func newAuditProject(t *testing.T, token string) int64 {
	t.Helper()
	resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/projects", &api.CreateProjectOption{Name: "audit-proj"}).AddTokenAuth(token), http.StatusCreated)
	var project struct{ ID int64 }
	DecodeJSON(t, resp, &project)
	return project.ID
}

func TestAuditPushMirrors(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Migrations.AllowLocalNetworks, true)()
	defer test.MockVariableValue(&setting.Migrations.AllowUnencrypted, true)()
	defer test.MockVariableValue(&setting.Mirror.Enabled, true)()
	require.NoError(t, migrations_allowlist.Init())
	repo := loadRepo(t, "user2", "repo1")
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	start := auditMaxID(t)
	address := "http://127.0.0.1:1/team/x.git?token=t0ken"

	// created on the web: the origin only, and that credentials were given
	since := auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings", map[string]string{
		"action": "push-mirror-add", "push_mirror_address": address, "push_mirror_username": "alice",
		"push_mirror_password": "s3cr3t-pass", "push_mirror_interval": "0",
	}), http.StatusSeeOther)
	data := auditData(t, repoOne(t, since, "repo.push_mirror.created", repo))
	assert.Equal(t, "http://127.0.0.1:1", data["address"])
	assert.Equal(t, true, data["credentials_set"])
	m := unittest.AssertExistsAndLoadBean(t, &repo_model.PushMirror{RepoID: repo.ID})

	// changed: one entry with the changed settings; the same save, and the sync it queues, record nothing
	update := map[string]string{
		"action": "push-mirror-update", "push_mirror_id": strconv.FormatInt(m.ID, 10), "push_mirror_interval": "8h",
		"push_mirror_branch_filter": "main",
	}
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings", update), http.StatusSeeOther)
	assert.Equal(t, map[string]any{"interval": "8h0m0s", "branch_filter": "main"}, auditData(t, repoOne(t, since, "repo.push_mirror.updated", repo))["after"])
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings", update), http.StatusSeeOther)
	m = unittest.AssertExistsAndLoadBean(t, &repo_model.PushMirror{ID: m.ID})
	require.NoError(t, repo_model.UpdatePushMirror(asActor(t, 2, "user2"), m))
	assert.Empty(t, auditActions(t, since, "repo.push_mirror.updated"))

	// sync now, on the web and the API
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings", map[string]string{
		"action": "push-mirror-sync", "push_mirror_id": strconv.FormatInt(m.ID, 10),
	}), http.StatusSeeOther)
	repoOne(t, since, "repo.push_mirror.sync_requested", repo)

	// created on the API
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/push_mirrors", &api.CreatePushMirrorOption{
		RemoteAddress: address, RemoteUsername: "alice", RemotePassword: "s3cr3t-pass", Interval: "0",
	}).AddTokenAuth(token), http.StatusOK)
	e := repoOne(t, since, "repo.push_mirror.created", repo)
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "POST", "/api/v1/repos/user2/repo1/push_mirrors-sync").AddTokenAuth(token), NoExpectedStatus)
	assert.NotEmpty(t, auditActions(t, since, "repo.push_mirror.sync_requested"))

	// deleted, on the API and the web
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/push_mirrors/"+e.TargetName).AddTokenAuth(token), http.StatusNoContent)
	repoOne(t, since, "repo.push_mirror.deleted", repo)
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings", map[string]string{
		"action": "push-mirror-remove", "push_mirror_id": strconv.FormatInt(m.ID, 10), "push_mirror_interval": "0",
	}), http.StatusSeeOther)
	repoOne(t, since, "repo.push_mirror.deleted", repo)

	assertNoSecrets(t, start, "alice", "s3cr3t-pass", "t0ken", "/team/")
}

func TestAuditGitHooks(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.DisableGitHooks, false)()
	repo := loadRepo(t, "user2", "repo1")
	session := loginUser(t, "user1")
	start := auditMaxID(t)
	form := map[string]string{"content": "#!/bin/sh\necho hook-body-xyz\n"}

	since := auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/hooks/git/pre-receive", form), http.StatusSeeOther)
	assert.Equal(t, map[string]any{"name": "pre-receive", "active": true}, auditData(t, repoOne(t, since, "repo.git_hook.updated", repo)))
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/hooks/git/pre-receive", form), http.StatusSeeOther)
	assert.Empty(t, auditActions(t, since, "repo.git_hook.updated"), "an unchanged save")

	// the API removes it
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/hooks/git/pre-receive").AddTokenAuth(token), http.StatusNoContent)
	assert.Equal(t, map[string]any{"name": "pre-receive", "active": false}, auditData(t, repoOne(t, since, "repo.git_hook.updated", repo)))

	assertNoSecrets(t, start, "hook-body-xyz")
}

func TestAuditWebhooks(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	repo := loadRepo(t, "user2", "repo1")
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeAll)
	start := auditMaxID(t)
	hook := func(url string) *api.CreateHookOption {
		return &api.CreateHookOption{
			Type: "forgejo", Active: true, AuthorizationHeader: "Bearer auth-t0ken",
			Config: api.CreateHookOptionConfig{"url": url, "content_type": "json", "secret": "hook-s3cret"},
		}
	}
	create := func(path string) int64 {
		resp := MakeRequest(t, NewRequestWithJSON(t, "POST", path, hook("http://hooks.example.com/p/q?tok=t0ken")).AddTokenAuth(token), http.StatusCreated)
		var h api.Hook
		DecodeJSON(t, resp, &h)
		return h.ID
	}
	edit := func(path string) {
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", path, &api.EditHookOption{Config: map[string]string{"url": "http://hooks.example.com/other"}}).AddTokenAuth(token), http.StatusOK)
	}

	// repository: the origin only, whether a secret and a header were set, and on update whether they changed
	since := auditMaxID(t)
	id := create("/api/v1/repos/user2/repo1/hooks")
	data := auditData(t, repoOne(t, since, "repo.webhook.created", repo))
	assert.Equal(t, "http://hooks.example.com", data["origin"])
	assert.Equal(t, true, data["secret_set"])
	assert.Equal(t, true, data["authorization_set"])
	since = auditMaxID(t)
	edit(fmt.Sprintf("/api/v1/repos/user2/repo1/hooks/%d", id))
	data = auditData(t, repoOne(t, since, "repo.webhook.updated", repo))
	assert.Equal(t, true, data["url_changed"])
	assert.Equal(t, false, data["secret_changed"])
	assert.Equal(t, true, data["authorization_changed"], "a PATCH without a header clears it")
	assert.Nil(t, data["before"], "the origin is unchanged")
	w := unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: id})
	since = auditMaxID(t)
	require.NoError(t, webhook_model.UpdateWebhook(asActor(t, 2, "user2"), w, false, false))
	assert.Empty(t, auditActions(t, since, "repo.webhook.updated"), "an unchanged save")
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/repos/user2/repo1/hooks/%d", id)).AddTokenAuth(token), http.StatusNoContent)
	repoOne(t, since, "repo.webhook.deleted", repo)

	// organization and project
	since = auditMaxID(t)
	id = create("/api/v1/orgs/org3/hooks")
	scopedOne(t, since, "org.webhook.created", audit_model.CategoryOrg, 3, 0)
	since = auditMaxID(t)
	edit(fmt.Sprintf("/api/v1/orgs/org3/hooks/%d", id))
	scopedOne(t, since, "org.webhook.updated", audit_model.CategoryOrg, 3, 0)
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/orgs/org3/hooks/%d", id)).AddTokenAuth(token), http.StatusNoContent)
	scopedOne(t, since, "org.webhook.deleted", audit_model.CategoryOrg, 3, 0)
	project := newAuditProject(t, token)
	since = auditMaxID(t)
	id = create(fmt.Sprintf("/api/v1/orgs/org3/projects/%d/hooks", project))
	scopedOne(t, since, "org.webhook.created", audit_model.CategoryOrg, 3, project)
	since = auditMaxID(t)
	edit(fmt.Sprintf("/api/v1/orgs/org3/projects/%d/hooks/%d", project, id))
	scopedOne(t, since, "org.webhook.updated", audit_model.CategoryOrg, 3, project)
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/orgs/org3/projects/%d/hooks/%d", project, id)).AddTokenAuth(token), http.StatusNoContent)
	scopedOne(t, since, "org.webhook.deleted", audit_model.CategoryOrg, 3, project)

	// user
	since = auditMaxID(t)
	id = create("/api/v1/user/hooks")
	assert.EqualValues(t, 2, scopedOne(t, since, "account.webhook.created", audit_model.CategoryAccount, 2, 0).SubjectUserID)
	since = auditMaxID(t)
	edit(fmt.Sprintf("/api/v1/user/hooks/%d", id))
	scopedOne(t, since, "account.webhook.updated", audit_model.CategoryAccount, 2, 0)
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/user/hooks/%d", id)).AddTokenAuth(token), http.StatusNoContent)
	scopedOne(t, since, "account.webhook.deleted", audit_model.CategoryAccount, 2, 0)

	// instance: system and default hooks; a repository created with a default hook counts it, unrecorded
	ctx := asActor(t, 1, "user1")
	system := &webhook_model.Webhook{URL: "http://hooks.example.com/sys", IsSystemWebhook: true, Type: "forgejo", ContentType: webhook_model.ContentTypeJSON, HookEvent: &webhook_module.HookEvent{PushOnly: true}}
	require.NoError(t, system.UpdateEvent())
	since = auditMaxID(t)
	require.NoError(t, webhook_model.CreateWebhook(ctx, system, ""))
	assert.Equal(t, "system", auditData(t, scopedOne(t, since, "admin.webhook.created", audit_model.CategoryAdmin, 0, 0))["kind"])
	system.IsActive = true
	since = auditMaxID(t)
	require.NoError(t, webhook_model.UpdateWebhook(ctx, system, false, false))
	scopedOne(t, since, "admin.webhook.updated", audit_model.CategoryAdmin, 0, 0)
	def := &webhook_model.Webhook{URL: "http://hooks.example.com/def", Type: "forgejo", ContentType: webhook_model.ContentTypeJSON, HookEvent: &webhook_module.HookEvent{PushOnly: true}}
	require.NoError(t, def.UpdateEvent())
	require.NoError(t, webhook_model.CreateWebhook(ctx, def, ""))
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "audit-defhook"}).AddTokenAuth(token), http.StatusCreated)
	assert.Empty(t, auditActions(t, since, "repo.webhook.created"))
	assert.Equal(t, map[string]any{"webhooks": float64(1)}, auditData(t, auditOne(t, since, "repo.repository.created"))["counts"])
	since = auditMaxID(t)
	require.NoError(t, webhook_model.DeleteDefaultSystemWebhook(ctx, def.ID))
	assert.Equal(t, "default", auditData(t, scopedOne(t, since, "admin.webhook.deleted", audit_model.CategoryAdmin, 0, 0))["kind"])

	assertNoSecrets(t, start, "hook-s3cret", "auth-t0ken", "t0ken", "/p/q", "/other")
}

func TestAuditBranchRules(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	repo := loadRepo(t, "user2", "repo1")
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeAll)
	approvals := func(n int64) *int64 { return &n }

	// repository: created, changed fields only, an unchanged save records nothing, deleted
	since := auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branch_protections", &api.CreateBranchProtectionOption{RuleName: "audit", RequiredApprovals: 1}).AddTokenAuth(token), http.StatusCreated)
	assert.Equal(t, "audit", auditData(t, repoOne(t, since, "repo.branch_protection.created", repo))["rule_name"])
	since = auditMaxID(t)
	edit := &api.EditBranchProtectionOption{RequiredApprovals: approvals(2)}
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/branch_protections/audit", edit).AddTokenAuth(token), http.StatusOK)
	data := auditData(t, repoOne(t, since, "repo.branch_protection.updated", repo))
	assert.Equal(t, map[string]any{"required_approvals": float64(1)}, data["before"])
	assert.Equal(t, map[string]any{"required_approvals": float64(2)}, data["after"])
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/branch_protections/audit", edit).AddTokenAuth(token), http.StatusOK)
	assert.Empty(t, auditActions(t, since, "repo.branch_protection.updated"))
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/branch_protections/audit").AddTokenAuth(token), http.StatusNoContent)
	repoOne(t, since, "repo.branch_protection.deleted", repo)

	// organization and project
	since = auditMaxID(t)
	org := &api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "audit"}}
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/branch_protections", org).AddTokenAuth(token), http.StatusCreated)
	scopedOne(t, since, "org.branch_protection.created", audit_model.CategoryOrg, 3, 0)
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/org3/branch_protections/audit", &api.EditOrgBranchProtectionOption{EditBranchProtectionOption: *edit}).AddTokenAuth(token), http.StatusOK)
	assert.Equal(t, map[string]any{"required_approvals": float64(2)}, auditData(t, scopedOne(t, since, "org.branch_protection.updated", audit_model.CategoryOrg, 3, 0))["after"])
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/orgs/org3/branch_protections/audit").AddTokenAuth(token), http.StatusNoContent)
	scopedOne(t, since, "org.branch_protection.deleted", audit_model.CategoryOrg, 3, 0)
	project := newAuditProject(t, token)
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/orgs/org3/projects/%d/branch_protections", project), org).AddTokenAuth(token), http.StatusCreated)
	scopedOne(t, since, "org.branch_protection.created", audit_model.CategoryOrg, 3, project)
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/orgs/org3/projects/%d/branch_protections/audit", project), &api.EditOrgBranchProtectionOption{EditBranchProtectionOption: *edit}).AddTokenAuth(token), http.StatusOK)
	data = auditData(t, scopedOne(t, since, "org.branch_protection.updated", audit_model.CategoryOrg, 3, project))
	assert.Equal(t, map[string]any{"required_approvals": float64(2)}, data["after"])
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/orgs/org3/projects/%d/branch_protections/audit", project)).AddTokenAuth(token), http.StatusNoContent)
	scopedOne(t, since, "org.branch_protection.deleted", audit_model.CategoryOrg, 3, project)

	// tag rules
	since = auditMaxID(t)
	resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/tag_protections", &api.CreateTagProtectionOption{NamePattern: "v*", WhitelistUsernames: []string{"user2"}}).AddTokenAuth(token), http.StatusCreated)
	var tag api.TagProtection
	DecodeJSON(t, resp, &tag)
	repoOne(t, since, "repo.tag_protection.created", repo)
	pattern := "v1*"
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/user2/repo1/tag_protections/%d", tag.ID), &api.EditTagProtectionOption{NamePattern: &pattern}).AddTokenAuth(token), http.StatusOK)
	assert.Equal(t, map[string]any{"name_pattern": "v1*"}, auditData(t, repoOne(t, since, "repo.tag_protection.updated", repo))["after"])
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/user2/repo1/tag_protections/%d", tag.ID), &api.EditTagProtectionOption{NamePattern: &pattern}).AddTokenAuth(token), http.StatusOK)
	assert.Empty(t, auditActions(t, since, "repo.tag_protection.updated"), "an unchanged save")
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/repos/user2/repo1/tag_protections/%d", tag.ID)).AddTokenAuth(token), http.StatusNoContent)
	repoOne(t, since, "repo.tag_protection.deleted", repo)

	// push rules
	ctx := asActor(t, 2, "user2")
	since = auditMaxID(t)
	require.NoError(t, git_model.UpsertPushRule(ctx, &git_model.PushRule{RepoID: repo.ID, BranchNameRegex: "^f", PRTitleRegex: "^T"}))
	assert.Equal(t, "^T", auditData(t, repoOne(t, since, "repo.push_rule.created", repo))["pr_title_regex"])
	since = auditMaxID(t)
	require.NoError(t, git_model.UpsertPushRule(ctx, &git_model.PushRule{RepoID: repo.ID, BranchNameRegex: "^f", PRTitleRegex: "^T"}))
	assert.Empty(t, auditActions(t, since, "repo.push_rule.updated"))
	require.NoError(t, git_model.UpsertPushRule(ctx, &git_model.PushRule{RepoID: repo.ID, BranchNameRegex: "^f", PRTitleRegex: "^T", MaxFileSizeMB: 5}))
	assert.Equal(t, map[string]any{"max_file_size_mb": float64(5)}, auditData(t, repoOne(t, since, "repo.push_rule.updated", repo))["after"])
}

func TestAuditActionsSecretsVariables(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	repo := loadRepo(t, "user2", "repo1")
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeAll)
	start := auditMaxID(t)

	for _, level := range []struct {
		path, category string
		owner          int64
		// secret created, updated, deleted; variable created, updated, deleted
		actions [6]string
	}{
		{"/api/v1/repos/user2/repo1", audit_model.CategoryRepo, 2, [6]string{
			"repo.actions_secret.created", "repo.actions_secret.updated", "repo.actions_secret.deleted",
			"repo.actions_variable.created", "repo.actions_variable.updated", "repo.actions_variable.deleted",
		}},
		{"/api/v1/orgs/org3", audit_model.CategoryOrg, 3, [6]string{
			"org.actions_secret.created", "org.actions_secret.updated", "org.actions_secret.deleted",
			"org.actions_variable.created", "org.actions_variable.updated", "org.actions_variable.deleted",
		}},
		{"/api/v1/user", audit_model.CategoryAccount, 2, [6]string{
			"account.actions_secret.created", "account.actions_secret.updated", "account.actions_secret.deleted",
			"account.actions_variable.created", "account.actions_variable.updated", "account.actions_variable.deleted",
		}},
	} {
		t.Run(level.category, func(t *testing.T) {
			one := func(since int64, action string) map[string]any {
				return auditData(t, scopedOne(t, since, action, level.category, level.owner, 0))
			}
			since := auditMaxID(t)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", level.path+"/actions/secrets/AUDIT_S", &api.CreateOrUpdateSecretOption{Data: "s3cret-value-1"}).AddTokenAuth(token), http.StatusCreated)
			assert.Equal(t, map[string]any{"name": "AUDIT_S"}, one(since, level.actions[0]))
			since = auditMaxID(t)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", level.path+"/actions/secrets/AUDIT_S", &api.CreateOrUpdateSecretOption{Data: "s3cret-value-2"}).AddTokenAuth(token), http.StatusNoContent)
			assert.Equal(t, map[string]any{"name": "AUDIT_S", "value_changed": true}, one(since, level.actions[1]))
			since = auditMaxID(t)
			MakeRequest(t, NewRequest(t, "DELETE", level.path+"/actions/secrets/AUDIT_S").AddTokenAuth(token), http.StatusNoContent)
			one(since, level.actions[2])

			since = auditMaxID(t)
			MakeRequest(t, NewRequestWithJSON(t, "POST", level.path+"/actions/variables/AUDIT_V", &api.CreateVariableOption{Value: "var-value-1"}).AddTokenAuth(token), http.StatusNoContent)
			one(since, level.actions[3])
			since = auditMaxID(t)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", level.path+"/actions/variables/AUDIT_V", &api.UpdateVariableOption{Name: "AUDIT_V", Value: "var-value-2"}).AddTokenAuth(token), http.StatusNoContent)
			assert.Equal(t, map[string]any{"name": "AUDIT_V", "value_changed": true}, one(since, level.actions[4]))
			since = auditMaxID(t)
			MakeRequest(t, NewRequestWithJSON(t, "PUT", level.path+"/actions/variables/AUDIT_V", &api.UpdateVariableOption{Name: "AUDIT_V", Value: "var-value-2"}).AddTokenAuth(token), http.StatusNoContent)
			assert.Empty(t, auditActions(t, since, level.actions[4]), "an unchanged save")
			since = auditMaxID(t)
			MakeRequest(t, NewRequest(t, "DELETE", level.path+"/actions/variables/AUDIT_V").AddTokenAuth(token), http.StatusNoContent)
			one(since, level.actions[5])
		})
	}
	assert.Equal(t, repo.ID, auditActions(t, start, "repo.actions_secret.created")[0].RepoID)
	assert.Equal(t, int64(2), auditActions(t, start, "account.actions_variable.created")[0].SubjectUserID)

	// project and instance levels
	ctx := asActor(t, 1, "user1")
	project := newAuditProject(t, token)
	since := auditMaxID(t)
	_, err := secret_model.InsertEncryptedSecret(ctx, 3, project, 0, "AUDIT_P", "s3cret-value-3")
	require.NoError(t, err)
	scopedOne(t, since, "org.actions_secret.created", audit_model.CategoryOrg, 3, project)
	base := fmt.Sprintf("/api/v1/orgs/org3/projects/%d/actions", project)
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/secrets/AUDIT_P", &api.CreateOrUpdateSecretOption{Data: "s3cret-value-4"}).AddTokenAuth(token), http.StatusNoContent)
	assert.Equal(t, map[string]any{"name": "AUDIT_P", "value_changed": true}, auditData(t, scopedOne(t, since, "org.actions_secret.updated", audit_model.CategoryOrg, 3, project)))
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", base+"/secrets/AUDIT_P").AddTokenAuth(token), http.StatusNoContent)
	scopedOne(t, since, "org.actions_secret.deleted", audit_model.CategoryOrg, 3, project)
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/variables/AUDIT_PV", &api.CreateVariableOption{Value: "var-value-5"}).AddTokenAuth(token), http.StatusNoContent)
	scopedOne(t, since, "org.actions_variable.created", audit_model.CategoryOrg, 3, project)
	since = auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/variables/AUDIT_PV", &api.UpdateVariableOption{Name: "AUDIT_PV", Value: "var-value-6"}).AddTokenAuth(token), http.StatusNoContent)
	scopedOne(t, since, "org.actions_variable.updated", audit_model.CategoryOrg, 3, project)
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", base+"/variables/AUDIT_PV").AddTokenAuth(token), http.StatusNoContent)
	scopedOne(t, since, "org.actions_variable.deleted", audit_model.CategoryOrg, 3, project)
	since = auditMaxID(t)
	v, err := actions_model.InsertVariable(ctx, 0, 0, 0, "AUDIT_I", "var-value-3")
	require.NoError(t, err)
	scopedOne(t, since, "admin.actions_variable.created", audit_model.CategoryAdmin, 0, 0)
	v.Data = "var-value-4"
	since = auditMaxID(t)
	_, err = actions_model.UpdateVariable(ctx, v)
	require.NoError(t, err)
	scopedOne(t, since, "admin.actions_variable.updated", audit_model.CategoryAdmin, 0, 0)
	since = auditMaxID(t)
	_, err = actions_model.DeleteVariable(ctx, v.ID, 0, 0, 0)
	require.NoError(t, err)
	scopedOne(t, since, "admin.actions_variable.deleted", audit_model.CategoryAdmin, 0, 0)

	assertNoSecrets(t, start, "s3cret-value", "var-value")
}

func TestAuditActionsRunDeletes(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	repo := loadRepo(t, "user2", "repo1")
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	ctx := asActor(t, 2, "user2")

	// delete older than: one entry with the selected runs, recorded before anything is deleted
	f := newOldRunsFixture(t)
	since := auditMaxID(t)
	_, _, err := actions_service.DeleteOldRuns(ctx, user2, repo, 30)
	require.NoError(t, err)
	data := auditData(t, repoOne(t, since, "repo.actions_runs.deleted_old", repo))
	assert.EqualValues(t, 30, data["older_than_days"])
	assert.EqualValues(t, len(f.deleted), data["count"])
	f.assertDeleted(t)

	f = newOldRunsFixture(t)
	restore := test.MockVariableValue(&audit_model.InsertEntry, func(ctx context.Context, e *audit_model.Entry) error {
		if strings.HasPrefix(e.Action, "repo.actions_run") {
			return errors.New("audit insert failed")
		}
		return db.Insert(ctx, e)
	})
	_, _, err = actions_service.DeleteOldRuns(ctx, user2, repo, 30)
	require.Error(t, err)
	f.assertUntouched(t)
	require.Error(t, actions_service.DeleteRun(ctx, f.deleted[0]), "a failed record deletes nothing")
	assert.True(t, f.exists(t, f.deleted[0]))
	restore()

	// an explicit delete, with its counts
	since = auditMaxID(t)
	require.NoError(t, actions_service.DeleteRun(ctx, f.deleted[0]))
	assert.Equal(t, map[string]any{"jobs": float64(0), "tasks": float64(0), "artifacts": float64(0)}, auditData(t, repoOne(t, since, "repo.actions_run.deleted", repo))["counts"])

	// a user deletes an artifact; the cleanup expires the others and their logs, recorded only when there were any
	sys := audit_model.WithSystem(t.Context(), "cron")
	session := loginUser(t, "user5")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user5/repo4/actions/artifacts/19").AddTokenAuth(token), http.StatusNoContent)
	repoOne(t, since, "repo.actions_artifact.deleted", loadRepo(t, "user5", "repo4"))
	since = auditMaxID(t)
	require.NoError(t, actions_service.CleanupArtifacts(sys))
	require.NoError(t, actions_service.CleanupArtifacts(sys))
	assert.NotZero(t, auditData(t, scopedOne(t, since, "admin.actions.artifacts_expired", audit_model.CategoryAdmin, 0, 0))["count"])
	defer test.MockVariableValue(&setting.Actions.LogRetentionDays, 1)()
	since = auditMaxID(t)
	require.NoError(t, actions_service.CleanupLogs(sys))
	require.NoError(t, actions_service.CleanupLogs(sys))
	assert.NotZero(t, auditData(t, scopedOne(t, since, "admin.actions.logs_expired", audit_model.CategoryAdmin, 0, 0))["count"])

	// the retention cleanup: one entry per repository, with the system actor
	defer test.MockVariableValue(&setting.Actions.RunRetentionDays, 30)()
	since = auditMaxID(t)
	require.NoError(t, actions_service.CleanupRuns(sys))
	repos := map[int64]*audit_model.Entry{}
	for _, e := range auditActions(t, since, "repo.actions_runs.cleaned") {
		assert.Nil(t, repos[e.RepoID], "one entry per repository")
		assert.Equal(t, audit_model.ActorSystem, e.ActorType)
		repos[e.RepoID] = e
	}
	require.NotNil(t, repos[repo.ID])
	assert.EqualValues(t, len(f.deleted)-1, auditData(t, repos[repo.ID])["count"])
	assert.NotNil(t, repos[4], "the other repository")
}

// A failed audit insert fails the change and leaves the rows as they were.
func TestAuditIntegrationsFailClosed(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeAll)
	defer test.MockVariableValue(&audit_model.InsertEntry, func(ctx context.Context, e *audit_model.Entry) error {
		if strings.Contains(e.Action, ".webhook.") || strings.Contains(e.Action, ".actions_secret.") || strings.Contains(e.Action, ".branch_protection.") {
			return errors.New("audit insert failed")
		}
		return db.Insert(ctx, e)
	})()

	hooks := unittest.GetCount(t, &webhook_model.Webhook{})
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/hooks", &api.CreateHookOption{
		Type: "forgejo", Config: api.CreateHookOptionConfig{"url": "http://hooks.example.com", "content_type": "json"},
	}).AddTokenAuth(token), http.StatusInternalServerError)
	assert.Equal(t, hooks, unittest.GetCount(t, &webhook_model.Webhook{}))

	MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/actions/secrets/AUDIT_F", &api.CreateOrUpdateSecretOption{Data: "x"}).AddTokenAuth(token), NoExpectedStatus)
	unittest.AssertNotExistsBean(t, &secret_model.Secret{Name: "AUDIT_F"})

	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branch_protections", &api.CreateBranchProtectionOption{RuleName: "audit-fail"}).AddTokenAuth(token), http.StatusInternalServerError)
	unittest.AssertNotExistsBean(t, &git_model.ProtectedBranch{RuleName: "audit-fail"})
}
