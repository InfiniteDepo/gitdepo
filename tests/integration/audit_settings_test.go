// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	quota_model "forgejo.org/models/quota"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	"forgejo.org/modules/json"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/routers"
	auth_service "forgejo.org/services/auth"
	"forgejo.org/services/auth/source/ldap"
	"forgejo.org/services/auth/source/pam"
	"forgejo.org/services/cron"
	logshipping_service "forgejo.org/services/logshipping"
	user_service "forgejo.org/services/user"
	usergroup_service "forgejo.org/services/usergroup"
	"forgejo.org/tests"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adminOne returns the one entry of action written after since, and checks it is an admin entry.
func adminOne(t *testing.T, since int64, action string) *audit_model.Entry {
	t.Helper()
	entries := auditActions(t, since, action)
	require.Len(t, entries, 1, action)
	assert.Equal(t, audit_model.CategoryAdmin, entries[0].Category)
	return entries[0]
}

func TestAuditLoginSource(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user1")
	payload := buildAuthSourceLDAPPayload("", "", "", "", "", "")
	payload["name"] = "audit-ldap"
	payload["bind_password"] = "audit-bind-secret"

	since := auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/auths/new", payload), http.StatusSeeOther)
	source := unittest.AssertExistsAndLoadBean(t, &auth_model.Source{Name: "audit-ldap"})
	e := adminOne(t, since, "admin.login_source.created")
	assert.EqualValues(t, 1, e.ActorID)
	assert.Equal(t, "login_source", e.TargetType)
	assert.Equal(t, source.ID, e.TargetID)
	assert.Equal(t, "audit-ldap", auditData(t, e)["name"])
	assert.Equal(t, true, auditData(t, e)["is_sync_enabled"])
	assertNoSecretIn(t, since, "audit-bind-secret")

	edit := fmt.Sprintf("/admin/auths/%d", source.ID)
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", edit, payload), http.StatusSeeOther)
	assert.Empty(t, auditSince(t, since), "an unchanged save records nothing")

	payload["bind_password"] = "audit-bind-secret-2"
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", edit, payload), http.StatusSeeOther)
	data := auditData(t, adminOne(t, since, "admin.login_source.updated"))
	assert.Equal(t, true, data["config_changed"])
	assert.NotContains(t, data, "before")
	assertNoSecretIn(t, since, "audit-bind-secret")

	payload["name"] = "audit-ldap-2"
	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", edit, payload), http.StatusSeeOther)
	data = auditData(t, adminOne(t, since, "admin.login_source.updated"))
	assert.Equal(t, map[string]any{"name": "audit-ldap"}, data["before"])
	assert.Equal(t, map[string]any{"name": "audit-ldap-2"}, data["after"])

	since = auditMaxID(t)
	session.MakeRequest(t, NewRequest(t, "POST", edit+"/delete"), http.StatusOK)
	e = adminOne(t, since, "admin.login_source.deleted")
	assert.Equal(t, source.ID, e.TargetID)
	assert.Equal(t, map[string]any{"authorization_tokens": float64(0), "team_memberships_unlinked": float64(0)}, auditData(t, e)["counts"])

	// the command line
	since = auditMaxID(t)
	_, err := runMainApp("admin", "auth", "add-ldap", "--name", "audit-cli-ldap", "--security-protocol", "unencrypted",
		"--host", "ldap.example.com", "--port", "389", "--user-search-base", "ou=people,dc=example,dc=com",
		"--user-filter", "(uid=%s)", "--email-attribute", "mail")
	require.NoError(t, err)
	e = adminOne(t, since, "admin.login_source.created")
	assert.Equal(t, audit_model.ActorCLI, e.ActorType)
	assert.Equal(t, "audit-cli-ldap", e.TargetName)
}

func TestAuditLoginSourceRegisterFailed(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	discovery := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer discovery.Close()
	session := loginUser(t, "user1")
	payload := authSourcePayloadOpenIDConnect("audit-oidc", discovery.URL+"/")
	payload["oauth2_key"] = "client-id"
	payload["oauth2_secret"] = "audit-client-secret"

	since := auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/auths/new", payload), http.StatusOK)
	unittest.AssertNotExistsBean(t, &auth_model.Source{Name: "audit-oidc"})
	created := adminOne(t, since, "admin.login_source.created")
	deleted := adminOne(t, since, "admin.login_source.deleted")
	assert.Equal(t, created.TargetID, deleted.TargetID)
	assert.Equal(t, "register_failed", auditData(t, deleted)["reason"])
	assertNoSecretIn(t, since, "audit-client-secret")
}

// TestAuditLoginSourceSync runs the LDAP sync the cron task runs. It needs the test LDAP server (TEST_LDAP=1).
func TestAuditLoginSourceSync(t *testing.T) {
	if skipLDAPTests() {
		t.Skip()
	}
	defer tests.PrepareTestEnv(t)()
	addAuthSourceLDAP(t, "", "", "", "")
	source := unittest.AssertExistsAndLoadBean(t, &auth_model.Source{Name: "ldap"})

	since := auditMaxID(t)
	require.NoError(t, auth_service.SyncExternalUsers(audit_model.WithSystem(t.Context(), "cron:sync_external_users"), true))
	e := adminOne(t, since, "admin.login_source.synced")
	assert.Equal(t, audit_model.ActorLoginSource, e.ActorType)
	assert.Equal(t, source.ID, e.ActorID)
	assert.EqualValues(t, len(gitLDAPUsers), auditData(t, e)["counts"].(map[string]any)["added"])
	for _, created := range auditActions(t, since, "account.user.created") {
		assert.Equal(t, audit_model.ActorLoginSource, created.ActorType)
	}
}

func TestAuditUserGroup(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := asActor(t, 1, "user1")
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	team := unittest.AssertExistsAndLoadBean(t, &org_model.Team{ID: 1})

	since := auditMaxID(t)
	group := &org_model.UserGroup{Name: "audit-group", GrantsAuditor: true}
	require.NoError(t, usergroup_service.CreateGroup(ctx, group))
	e := adminOne(t, since, "admin.user_group.created")
	assert.EqualValues(t, 1, e.ActorID)
	assert.Equal(t, group.ID, e.TargetID)
	assert.Equal(t, true, auditData(t, e)["grants_auditor"])

	since = auditMaxID(t)
	group.Description = "only text"
	require.NoError(t, usergroup_service.UpdateGroup(ctx, group))
	assert.Empty(t, auditActions(t, since, "admin.user_group.updated"))
	group.GrantsAuditor = false
	require.NoError(t, usergroup_service.UpdateGroup(ctx, group))
	data := auditData(t, adminOne(t, since, "admin.user_group.updated"))
	assert.Equal(t, map[string]any{"grants_auditor": true}, data["before"])
	assert.Equal(t, map[string]any{"grants_auditor": false}, data["after"])

	since = auditMaxID(t)
	require.NoError(t, usergroup_service.AddMember(ctx, group, user))
	e = adminOne(t, since, "admin.user_group.member_added")
	assert.EqualValues(t, 2, e.SubjectUserID)
	assert.EqualValues(t, 2, auditData(t, e)["user_id"])

	since = auditMaxID(t)
	require.NoError(t, usergroup_service.RemoveMember(ctx, group, user.ID))
	assert.EqualValues(t, 2, adminOne(t, since, "admin.user_group.member_removed").SubjectUserID)
	require.NoError(t, usergroup_service.RemoveMember(ctx, group, user.ID))
	assert.Len(t, auditActions(t, since, "admin.user_group.member_removed"), 1, "removing a non-member records nothing")

	since = auditMaxID(t)
	require.NoError(t, usergroup_service.LinkTeam(ctx, group, team))
	e = adminOne(t, since, "admin.user_group.team_linked")
	assert.Equal(t, team.OrgID, e.OwnerID)
	assert.EqualValues(t, team.ID, auditData(t, e)["team_id"])
	require.NoError(t, usergroup_service.UnlinkTeam(ctx, group, team))
	assert.Equal(t, team.OrgID, adminOne(t, since, "admin.user_group.team_unlinked").OwnerID)
	require.NoError(t, usergroup_service.UnlinkTeam(ctx, group, team))
	assert.Len(t, auditActions(t, since, "admin.user_group.team_unlinked"), 1, "unlinking a team that isn't linked records nothing")

	// a login source sync: the source is the actor, and only its own memberships are removed
	sync := audit_model.WithLoginSource(ctx, 77, "audit-source")
	mapping := map[string]container.Set[string]{"devs": container.SetOf("audit-group")}
	since = auditMaxID(t)
	require.NoError(t, usergroup_service.SyncDirectoryGroups(sync, user, 77, container.SetOf("devs"), mapping, true))
	e = adminOne(t, since, "admin.user_group.member_added")
	assert.Equal(t, audit_model.ActorLoginSource, e.ActorType)
	assert.EqualValues(t, 77, e.ActorID)
	assert.EqualValues(t, 77, auditData(t, e)["login_source_id"])
	require.NoError(t, usergroup_service.SyncDirectoryGroups(sync, user, 77, container.Set[string]{}, mapping, true))
	e = adminOne(t, since, "admin.user_group.member_removed")
	assert.Equal(t, "login_source_sync", auditData(t, e)["reason"])
	assert.Equal(t, audit_model.ActorLoginSource, e.ActorType)

	since = auditMaxID(t)
	require.NoError(t, usergroup_service.SetOrgAdminExclusions(ctx, []int64{3}))
	data = auditData(t, adminOne(t, since, "admin.user_group.org_admin_exclusions_changed"))
	assert.Equal(t, map[string]any{"org_ids": []any{}}, data["before"])
	assert.Equal(t, map[string]any{"org_ids": []any{float64(3)}}, data["after"])
	require.NoError(t, usergroup_service.SetOrgAdminExclusions(ctx, []int64{3}))
	assert.Len(t, auditActions(t, since, "admin.user_group.org_admin_exclusions_changed"), 1, "no change records nothing")

	require.NoError(t, usergroup_service.AddMember(ctx, group, user))
	require.NoError(t, usergroup_service.LinkTeam(ctx, group, team))
	since = auditMaxID(t)
	require.NoError(t, usergroup_service.DeleteGroup(ctx, group))
	e = adminOne(t, since, "admin.user_group.deleted")
	assert.Equal(t, map[string]any{"members": float64(1), "teams": float64(1)}, auditData(t, e)["counts"])
	assert.Len(t, auditActions(t, since, "admin.user_group.team_unlinked"), 1)
}

func TestAuditSettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user1")
	key := setting.Config().Picture.DisableGravatar.DynKey()

	// the fixtures store true
	since := auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/config", map[string]string{"key": key, "value": "false"}), http.StatusOK)
	bumpSettingsRevision(t)
	e := adminOne(t, since, "admin.setting.changed")
	assert.EqualValues(t, 1, e.ActorID)
	data := auditData(t, e)
	assert.Equal(t, []any{key}, data["keys"])
	assert.Equal(t, map[string]any{key: true}, data["before"])
	assert.Equal(t, map[string]any{key: false}, data["after"])

	since = auditMaxID(t)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/config", map[string]string{"key": key, "value": "false"}), http.StatusOK)
	bumpSettingsRevision(t)
	assert.Empty(t, auditActions(t, since, "admin.setting.changed"), "an unchanged value records nothing")

	// a key that isn't known to hold no secret is recorded only as a hash
	ctx := asActor(t, 1, "user1")
	since = auditMaxID(t)
	require.NoError(t, system_model.SetSettings(ctx, map[string]string{"audit.unknown": "plain-value-123"}))
	bumpSettingsRevision(t)
	data = auditData(t, adminOne(t, since, "admin.setting.changed"))
	assert.NotContains(t, data, "after")
	assert.Contains(t, data["hashed"], "audit.unknown")
	assertNoSecretIn(t, since, "plain-value-123")
}

func TestAuditLogShipping(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Webhook.AllowedHostList, "*")()
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	ctx := asActor(t, 1, "user1")
	t.Cleanup(func() {
		require.NoError(t, logshipping_service.Apply(context.Background(), setting.LogShippingState{}))
	})

	since := auditMaxID(t)
	d, err := logshipping_service.Save(ctx, admin, "", logshipping_service.Input{
		Name: new("audit-dest"), Type: new("http"), Endpoint: new("https://logs.example.com:8443/ingest/secret-path"),
		LogTypes: &[]string{"access"}, Headers: &[]logshipping_service.HeaderInput{{Name: "X-Auth", Value: "audit-header-value"}},
	})
	require.NoError(t, err)
	bumpSettingsRevision(t)
	e := adminOne(t, since, "admin.log_shipping.created")
	assert.EqualValues(t, 1, e.ActorID)
	data := auditData(t, e)
	assert.Equal(t, "https://logs.example.com:8443", data["endpoint"])
	assert.Equal(t, []any{"X-Auth"}, data["header_names"])
	assert.Empty(t, auditActions(t, since, "admin.setting.changed"), "the destinations are recorded by log shipping only")
	assertNoSecretIn(t, since, "audit-header-value", "secret-path")

	since = auditMaxID(t)
	_, err = logshipping_service.Save(ctx, admin, d.ID, logshipping_service.Input{Name: new("audit-dest")})
	require.NoError(t, err)
	bumpSettingsRevision(t)
	assert.Empty(t, auditSince(t, since), "an unchanged save records nothing")

	_, err = logshipping_service.Save(ctx, admin, d.ID, logshipping_service.Input{Name: new("audit-dest-2"), Expression: new("secret-regex")})
	require.NoError(t, err)
	bumpSettingsRevision(t)
	data = auditData(t, adminOne(t, since, "admin.log_shipping.updated"))
	assert.Equal(t, map[string]any{"name": "audit-dest"}, data["before"])
	assert.Equal(t, map[string]any{"name": "audit-dest-2"}, data["after"])
	assert.Equal(t, true, data["filter_changed"])
	assertNoSecretIn(t, since, "secret-regex")

	since = auditMaxID(t)
	require.NoError(t, logshipping_service.Remove(ctx, admin, d.ID))
	bumpSettingsRevision(t)
	assert.Equal(t, "audit-dest-2", adminOne(t, since, "admin.log_shipping.deleted").TargetName)
}

func TestAuditQuota(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := asActor(t, 1, "user1")

	since := auditMaxID(t)
	rule, err := quota_model.CreateRule(ctx, "audit-rule", 100, quota_model.LimitSubjects{quota_model.LimitSubjectSizeReposAll})
	require.NoError(t, err)
	data := auditData(t, adminOne(t, since, "admin.quota_rule.created"))
	assert.EqualValues(t, 100, data["limit"])
	assert.Equal(t, []any{"size:repos:all"}, data["subjects"])

	since = auditMaxID(t)
	limit := int64(100)
	_, err = rule.Edit(ctx, &limit, nil)
	require.NoError(t, err)
	assert.Empty(t, auditActions(t, since, "admin.quota_rule.updated"))
	limit = 200
	_, err = rule.Edit(ctx, &limit, nil)
	require.NoError(t, err)
	data = auditData(t, adminOne(t, since, "admin.quota_rule.updated"))
	assert.Equal(t, map[string]any{"limit": float64(100)}, data["before"])
	assert.Equal(t, map[string]any{"limit": float64(200)}, data["after"])

	since = auditMaxID(t)
	group, err := quota_model.CreateGroup(ctx, "audit-quota")
	require.NoError(t, err)
	adminOne(t, since, "admin.quota_group.created")
	require.NoError(t, group.AddRuleByName(ctx, "audit-rule"))
	assert.Equal(t, "audit-rule", auditData(t, adminOne(t, since, "admin.quota_group.rule_added"))["rule_name"])
	require.NoError(t, group.AddUserByID(ctx, 2))
	assert.EqualValues(t, 2, adminOne(t, since, "admin.quota_group.user_added").SubjectUserID)
	require.NoError(t, group.RemoveUserByID(ctx, 2))
	assert.EqualValues(t, 2, adminOne(t, since, "admin.quota_group.user_removed").SubjectUserID)

	since = auditMaxID(t)
	require.NoError(t, quota_model.SetUserGroups(ctx, 2, &[]string{"audit-quota"}))
	e := adminOne(t, since, "admin.quota_group.user_groups_set")
	assert.EqualValues(t, 2, e.SubjectUserID)
	assert.Equal(t, map[string]any{"groups": []any{"audit-quota"}}, auditData(t, e)["after"])
	assert.Empty(t, auditActions(t, since, "admin.quota_group.user_added"), "recorded once, as the set")

	since = auditMaxID(t)
	require.NoError(t, group.RemoveRuleByName(ctx, "audit-rule"))
	adminOne(t, since, "admin.quota_group.rule_removed")
	require.NoError(t, quota_model.DeleteGroupByName(ctx, "audit-quota"))
	assert.Equal(t, map[string]any{"users": float64(1), "rules": float64(0)}, auditData(t, adminOne(t, since, "admin.quota_group.deleted"))["counts"])
	require.NoError(t, quota_model.DeleteRuleByName(ctx, "audit-rule"))
	adminOne(t, since, "admin.quota_rule.deleted")
}

func TestAuditCronRun(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)

	since := auditMaxID(t)
	MakeRequest(t, NewRequest(t, "POST", "/api/v1/admin/cron/archive_cleanup").AddTokenAuth(token), http.StatusNoContent)
	e := adminOne(t, since, "admin.cron.run")
	assert.EqualValues(t, 1, e.ActorID)
	assert.Equal(t, audit_model.ActorUser, e.ActorType)
	assert.Equal(t, "archive_cleanup", e.TargetName)

	since = auditMaxID(t)
	session := loginUser(t, "user1")
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin", map[string]string{"op": "archive_cleanup"}), http.StatusSeeOther)
	assert.Eventually(t, func() bool {
		n, err := db.GetEngine(db.DefaultContext).Where("id > ? AND action = ? AND actor_id = 1", since, "admin.cron.run").Count(new(audit_model.Entry))
		return err == nil && n == 1
	}, 10*time.Second, 50*time.Millisecond)

	// a scheduled run, and a run that maintenance mode stops, record nothing
	task := cron.GetTask("archive_cleanup")
	since = auditMaxID(t)
	task.Run()
	func() {
		defer test.MockVariableValue(&setting.Maintenance.Mode, setting.MaintenanceReadOnly)()
		task.RunWithUser(asActor(t, 1, "user1"), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}), nil)
	}()
	assert.Empty(t, auditActions(t, since, "admin.cron.run"))
}

func TestAuditManagerLogging(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	call := func(path string, body any) {
		t.Helper()
		recorder := httptest.NewRecorder()
		req := NewRequest(t, "POST", path)
		if body != nil {
			req = NewRequestWithJSON(t, "POST", path, body)
		}
		routers.InternalRoutes().ServeHTTP(recorder, req.Request)
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	}
	file := filepath.Join(t.TempDir(), "audit-secret-name.log")

	since := auditMaxID(t)
	call("/api/internal/manager/pause-logging", nil)
	call("/api/internal/manager/resume-logging", nil)
	call("/api/internal/manager/add-logger", map[string]any{"logger": "access", "writer": "audit-writer", "mode": "file", "config": map[string]any{"filename": file}})
	call("/api/internal/manager/remove-logger/access/audit-writer", nil)
	entries := auditActions(t, since, "admin.logging.changed")
	require.Len(t, entries, 4)
	ops := []any{}
	for _, e := range entries {
		assert.Equal(t, audit_model.ActorCLI, e.ActorType)
		ops = append(ops, auditData(t, e)["op"])
	}
	assert.Equal(t, []any{"pause", "resume", "add", "remove"}, ops)
	assert.Equal(t, map[string]any{"op": "add", "logger": "access", "writer": "audit-writer", "mode": "file"}, auditData(t, entries[2]))
	assertNoSecretIn(t, since, "audit-secret-name")
}

// TestAuditUserFields checks the admin fields of an account that the audit log follows (M2).
func TestAuditUserFields(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	allow := true
	since := auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/user2", &api.EditUserOption{AllowGitHook: &allow}).AddTokenAuth(token), http.StatusOK)
	data := auditData(t, accountOne(t, since, "account.user.updated"))
	assert.Equal(t, map[string]any{"allow_git_hook": false}, data["before"])
	assert.Equal(t, map[string]any{"allow_git_hook": true}, data["after"])
}

func TestAuditSettingsFailClosed(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error {
		return errors.New("audit down")
	})()
	defer test.MockVariableValue(&setting.Webhook.AllowedHostList, "*")()
	ctx := asActor(t, 1, "user1")

	require.Error(t, auth_model.CreateSource(ctx, &auth_model.Source{Type: auth_model.PAM, Name: "audit-fail", IsActive: true, Cfg: &pam.Source{ServiceName: "audit"}}))
	unittest.AssertNotExistsBean(t, &auth_model.Source{Name: "audit-fail"})

	key := setting.Config().Picture.DisableGravatar.DynKey()
	_, before, err := system_model.GetAllSettings(t.Context())
	require.NoError(t, err)
	require.Error(t, system_model.SetSettings(ctx, map[string]string{key: "audit-fail"}))
	_, after, err := system_model.GetAllSettings(t.Context())
	require.NoError(t, err)
	assert.Equal(t, before[key], after[key])

	name := "audit-fail-dest"
	_, err = logshipping_service.Save(ctx, nil, "", logshipping_service.Input{
		Name: &name, Type: new("http"), Endpoint: new("https://logs.example.com/x"), LogTypes: &[]string{"access"},
	})
	require.Error(t, err)
	_, after, err = system_model.GetAllSettings(t.Context())
	require.NoError(t, err)
	assert.Equal(t, before[setting.Config().LogShipping.DynKey()], after[setting.Config().LogShipping.DynKey()])
	raw, _ := json.Marshal(after)
	assert.NotContains(t, string(raw), name)
}

// TestAuditLoginSourceSyncCounts runs the LDAP sync on a directory answer given by the test, so it needs no server.
func TestAuditLoginSourceSyncCounts(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	payload := buildAuthSourceLDAPPayload("", "", "", "", "", "")
	payload["name"] = "audit-sync"
	payload["admin_filter"], payload["restricted_filter"] = "", ""
	source := addAuthSource(t, payload)
	entries := []*ldap.SearchResult{
		{Username: "audit-sync-a", LowerName: "audit-sync-a", Mail: "audit-sync-a@example.com"},
		{Username: "audit-sync-b", LowerName: "audit-sync-b", Mail: "audit-sync-b@example.com"},
	}
	defer test.MockVariableValue(&ldap.SearchSyncEntries, func(*ldap.Source) ([]*ldap.SearchResult, error) { return entries, nil })()
	ctx := audit_model.WithSystem(t.Context(), "cron:sync_external_users")
	counts := func(since int64) map[string]any {
		t.Helper()
		e := adminOne(t, since, "admin.login_source.synced")
		assert.Equal(t, audit_model.ActorLoginSource, e.ActorType)
		assert.Equal(t, source.ID, e.ActorID)
		assert.Equal(t, "cron:sync_external_users", audit_model.ActorFromContext(ctx).Name, "the cron actor is left as it was")
		return auditData(t, e)["counts"].(map[string]any)
	}

	since := auditMaxID(t)
	require.NoError(t, auth_service.SyncExternalUsers(ctx, true))
	assert.Equal(t, map[string]any{"added": float64(2), "updated": float64(0), "disabled": float64(0)}, counts(since))
	created := auditActions(t, since, "account.user.created")
	require.Len(t, created, 2)
	for _, e := range created {
		assert.Equal(t, audit_model.ActorLoginSource, e.ActorType)
		assert.Equal(t, source.ID, e.ActorID)
	}

	// b leaves the directory: disabled once, and not counted again while it stays inactive
	entries = entries[:1]
	since = auditMaxID(t)
	require.NoError(t, auth_service.SyncExternalUsers(ctx, true))
	assert.Equal(t, map[string]any{"added": float64(0), "updated": float64(0), "disabled": float64(1)}, counts(since))
	assert.Equal(t, audit_model.ActorLoginSource, accountOne(t, since, "account.user.updated").ActorType)
	since = auditMaxID(t)
	require.NoError(t, auth_service.SyncExternalUsers(ctx, true))
	assert.Equal(t, map[string]any{"added": float64(0), "updated": float64(0), "disabled": float64(0)}, counts(since))
	assert.Empty(t, auditActions(t, since, "account.user.updated"))
}

func TestAuditLoginSourceCLIAndRestore(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	since := auditMaxID(t)
	_, err := runMainApp("admin", "auth", "add-ldap", "--name", "audit-cli-ldap", "--security-protocol", "unencrypted",
		"--host", "ldap.example.com", "--port", "389", "--user-search-base", "ou=people,dc=example,dc=com",
		"--user-filter", "(uid=%s)", "--email-attribute", "mail")
	require.NoError(t, err)
	source := unittest.AssertExistsAndLoadBean(t, &auth_model.Source{Name: "audit-cli-ldap"})
	id := fmt.Sprint(source.ID)
	_, err = runMainApp("admin", "auth", "update-ldap", "--id", id, "--host", "ldap2.example.com")
	require.NoError(t, err)
	e := adminOne(t, since, "admin.login_source.updated")
	assert.Equal(t, audit_model.ActorCLI, e.ActorType)
	assert.Equal(t, true, auditData(t, e)["config_changed"])
	_, err = runMainApp("admin", "auth", "delete", "--id", id)
	require.NoError(t, err)
	assert.Equal(t, audit_model.ActorCLI, adminOne(t, since, "admin.login_source.deleted").ActorType)

	// an OpenID Connect source whose new discovery URL fails to register is restored, and that is recorded
	failing := false
	var discovery *httptest.Server
	discovery = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing && r.URL.Path == "/new/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": discovery.URL, "authorization_endpoint": discovery.URL + "/auth", "token_endpoint": discovery.URL + "/token",
			"userinfo_endpoint": discovery.URL + "/userinfo", "jwks_uri": discovery.URL + "/keys",
		})
	}))
	defer discovery.Close()
	payload := authSourcePayloadOpenIDConnect("audit-oidc-restore", discovery.URL+"/")
	payload["oauth2_key"], payload["oauth2_secret"] = "client-id", "audit-client-secret"
	oidc := addAuthSource(t, payload)
	failing = true
	payload["open_id_connect_auto_discovery_url"] = discovery.URL + "/new/.well-known/openid-configuration"
	since = auditMaxID(t)
	loginUser(t, "user1").MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/admin/auths/%d", oidc.ID), payload), http.StatusOK)
	updates := auditActions(t, since, "admin.login_source.updated")
	require.Len(t, updates, 2)
	assert.NotContains(t, auditData(t, updates[0]), "reason")
	assert.Equal(t, "register_failed", auditData(t, updates[1])["reason"])
	assert.Equal(t, true, auditData(t, updates[1])["config_changed"])
	assertNoSecretIn(t, since, "audit-client-secret")
}

func TestAuditUserFieldsTable(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	yes, maxRepos, limit := true, 7, int64(1<<20)
	for field, opt := range map[string]*api.EditUserOption{
		"allow_import_local":       {AllowImportLocal: &yes},
		"max_repo_creation":        {MaxRepoCreation: &maxRepos},
		"personal_repo_size_limit": {PersonalRepoSizeLimit: &limit},
	} {
		since := auditMaxID(t)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/user2", opt).AddTokenAuth(token), http.StatusOK)
		data := auditData(t, accountOne(t, since, "account.user.updated"))
		assert.Contains(t, data["after"], field, field)
	}
	// category_id is set only on organizations (whose settings are recorded with the organization); the user fields follow it
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	since := auditMaxID(t)
	require.NoError(t, user_service.UpdateUser(asActor(t, 1, "user1"), user, &user_service.UpdateOptions{CategoryID: optional.Some[int64](3)}))
	assert.Equal(t, map[string]any{"category_id": float64(3)}, auditData(t, accountOne(t, since, "account.user.updated"))["after"])
}

func TestAuditOAuth2QuotaGroupSync(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	_, err := quota_model.CreateGroup(asActor(t, 1, "user1"), "audit-sso-quota")
	require.NoError(t, err)
	payload := authSourcePayloadGitLabCustom("gitlab")
	payload["oauth2_quota_group_claim_name"] = "groups"
	payload["oauth2_quota_group_map"] = `{"devs": ["audit-sso-quota"]}`
	gitlab := addAuthSource(t, payload)
	userGitLab := &user_model.User{
		Name: "gitlabuser", Email: "gitlabuser@example.com", Passwd: "gitlabuserpassword",
		Type: user_model.UserTypeIndividual, LoginType: auth_model.OAuth2, LoginSource: gitlab.ID, LoginName: "5678",
	}
	defer createUser(t.Context(), t, userGitLab)()
	defer mockCompleteUserAuth(func(res http.ResponseWriter, req *http.Request) (goth.User, error) {
		return goth.User{Provider: "gitlab", UserID: "5678", Email: userGitLab.Email, RawData: map[string]any{"groups": []string{"devs"}}}, nil
	})()

	since := auditMaxID(t)
	MakeRequest(t, NewRequest(t, "GET", "/user/oauth2/gitlab/callback?code=XYZ&state=XYZ"), http.StatusSeeOther)
	e := adminOne(t, since, "admin.quota_group.user_added")
	assert.Equal(t, audit_model.ActorLoginSource, e.ActorType)
	assert.Equal(t, gitlab.ID, e.ActorID)
	assert.Equal(t, userGitLab.ID, e.SubjectUserID)
	// the sign-in keeps its own actor: the user
	signin := auditActions(t, since, "auth.signin.success")
	require.Len(t, signin, 1)
	assert.Equal(t, audit_model.ActorUser, signin[0].ActorType)
}
