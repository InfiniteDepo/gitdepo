// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/perm"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	"forgejo.org/modules/git"
	"forgejo.org/modules/json"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/routers/common"
	app_context "forgejo.org/services/context"
	maintenance_service "forgejo.org/services/maintenance"
	"forgejo.org/tests"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const maintenanceMessage = "Upgrade in progress"

// setMaintenance turns the mode on and returns a function that turns it off
func setMaintenance(t *testing.T, mode string, until time.Time) func() {
	t.Helper()
	require.NoError(t, maintenance_service.Set(db.DefaultContext, nil, mode, maintenanceMessage, until))
	bumpSettingsRevision(t) // fixtures reset the revision, so a cached value of another test could win
	return func() { maintenanceOff(t) }
}

func maintenanceOff(t *testing.T) {
	t.Helper()
	require.NoError(t, maintenance_service.Set(db.DefaultContext, nil, setting.MaintenanceOff, "", time.Time{}))
	bumpSettingsRevision(t)
}

func assertMaintenanceFlash(t *testing.T, session *TestSession) {
	t.Helper()
	cookie := session.GetCookie(app_context.CookieNameFlash)
	require.NotNil(t, cookie)
	v, err := url.QueryUnescape(cookie.Value)
	require.NoError(t, err)
	v, err = url.QueryUnescape(v)
	require.NoError(t, err)
	assert.Contains(t, v, "This instance is in read-only mode: "+maintenanceMessage)
	session.SetCookie(&http.Cookie{Name: app_context.CookieNameFlash, Value: "", MaxAge: -1})
}

// AC1: the state is stored with who set it, and an end time in the past turns it off without an admin action
func TestMaintenanceState(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user1")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteAdmin)
	user2Token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteIssue)

	req := NewRequestWithJSON(t, "PUT", "/api/v1/admin/maintenance", &api.EditMaintenanceOption{Mode: setting.MaintenanceReadOnly, Message: maintenanceMessage}).AddTokenAuth(token)
	MakeRequest(t, req, http.StatusOK)
	defer maintenanceOff(t)
	var m api.Maintenance
	DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/maintenance").AddTokenAuth(token), http.StatusOK), &m)
	assert.Equal(t, api.Maintenance{Mode: setting.MaintenanceReadOnly, Message: maintenanceMessage, SetBy: "user1"}, m)

	createIssue := func(status int) {
		req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/issues", &api.CreateIssueOption{Title: "maintenance"}).AddTokenAuth(user2Token)
		MakeRequest(t, req, status)
	}
	createIssue(http.StatusServiceUnavailable)

	// write an end time in the past straight to the database
	v, err := json.Marshal(setting.MaintenanceState{Mode: setting.MaintenanceReadOnly, Until: time.Now().Unix() - 1})
	require.NoError(t, err)
	require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{"maintenance.state": string(v)}))
	config.GetDynGetter().InvalidateCache()
	createIssue(http.StatusCreated)
}

// AC2: [maintenance] MODE in app.ini wins over the database and can't be changed from the UI or API
func TestMaintenanceConfigOverride(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user1")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteAdmin)
	defer test.MockVariableValue(&setting.Maintenance.Mode, setting.MaintenanceReadOnly)()
	defer test.MockVariableValue(&setting.Maintenance.Message, maintenanceMessage)()

	req := NewRequestWithJSON(t, "PUT", "/api/v1/admin/maintenance", &api.EditMaintenanceOption{Mode: setting.MaintenanceOff}).AddTokenAuth(token)
	MakeRequest(t, req, http.StatusConflict)
	var m api.Maintenance
	DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/maintenance").AddTokenAuth(token), http.StatusOK), &m)
	assert.True(t, m.FromConfig)
	assert.Equal(t, setting.MaintenanceReadOnly, m.Mode)

	resp := session.MakeRequest(t, NewRequest(t, "GET", "/admin/maintenance"), http.StatusOK)
	htmlDoc := NewHTMLParser(t, resp.Body)
	htmlDoc.AssertElement(t, "fieldset[disabled]", true)
	assert.Contains(t, htmlDoc.Find(".admin-setting-content .warning.message").Text(), "can't be changed here")

	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/maintenance", map[string]string{"mode": "off"}), http.StatusSeeOther)
	assert.True(t, setting.GetMaintenance(db.DefaultContext).ReadOnly())
}

// AC3: a site admin turns the mode on and off on the admin page; non-admins get 403
func TestMaintenanceAdminPage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	user2 := loginUser(t, "user2")
	user2.MakeRequest(t, NewRequest(t, "GET", "/admin/maintenance"), http.StatusForbidden)
	user2.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/maintenance", map[string]string{"mode": "read-only"}), http.StatusForbidden)
	assert.False(t, setting.GetMaintenance(db.DefaultContext).ReadOnly())

	admin := loginUser(t, "user1")
	admin.MakeRequest(t, NewRequest(t, "GET", "/admin/maintenance"), http.StatusOK)
	until := time.Now().Add(time.Hour).In(setting.DefaultUILocation).Format("2006-01-02T15:04")
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/maintenance", map[string]string{"mode": "read-only", "message": maintenanceMessage, "until": until}), http.StatusSeeOther)
	defer maintenanceOff(t)
	s := setting.GetMaintenance(db.DefaultContext)
	assert.Equal(t, setting.MaintenanceReadOnly, s.Mode)
	assert.Equal(t, maintenanceMessage, s.Message)
	assert.NotZero(t, s.Until)
	assert.Equal(t, "user1", s.SetByName)

	// the form is on the allow-list, so the admin can turn it off again
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/maintenance", map[string]string{"mode": "off"}), http.StatusSeeOther)
	assert.False(t, setting.GetMaintenance(db.DefaultContext).ReadOnly())
}

// AC4: GET/PUT /admin/maintenance for site admins with the admin scope, with validation; it still works while read-only
func TestAPIMaintenance(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user1")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteAdmin)
	readToken := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadAdmin)
	user2Token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteAdmin)
	put := func(token string, opt *api.EditMaintenanceOption, status int) {
		t.Helper()
		MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/admin/maintenance", opt).AddTokenAuth(token), status)
	}

	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/maintenance").AddTokenAuth(readToken), http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/maintenance").AddTokenAuth(user2Token), http.StatusForbidden)
	put(user2Token, &api.EditMaintenanceOption{Mode: setting.MaintenanceReadOnly}, http.StatusForbidden)
	put(readToken, &api.EditMaintenanceOption{Mode: setting.MaintenanceReadOnly}, http.StatusForbidden)
	put(token, &api.EditMaintenanceOption{Mode: "everything"}, http.StatusUnprocessableEntity)
	past := time.Now().Add(-time.Hour)
	put(token, &api.EditMaintenanceOption{Mode: setting.MaintenanceReadOnly, Until: &past}, http.StatusUnprocessableEntity)
	assert.False(t, setting.GetMaintenance(db.DefaultContext).ReadOnly())

	future := time.Now().Add(time.Hour)
	put(token, &api.EditMaintenanceOption{Mode: setting.MaintenanceReadOnly, Message: maintenanceMessage, Until: &future}, http.StatusOK)
	defer maintenanceOff(t)
	assert.Equal(t, future.Unix(), setting.GetMaintenance(db.DefaultContext).Until)
	put(token, &api.EditMaintenanceOption{Mode: setting.MaintenanceOff}, http.StatusOK)
	assert.False(t, setting.GetMaintenance(db.DefaultContext).ReadOnly())
}

// AC5: the CLI turns the mode on and off straight in the database, without the web server; no accounts while on
func TestMaintenanceCLI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	until := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	_, err := runMainApp("admin", "maintenance", "enable", "--mode", "read-only", "--message", maintenanceMessage, "--until", until)
	require.NoError(t, err)
	// the CLI runs in another process, so don't wait for this one's settings cache
	config.GetDynGetter().InvalidateCache()
	defer maintenanceOff(t)
	s := setting.GetMaintenance(db.DefaultContext)
	assert.Equal(t, setting.MaintenanceReadOnly, s.Mode)
	assert.Equal(t, maintenanceMessage, s.Message)
	assert.NotZero(t, s.Until)

	_, err = runMainApp("admin", "user", "create", "--username", "maintenance-cli", "--password", "password", "--email", "maintenance-cli@example.com")
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Contains(t, string(exitErr.Stderr), "This instance is in read-only mode")
	unittest.AssertNotExistsBean(t, &user_model.User{Name: "maintenance-cli"})

	_, err = runMainApp("admin", "maintenance", "enable", "--mode", "everything")
	require.Error(t, err)

	_, err = runMainApp("admin", "maintenance", "disable")
	require.NoError(t, err)
	config.GetDynGetter().InvalidateCache()
	assert.False(t, setting.GetMaintenance(db.DefaultContext).ReadOnly())
}

// AC6: reads keep working while read-only
func TestMaintenanceReadOnlyReads(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	// a package to download, uploaded before the mode is on
	packageURL := "/api/packages/user2/generic/maintenance/1.0/file.txt"
	MakeRequest(t, NewRequestWithBody(t, "PUT", packageURL, strings.NewReader("hello")).AddBasicAuth("user2"), http.StatusCreated)
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository)
	defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()

	for _, s := range []*TestSession{emptyTestSession(t), session} {
		for _, link := range []string{"/user2/repo1", "/user2/repo1/issues/1", "/explore/repos?q=repo1", "/user2/repo1/raw/branch/master/README.md", "/user2/repo1/archive/master.zip"} {
			s.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
		}
		// archive downloads are requested with a POST
		s.MakeRequest(t, NewRequest(t, "POST", "/user2/repo1/archive/master.zip"), http.StatusOK)
	}
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1").AddTokenAuth(token), http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack").AddBasicAuth("user2"), http.StatusOK)
	resp := MakeRequest(t, NewRequest(t, "GET", packageURL).AddBasicAuth("user2"), http.StatusOK)
	assert.Equal(t, "hello", resp.Body.String())
}

// AC7: writes over the web and the API are refused
func TestMaintenanceReadOnlyWrites(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteIssue, auth_model.AccessTokenScopeWritePackage)
	issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{RepoID: 1, Index: 1})
	defer setMaintenance(t, setting.MaintenanceReadOnly, time.Now().Add(time.Hour))()

	for link, values := range map[string]map[string]string{
		"/user2/repo1/issues/1/comments":        {"content": "maintenance"},
		"/user2/repo1/issues/1/title":           {"title": "maintenance"},
		"/user2/repo1/issues/1/reactions/react": {"content": "+1"},
		"/user2/repo1/pulls/2/merge":            {"do": "merge"},
		"/user2/repo1/_edit/master/README.md":   {"content": "maintenance", "commit_choice": "direct"},
		"/user/settings":                        {"name": "user2", "full_name": "maintenance"},
	} {
		req := NewRequestWithValues(t, "POST", link, values)
		req.Header.Set("Referer", setting.AppURL+"user2/repo1")
		resp := session.MakeRequest(t, req, http.StatusSeeOther)
		assert.Equal(t, setting.AppURL+"user2/repo1", resp.Header().Get("Location"), link)
		assertMaintenanceFlash(t, session)
	}
	unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: issue.ID, Title: issue.Title, NumComments: issue.NumComments})

	resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/issues", &api.CreateIssueOption{Title: "maintenance"}).AddTokenAuth(token), http.StatusServiceUnavailable)
	assert.JSONEq(t, `{"message":"read-only mode","detail":"`+maintenanceMessage+`"}`, resp.Body.String())
	retryAfter, err := strconv.Atoi(resp.Header().Get("Retry-After"))
	require.NoError(t, err)
	assert.InDelta(t, 3600, retryAfter, 60)

	resp = MakeRequest(t, NewRequestWithBody(t, "PUT", "/api/packages/user2/generic/maintenance/1.0/file.txt", strings.NewReader("hello")).AddBasicAuth("user2"), http.StatusServiceUnavailable)
	assert.Contains(t, resp.Body.String(), "This instance is in read-only mode: "+maintenanceMessage)

	lfsBatch := func(operation string, status int) {
		req := NewRequestWithBody(t, "POST", "/user2/repo1.git/info/lfs/objects/batch",
			strings.NewReader(`{"operation":"`+operation+`","objects":[{"oid":"`+strings.Repeat("a", 64)+`","size":1}]}`)).AddBasicAuth("user2")
		req.Header.Set("Accept", "application/vnd.git-lfs+json")
		req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
		MakeRequest(t, req, status)
	}
	lfsBatch("upload", http.StatusServiceUnavailable)
	lfsBatch("download", http.StatusOK)
}

// AC8: git pushes over HTTP and SSH are refused early and in the pre-receive hook
// the OAuth2 application policy stays changeable by a site admin in read-only mode
func TestMaintenanceOAuth2AppPolicy(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer setMaintenance(t, setting.MaintenanceReadOnly, time.Now().Add(time.Hour))()
	loginUser(t, "user1").MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/applications/policy", map[string]string{"mode": "everyone"}), http.StatusSeeOther)
	assert.Equal(t, setting.OAuth2AppPolicyEveryone, setting.Config().OAuth2AppPolicy.Value(db.DefaultContext).Mode)
}

func TestMaintenanceGitPush(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		u.Path = "user2/repo1.git"
		u.User = url.UserPassword("user2", userPassword)
		dstPath := t.TempDir()
		doGitClone(dstPath, u)(t)
		doGitAddSomeCommits(dstPath, "master")(t)

		defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()
		// clone and fetch still work
		doGitClone(t.TempDir(), u)(t)
		_, _, err := git.NewCommand(git.DefaultContext, "fetch", "origin").RunStdString(&git.RunOpts{Dir: dstPath})
		require.NoError(t, err)

		stderr := doGitPushTestRepositoryFail(t, dstPath, "origin", "master")
		assert.Contains(t, stderr, "This instance is in read-only mode: "+maintenanceMessage)

		// wiki pushes and push-to-create are refused before the repository is looked up
		for _, repo := range []string{"user2/repo1.wiki.git", "user2/maintenance-new.git"} {
			resp := MakeRequest(t, NewRequest(t, "GET", "/"+repo+"/info/refs?service=git-receive-pack").AddBasicAuth("user2"), http.StatusServiceUnavailable)
			assert.Equal(t, "This instance is in read-only mode: "+maintenanceMessage, strings.TrimSpace(resp.Body.String()))
		}

		// SSH: serv refuses writes and allows reads; the hook refuses pushes that get that far
		_, extra := private.ServCommand(t.Context(), 1, "user2", "repo1", perm.AccessModeWrite, "", "git-receive-pack")
		assert.Equal(t, "This instance is in read-only mode: "+maintenanceMessage, extra.UserMsg)
		_, extra = private.ServCommand(t.Context(), 1, "user2", "repo1.wiki", perm.AccessModeWrite, "", "git-receive-pack")
		assert.Equal(t, "This instance is in read-only mode: "+maintenanceMessage, extra.UserMsg)
		_, extra = private.ServCommand(t.Context(), 1, "user2", "repo1", perm.AccessModeRead, "", "git-upload-pack")
		require.NoError(t, extra.Error)
		extra = private.HookPreReceive(t.Context(), repoIDByName(t, "user2", "repo1"), private.HookOptions{UserID: 2, RefFullNames: []git.RefName{"refs/heads/master"}, OldCommitIDs: []string{"a"}, NewCommitIDs: []string{"b"}})
		assert.Equal(t, "This instance is in read-only mode: "+maintenanceMessage, extra.UserMsg)

		// full maintenance: non-admins can't use git at all
		setMaintenance(t, setting.MaintenanceFull, time.Time{})
		_, extra = private.ServCommand(t.Context(), 1, "user2", "repo1", perm.AccessModeRead, "", "git-upload-pack")
		assert.Equal(t, "This instance is in maintenance mode: "+maintenanceMessage, extra.UserMsg)
		MakeRequest(t, NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack").AddBasicAuth("user2"), http.StatusServiceUnavailable)
		MakeRequest(t, NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack").AddBasicAuth("user1"), http.StatusOK)
	})
}

// AC9: sign-in, sign-out, the admin settings on the allow-list, health checks and previews still work
func TestMaintenanceAllowed(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()

	session := loginUser(t, "user2")
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/markup", map[string]string{"text": "**hi**", "mode": "gfm"}), http.StatusOK)
	session.MakeRequest(t, NewRequest(t, "POST", "/user/logout"), http.StatusSeeOther)
	MakeRequest(t, NewRequest(t, "GET", "/api/healthz"), http.StatusOK)

	admin := loginUser(t, "user1")
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/config", map[string]string{"key": "picture.enable_federated_avatar", "value": "false"}), http.StatusOK)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/users/2/edit", map[string]string{"login_name": "user2", "email": "user2@example.com", "full_name": "maintenance"}), http.StatusSeeOther)
	assertMaintenanceFlash(t, admin)
	unittest.AssertNotExistsBean(t, &user_model.User{ID: 2, FullName: "maintenance"})

	// every allow-listed route exists, so the list can't silently go stale
	routes := container.Set[string]{}
	require.NoError(t, chi.Walk(testWebRoutes.R, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes.Add(method + " " + strings.ReplaceAll(route, "/*/", "/"))
		return nil
	}))
	for _, list := range []container.Set[string]{common.MaintenanceSignInRoutes, common.MaintenanceReadRoutes, common.MaintenanceRevokeRoutes, common.MaintenanceAdminRoutes} {
		for r := range list {
			assert.True(t, routes.Contains(r), r)
		}
	}
}

// AC10: in full maintenance mode only site admins can use the web UI and the API
func TestMaintenanceFull(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	user2 := loginUser(t, "user2")
	user2Token := getTokenForLoggedInUser(t, user2, auth_model.AccessTokenScopeReadRepository)
	admin := loginUser(t, "user1")
	adminToken := getTokenForLoggedInUser(t, admin, auth_model.AccessTokenScopeReadRepository)
	defer setMaintenance(t, setting.MaintenanceFull, time.Now().Add(time.Hour))()

	for _, s := range []*TestSession{emptyTestSession(t), user2} {
		resp := s.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1"), http.StatusServiceUnavailable)
		assert.Contains(t, resp.Body.String(), "Please try again later")
		assert.NotEmpty(t, resp.Header().Get("Retry-After"))
	}
	emptyTestSession(t).MakeRequest(t, NewRequest(t, "GET", "/user/login"), http.StatusOK)
	resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1").AddTokenAuth(user2Token), http.StatusServiceUnavailable)
	assert.JSONEq(t, `{"message":"maintenance mode","detail":"`+maintenanceMessage+`"}`, resp.Body.String())
	assert.NotEmpty(t, resp.Header().Get("Retry-After"))
	MakeRequest(t, NewRequest(t, "GET", "/api/packages/user2/generic/maintenance/1.0/file.txt").AddBasicAuth("user2"), http.StatusServiceUnavailable)

	admin.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1"), http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1").AddTokenAuth(adminToken), http.StatusOK)
	// still read-only for admins
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/issues/1/comments", map[string]string{"content": "maintenance"}), http.StatusSeeOther)

	// a fresh sign-in works, so admins can get in
	loginUser(t, "user1")
}

// AC11: a banner with the mode, the message and the end time on every page, also for anonymous visitors
func TestMaintenanceBanner(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	for _, s := range []*TestSession{emptyTestSession(t), session} {
		NewHTMLParser(t, s.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1"), http.StatusOK).Body).AssertElement(t, "#maintenance-banner", false)
	}

	defer setMaintenance(t, setting.MaintenanceReadOnly, time.Now().Add(time.Hour))()
	for _, s := range []*TestSession{emptyTestSession(t), session} {
		banner := NewHTMLParser(t, s.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1"), http.StatusOK).Body).Find("#maintenance-banner").Text()
		assert.Contains(t, banner, "This instance is in read-only mode")
		assert.Contains(t, banner, maintenanceMessage)
		assert.Contains(t, banner, "Expected to end at")
	}
}

// AC12: new Actions jobs don't start while the mode is on, and start after it
func TestMaintenanceActions(t *testing.T) {
	if !setting.Database.Type.IsSQLite3() {
		t.Skip()
	}
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		session := loginUser(t, user2.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
		apiRepo := createActionsTestRepo(t, token, "actions-maintenance", false)
		runner := newMockRunner()
		runner.registerAsRepoRunner(t, user2.Name, apiRepo.Name, "mock-runner", []string{"ubuntu-latest"})
		treePath := ".gitea/workflows/maintenance.yml"
		opts := getWorkflowCreateFileOptions(user2, apiRepo.DefaultBranch, "create "+treePath, `name: maintenance
on: push
jobs:
  job1:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`)
		createWorkflowFile(t, token, user2.Name, apiRepo.Name, treePath, opts)

		off := setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})
		assert.Nil(t, runner.maybeFetchTask(t))
		assert.Nil(t, runner.maybeFetchTask(t))
		off()
		runner.succeedAtTask(t, runner.fetchTask(t))

		doAPIDeleteRepository(NewAPITestContext(t, user2.Name, apiRepo.Name, auth_model.AccessTokenScopeWriteUser))(t)
	})
}
