// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/cache"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/routers"
	"forgejo.org/routers/api/actions"
	actions_service "forgejo.org/services/actions"
	org_service "forgejo.org/services/org"
	trash_service "forgejo.org/services/trash"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

// postOrgUnits submits the organization units form with the given units on (name keys) and the others off
func postOrgUnits(t *testing.T, session *TestSession, org string, status int, on ...string) *httptest.ResponseRecorder {
	t.Helper()
	form := map[string]string{}
	for _, key := range on {
		form["on_"+key] = "on"
	}
	return session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/"+org+"/settings/units", form), status)
}

// allOrgUnitsBut returns the name keys of the policy units except the given ones
func allOrgUnitsBut(except ...unit_model.Type) []string {
	var keys []string
	for _, t := range repo_model.PolicyUnitTypes() {
		if !slices.Contains(except, t) {
			keys = append(keys, unit_model.Units[t].NameKey)
		}
	}
	return keys
}

// B-AC4, B-AC10: the org units page is for org owners and site admins; locked units are refused
func TestOrgUnitPolicyPage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)

	owner := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
	createUnitPolicyOrgRepo(t, token, "unit-org-p", "r")

	doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org/unit-org-p/settings/units"), http.StatusOK).Body)
	assert.Equal(t, 9, doc.Find(".org-unit").Length())
	assert.Equal(t, 9, doc.Find(`input[name^="on_"][checked]`).Length())

	// a team with admin rights that isn't the owner team, and a non-member, get 404
	var team api.Team
	DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/unit-org-p/teams", &api.CreateTeamOption{Name: "admins", Permission: "admin", IncludesAllRepositories: true}).AddTokenAuth(token), http.StatusCreated), &team)
	MakeRequest(t, NewRequest(t, "PUT", fmt.Sprintf("/api/v1/teams/%d/members/user5", team.ID)).AddTokenAuth(token), http.StatusNoContent)
	for _, name := range []string{"user5", "user4"} {
		s := loginUser(t, name)
		s.MakeRequest(t, NewRequest(t, "GET", "/org/unit-org-p/settings/units"), http.StatusNotFound)
		postOrgUnits(t, s, "unit-org-p", http.StatusNotFound)
	}
	unittest.AssertNotExistsBean(t, &repo_model.OrgUnit{})

	// the owner turns Issues off
	postOrgUnits(t, owner, "unit-org-p", http.StatusSeeOther, allOrgUnitsBut(unit_model.TypeIssues)...)
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "unit-org-p"})
	row := unittest.AssertExistsAndLoadBean(t, &repo_model.OrgUnit{OrgID: org.ID, Type: unit_model.TypeIssues})
	assert.True(t, row.Disabled)
	assert.EqualValues(t, 2, row.UpdatedBy)
	doc = NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org/unit-org-p/settings/units"), http.StatusOK).Body)
	assert.Contains(t, doc.Find(`.org-unit[data-unit="repo.issues"]`).Text(), "by user2")
	assert.Contains(t, doc.Find(`.org-unit[data-unit="repo.issues"]`).Text(), row.UpdatedUnix.AsTime().Format("2006-01-02"))

	// a forged field for Code or an unknown unit is refused and nothing changes
	for _, key := range []string{"repo.code", "repo.nope"} {
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/unit-org-p/settings/units", map[string]string{"on_" + key: "on"}), http.StatusBadRequest)
	}
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &repo_model.OrgUnit{OrgID: org.ID, Type: unit_model.TypeIssues}).Disabled)
	assert.Equal(t, 0, doc.Find(`input[name="on_repo.issues"][checked]`).Length())

	// read-only maintenance refuses the change
	undoMaintenance := setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})
	postOrgUnits(t, owner, "unit-org-p", http.StatusSeeOther, allOrgUnitsBut()...)
	assertMaintenanceFlash(t, owner)
	undoMaintenance()
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &repo_model.OrgUnit{OrgID: org.ID, Type: unit_model.TypeIssues}).Disabled)

	// a site admin can change it too
	postOrgUnits(t, loginUser(t, "user1"), "unit-org-p", http.StatusSeeOther, allOrgUnitsBut()...)
	row = unittest.AssertExistsAndLoadBean(t, &repo_model.OrgUnit{OrgID: org.ID, Type: unit_model.TypeIssues})
	assert.False(t, row.Disabled)
	assert.EqualValues(t, 1, row.UpdatedBy)

	// Not allowed by the site: shown locked with the reason, a forged field is refused and nothing is written
	denyRepoUnits(t, nil, unit_model.TypeWiki)
	doc = NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org/unit-org-p/settings/units"), http.StatusOK).Body)
	assert.Equal(t, 1, doc.Find(`input[name="on_repo.wiki"][disabled]`).Length())
	assert.Contains(t, doc.Find(`.org-unit[data-unit="repo.wiki"]`).Text(), "site administrator")
	postOrgUnits(t, owner, "unit-org-p", http.StatusBadRequest, allOrgUnitsBut()...)
	unittest.AssertNotExistsBean(t, &repo_model.OrgUnit{OrgID: org.ID, Type: unit_model.TypeWiki})

	// disabled in app.ini: the same
	disabled := unit_model.DisabledRepoUnitsGet()
	unit_model.DisabledRepoUnitsSet([]unit_model.Type{unit_model.TypeProjects})
	defer unit_model.DisabledRepoUnitsSet(disabled)
	postOrgUnits(t, owner, "unit-org-p", http.StatusBadRequest, "repo.projects")
	unittest.AssertNotExistsBean(t, &repo_model.OrgUnit{OrgID: org.ID, Type: unit_model.TypeProjects})
}

// B-AC3, B-AC4, B-AC5, B-AC7, B-AC9: the three levels
func TestOrgUnitPolicyMatrix(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)

	owner := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
	repoA := createUnitPolicyOrgRepo(t, token, "unit-org-a", "r")
	repoB := createUnitPolicyOrgRepo(t, token, "unit-org-b", "r")
	issues := func(org string, status int) {
		t.Helper()
		owner.MakeRequest(t, NewRequest(t, "GET", "/"+org+"/r/issues"), status)
	}

	// Not allowed for every organization but B
	denyRepoUnits(t, []string{"unit-org-b"}, unit_model.TypeIssues)
	issues("unit-org-a", http.StatusNotFound)
	postOrgUnits(t, owner, "unit-org-a", http.StatusBadRequest, allOrgUnitsBut()...)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/unit-org-a/r", &api.EditRepoOption{HasIssues: new(true)}).AddTokenAuth(token), http.StatusForbidden)

	// Allowed for B, turned off by its owner: the repo admin can't turn it on, the data is kept
	issues("unit-org-b", http.StatusOK)
	issuesUnit := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: repoB.ID, Type: unit_model.TypeIssues})
	postOrgUnits(t, owner, "unit-org-b", http.StatusSeeOther, allOrgUnitsBut(unit_model.TypeIssues, unit_model.TypeExternalTracker)...)
	issues("unit-org-b", http.StatusNotFound)
	units := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/unit-org-b/r/settings/units"), http.StatusOK).Body)
	assert.Equal(t, 0, units.Find(`input[name="enable_issues"]`).Length())
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/unit-org-b/r", &api.EditRepoOption{HasIssues: new(true)}).AddTokenAuth(token), http.StatusForbidden)
	owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/unit-org-b/r/settings/units", map[string]string{"enable_code": "on", "enable_issues": "on"}), http.StatusSeeOther)
	assert.Equal(t, issuesUnit.Config, unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: repoB.ID, Type: unit_model.TypeIssues}).Config)
	issues("unit-org-b", http.StatusNotFound)

	// a new repository of B starts without it
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/unit-org-b/repos", &api.CreateRepoOption{Name: "new"}).AddTokenAuth(token), http.StatusCreated)
	newRepo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "unit-org-b", LowerName: "new"})
	unittest.AssertNotExistsBean(t, &repo_model.RepoUnit{RepoID: newRepo.ID, Type: unit_model.TypeIssues})

	// on again: back with its data; the repo admin can turn it off and on
	postOrgUnits(t, owner, "unit-org-b", http.StatusSeeOther, allOrgUnitsBut()...)
	issues("unit-org-b", http.StatusOK)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/unit-org-b/r", &api.EditRepoOption{HasIssues: new(false)}).AddTokenAuth(token), http.StatusOK)
	issues("unit-org-b", http.StatusNotFound)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/unit-org-b/r", &api.EditRepoOption{HasIssues: new(true)}).AddTokenAuth(token), http.StatusOK)
	issues("unit-org-b", http.StatusOK)

	// users' repositories are never restricted: with Issues still Not allowed for organizations, the user turns them
	// off and on
	owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/issues"), http.StatusOK)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", &api.EditRepoOption{HasIssues: new(false)}).AddTokenAuth(token), http.StatusOK)
	owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/issues"), http.StatusNotFound)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", &api.EditRepoOption{HasIssues: new(true)}).AddTokenAuth(token), http.StatusOK)
	owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/issues"), http.StatusOK)
	_ = repoA
}

// B-AC6: org Projects, Packages and Actions follow the organization's units
func TestOrgUnitPolicyOrgFeatures(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)
	defer test.MockVariableValue(&setting.Quota.Enabled, true)()
	defer test.MockVariableValue(&testWebRoutes, routers.NormalRoutes())()

	owner := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWritePackage, auth_model.AccessTokenScopeReadUser)
	createUnitPolicyOrgRepo(t, token, "unit-org-f", "r")
	MakeRequest(t, NewRequestWithBody(t, "PUT", "/api/packages/unit-org-f/generic/p/1.0/f.bin", bytes.NewReader([]byte{1})).AddTokenAuth(token), http.StatusCreated)

	features := func(t *testing.T, want bool) {
		t.Helper()
		status := map[bool]int{true: http.StatusOK, false: http.StatusNotFound}[want]
		owner.MakeRequest(t, NewRequest(t, "GET", "/unit-org-f/-/projects"), status)
		owner.MakeRequest(t, NewRequest(t, "GET", "/unit-org-f/-/packages"), status)
		owner.MakeRequest(t, NewRequest(t, "GET", "/org/unit-org-f/settings/packages"), status)
		MakeRequest(t, NewRequest(t, "GET", "/api/packages/unit-org-f/generic/p/1.0/f.bin").AddTokenAuth(token), status)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/unit-org-f/quota/packages").AddTokenAuth(token), status)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/unit-org-f/quota/artifacts").AddTokenAuth(token), status)
		owner.MakeRequest(t, NewRequest(t, "GET", "/org/unit-org-f/settings/actions/runners"), status)
		owner.MakeRequest(t, NewRequest(t, "GET", "/org/unit-org-f/settings/actions/secrets"), status)
		owner.MakeRequest(t, NewRequest(t, "GET", "/org/unit-org-f/settings/actions/variables"), status)
		owner.MakeRequest(t, NewRequest(t, "GET", "/org/unit-org-f/actions"), status)
		for _, p := range []string{"secrets", "variables", "runners", "runners/registration-token"} {
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/unit-org-f/actions/"+p).AddTokenAuth(token), status)
		}
		// the header tabs follow
		home := owner.MakeRequest(t, NewRequest(t, "GET", "/unit-org-f"), http.StatusOK).Body.String()
		assert.Equal(t, want, strings.Contains(home, "/unit-org-f/-/projects"), "projects tab")
		assert.Equal(t, want, strings.Contains(home, "/unit-org-f/-/packages"), "packages tab")
	}
	features(t, true)

	postOrgUnits(t, owner, "unit-org-f", http.StatusSeeOther, allOrgUnitsBut(unit_model.TypeProjects, unit_model.TypePackages, unit_model.TypeActions)...)
	features(t, false)

	postOrgUnits(t, owner, "unit-org-f", http.StatusSeeOther, allOrgUnitsBut()...)
	features(t, true)
}

// B-AC6: a running task loses its artifact and ID token access once Actions is hidden at any level
func TestOrgUnitPolicyRunningTask(t *testing.T) {
	defer tests.PrepareTestEnv(t, 1)()
	tests.PrepareArtifactsStorage(t)
	defer resetRepoUnitPolicy(t)

	upload := func(status int) {
		t.Helper()
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/actions_pipeline/_apis/pipelines/workflows/791/artifacts", getUploadArtifactRequest{
			Type: "actions_storage",
			Name: "artifact",
		}).AddTokenAuth("8061e833a55f6fc0157c98b883e91fcfeeb1a71a"), status)
	}
	task, err := actions_model.GetTaskByID(db.DefaultContext, 48)
	require.NoError(t, err)
	require.NoError(t, task.LoadAttributes(db.DefaultContext))
	gitCtx, err := actions_service.GenerateGiteaContext(task.Job.Run, task.Job)
	require.NoError(t, err)
	idToken, err := actions_service.CreateAuthorizationToken(task, gitCtx, true, &repo_model.ActionsConfig{})
	require.NoError(t, err)
	idTokenStatus := func(status int) {
		t.Helper()
		MakeRequest(t, NewRequest(t, "GET", "/api/actions/_apis/pipelines/workflows/792/idtoken?placeholder=true").AddTokenAuth(idToken), status)
	}
	var signedUpload string
	createV4 := func(status int) {
		t.Helper()
		resp := MakeRequest(t, NewRequestWithBody(t, "POST", "/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact", toProtoJSON(&actions.CreateArtifactRequest{
			Version: 4, Name: "unit-policy-v4", WorkflowRunBackendId: "792", WorkflowJobRunBackendId: "193",
		})).AddTokenAuth(idToken), status)
		if status == http.StatusOK && signedUpload == "" {
			var created actions.CreateArtifactResponse
			require.NoError(t, protojson.Unmarshal(resp.Body.Bytes(), &created))
			_, path, ok := strings.Cut(created.SignedUploadUrl, "/twirp/")
			require.True(t, ok)
			signedUpload = "/twirp/" + path + "&comp=block"
		}
	}
	both := func(status int) {
		t.Helper()
		createV4(status)
		// a signed v4 upload URL handed out before
		MakeRequest(t, NewRequestWithBody(t, "PUT", signedUpload, strings.NewReader("A")), map[int]int{http.StatusOK: http.StatusCreated, http.StatusNotFound: http.StatusNotFound}[status])
		upload(status)
		idTokenStatus(status)
		// the same task's GITEA_TOKEN on the API
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repositories/4").AddTokenAuth("8061e833a55f6fc0157c98b883e91fcfeeb1a71a"), map[int]int{http.StatusOK: http.StatusOK, http.StatusNotFound: http.StatusUnauthorized}[status])
	}

	// the tasks run in user5/repo4; a repository admin turning Actions off leaves running tasks alone, as upstream
	both(http.StatusOK)
	_, err = db.GetEngine(db.DefaultContext).Exec("DELETE FROM repo_unit WHERE repo_id = 4 AND type = ?", unit_model.TypeActions)
	require.NoError(t, err)
	both(http.StatusOK)

	// app.ini DISABLED_REPO_UNITS
	disabled := unit_model.DisabledRepoUnitsGet()
	defer unit_model.DisabledRepoUnitsSet(disabled)
	unit_model.DisabledRepoUnitsSet(append(slices.Clone(disabled), unit_model.TypeActions))
	both(http.StatusNotFound)
	unit_model.DisabledRepoUnitsSet(disabled)
	both(http.StatusOK)

	// move it into org3
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET owner_id = 3 WHERE id = 4")
	require.NoError(t, err)
	both(http.StatusOK)

	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	require.NoError(t, repo_model.SetOrgUnits(db.DefaultContext, org3, 2, map[unit_model.Type]bool{unit_model.TypeActions: false}))
	both(http.StatusNotFound)
	require.NoError(t, repo_model.SetOrgUnits(db.DefaultContext, org3, 2, map[unit_model.Type]bool{unit_model.TypeActions: true}))
	both(http.StatusOK)

	// Not allowed by the site
	denyRepoUnits(t, nil, unit_model.TypeActions)
	both(http.StatusNotFound)
}

// Must-fix 2 of the PR B review: trashing an organization keeps its rows, purging it deletes them
func TestOrgUnitPolicyPurge(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "unit-org-gone"}).AddTokenAuth(token), http.StatusCreated)
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "unit-org-gone"})
	require.NoError(t, repo_model.SetOrgUnits(db.DefaultContext, org, 2, map[unit_model.Type]bool{unit_model.TypeWiki: false}))

	require.NoError(t, org_service.TrashOrganization(db.DefaultContext, admin, organization.OrgFromUser(org)))
	unittest.AssertExistsAndLoadBean(t, &repo_model.OrgUnit{OrgID: org.ID})
	require.NoError(t, trash_service.PurgeOrg(db.DefaultContext, admin, org.ID))
	unittest.AssertNotExistsBean(t, &repo_model.OrgUnit{OrgID: org.ID})
}

// Must-fix 1 of the PR B review: an organization's off units are read once per request, whatever the page asks
func TestOrgUnitPolicyQueries(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)

	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	repo_model.HiddenUnits(db.DefaultContext, org3) // warm up the settings cache
	for _, rows := range []bool{false, true} {
		if rows {
			require.NoError(t, repo_model.SetOrgUnits(db.DefaultContext, org3, 2, map[unit_model.Type]bool{unit_model.TypeWiki: false}))
		}
		// whether any org turned a unit off, then (only if so) the org's rows, once per request
		ctx := cache.WithCacheContext(db.DefaultContext)
		assert.EqualValues(t, map[bool]int{false: 1, true: 2}[rows], countQueries(t, func() {
			for range 5 {
				repo_model.HiddenUnits(ctx, org3)
			}
		}), "rows: %v", rows)
	}

	// a whole org page reads the org's rows once
	session := loginUser(t, "user2")
	session.MakeRequest(t, NewRequest(t, "GET", "/org3/-/projects"), http.StatusOK)
	withRows := stableQueryCount(t, func() { session.MakeRequest(t, NewRequest(t, "GET", "/org3/-/projects"), http.StatusOK) })
	_, err := db.GetEngine(db.DefaultContext).Exec("DELETE FROM org_unit")
	require.NoError(t, err)
	withoutRows := stableQueryCount(t, func() { session.MakeRequest(t, NewRequest(t, "GET", "/org3/-/projects"), http.StatusOK) })
	assert.Equal(t, withoutRows+1, withRows)
}

// The org settings menu links Packages and Actions only while their routes accept the owner
func TestOrgSettingsMenuHiddenUnits(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)

	owner := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
	createUnitPolicyOrgRepo(t, token, "unit-org-m", "r")

	menu := func(t *testing.T, wantPackages, wantActions bool) {
		t.Helper()
		page := owner.MakeRequest(t, NewRequest(t, "GET", "/org/unit-org-m/settings"), http.StatusOK).Body.String()
		assert.Equal(t, wantPackages, strings.Contains(page, `href="/org/unit-org-m/settings/packages"`), "packages item")
		assert.Equal(t, wantActions, strings.Contains(page, `href="/org/unit-org-m/settings/actions/runners"`), "actions item")
	}
	menu(t, true, true)

	// each unit alone, by site policy and by the org's Units setting
	for _, hidden := range []unit_model.Type{unit_model.TypePackages, unit_model.TypeActions} {
		wantPackages, wantActions := hidden != unit_model.TypePackages, hidden != unit_model.TypeActions
		t.Run("site policy "+unit_model.Units[hidden].NameKey, func(t *testing.T) {
			defer denyRepoUnits(t, nil, hidden)()
			menu(t, wantPackages, wantActions)
		})
		t.Run("org units "+unit_model.Units[hidden].NameKey, func(t *testing.T) {
			postOrgUnits(t, owner, "unit-org-m", http.StatusSeeOther, allOrgUnitsBut(hidden)...)
			menu(t, wantPackages, wantActions)
			postOrgUnits(t, owner, "unit-org-m", http.StatusSeeOther, allOrgUnitsBut()...)
		})
		menu(t, true, true)
	}

	t.Run("both", func(t *testing.T) {
		defer denyRepoUnits(t, nil, unit_model.TypePackages, unit_model.TypeActions)()
		menu(t, false, false)
	})

	t.Run("app.ini", func(t *testing.T) {
		t.Run("packages", func(t *testing.T) {
			defer test.MockVariableValue(&setting.Packages.Enabled, false)()
			menu(t, false, true)
		})
		t.Run("actions", func(t *testing.T) {
			defer test.MockVariableValue(&setting.Actions.Enabled, false)()
			menu(t, true, false)
		})
	})
}

// The Actions tab of the org pages is shown only while the org Actions page accepts the member
func TestOrgMenuHiddenUnits(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)

	owner := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
	createUnitPolicyOrgRepo(t, token, "unit-org-n", "r")

	tab := func(t *testing.T, want bool) {
		t.Helper()
		page := owner.MakeRequest(t, NewRequest(t, "GET", "/unit-org-n"), http.StatusOK).Body.String()
		assert.Equal(t, want, strings.Contains(page, `href="/org/unit-org-n/actions"`), "actions tab")
		status := map[bool]int{true: http.StatusOK, false: http.StatusNotFound}[want]
		owner.MakeRequest(t, NewRequest(t, "GET", "/org/unit-org-n/actions"), status)
	}
	tab(t, true)

	t.Run("site policy", func(t *testing.T) {
		defer denyRepoUnits(t, nil, unit_model.TypeActions)()
		tab(t, false)
	})
	t.Run("site policy other unit", func(t *testing.T) {
		defer denyRepoUnits(t, nil, unit_model.TypePackages)()
		tab(t, true)
	})
	t.Run("org units", func(t *testing.T) {
		postOrgUnits(t, owner, "unit-org-n", http.StatusSeeOther, allOrgUnitsBut(unit_model.TypeActions)...)
		tab(t, false)
		postOrgUnits(t, owner, "unit-org-n", http.StatusSeeOther, allOrgUnitsBut(unit_model.TypePackages)...)
		tab(t, true)
		postOrgUnits(t, owner, "unit-org-n", http.StatusSeeOther, allOrgUnitsBut()...)
	})
	t.Run("app.ini", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Actions.Enabled, false)()
		tab(t, false)
	})
	tab(t, true)
}
