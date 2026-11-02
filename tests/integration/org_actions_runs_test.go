// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"

	actions_model "forgejo.org/models/actions"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	webhook_module "forgejo.org/modules/webhook"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prepareOrgRuns gives org3's repositories repo3 and repo5 (private) and repo21 (id 32, public) an Actions unit and
// runs, lets team1 (user4) read the Actions of repo3, and returns the run of each repository by repository ID.
func prepareOrgRuns(t *testing.T) map[int64]*actions_model.ActionRun {
	t.Helper()
	ctx := db.DefaultContext
	runs := map[int64]*actions_model.ActionRun{}
	for i, id := range []int64{3, 5, 32} {
		require.NoError(t, db.Insert(ctx, &repo_model.RepoUnit{RepoID: id, Type: unit.TypeActions, Config: &repo_model.ActionsConfig{}}))
		run := &actions_model.ActionRun{
			Title: fmt.Sprintf("run %d", id), RepoID: id, OwnerID: 3, WorkflowID: fmt.Sprintf("wf%d.yaml", id), Index: int64(100 + i),
			TriggerUserID: 2, Ref: "refs/heads/main", CommitSHA: "c2d72f548424103f01ee1dc02889c1e2bff816b0",
			Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusSuccess,
		}
		require.NoError(t, db.Insert(ctx, run))
		runs[id] = run
	}
	require.NoError(t, db.Insert(ctx, &organization.TeamUnit{OrgID: 3, TeamID: 2, Type: unit.TypeActions, AccessMode: 1}))
	// repo5 has a failed pull request run by user4
	_, err := db.GetEngine(ctx).Exec("UPDATE action_run SET status = ?, event = ?, trigger_event = ?, ref = ?, trigger_user_id = ? WHERE id = ?",
		actions_model.StatusFailure, webhook_module.HookEventPullRequest, "pull_request", "refs/pull/7/head", 4, runs[5].ID)
	require.NoError(t, err)
	return runs
}

func orgRunRows(t *testing.T, session *TestSession, query string) *HTMLDoc {
	t.Helper()
	return NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions"+query), http.StatusOK).Body)
}

func orgRunRepos(doc *HTMLDoc) []string {
	var repos []string
	doc.Find("table.org-runs tbody tr").Each(func(_ int, s *goquery.Selection) {
		repos = append(repos, s.AttrOr("data-repo", ""))
	})
	return repos
}

func apiOrgRuns(t *testing.T, token, query string, status int) *api.ListActionRunSummaryResponse {
	t.Helper()
	resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/actions/runs"+query).AddTokenAuth(token), status)
	var list api.ListActionRunSummaryResponse
	if status == http.StatusOK {
		DecodeJSON(t, resp, &list)
	}
	return &list
}

func TestOrgActionsRunsPage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareOrgRuns(t)

	t.Run("owner sees every repository, with all columns", func(t *testing.T) {
		doc := orgRunRows(t, loginUser(t, "user2"), "")
		assert.ElementsMatch(t, []string{"org3/repo3", "org3/repo5", "org3/repo21"}, orgRunRepos(doc))
		row := doc.Find(`table.org-runs tbody tr[data-repo="org3/repo5"]`)
		for _, cell := range []string{"org3/repo5", "wf5.yaml", "#7", "pull_request", "Failure", "user4"} {
			assert.Contains(t, row.Text(), cell)
		}
		link, _ := row.Find("a.run-link").Attr("href")
		assert.Equal(t, "/org3/repo5/actions/runs/101", link)
	})

	t.Run("a member sees only the repositories they can read", func(t *testing.T) {
		// user4: team1 reads repo3's Actions, repo5 is out of reach, and the public repo21 is readable by every member
		assert.ElementsMatch(t, []string{"org3/repo3", "org3/repo21"}, orgRunRepos(orgRunRows(t, loginUser(t, "user4"), "")))
	})

	t.Run("who may open it", func(t *testing.T) {
		require.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).Visibility.IsPublic(), "a PUBLIC org: only membership keeps user5 out")
		loginUser(t, "user5").MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions"), http.StatusNotFound) // signed in, not a member
		MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions"), http.StatusSeeOther)                       // anonymous
		// a site admin who isn't a member sees everything (and so does the count)
		assert.Len(t, orgRunRepos(orgRunRows(t, loginUser(t, "user1"), "")), 3)
	})

	t.Run("filters combine", func(t *testing.T) {
		session := loginUser(t, "user2")
		for query, want := range map[string][]string{
			"?status=failure":                       {"org3/repo5"},
			"?event=push":                           {"org3/repo3", "org3/repo21"},
			"?event=push&event=pull_request":        {"org3/repo3", "org3/repo5", "org3/repo21"},
			"?repo=repo3":                           {"org3/repo3"},
			"?workflow_id=wf5.yaml":                 {"org3/repo5"},
			"?branch=main":                          {"org3/repo3", "org3/repo21"},
			"?actor=user4":                          {"org3/repo5"},
			"?actor=user4&status=success":           nil,
			"?actor=nobody":                         nil,
			"?repo=nope":                            nil,
			"?from=2999-01-01":                      nil,
			"?to=2000-01-01":                        nil,
			"?from=2000-01-01&to=2999-01-01&repo=5": nil, // a repository name is exact, not a substring
		} {
			assert.ElementsMatch(t, want, orgRunRepos(orgRunRows(t, session, query)), query)
		}
		session.MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions?status=bogus"), http.StatusBadRequest)
		session.MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions?from=yesterday"), http.StatusBadRequest)
	})

	t.Run("paging", func(t *testing.T) {
		session := loginUser(t, "user2")
		var all []string
		for page := 1; page <= 3; page++ {
			repos := orgRunRepos(orgRunRows(t, session, "?limit=1&page="+strconv.Itoa(page)))
			assert.Len(t, repos, 1)
			all = append(all, repos...)
		}
		assert.ElementsMatch(t, []string{"org3/repo3", "org3/repo5", "org3/repo21"}, all)
		assert.Empty(t, orgRunRepos(orgRunRows(t, session, "?limit=1&page=4")))
	})

	t.Run("trashed repository", func(t *testing.T) {
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 32")
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET trashed_unix = 0 WHERE id = 32")
			require.NoError(t, err)
		}()
		assert.ElementsMatch(t, []string{"org3/repo3", "org3/repo5"}, orgRunRepos(orgRunRows(t, loginUser(t, "user2"), "")))
		assert.ElementsMatch(t, []string{"org3/repo3", "org3/repo5"}, orgRunRepos(orgRunRows(t, loginUser(t, "user1"), "")))
	})

	t.Run("actions disabled on a repository", func(t *testing.T) {
		_, err := db.GetEngine(db.DefaultContext).Exec("DELETE FROM repo_unit WHERE repo_id = 5 AND type = ?", unit.TypeActions)
		require.NoError(t, err)
		assert.NotContains(t, orgRunRepos(orgRunRows(t, loginUser(t, "user2"), "")), "org3/repo5")
	})
}

func TestOrgActionsRunsButtons(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	runs := prepareOrgRuns(t)
	// user4 reads repo3's Actions, user2 owns the org
	hasButton := func(doc *HTMLDoc, repo, action string) bool {
		return doc.Find(fmt.Sprintf(`table.org-runs tbody tr[data-repo="%s"] button.link-action[data-url$="/%s"]`, repo, action)).Length() > 0
	}
	owner := orgRunRows(t, loginUser(t, "user2"), "")
	assert.True(t, hasButton(owner, "org3/repo3", "rerun"), "a finished run can be rerun")
	assert.False(t, hasButton(owner, "org3/repo3", "cancel"))
	reader := orgRunRows(t, loginUser(t, "user4"), "")
	assert.False(t, hasButton(reader, "org3/repo3", "rerun"))
	assert.False(t, hasButton(reader, "org3/repo3", "cancel"))

	// the buttons only point at the repository routes, which refuse a reader
	link := fmt.Sprintf("/org3/repo3/actions/runs/%d/rerun", runs[3].Index)
	loginUser(t, "user4").MakeRequest(t, NewRequest(t, "POST", link), http.StatusNotFound)

	// a running run offers cancel, not rerun
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE action_run SET status = ? WHERE id = ?", actions_model.StatusRunning, runs[3].ID)
	require.NoError(t, err)
	owner = orgRunRows(t, loginUser(t, "user2"), "")
	assert.True(t, hasButton(owner, "org3/repo3", "cancel"))
	assert.False(t, hasButton(owner, "org3/repo3", "rerun"))

	// no buttons on an archived repository
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET is_archived = ? WHERE id = 3", true)
	require.NoError(t, err)
	owner = orgRunRows(t, loginUser(t, "user2"), "")
	assert.False(t, hasButton(owner, "org3/repo3", "cancel"))
	assert.True(t, hasButton(owner, "org3/repo5", "rerun"))
}

func TestAPIOrgActionsRuns(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareOrgRuns(t)

	repoNames := func(list *api.ListActionRunSummaryResponse) []string {
		var names []string
		for _, r := range list.Entries {
			names = append(names, r.Repo.FullName)
		}
		return names
	}
	read := []auth_model.AccessTokenScope{auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository}
	ownerToken := getUserToken(t, "user2", read...)

	t.Run("parity with the page", func(t *testing.T) {
		for _, query := range []string{"", "?status=failure", "?event=push", "?repo=repo3", "?actor=user4", "?branch=main", "?workflow_id=wf5.yaml", "?limit=2&page=2"} {
			list := apiOrgRuns(t, ownerToken, query, http.StatusOK)
			assert.ElementsMatch(t, orgRunRepos(orgRunRows(t, loginUser(t, "user2"), query)), repoNames(list), query)
		}
		list := apiOrgRuns(t, ownerToken, "?limit=2", http.StatusOK)
		assert.EqualValues(t, 3, list.TotalCount)
		assert.Len(t, list.Entries, 2)
		assert.Empty(t, apiOrgRuns(t, ownerToken, "?actor=nobody", http.StatusOK).Entries)
		assert.Empty(t, apiOrgRuns(t, ownerToken, "?repo=nope", http.StatusOK).Entries)
		apiOrgRuns(t, ownerToken, "?status=bogus", http.StatusBadRequest)
	})

	t.Run("lean output", func(t *testing.T) {
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/actions/runs?repo=repo5").AddTokenAuth(ownerToken), http.StatusOK)
		var raw struct {
			Entries []map[string]any `json:"workflow_runs"`
		}
		DecodeJSON(t, resp, &raw)
		require.Len(t, raw.Entries, 1)
		for _, key := range []string{"event_payload", "approved_by"} {
			assert.NotContains(t, raw.Entries[0], key)
		}
		assert.Equal(t, "pull_request", raw.Entries[0]["event"])
		assert.Equal(t, "#7", raw.Entries[0]["prettyref"])
		assert.NotEmpty(t, raw.Entries[0]["html_url"])
	})

	t.Run("who may read", func(t *testing.T) {
		// a member only gets what they can read
		member := getUserToken(t, "user4", read...)
		assert.ElementsMatch(t, []string{"org3/repo3", "org3/repo21"}, repoNames(apiOrgRuns(t, member, "", http.StatusOK)))
		// not a member
		apiOrgRuns(t, getUserToken(t, "user5", read...), "", http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/actions/runs"), http.StatusUnauthorized)
		// read:organization alone doesn't unlock the runs of private repositories
		apiOrgRuns(t, getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization), "", http.StatusForbidden)
		apiOrgRuns(t, getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository), "", http.StatusForbidden)
	})

	t.Run("restricted tokens", func(t *testing.T) {
		publicOnly := getUserToken(t, "user2", auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository)
		assert.Equal(t, []string{"org3/repo21"}, repoNames(apiOrgRuns(t, publicOnly, "", http.StatusOK)))
		specific := createFineGrainedRepoAccessToken(t, "user2", read, []int64{3})
		assert.ElementsMatch(t, []string{"org3/repo3", "org3/repo21"}, repoNames(apiOrgRuns(t, specific, "", http.StatusOK)))
		// a site admin's restricted token doesn't act as a site admin: it needs membership, and then it is limited too
		adminSpecific := createFineGrainedRepoAccessToken(t, "user1", read, []int64{3})
		apiOrgRuns(t, adminSpecific, "", http.StatusForbidden)
		require.NoError(t, db.Insert(db.DefaultContext, &organization.OrgUser{OrgID: 3, UID: 1}))
		require.NoError(t, db.Insert(db.DefaultContext, &organization.TeamUser{OrgID: 3, TeamID: 1, UID: 1}))
		assert.ElementsMatch(t, []string{"org3/repo3", "org3/repo21"}, repoNames(apiOrgRuns(t, adminSpecific, "", http.StatusOK)))
	})
}

// The number of queries depends on the repositories on a page, not on the runs, actors or the number of pages.
func TestOrgActionsRunsQueryCount(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareOrgRuns(t)
	ctx := db.DefaultContext
	owner := loginUser(t, "user2")
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository)

	count := func() (web, apiCount int64) {
		web = stableQueryCount(t, func() { owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions?limit=50"), http.StatusOK) })
		apiCount = stableQueryCount(t, func() {
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/actions/runs?limit=50").AddTokenAuth(token), http.StatusOK)
		})
		return web, apiCount
	}
	// once, as ToUser saves a generated avatar the first time it renders a user
	count()
	web1, api1 := count()
	for i := range 20 {
		repoID := []int64{3, 5, 32}[i%3]
		require.NoError(t, db.Insert(ctx, &actions_model.ActionRun{
			Title: "more", RepoID: repoID, OwnerID: 3, WorkflowID: "more.yaml", Index: int64(1000 + i), TriggerUserID: int64(1 + i%4),
			Ref: "refs/heads/main", Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusSuccess,
		}))
	}
	count() // new actors
	web2, api2 := count()
	assert.Equal(t, web1, web2)
	assert.Equal(t, api1, api2)
}

func TestOrgActionsRunsPageSizeClamp(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareOrgRuns(t)
	for i := range setting.API.MaxResponseItems + 5 {
		require.NoError(t, db.Insert(db.DefaultContext, &actions_model.ActionRun{
			Title: "more", RepoID: 3, OwnerID: 3, WorkflowID: "more.yaml", Index: int64(1000 + i), TriggerUserID: 2,
			Ref: "refs/heads/main", Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusSuccess,
		}))
	}
	session := loginUser(t, "user2")
	assert.Len(t, orgRunRepos(orgRunRows(t, session, "?limit=100000")), setting.API.MaxResponseItems)
	assert.Len(t, apiOrgRuns(t, getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository), "?limit=100000", http.StatusOK).Entries, setting.API.MaxResponseItems)
}

func TestOrgActionsRunsActionsDisabled(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareOrgRuns(t)
	defer test.MockVariableValue(&setting.Actions.Enabled, false)()
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository)
	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions"), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/actions/runs").AddTokenAuth(token), http.StatusNotFound)
}
