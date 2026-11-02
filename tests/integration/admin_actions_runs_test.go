// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	webhook_module "forgejo.org/modules/webhook"
	"forgejo.org/routers/web/admin"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prepareInstanceRuns adds to prepareOrgRuns a run of user2/repo1 (public, a stale owner_id) and a run of
// user2/repo2, which is in the trash.
func prepareInstanceRuns(t *testing.T) {
	t.Helper()
	ctx := db.DefaultContext
	_, err := db.GetEngine(ctx).Exec("DELETE FROM action_run") // the fixtures' runs are in other repositories
	require.NoError(t, err)
	prepareOrgRuns(t)
	for i, id := range []int64{1, 2} {
		require.NoError(t, db.Insert(ctx, &repo_model.RepoUnit{RepoID: id, Type: unit.TypeActions, Config: &repo_model.ActionsConfig{}}))
		require.NoError(t, db.Insert(ctx, &actions_model.ActionRun{
			Title: fmt.Sprintf("run %d", id), RepoID: id, OwnerID: 999, WorkflowID: "u.yaml", Index: int64(200 + i),
			TriggerUserID: 2, Ref: "refs/heads/main", Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusFailure,
		}))
	}
	_, err = db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 2")
	require.NoError(t, err)
}

func adminRunRows(t *testing.T, session *TestSession, query string) []string {
	t.Helper()
	return orgRunRepos(NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/admin/actions/runs"+query), http.StatusOK).Body))
}

func apiAdminRuns(t *testing.T, token, query string, status int) *api.ListActionRunSummaryResponse {
	t.Helper()
	resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/actions/runs"+query).AddTokenAuth(token), status)
	var list api.ListActionRunSummaryResponse
	if status == http.StatusOK {
		DecodeJSON(t, resp, &list)
	}
	return &list
}

func TestAdminActionsRunsPage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareInstanceRuns(t)
	adminSession := loginUser(t, "user1")

	all := []string{"org3/repo3", "org3/repo5", "org3/repo21", "user2/repo1"}
	t.Run("a site admin sees every repository that isn't trashed", func(t *testing.T) {
		assert.ElementsMatch(t, all, adminRunRows(t, adminSession, ""))
	})
	t.Run("filters", func(t *testing.T) {
		for query, want := range map[string][]string{
			"?repo=org3/repo5":           {"org3/repo5"},
			"?repo=ORG3/Repo5":           {"org3/repo5"},
			"?repo=repo1":                {"user2/repo1"},
			"?repo=org3/repo1":           nil,
			"?repo=user2/repo2":          nil, // trashed
			"?status=failure":            {"org3/repo5", "user2/repo1"},
			"?workflow_id=u.yaml":        {"user2/repo1"},
			"?actor=user4":               {"org3/repo5"},
			"?actor=nobody":              nil,
			"?event=push":                {"org3/repo3", "org3/repo21", "user2/repo1"},
			"?status=failure&repo=repo1": {"user2/repo1"},
			"?from=2999-01-01":           nil,
		} {
			assert.ElementsMatch(t, want, adminRunRows(t, adminSession, query), query)
		}
		adminSession.MakeRequest(t, NewRequest(t, "GET", "/admin/actions/runs?status=bogus"), http.StatusBadRequest)
	})
	t.Run("pagination", func(t *testing.T) {
		assert.Len(t, adminRunRows(t, adminSession, "?limit=3"), 3)
		assert.Len(t, adminRunRows(t, adminSession, "?limit=3&page=2"), 1)
	})
	t.Run("buttons", func(t *testing.T) {
		doc := NewHTMLParser(t, adminSession.MakeRequest(t, NewRequest(t, "GET", "/admin/actions/runs"), http.StatusOK).Body)
		assert.Positive(t, doc.Find("table.org-runs button.link-action").Length())
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET is_archived = ? WHERE id = 1", true)
		require.NoError(t, err)
		doc = NewHTMLParser(t, adminSession.MakeRequest(t, NewRequest(t, "GET", "/admin/actions/runs?repo=repo1"), http.StatusOK).Body)
		assert.Zero(t, doc.Find("table.org-runs button.link-action").Length(), "no buttons for an archived repository")
	})
	t.Run("everyone else is refused", func(t *testing.T) {
		for _, name := range []string{"user2" /* owner of org3 */, "user4", "user5"} {
			loginUser(t, name).MakeRequest(t, NewRequest(t, "GET", "/admin/actions/runs"), http.StatusForbidden)
			loginUser(t, name).MakeRequest(t, NewRequest(t, "GET", "/admin/actions/runs/export"), http.StatusForbidden)
			loginUser(t, name).MakeRequest(t, NewRequest(t, "GET", "/admin/actions/usage"), http.StatusForbidden)
		}
		MakeRequest(t, NewRequest(t, "GET", "/admin/actions/runs"), http.StatusSeeOther)
	})
	t.Run("an admin who may not log in is refused", func(t *testing.T) {
		session := loginUser(t, "user1")
		user1 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		user1.ProhibitLogin = true
		require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, user1, "prohibit_login"))
		defer func() {
			user1.ProhibitLogin = false
			require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, user1, "prohibit_login"))
		}()
		for _, path := range []string{"/admin/actions/runs", "/admin/actions/runs/export", "/admin/actions/usage"} {
			resp := session.MakeRequest(t, NewRequest(t, "GET", path), NoExpectedStatus)
			// the session middleware shows its "account suspended" page; nothing of the data
			assert.NotContains(t, resp.Body.String(), "org3/repo3", path)
			assert.Contains(t, resp.Body.String(), "suspended", path)
		}
	})
	t.Run("an inactive admin is refused", func(t *testing.T) {
		session := loginUser(t, "user1")
		user1 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		user1.IsActive = false
		require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, user1, "is_active"))
		defer func() {
			user1.IsActive = true
			require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, user1, "is_active"))
		}()
		for _, path := range []string{"/admin/actions/runs", "/admin/actions/runs/export", "/admin/actions/usage"} {
			resp := session.MakeRequest(t, NewRequest(t, "GET", path), NoExpectedStatus)
			assert.NotContains(t, resp.Body.String(), "org3/repo3", path)
			assert.NotContains(t, resp.Body.String(), "unstackable usage", path)
		}
	})
	t.Run("the menu", func(t *testing.T) {
		body := adminSession.MakeRequest(t, NewRequest(t, "GET", "/admin/actions/runs"), http.StatusOK).Body.String()
		assert.Contains(t, body, `href="/admin/actions/runs"`)
		assert.Contains(t, body, `href="/admin/actions/usage"`)
	})
}

func TestAdminActionsRunsActionsDisabled(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareInstanceRuns(t)
	defer test.MockVariableValue(&setting.Actions.Enabled, false)()
	loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", "/admin/actions/runs"), http.StatusNotFound)
	loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", "/admin/actions/usage"), http.StatusNotFound)
}

func TestAPIAdminActionsRuns(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareInstanceRuns(t)
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin, auth_model.AccessTokenScopeReadRepository)
	names := func(l *api.ListActionRunSummaryResponse) []string {
		var out []string
		for _, r := range l.Entries {
			out = append(out, r.Repo.FullName)
		}
		return out
	}

	t.Run("parity with the page", func(t *testing.T) {
		for _, query := range []string{"", "?status=failure", "?event=push", "?repo=org3/repo3", "?repo=repo1", "?actor=user4", "?branch=main", "?workflow_id=u.yaml", "?limit=3&page=2"} {
			assert.ElementsMatch(t, adminRunRows(t, loginUser(t, "user1"), query), names(apiAdminRuns(t, token, query, http.StatusOK)), query)
		}
		list := apiAdminRuns(t, token, "?limit=3", http.StatusOK)
		assert.EqualValues(t, 4, list.TotalCount)
		assert.Len(t, list.Entries, 3)
		assert.Empty(t, apiAdminRuns(t, token, "?actor=nobody", http.StatusOK).Entries)
		assert.Empty(t, apiAdminRuns(t, token, "?repo=nope", http.StatusOK).Entries)
		apiAdminRuns(t, token, "?status=bogus", http.StatusBadRequest)
	})
	t.Run("lean output", func(t *testing.T) {
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/actions/runs?repo=org3/repo5").AddTokenAuth(token), http.StatusOK)
		var raw struct {
			Entries []map[string]any `json:"workflow_runs"`
		}
		DecodeJSON(t, resp, &raw)
		require.Len(t, raw.Entries, 1)
		for _, key := range []string{"event_payload", "approved_by"} {
			assert.NotContains(t, raw.Entries[0], key)
		}
	})
	t.Run("who may read", func(t *testing.T) {
		apiAdminRuns(t, getUserToken(t, "user2", auth_model.AccessTokenScopeReadAdmin), "", http.StatusForbidden) // owner of org3, not a site admin
		apiAdminRuns(t, getUserToken(t, "user1", auth_model.AccessTokenScopeReadRepository), "", http.StatusForbidden)
		// admin scope alone isn't enough: run data is repository data
		apiAdminRuns(t, getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin), "", http.StatusForbidden)
		apiAdminRuns(t, getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin), "", http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/actions/runs"), http.StatusUnauthorized)
	})
	t.Run("an inactive or prohibited admin is refused", func(t *testing.T) {
		user1 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		for _, col := range []string{"is_active", "prohibit_login"} {
			user1.IsActive, user1.ProhibitLogin = col != "is_active", col == "prohibit_login"
			require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, user1, "is_active", "prohibit_login"))
			for _, path := range []string{"/api/v1/admin/actions/runs", "/api/v1/admin/actions/usage?group_by=repo"} {
				resp := MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), NoExpectedStatus)
				assert.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, resp.Code, "%s %s", col, path)
				assert.NotContains(t, resp.Body.String(), "org3/repo3")
			}
		}
		user1.IsActive, user1.ProhibitLogin = true, false
		require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, user1, "is_active", "prohibit_login"))
		apiAdminRuns(t, token, "", http.StatusOK)
	})
	t.Run("restricted tokens", func(t *testing.T) {
		publicOnly := getUserToken(t, "user1", auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeReadAdmin)
		// a restricted token gets no admin override, so it can't act as a site admin
		apiAdminRuns(t, publicOnly, "", http.StatusForbidden)
		specific := createFineGrainedRepoAccessToken(t, "user1", []auth_model.AccessTokenScope{auth_model.AccessTokenScopeReadAdmin}, []int64{3})
		apiAdminRuns(t, specific, "", http.StatusForbidden)
	})
}

// addJob inserts a finished job of repoID that ran for seconds, ending now, on the runner of a new task.
func addAdminJob(t *testing.T, repoID, runnerID int64, started timeutil.TimeStamp, seconds int64, status actions_model.Status) {
	t.Helper()
	job := &actions_model.ActionRunJob{
		RunID: 1, RepoID: repoID, OwnerID: 999, Name: "j", Attempt: 1, Status: status, Started: started, Stopped: started + timeutil.TimeStamp(seconds),
		Handle: fmt.Sprintf("admin-usage-%d-%d-%d", repoID, started, seconds),
	}
	require.NoError(t, db.Insert(db.DefaultContext, job))
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE action_run_job SET updated = ? WHERE id = ?", job.Stopped, job.ID)
	require.NoError(t, err)
	if runnerID != 0 {
		task := &actions_model.ActionTask{JobID: job.ID, RunnerID: runnerID, RepoID: repoID, Status: status, TokenHash: fmt.Sprintf("tok-%s", job.Handle)}
		require.NoError(t, db.Insert(db.DefaultContext, task))
		_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE action_run_job SET task_id = ? WHERE id = ?", task.ID, job.ID)
		require.NoError(t, err)
	}
}

func TestAPIAdminActionsUsage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareInstanceRuns(t)
	now := timeutil.TimeStampNow()
	require.NoError(t, db.Insert(db.DefaultContext, &actions_model.ActionRunner{ID: 911, UUID: "00000000-0000-0000-0000-000000000911", Name: "usage-runner", TokenHash: "usage-it-r"}))
	addAdminJob(t, 3, 911, now-86400*2, 600, actions_model.StatusSuccess)
	addAdminJob(t, 3, 911, now-86400*3, 120, actions_model.StatusFailure)
	addAdminJob(t, 5, 0, now-86400*2, 60, actions_model.StatusSuccess)
	addAdminJob(t, 1, 911, now-86400*4, 300, actions_model.StatusSuccess)
	addAdminJob(t, 2, 911, now-86400*4, 900, actions_model.StatusSuccess)   // trashed
	addAdminJob(t, 3, 911, now-86400*40, 5000, actions_model.StatusSuccess) // outside the default period
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin, auth_model.AccessTokenScopeReadRepository)
	get := func(query string, status int) *api.ActionUsage {
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/actions/usage"+query).AddTokenAuth(token), status)
		var u api.ActionUsage
		if status == http.StatusOK {
			DecodeJSON(t, resp, &u)
		}
		return &u
	}
	byName := func(entries []*api.ActionUsageEntry) map[string]*api.ActionUsageEntry {
		m := map[string]*api.ActionUsageEntry{}
		for _, e := range entries {
			m[e.Name] = e
		}
		return m
	}

	t.Run("totals", func(t *testing.T) {
		u := get("?group_by=repo", http.StatusOK)
		m := byName(u.Entries)
		require.Len(t, m, 3)
		assert.InDelta(t, 12, m["org3/repo3"].JobMinutes, 0.001)
		assert.EqualValues(t, 2, m["org3/repo3"].Jobs)
		assert.EqualValues(t, 1, m["org3/repo3"].FailedJobs)
		assert.InDelta(t, 1, m["org3/repo5"].JobMinutes, 0.001)
		assert.InDelta(t, 5, m["user2/repo1"].JobMinutes, 0.001)
		assert.Equal(t, "org3/repo3", u.TopReposByMinutes[0].Name)
		require.NotEmpty(t, u.TopReposByFailures)
		assert.Equal(t, "user2/repo1", u.TopReposByFailures[0].Name) // the failed runs: repo5 and repo1 one each
		for _, e := range u.TopReposByFailures {
			assert.NotEqual(t, "user2/repo2", e.Name, "trashed")
		}

		m = byName(get("?group_by=org", http.StatusOK).Entries)
		assert.InDelta(t, 13, m["org3"].JobMinutes, 0.001)
		assert.InDelta(t, 5, m["user2"].JobMinutes, 0.001)

		m = byName(get("?group_by=runner", http.StatusOK).Entries)
		assert.InDelta(t, 17, m["usage-runner"].JobMinutes, 0.001)
		assert.InDelta(t, 1, m[""].JobMinutes, 0.001) // no runner
		assert.EqualValues(t, 0, m[""].ID)

		// a longer range takes in the old job
		u = get("?group_by=repo&from="+now.AsTime().AddDate(0, 0, -60).UTC().Format("2006-01-02"), http.StatusOK)
		assert.InDelta(t, 12+5000/60.0, byName(u.Entries)["org3/repo3"].JobMinutes, 0.001)
	})
	t.Run("limit", func(t *testing.T) {
		assert.Len(t, get("?group_by=repo&limit=1", http.StatusOK).Entries, 1)
		assert.LessOrEqual(t, len(get("?group_by=repo&limit=100000", http.StatusOK).Entries), 200)
	})
	t.Run("bad requests", func(t *testing.T) {
		for _, q := range []string{
			"", "?group_by=user", "?group_by=repo&from=nonsense", "?group_by=repo&to=nonsense",
			"?group_by=repo&from=2026-02-02&to=2026-02-01", "?group_by=repo&from=2020-01-01&to=2026-01-01",
		} {
			get(q, http.StatusBadRequest)
		}
	})
	t.Run("who may read", func(t *testing.T) {
		for _, tok := range []string{
			getUserToken(t, "user2", auth_model.AccessTokenScopeReadAdmin, auth_model.AccessTokenScopeReadRepository), // not a site admin
			getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin),
			getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin),
		} {
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/actions/usage?group_by=repo").AddTokenAuth(tok), http.StatusForbidden)
		}
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/actions/usage?group_by=runner").AddTokenAuth(token), http.StatusOK)
		for _, secret := range []string{"uuid", "00000000-0000-0000-0000-000000000911", "token", "usage-it-r"} {
			assert.NotContains(t, resp.Body.String(), secret, "no runner secrets")
		}
		publicOnly := getUserToken(t, "user1", auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeReadAdmin)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/actions/usage?group_by=repo").AddTokenAuth(publicOnly), http.StatusForbidden)
		specific := createFineGrainedRepoAccessToken(t, "user1", []auth_model.AccessTokenScope{auth_model.AccessTokenScopeReadAdmin}, []int64{3})
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/actions/usage?group_by=repo").AddTokenAuth(specific), http.StatusForbidden)
	})
	t.Run("a runner that was deleted is one bucket", func(t *testing.T) {
		addAdminJob(t, 3, 4242, now-3600, 60, actions_model.StatusSuccess)
		addAdminJob(t, 5, 4343, now-3500, 60, actions_model.StatusSuccess)
		var gone *api.ActionUsageEntry
		for _, e := range get("?group_by=runner", http.StatusOK).Entries {
			if e.ID == -1 {
				require.Nil(t, gone, "one entry")
				gone = e
			}
		}
		require.NotNil(t, gone)
		assert.EqualValues(t, 2, gone.Jobs)
	})
	t.Run("the page", func(t *testing.T) {
		session := loginUser(t, "user1")
		for _, q := range []string{"", "?group_by=org", "?group_by=runner"} {
			body := session.MakeRequest(t, NewRequest(t, "GET", "/admin/actions/usage"+q), http.StatusOK).Body.String()
			assert.Contains(t, body, "unstackable usage", q)
		}
		body := session.MakeRequest(t, NewRequest(t, "GET", "/admin/actions/usage?group_by=runner"), http.StatusOK).Body.String()
		assert.Contains(t, body, "usage-runner")
		assert.NotContains(t, body, "00000000-0000-0000-0000-000000000911", "no runner UUID")
		session.MakeRequest(t, NewRequest(t, "GET", "/admin/actions/usage?group_by=bogus"), http.StatusBadRequest)
		session.MakeRequest(t, NewRequest(t, "GET", "/admin/actions/usage?from=2020-01-01"), http.StatusBadRequest)
	})
	t.Run("a job that started before the period but was updated inside it is left out", func(t *testing.T) {
		old := now - 86400*40
		addAdminJob(t, 5, 0, old, 50, actions_model.StatusSuccess)
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE action_run_job SET updated = ? WHERE started = ? AND repo_id = 5", now-86400, old)
		require.NoError(t, err)
		m := byName(get("?group_by=repo", http.StatusOK).Entries)
		assert.InDelta(t, 2, m["org3/repo5"].JobMinutes, 0.001) // 1 min no runner + 1 min of the deleted runner above, not the 50 s job
	})
}

func TestAdminActionsRunsExport(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareInstanceRuns(t)
	session := loginUser(t, "user1")
	titles := []string{"=1+2", "+1", "-1", "@SUM(A1)", "\tx", "\rx", "  =1+2", "\n=1+2", " \n@x", "plain, with \"quotes\""}
	for i, title := range titles {
		require.NoError(t, db.Insert(db.DefaultContext, &actions_model.ActionRun{
			Title: title, RepoID: 3, OwnerID: 3, WorkflowID: "csv.yaml", Index: int64(500 + i), TriggerUserID: 2,
			Ref: "refs/heads/main", Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusSuccess,
		}))
	}
	for i, wf := range []string{"+wf.yaml", "-wf.yaml", " @wf.yaml", "\n=wf.yaml", "\t=wf.yaml", "\r=wf.yaml", " \n +wf.yaml"} {
		require.NoError(t, db.Insert(db.DefaultContext, &actions_model.ActionRun{
			Title: "v", RepoID: 3, OwnerID: 3, WorkflowID: wf, Index: int64(700 + i), TriggerUserID: 2,
			Ref: "refs/heads/main", Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusSuccess,
		}))
	}
	require.NoError(t, db.Insert(db.DefaultContext, &actions_model.ActionRun{
		Title: "t", RepoID: 3, OwnerID: 3, WorkflowID: "=wf.yaml", Index: 600, TriggerUserID: 2,
		Ref: "refs/heads/@b", Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusSuccess,
	}))
	read := func(query string) ([][]string, *http.Response) {
		resp := session.MakeRequest(t, NewRequest(t, "GET", "/admin/actions/runs/export"+query), http.StatusOK)
		rows, err := csv.NewReader(strings.NewReader(resp.Body.String())).ReadAll()
		require.NoError(t, err)
		return rows, resp.Result()
	}

	t.Run("headers", func(t *testing.T) {
		_, res := read("")
		assert.Equal(t, "text/csv; charset=utf-8", res.Header.Get("Content-Type"))
		assert.Contains(t, res.Header.Get("Content-Disposition"), `filename="actions-runs.csv"`)
		assert.Equal(t, "nosniff", res.Header.Get("X-Content-Type-Options"))
		assert.Empty(t, res.Header.Get("X-Truncated"))
	})
	t.Run("same rows as the page", func(t *testing.T) {
		rows, _ := read("")
		assert.Len(t, rows, 1+4+len(titles)+1+7)
		rows, _ = read("?repo=org3/repo5")
		require.Len(t, rows, 2)
		assert.Equal(t, "org3/repo5", rows[1][1])
		assert.Equal(t, "failure", rows[1][7])
		for _, r := range rows[1:] {
			assert.NotEqual(t, "user2/repo2", r[1], "trashed")
		}
		rows, _ = read("?status=failure")
		assert.Len(t, rows, 3)
		session.MakeRequest(t, NewRequest(t, "GET", "/admin/actions/runs/export?status=bogus"), http.StatusBadRequest)
	})
	t.Run("cells cannot start a formula", func(t *testing.T) {
		rows, _ := read("?workflow_id=csv.yaml")
		require.Len(t, rows, 1+len(titles))
		got := map[string]bool{}
		for _, r := range rows[1:] {
			got[r[4]] = true
			assert.NotContains(t, "=+-@\t\r\n", string(strings.TrimLeft(r[4], " \n")[0]), "title %q", r[4])
		}
		for _, title := range titles[:9] {
			assert.True(t, got["'"+title], "%q", title)
		}
		assert.True(t, got[titles[9]])
	})
	t.Run("no cell of any column can start a formula", func(t *testing.T) {
		rows, _ := read("")
		for _, r := range rows {
			for _, cell := range r {
				if trimmed := strings.TrimLeft(cell, " \n"); trimmed != "" {
					assert.NotContains(t, "=+-@\t\r\n", string(trimmed[0]), "%q", cell)
				}
			}
		}
		rows, _ = read("?actor=user2&workflow_id=%2Bwf.yaml")
		require.Len(t, rows, 2)
		assert.Equal(t, "'+wf.yaml", rows[1][2])
		rows, _ = read("?branch=@b")
		require.Len(t, rows, 2)
		assert.Equal(t, "'=wf.yaml", rows[1][2])
		assert.Equal(t, "'@b", rows[1][5])
	})
	t.Run("capped", func(t *testing.T) {
		defer test.MockVariableValue(&admin.RunsExportMax, 3)()
		rows, res := read("")
		assert.Len(t, rows, 1+3)
		assert.Equal(t, "true", res.Header.Get("X-Truncated"))
	})
}

// The number of queries doesn't grow with the runs, repositories, owners or actors.
func TestAdminActionsRunsQueryCount(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareInstanceRuns(t)
	session := loginUser(t, "user1")
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin, auth_model.AccessTokenScopeReadRepository)
	now := timeutil.TimeStampNow()
	addAdminJob(t, 3, 0, now-100, 10, actions_model.StatusSuccess)

	paths := []string{
		"/admin/actions/runs?limit=50", "/admin/actions/runs/export", "/admin/actions/usage?group_by=repo", "/admin/actions/usage?group_by=org", "/admin/actions/usage?group_by=runner",
	}
	apiPaths := []string{"/api/v1/admin/actions/runs?limit=50", "/api/v1/admin/actions/usage?group_by=repo", "/api/v1/admin/actions/usage?group_by=runner"}
	stable := func(f func()) int64 { return stableQueryCount(t, f) }
	count := func() (counts []int64) {
		for _, p := range paths {
			counts = append(counts, stable(func() { session.MakeRequest(t, NewRequest(t, "GET", p), http.StatusOK) }))
		}
		for _, p := range apiPaths {
			counts = append(counts, stable(func() { MakeRequest(t, NewRequest(t, "GET", p).AddTokenAuth(token), http.StatusOK) }))
		}
		return counts
	}
	count() // once, as ToUser saves a generated avatar the first time it renders a user
	before := count()

	ctx := db.DefaultContext
	for i := range 20 {
		repoID := []int64{3, 5, 32, 1}[i%4]
		require.NoError(t, db.Insert(ctx, &actions_model.ActionRun{
			Title: "more", RepoID: repoID, OwnerID: 3, WorkflowID: "more.yaml", Index: int64(1000 + i), TriggerUserID: int64(1 + i%4),
			Ref: "refs/heads/main", Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusFailure,
		}))
		addAdminJob(t, repoID, int64(0), now-int64ToTS(i+1)*60, int64(30+i), actions_model.StatusSuccess)
	}
	count() // new actors
	assert.Equal(t, before, count())
}

func int64ToTS(i int) timeutil.TimeStamp { return timeutil.TimeStamp(i) }

// A page and the endpoints only read, so maintenance mode needs no entry for them.
func TestAdminActionsRunsGetOnly(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user1")
	for _, p := range []string{"/admin/actions/runs", "/admin/actions/runs/export", "/admin/actions/usage"} {
		resp := session.MakeRequest(t, NewRequest(t, "POST", p), NoExpectedStatus)
		assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, resp.Code, p)
	}
}

func TestOrgActionsRunsMemberNeverSeesOtherOwners(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareInstanceRuns(t) // user2/repo1 (public) has a run too
	for _, name := range []string{"user2", "user4"} {
		repos := orgRunRepos(orgRunRows(t, loginUser(t, name), ""))
		assert.NotEmpty(t, repos)
		for _, repo := range repos {
			assert.True(t, strings.HasPrefix(repo, "org3/"), "%s: %s", name, repo)
		}
		token := getUserToken(t, name, auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository)
		for _, e := range apiOrgRuns(t, token, "?repo=user2/repo1", http.StatusOK).Entries {
			t.Errorf("%s got %s", name, e.Repo.FullName)
		}
		for _, e := range apiOrgRuns(t, token, "", http.StatusOK).Entries {
			assert.True(t, strings.HasPrefix(e.Repo.FullName, "org3/"), "%s: %s", name, e.Repo.FullName)
		}
	}
}

// The pages only read, so they work in read-only maintenance mode.
func TestAdminActionsRunsMaintenanceReadOnly(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareInstanceRuns(t)
	session := loginUser(t, "user1")
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin, auth_model.AccessTokenScopeReadRepository)
	defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()
	for _, path := range []string{"/admin/actions/runs", "/admin/actions/runs/export", "/admin/actions/usage?group_by=repo"} {
		session.MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK)
	}
	for _, path := range []string{"/api/v1/admin/actions/runs", "/api/v1/admin/actions/usage?group_by=org"} {
		MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusOK)
	}
}
