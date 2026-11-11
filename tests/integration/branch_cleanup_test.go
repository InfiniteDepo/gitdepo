// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/cron"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bcPost(t *testing.T, s *TestSession, link string, values map[string]string, expected int) {
	t.Helper()
	s.MakeRequest(t, NewRequestWithValues(t, "POST", link, values), expected)
}

// bcSubmitTurnOn submits the "Turn on cleanup" form of a preview page exactly as it is rendered (its action and its
// fields are read from the page), so a renamed field is caught.
func bcSubmitTurnOn(t *testing.T, s *TestSession, previewLink string, expected int) {
	t.Helper()
	doc := NewHTMLParser(t, s.MakeRequest(t, NewRequest(t, "GET", previewLink), http.StatusOK).Body)
	form := doc.Find(`form[action="` + strings.SplitN(previewLink, "?", 2)[0] + `"]`).Last()
	require.Equal(t, 1, form.Length(), "turn-on form")
	values := map[string]string{}
	form.Find("input").Each(func(_ int, in *goquery.Selection) {
		if n, ok := in.Attr("name"); ok {
			values[n], _ = in.Attr("value")
		}
	})
	require.Contains(t, values, "cleanup_days")
	s.MakeRequest(t, NewRequestWithValues(t, "POST", form.AttrOr("action", ""), values), expected)
}

// bcAge makes every branch row of repo older than the given days.
func bcAge(t *testing.T, repo *repo_model.Repository, days int) {
	t.Helper()
	_, err := db.GetEngine(t.Context()).Exec("UPDATE branch SET updated_unix = ? WHERE repo_id = ?", time.Now().AddDate(0, 0, -days).Unix(), repo.ID)
	require.NoError(t, err)
}

func TestBranchCleanupSettings(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		owner := loginUser(t, "user2")
		reader := loginUser(t, "user4")
		repo := bwRepo(t, "bc-settings")
		repoPage := path.Join("/org3", repo, "settings/branch_workflow")
		repoLink := path.Join("/org3", repo, "settings/branch_workflow/cleanup")
		orgLink := "/org/org3/settings/branch_workflow/cleanup"

		bcPost(t, owner, repoLink, map[string]string{"cleanup_days": "30"}, http.StatusSeeOther)
		resp := owner.MakeRequest(t, NewRequest(t, "GET", repoPage), http.StatusOK)
		assert.Contains(t, resp.Body.String(), `name="cleanup_days"`)
		assert.Contains(t, resp.Body.String(), "7 days")

		// invalid days change nothing
		for _, d := range []string{"abc", "3651", "-1"} {
			bcPost(t, owner, repoLink, map[string]string{"cleanup_days": d}, http.StatusSeeOther)
			assert.NotEmpty(t, bwFlash(owner), d)
		}
		r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", LowerName: repo})
		cfg := r.MustGetUnit(t.Context(), 3).PullRequestsConfig()
		require.NotNil(t, cfg.BranchCleanup)
		assert.Equal(t, 30, cfg.BranchCleanup.Days)

		// the setting is audited
		e := auditActions(t, 0, "repo.branch_workflow.changed")
		assert.NotEmpty(t, e)

		// readers see nothing
		reader.MakeRequest(t, NewRequest(t, "GET", repoLink), http.StatusNotFound)
		bcPost(t, reader, repoLink, map[string]string{"cleanup_days": "5"}, http.StatusNotFound)
		reader.MakeRequest(t, NewRequest(t, "GET", orgLink), http.StatusNotFound)
		bcPost(t, reader, orgLink, map[string]string{"cleanup_days": "5"}, http.StatusNotFound)

		// an organization lock stops the repository's own setting
		bcPost(t, owner, orgLink, map[string]string{"cleanup_days": "60", "cleanup_enforce": "on"}, http.StatusSeeOther)
		bcPost(t, owner, repoLink, map[string]string{"cleanup_days": "10"}, http.StatusForbidden)
		resp = owner.MakeRequest(t, NewRequest(t, "GET", repoPage), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "disabled")
		bcPost(t, owner, orgLink, map[string]string{"cleanup_days": "60"}, http.StatusSeeOther)
		bcPost(t, owner, repoLink, map[string]string{"cleanup_days": "10"}, http.StatusSeeOther)
		bcPost(t, owner, orgLink, map[string]string{"cleanup_days": "abc"}, http.StatusSeeOther)
		assert.NotEmpty(t, bwFlash(owner))

		assert.NotNil(t, cron.GetTask(repo_service.CleanupTaskName))
	})
}

func auditSinceID(t *testing.T) int64 {
	t.Helper()
	var id int64
	_, err := db.GetEngine(t.Context()).Table("audit_event").Select("COALESCE(MAX(id), 0)").Get(&id)
	require.NoError(t, err)
	return id
}

func TestBranchCleanupPreviewAndRun(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		s := loginUser(t, "user2")
		reader := loginUser(t, "user4")
		repo := bkRepo(t, s, "bc-run")
		link := path.Join("/org3", repo.Name, "settings/branch_workflow/cleanup")
		before := dmBranches(t, repo)

		// a branch younger than the days is not due, older ones are
		bcAge(t, repo, 100)
		_, err := db.GetEngine(t.Context()).Exec("UPDATE branch SET updated_unix = ? WHERE repo_id = ? AND name = ?", time.Now().Unix(), repo.ID, "m-keep")
		require.NoError(t, err)

		resp := s.MakeRequest(t, NewRequest(t, "GET", link+"?days=30"), http.StatusOK)
		body := resp.Body.String()
		assert.Contains(t, body, "cleanup-due")
		assert.Contains(t, body, "merged-old")
		assert.Contains(t, body, "cleanup-not-due")
		assert.Contains(t, body, "cleanup-kept")
		assert.Contains(t, body, "prot-merged")
		assert.Equal(t, before, dmBranches(t, repo), "GET deletes nothing")

		// turning it on (with the rendered form) waits 7 days
		bcSubmitTurnOn(t, s, link+"?days=30", http.StatusSeeOther)
		own := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
		eff, err := branchworkflow.GetEffectiveCleanup(t.Context(), own)
		require.NoError(t, err)
		assert.Equal(t, 30, eff.Wanted)
		resp = s.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
		assert.NotContains(t, resp.Body.String(), `<button class="ui primary button">`)
		assert.Contains(t, resp.Body.String(), "pending until")

		// read-only maintenance pauses the run and the page says so
		test.MockVariableValue(&setting.Maintenance.Mode, "read-only")
		resp = s.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "paused")
		// the notice of the settings page is outside the form (Fomantic hides it inside)
		page := NewHTMLParser(t, s.MakeRequest(t, NewRequest(t, "GET", path.Join("/org3", repo.Name, "settings/branch_workflow")), http.StatusOK).Body)
		assert.Contains(t, page.Find(".ui.warning.message").Text(), "paused")
		assert.Zero(t, page.Find("form.ui.form .ui.warning.message").Length())
		run, err := repo_service.RunBranchCleanup(t.Context(), repo)
		require.NoError(t, err)
		assert.Zero(t, run.Deleted)
		setting.Maintenance.Mode = ""

		// while waiting, nothing is deleted
		require.NoError(t, repo_service.CleanupMergedBranches(audit_model.WithSystem(t.Context(), "cron:"+repo_service.CleanupTaskName)))
		assert.Equal(t, before, dmBranches(t, repo))

		// the wait is over
		st, err := repo_model.GetBranchCleanupState(t.Context(), repo.ID)
		require.NoError(t, err)
		require.NotNil(t, st)
		assert.Zero(t, st.Days)
		assert.Equal(t, 30, st.PendingDays)
		_, err = db.GetEngine(t.Context()).Exec("UPDATE branch_cleanup_state SET pending_from = ? WHERE repo_id = ?", time.Now().Add(-time.Hour).Unix(), repo.ID)
		require.NoError(t, err)

		// a push after the preview survives (new commit moves the row and the tip)
		testEditFileToNewBranch(t, s, "org3", repo.Name, "m-b", "m-b", "README.md", "late\n")

		since := auditSinceID(t)
		require.NoError(t, repo_service.CleanupMergedBranches(audit_model.WithSystem(t.Context(), "cron:"+repo_service.CleanupTaskName)))
		after := dmBranches(t, repo)
		assert.NotContains(t, after, "merged-old")
		assert.NotContains(t, after, "m-a")
		for _, kept := range []string{"master", "m-keep", "m-b", "prot-merged", "pr-base", "at-tip", "unmerged", "unmerged2"} {
			assert.Contains(t, after, kept)
		}

		var entries []*audit_model.Entry
		require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND action = ?", since, "repo.branch.deleted").Find(&entries))
		require.NotEmpty(t, entries)
		for _, e := range entries {
			assert.Equal(t, "cleanup", auditData(t, e)["via"])
			assert.Equal(t, audit_model.ActorSystem, e.ActorType)
		}
		var sums []*audit_model.Entry
		require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND action = ?", since, "repo.branches.cleanup_deleted").Find(&sums))
		assert.Len(t, sums, 1)

		// every deleted branch can be restored
		deleted, err := db.GetEngine(t.Context()).Where("repo_id = ? AND name = ? AND is_deleted = ?", repo.ID, "m-a", true).Count(new(git_model.Branch))
		require.NoError(t, err)
		require.EqualValues(t, 1, deleted)
		var b git_model.Branch
		_, err = db.GetEngine(t.Context()).Where("repo_id = ? AND name = ? AND is_deleted = ?", repo.ID, "m-a", true).Get(&b)
		require.NoError(t, err)
		s.MakeRequest(t, NewRequestWithURLValues(t, "POST", path.Join("/org3", repo.Name, "branches/restore_selected"), url.Values{"branch_id": {strconv.FormatInt(b.ID, 10)}}), http.StatusSeeOther)
		assert.Contains(t, dmBranches(t, repo), "m-a")

		// readers get nothing
		reader.MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound)

		// the organization's preview lists the repository
		resp = s.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/branch_workflow/cleanup?days=30"), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "bc-run")
		bcSubmitTurnOn(t, s, "/org/org3/settings/branch_workflow/cleanup?days=45", http.StatusSeeOther)
		c, _, err := branchworkflow.GetOrgCleanup(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}))
		require.NoError(t, err)
		require.NotNil(t, c)
		assert.Equal(t, 45, c.Days)
	})
}
