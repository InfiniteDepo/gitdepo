// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"path"
	"strconv"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/services/cron"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bcPost(t *testing.T, s *TestSession, link string, values map[string]string, expected int) {
	t.Helper()
	s.MakeRequest(t, NewRequestWithValues(t, "POST", link, values), expected)
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

		bcPost(t, owner, repoLink, map[string]string{"days": "30"}, http.StatusSeeOther)
		resp := owner.MakeRequest(t, NewRequest(t, "GET", repoPage), http.StatusOK)
		assert.Contains(t, resp.Body.String(), `name="days"`)
		assert.Contains(t, resp.Body.String(), "7 days")

		// invalid days change nothing
		for _, d := range []string{"abc", "3651", "-1"} {
			bcPost(t, owner, repoLink, map[string]string{"days": d}, http.StatusSeeOther)
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
		bcPost(t, reader, repoLink, map[string]string{"days": "5"}, http.StatusNotFound)
		reader.MakeRequest(t, NewRequest(t, "GET", orgLink), http.StatusNotFound)
		bcPost(t, reader, orgLink, map[string]string{"days": "5"}, http.StatusNotFound)

		// an organization lock stops the repository's own setting
		bcPost(t, owner, orgLink, map[string]string{"days": "60", "enforce": "on"}, http.StatusSeeOther)
		bcPost(t, owner, repoLink, map[string]string{"days": "10"}, http.StatusForbidden)
		resp = owner.MakeRequest(t, NewRequest(t, "GET", repoPage), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "disabled")
		bcPost(t, owner, orgLink, map[string]string{"days": "60"}, http.StatusSeeOther)
		bcPost(t, owner, repoLink, map[string]string{"days": "10"}, http.StatusSeeOther)
		bcPost(t, owner, orgLink, map[string]string{"days": "abc"}, http.StatusSeeOther)
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
		assert.Contains(t, body, `value="30"`) // turn-on form

		// turning it on waits 7 days
		bcPost(t, s, link, map[string]string{"days": "30"}, http.StatusSeeOther)
		resp = s.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
		assert.NotContains(t, resp.Body.String(), `<button class="ui primary button">`)

		// read-only maintenance pauses the run and the page says so
		test.MockVariableValue(&setting.Maintenance.Mode, "read-only")
		resp = s.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "paused")
		run, err := repo_service.RunBranchCleanup(t.Context(), repo)
		require.NoError(t, err)
		assert.Zero(t, run.Deleted)
		setting.Maintenance.Mode = ""

		// while waiting, nothing is deleted
		run, err = repo_service.RunBranchCleanup(t.Context(), repo)
		require.NoError(t, err)
		assert.Zero(t, run.Deleted)

		// the wait is over
		repoRow := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
		u := repoRow.MustGetUnit(t.Context(), 3)
		cfg := u.PullRequestsConfig()
		cfg.BranchCleanup.EffectiveFrom = time.Now().Add(-time.Hour).Unix()
		u.Config = cfg
		require.NoError(t, repo_model.UpdateRepoUnit(t.Context(), u))

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
	})
}
