// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/modules/test"
	metrics_service "forgejo.org/services/metrics"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// insertMetricsPull adds a pull request merged now, opened as a draft and made ready, with a review by each reviewer.
func insertMetricsPull(t *testing.T, repoID, poster int64, title string, reviewers ...int64) {
	t.Helper()
	ctx := db.DefaultContext
	var n int64
	_, err := db.GetEngine(ctx).SQL("SELECT COALESCE(MAX(`index`), 0) FROM issue WHERE repo_id = ?", repoID).Get(&n)
	require.NoError(t, err)
	issue := &issues_model.Issue{RepoID: repoID, Index: n + 1, PosterID: poster, Title: title, IsPull: true}
	require.NoError(t, db.Insert(ctx, issue))
	require.NoError(t, db.Insert(ctx, &issues_model.PullRequest{IssueID: issue.ID, Index: issue.Index, BaseRepoID: repoID, HeadRepoID: repoID, HasMerged: true, CommitsAhead: 3}))
	require.NoError(t, db.Insert(ctx, &issues_model.Comment{Type: issues_model.CommentTypeChangeTitle, PosterID: poster, IssueID: issue.ID, OldTitle: "WIP: " + title, NewTitle: title}))
	for _, r := range reviewers {
		require.NoError(t, db.Insert(ctx, &issues_model.Comment{Type: issues_model.CommentTypeReview, PosterID: r, IssueID: issue.ID}))
	}
}

// metricsCSV returns the repositories (sorted, one per row) of the CSV at url, and the response.
func metricsCSV(t *testing.T, session *TestSession, url string) ([]string, [][]string) {
	t.Helper()
	resp := session.MakeRequest(t, NewRequest(t, "GET", url+"?format=csv"), http.StatusOK)
	lines, err := csv.NewReader(resp.Body).ReadAll()
	require.NoError(t, err)
	var repos []string
	for _, l := range lines[1:] {
		repos = append(repos, l[0])
	}
	slices.Sort(repos)
	return slices.Compact(repos), lines
}

// org3 has the private repo3 (user4 reads it through team1) and repo5, and repo21 (id 32) without pull requests.
func preparePullMetrics(t *testing.T) {
	t.Helper()
	insertMetricsPull(t, 1, 2, "repo1 pull", 4, 5)
	insertMetricsPull(t, 3, 2, "=HYPERLINK(\"x\")", 4)
	insertMetricsPull(t, 5, 2, "repo5 pull", 4)
	insertMetricsPull(t, 32, 2, "repo21 pull", 4)
}

func TestPullMetricsRepo(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	preparePullMetrics(t)
	ctx := db.DefaultContext
	anon := emptyTestSession(t)
	owner := loginUser(t, "user2")
	member := loginUser(t, "user4")

	page := NewHTMLParser(t, anon.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/activity/metrics"), http.StatusOK).Body)
	assert.Equal(t, 1, page.Find(`[data-card="merge"]`).Length())
	assert.Equal(t, "2", strings.TrimSpace(page.Find(`[data-card="reviews"] .value`).Text()))
	assert.Zero(t, page.Find(`[data-table="review-load"]`).Length(), "per-person numbers are for repository admins")
	assert.Equal(t, 1, page.Find(`.flex-container-nav a[href="/user2/repo1/activity/metrics"].active`).Length())

	page = NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/activity/metrics?period=7"), http.StatusOK).Body)
	assert.Equal(t, 2, page.Find(`[data-table="review-load"] tbody tr`).Length())
	assert.Equal(t, 1, page.Find(`[data-table="weekly"] tbody tr`).Length())

	anon.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/activity/metrics"), http.StatusNotFound)
	member.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/activity/metrics"), http.StatusOK)
	member.MakeRequest(t, NewRequest(t, "GET", "/org3/repo5/activity/metrics"), http.StatusNotFound)

	t.Run("CSV", func(t *testing.T) {
		resp := owner.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/activity/metrics?format=csv"), http.StatusOK)
		assert.Equal(t, "text/csv; charset=utf-8", resp.Header().Get("Content-Type"))
		assert.Equal(t, "nosniff", resp.Header().Get("X-Content-Type-Options"))
		assert.Contains(t, resp.Header().Get("Content-Disposition"), "pull-request-metrics.csv")
		assert.Empty(t, resp.Header().Get("X-Truncated"))
		lines, err := csv.NewReader(resp.Body).ReadAll()
		require.NoError(t, err)
		require.Len(t, lines, 2)
		assert.Equal(t, "org3/repo3", lines[1][0])
		assert.Equal(t, `'=HYPERLINK("x")`, lines[1][2])
		assert.NotEmpty(t, lines[1][5], "ready")
		assert.Equal(t, "3", lines[1][10])

		defer test.MockVariableValue(&metrics_service.MaxPRs, 1)()
		insertMetricsPull(t, 3, 2, "second")
		resp = owner.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/activity/metrics?format=csv"), http.StatusOK)
		assert.Equal(t, "true", resp.Header().Get("X-Truncated"))
		assert.Contains(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/activity/metrics"), http.StatusOK).Body.String(), "only the newest 1 were counted")
	})

	t.Run("unit off", func(t *testing.T) {
		_, err := db.DeleteByBean(ctx, &repo_model.RepoUnit{RepoID: 1, Type: unit.TypePullRequests})
		require.NoError(t, err)
		defer func() {
			require.NoError(t, db.Insert(ctx, &repo_model.RepoUnit{RepoID: 1, Type: unit.TypePullRequests, Config: &repo_model.PullRequestsConfig{}}))
		}()
		owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/activity/metrics"), http.StatusNotFound)
	})

	t.Run("disabled repo units", func(t *testing.T) {
		disabled := unit.DisabledRepoUnitsGet()
		unit.DisabledRepoUnitsSet([]unit.Type{unit.TypePullRequests})
		defer unit.DisabledRepoUnitsSet(disabled)
		owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/activity/metrics"), http.StatusNotFound)
		owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/metrics"), http.StatusNotFound)
	})

	t.Run("unit policy", func(t *testing.T) {
		defer denyRepoUnits(t, nil, unit.TypePullRequests)()
		owner.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/activity/metrics"), http.StatusNotFound)
		owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/activity/metrics"), http.StatusOK)
	})

	t.Run("trashed", func(t *testing.T) {
		_, err := db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 1")
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 0 WHERE id = 1")
			require.NoError(t, err)
		}()
		owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/activity/metrics"), http.StatusNotFound)
	})
}

func TestPullMetricsOrg(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	preparePullMetrics(t)
	ctx := db.DefaultContext
	owner := loginUser(t, "user2")
	member := loginUser(t, "user4")

	emptyTestSession(t).MakeRequest(t, NewRequest(t, "GET", "/org/org3/metrics"), http.StatusSeeOther)
	loginUser(t, "user5").MakeRequest(t, NewRequest(t, "GET", "/org/org3/metrics"), http.StatusNotFound)

	page := NewHTMLParser(t, member.MakeRequest(t, NewRequest(t, "GET", "/org/org3/metrics"), http.StatusOK).Body)
	assert.Equal(t, 1, page.Find(`.overflow-menu-items a[href="/org/org3/metrics"].active`).Length())
	assert.Zero(t, page.Find(`[data-table="review-load"]`).Length())
	repos, _ := metricsCSV(t, member, "/org/org3/metrics")
	assert.Equal(t, []string{"org3/repo3"}, repos)

	page = NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/metrics"), http.StatusOK).Body)
	assert.Equal(t, 1, page.Find(`[data-table="review-load"] tbody tr`).Length())
	repos, _ = metricsCSV(t, owner, "/org/org3/metrics")
	assert.Equal(t, []string{"org3/repo3", "org3/repo5"}, repos, "repo21 has no pull requests unit")

	page = NewHTMLParser(t, loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", "/org/org3/metrics"), http.StatusOK).Body)
	assert.Equal(t, 1, page.Find(`[data-table="review-load"] tbody tr`).Length(), "site admins act as owners")

	t.Run("trashed", func(t *testing.T) {
		_, err := db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 5")
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 0 WHERE id = 5")
			require.NoError(t, err)
		}()
		repos, _ := metricsCSV(t, owner, "/org/org3/metrics")
		assert.Equal(t, []string{"org3/repo3"}, repos)
	})

	t.Run("unit policy", func(t *testing.T) {
		defer denyRepoUnits(t, nil, unit.TypePullRequests)()
		owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/metrics"), http.StatusNotFound)
	})

	t.Run("org unit off", func(t *testing.T) {
		require.NoError(t, db.Insert(ctx, &repo_model.OrgUnit{OrgID: 3, Type: unit.TypePullRequests, Disabled: true}))
		defer func() {
			_, err := db.DeleteByBean(ctx, &repo_model.OrgUnit{OrgID: 3})
			require.NoError(t, err)
		}()
		owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/metrics"), http.StatusNotFound)
	})

	t.Run("team without the unit", func(t *testing.T) {
		// test_team (user15) reads only issues; give it the private repo5
		require.NoError(t, db.Insert(ctx, &organization.TeamRepo{OrgID: 3, TeamID: 7, RepoID: 5}))
		require.NoError(t, db.Insert(ctx, &organization.OrgUser{OrgID: 3, UID: 15}))
		repos, _ := metricsCSV(t, loginUser(t, "user15"), "/org/org3/metrics")
		assert.Empty(t, repos)
	})

	t.Run("two-factor requirement", func(t *testing.T) {
		_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = 3", false)
			require.NoError(t, err)
		}()
		repos, _ := metricsCSV(t, member, "/org/org3/metrics")
		assert.Empty(t, repos, "a member without 2FA sees what a stranger sees")
		member.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/activity/metrics"), http.StatusForbidden)
	})
}

// The number of queries doesn't grow with pull requests, reviews, reviewers or title changes.
func TestPullMetricsQueryCount(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	preparePullMetrics(t)
	owner := loginUser(t, "user2")
	urls := []string{"/user2/repo1/activity/metrics", "/user2/repo1/activity/metrics?format=csv", "/org/org3/metrics", "/org/org3/metrics?format=csv"}
	count := func() []int64 {
		var counts []int64
		for _, url := range urls {
			counts = append(counts, stableQueryCount(t, func() { owner.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK) }))
		}
		return counts
	}
	count() // warm up
	before := count()
	for i := range 20 {
		insertMetricsPull(t, []int64{1, 3, 5}[i%3], 2, fmt.Sprintf("more %d", i), 4, 5, int64(8+i%4), 1)
	}
	assert.Equal(t, before, count())
}
