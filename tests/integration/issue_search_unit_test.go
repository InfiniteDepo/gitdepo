// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/unittest"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A repository whose owner turned off Issues (Pull requests) keeps the rows, but they leave every issue list for
// everyone, administrators and anonymous visitors included, and come back with the unit.
func TestIssueSearchOwnerDisabledUnit(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	// user2/repo1 is public: issue 1, pull requests 2 and 3
	owner := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeReadIssue)
	admin := getUserToken(t, "user1", auth_model.AccessTokenScopeReadIssue)
	other := getUserToken(t, "user5", auth_model.AccessTokenScopeReadIssue)
	web := loginUser(t, "user5")

	ids := func(token, query string) []int64 {
		req := NewRequest(t, "GET", "/api/v1/repos/issues/search?limit=50&"+query)
		if token != "" {
			req.AddTokenAuth(token)
		}
		var found []*api.Issue
		DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &found)
		var res []int64
		for _, i := range found {
			res = append(res, i.ID)
		}
		return res
	}
	webAdmin := loginUser(t, "user1")
	webIDs := func(sess *TestSession, query string) []int64 {
		var found []*api.Issue
		DecodeJSON(t, sess.MakeRequest(t, NewRequest(t, "GET", "/issues/search?limit=50&"+query), http.StatusOK), &found)
		var res []int64
		for _, i := range found {
			res = append(res, i.ID)
		}
		return res
	}
	// repo1 has issues 1 and pulls 2, 3 (open); a dashboard also lists the pulls
	check := func(t *testing.T, wantIssue, wantPulls bool) {
		t.Helper()
		for name, got := range map[string][]int64{
			"anonymous issues": ids("", "type=issues"),
			"user issues":      ids(other, "type=issues"),
			"admin issues":     ids(admin, "type=issues"),
			"web issues":       webIDs(web, "type=issues"),
			"web admin issues": webIDs(webAdmin, "type=issues"),
			"admin both":       ids(admin, ""),
			"owner both":       ids(owner, ""),
		} {
			assert.Equal(t, wantIssue, slices.Contains(got, 1), "%s: issue 1", name)
		}
		for name, got := range map[string][]int64{
			"anonymous pulls": ids("", "type=pulls"),
			"user pulls":      ids(other, "type=pulls"),
			"admin pulls":     ids(admin, "type=pulls"),
			"web pulls":       webIDs(web, "type=pulls"),
			"web admin pulls": webIDs(webAdmin, "type=pulls"),
			"admin both":      ids(admin, ""),
			"owner both":      ids(owner, ""),
		} {
			assert.Equal(t, wantPulls, slices.Contains(got, 2) || slices.Contains(got, 3), "%s: pulls", name)
		}
		// the dashboard of the owner
		owner := loginUser(t, "user2")
		issues := owner.MakeRequest(t, NewRequest(t, "GET", "/issues?type=your_repositories&state=open"), http.StatusOK).Body.String()
		assert.Equal(t, wantIssue, containsLink(issues, "/user2/repo1/issues/1"), "dashboard issue")
		pulls := owner.MakeRequest(t, NewRequest(t, "GET", "/pulls?type=your_repositories&state=open"), http.StatusOK).Body.String()
		assert.Equal(t, wantPulls, containsLink(pulls, "/user2/repo1/pulls/3"), "dashboard pull")
		// the milestones list shows a repository with at least one of the two units
		milestones := owner.MakeRequest(t, NewRequest(t, "GET", "/milestones?repos=[1]"), http.StatusOK).Body.String()
		assert.Equal(t, wantIssue || wantPulls, strings.Contains(milestones, "milestone1"), "milestones")
	}
	patch := func(opt api.EditRepoOption) {
		t.Helper()
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", &opt).AddTokenAuth(owner), http.StatusOK)
	}
	check(t, true, true)

	patch(api.EditRepoOption{HasIssues: new(false)})
	check(t, false, true)
	patch(api.EditRepoOption{HasIssues: new(true)})
	check(t, true, true)

	patch(api.EditRepoOption{HasPullRequests: new(false)})
	check(t, true, false)
	patch(api.EditRepoOption{HasPullRequests: new(true)})
	check(t, true, true)

	patch(api.EditRepoOption{HasIssues: new(false), HasPullRequests: new(false)})
	check(t, false, false)
	patch(api.EditRepoOption{HasIssues: new(true), HasPullRequests: new(true)})
	check(t, true, true)

	// the rows were never touched
	unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 1, RepoID: 1})
	unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 2, RepoID: 1})
}

func containsLink(body, href string) bool {
	return strings.Contains(body, fmt.Sprintf(`href="%s"`, href))
}

// Filtering a page by the units of its repositories costs the same queries for one issue as for many
func TestIssueListFilterHiddenUnitsQueries(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	var all issues_model.IssueList
	require.NoError(t, db.GetEngine(db.DefaultContext).Limit(20).Find(&all))
	require.Greater(t, len(all), 10)
	filter := func(n int) int64 {
		return stableQueryCount(t, func() {
			list := slices.Clone(all[:n]) // FilterHiddenUnits may filter in place
			for _, i := range list {
				i.Repo = nil // every reading starts cold
			}
			_, err := list.FilterHiddenUnits(db.DefaultContext)
			require.NoError(t, err)
		})
	}
	filter(1) // warm up the settings cache
	one := filter(1)
	assert.Equal(t, one, filter(len(all)))
}
