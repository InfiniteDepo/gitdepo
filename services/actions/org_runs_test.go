// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"fmt"
	"net/url"
	"testing"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	webhook_module "forgejo.org/modules/webhook"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
)

type testForm url.Values

func (f testForm) FormString(key string) string { return url.Values(f).Get(key) }
func (f testForm) FormStrings(key string) []string {
	return url.Values(f)[key]
}

// orgRunsSetup enables the Actions unit on every repository of org3 and org17 and gives each of them one run,
// whose ID is returned per repository ID.
func orgRunsSetup(t *testing.T) map[int64]int64 {
	t.Helper()
	require.NoError(t, unittest.PrepareTestDatabase())
	runs := map[int64]int64{}
	var repos []*repo_model.Repository
	require.NoError(t, db.GetEngine(t.Context()).In("owner_id", 3, 17).Find(&repos))
	for _, repo := range repos {
		has, err := db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", repo.ID, unit.TypeActions).Exist(new(repo_model.RepoUnit))
		require.NoError(t, err)
		if !has {
			require.NoError(t, db.Insert(t.Context(), &repo_model.RepoUnit{RepoID: repo.ID, Type: unit.TypeActions}))
		}
		run := &actions_model.ActionRun{
			Title: fmt.Sprintf("run of %s", repo.Name), RepoID: repo.ID, OwnerID: repo.OwnerID, WorkflowID: "ci.yaml",
			Index: 9000 + repo.ID, TriggerUserID: 2, Ref: "refs/heads/main", CommitSHA: "c2d72f548424103f01ee1dc02889c1e2bff816b0",
			Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusSuccess,
		}
		require.NoError(t, db.Insert(t.Context(), run))
		runs[repo.ID] = run.ID
	}
	return runs
}

func orgRunIDs(runs actions_model.RunList) []int64 {
	ids := make([]int64, len(runs))
	for i, r := range runs {
		ids[i] = r.ID
	}
	return ids
}

func TestFindOrgRunsVisibility(t *testing.T) {
	runIDs := orgRunsSetup(t)

	// every user x every repo of the two orgs: a run is listed iff the user can read the Actions unit
	var users []*user_model.User
	require.NoError(t, db.GetEngine(t.Context()).Where("type = ?", user_model.UserTypeIndividual).Find(&users))
	var repos []*repo_model.Repository
	require.NoError(t, db.GetEngine(t.Context()).In("owner_id", 3, 17).Find(&repos))
	for _, orgID := range []int64{3, 17} {
		org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: orgID})
		for _, doer := range users {
			listed, _, err := FindOrgRuns(t.Context(), org, doer, doer.IsAdmin, nil, OrgRunFilter{}, db.ListOptions{ListAll: true})
			require.NoError(t, err)
			inList := map[int64]bool{}
			for _, r := range listed {
				inList[r.RepoID] = true
			}
			for _, repo := range repos {
				if repo.OwnerID != orgID {
					continue
				}
				perm, err := access_model.GetUserRepoPermission(t.Context(), repo, doer)
				require.NoError(t, err)
				assert.Equal(t, perm.CanRead(unit.TypeActions), inList[repo.ID], "user %s, repo %s", doer.Name, repo.FullName())
			}
		}
	}

	t.Run("trashed repository", func(t *testing.T) {
		org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 3})
		admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		_, err := db.GetEngine(t.Context()).ID(32).Cols("trashed_unix").Update(&repo_model.Repository{TrashedUnix: 1})
		require.NoError(t, err)
		for _, doer := range []*user_model.User{admin, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})} {
			listed, total, err := FindOrgRuns(t.Context(), org, doer, doer.IsAdmin, nil, OrgRunFilter{}, db.ListOptions{ListAll: true})
			require.NoError(t, err)
			assert.NotContains(t, orgRunIDs(listed), runIDs[32])
			assert.Equal(t, int64(len(listed)), total)
		}
	})

	t.Run("token reducer", func(t *testing.T) {
		org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 17})
		admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		listed, _, err := FindOrgRuns(t.Context(), org, admin, true, builder.Eq{"repository.id": 24}, OrgRunFilter{}, db.ListOptions{ListAll: true})
		require.NoError(t, err)
		assert.Equal(t, []int64{runIDs[24]}, orgRunIDs(listed))
	})

	t.Run("actions unit disabled", func(t *testing.T) {
		org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 17})
		_, err := db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", 23, unit.TypeActions).Delete(new(repo_model.RepoUnit))
		require.NoError(t, err)
		listed, _, err := FindOrgRuns(t.Context(), org, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 15}), false, nil, OrgRunFilter{}, db.ListOptions{ListAll: true})
		require.NoError(t, err)
		assert.NotContains(t, orgRunIDs(listed), runIDs[23])
		assert.Contains(t, orgRunIDs(listed), runIDs[24])
	})

	t.Run("stale owner_id after a transfer", func(t *testing.T) {
		org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 3})
		// the repository moved from org17 to org3, but its run still says owner_id 17
		_, err := db.GetEngine(t.Context()).ID(24).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 3})
		require.NoError(t, err)
		_, err = db.GetEngine(t.Context()).ID(runIDs[24]).Cols("owner_id").Update(&actions_model.ActionRun{OwnerID: 17})
		require.NoError(t, err)
		admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		listed, _, err := FindOrgRuns(t.Context(), org, admin, true, nil, OrgRunFilter{}, db.ListOptions{ListAll: true})
		require.NoError(t, err)
		assert.Contains(t, orgRunIDs(listed), runIDs[24], "ownership comes from the repository, not from action_run.owner_id")
	})
}

// A team with admin authorize reaches every unit of its repositories, with or without a team_unit row for Actions
// (the fixtures' owner teams have none), as GetUserRepoPermission does; a read team without that row doesn't.
func TestFindOrgRunsAdminTeamWithoutUnitRow(t *testing.T) {
	runIDs := orgRunsSetup(t)
	org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 17})
	has, err := db.GetEngine(t.Context()).Where("team_id = 5 AND type = ?", unit.TypeActions).Exist(new(organization.TeamUnit))
	require.NoError(t, err)
	require.False(t, has, "the owner team has no Actions team_unit row")
	listed, _, err := FindOrgRuns(t.Context(), org, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 15}), false, nil, OrgRunFilter{}, db.ListOptions{ListAll: true})
	require.NoError(t, err)
	assert.ElementsMatch(t, []int64{runIDs[23], runIDs[24]}, orgRunIDs(listed))

	// user 20 is in the read-only review_team of repo 24, which has no Actions row: only the public repo
	listed, _, err = FindOrgRuns(t.Context(), org, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 20}), false, nil, OrgRunFilter{}, db.ListOptions{ListAll: true})
	require.NoError(t, err)
	assert.Equal(t, []int64{runIDs[23]}, orgRunIDs(listed))
}

// Owning the organization gives no reach beyond the repositories whose Actions can be read: not another
// organization's, nor a trashed one, nor one with Actions off.
func TestFindOrgRunsOrgOwnerNoExtraReach(t *testing.T) {
	runIDs := orgRunsSetup(t)
	org17 := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 17})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 15})
	_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 23")
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Exec("DELETE FROM repo_unit WHERE repo_id = 24 AND type = ?", unit.TypeActions)
	require.NoError(t, err)
	listed, total, err := FindOrgRuns(t.Context(), org17, owner, false, nil, OrgRunFilter{}, db.ListOptions{ListAll: true})
	require.NoError(t, err)
	assert.Empty(t, listed)
	assert.Zero(t, total)
	// the other organization's runs are not reachable through this one
	listed, _, err = FindOrgRuns(t.Context(), org17, owner, false, nil, OrgRunFilter{Repo: "repo21"}, db.ListOptions{ListAll: true})
	require.NoError(t, err)
	assert.NotContains(t, orgRunIDs(listed), runIDs[32])
	assert.Empty(t, listed)
}

func TestOrgRunFilterCap(t *testing.T) {
	values := make([]string, 50)
	for i := range values {
		values[i] = fmt.Sprintf("v%d", i)
	}
	assert.Len(t, dedupe(values), orgRunsMaxValues, "status and event values share the cap")
	assert.Equal(t, []string{"a", "b"}, dedupe([]string{"a", " ", "b", "a"}))
	f, err := ParseOrgRunFilter(testForm{"status": {"success", "success", "failure", "success"}})
	require.NoError(t, err)
	assert.Equal(t, []actions_model.Status{actions_model.StatusSuccess, actions_model.StatusFailure}, f.Statuses)
}

func TestFindOrgRunsFilters(t *testing.T) {
	runIDs := orgRunsSetup(t)
	org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 17})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 15})
	find := func(f OrgRunFilter) []int64 {
		t.Helper()
		listed, total, err := FindOrgRuns(t.Context(), org, owner, false, nil, f, db.ListOptions{ListAll: true})
		require.NoError(t, err)
		assert.Equal(t, int64(len(listed)), total)
		return orgRunIDs(listed)
	}
	// make run 24 a failed pull_request run of another workflow, by another user, on a PR ref
	// (a plain Update leaves `created` alone, so use SQL)
	_, err := db.GetEngine(t.Context()).Exec("UPDATE action_run SET status = ?, event = ?, trigger_event = ?, workflow_id = ?, trigger_user_id = ?, ref = ?, created = ? WHERE id = ?",
		actions_model.StatusFailure, webhook_module.HookEventPullRequest, "pull_request", "lint.yaml", 18, "refs/pull/7/head", 2000, runIDs[24])
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Exec("UPDATE action_run SET created = ? WHERE id = ?", 1000, runIDs[23])
	require.NoError(t, err)

	assert.ElementsMatch(t, []int64{runIDs[23], runIDs[24]}, find(OrgRunFilter{}))
	assert.Equal(t, []int64{runIDs[24]}, find(OrgRunFilter{Statuses: []actions_model.Status{actions_model.StatusFailure}}))
	assert.Equal(t, []int64{runIDs[23]}, find(OrgRunFilter{Events: []string{"push"}}))
	assert.Equal(t, []int64{runIDs[24]}, find(OrgRunFilter{Workflow: "lint.yaml"}))
	assert.Equal(t, []int64{runIDs[23]}, find(OrgRunFilter{Branch: "main"}), "a pull request ref is not a branch")
	assert.Equal(t, []int64{runIDs[24]}, find(OrgRunFilter{Actor: "user18"}))
	assert.Equal(t, []int64{runIDs[24]}, find(OrgRunFilter{Repo: "BIG_test_private_4"}), "repository names are case insensitive")
	assert.Equal(t, []int64{runIDs[24]}, find(OrgRunFilter{From: 1500}))
	assert.Equal(t, []int64{runIDs[23]}, find(OrgRunFilter{To: 1500}))

	// filters are ANDed
	assert.Equal(t, []int64{runIDs[24]}, find(OrgRunFilter{Statuses: []actions_model.Status{actions_model.StatusFailure}, Events: []string{"pull_request"}, Actor: "user18"}))
	assert.Empty(t, find(OrgRunFilter{Statuses: []actions_model.Status{actions_model.StatusFailure}, Events: []string{"push"}}))

	// unknown or hidden names are an empty list, not an error
	assert.Empty(t, find(OrgRunFilter{Actor: "no-such-user"}))
	assert.Empty(t, find(OrgRunFilter{Repo: "no-such-repo"}))
	assert.Empty(t, find(OrgRunFilter{Repo: "repo1"}), "a repository of another owner")
}

func TestFindOrgRunsPaging(t *testing.T) {
	runIDs := orgRunsSetup(t)
	org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 17})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 15})
	page1, total, err := FindOrgRuns(t.Context(), org, owner, false, nil, OrgRunFilter{}, db.ListOptions{Page: 1, PageSize: 1})
	require.NoError(t, err)
	assert.EqualValues(t, 2, total)
	page2, _, err := FindOrgRuns(t.Context(), org, owner, false, nil, OrgRunFilter{}, db.ListOptions{Page: 2, PageSize: 1})
	require.NoError(t, err)
	assert.Equal(t, []int64{runIDs[24], runIDs[23]}, append(orgRunIDs(page1), orgRunIDs(page2)...), "newest first")
}

func TestParseOrgRunFilter(t *testing.T) {
	f, err := ParseOrgRunFilter(testForm{
		"status": {"failure", "failure", "running"}, "event": {"push", "push"}, "repo": {" Repo "},
		"workflow_id": {"ci.yaml"}, "branch": {"main"}, "actor": {"user2"}, "from": {"2026-01-02"}, "to": {"2026-01-03"},
	})
	require.NoError(t, err)
	assert.Equal(t, []actions_model.Status{actions_model.StatusFailure, actions_model.StatusRunning}, f.Statuses)
	assert.Equal(t, []string{"push"}, f.Events)
	assert.Equal(t, "Repo", f.Repo)
	assert.Equal(t, "ci.yaml", f.Workflow)
	assert.EqualValues(t, 1767312000, f.From)
	assert.EqualValues(t, 1767484799, f.To, "a date `to` includes that whole day")

	f, err = ParseOrgRunFilter(testForm{"from": {"2026-01-02T03:04:05Z"}})
	require.NoError(t, err)
	assert.EqualValues(t, 1767323045, f.From)

	for _, bad := range []url.Values{{"status": {"bogus"}}, {"from": {"yesterday"}}, {"to": {"x"}}} {
		_, err = ParseOrgRunFilter(testForm(bad))
		require.Error(t, err, bad)
	}

	many := make([]string, 50)
	for i := range many {
		many[i] = fmt.Sprintf("event%d", i)
	}
	f, err = ParseOrgRunFilter(testForm{"event": many})
	require.NoError(t, err)
	assert.Len(t, f.Events, orgRunsMaxValues)
}

func TestOrgRunPermissions(t *testing.T) {
	orgRunsSetup(t)
	org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 17})
	reader := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 20}) // sees only the public repo 23
	runs, _, err := FindOrgRuns(t.Context(), org, reader, false, nil, OrgRunFilter{}, db.ListOptions{ListAll: true})
	require.NoError(t, err)
	require.NoError(t, runs.LoadRepos(t.Context()))
	perms, err := OrgRunPermissions(t.Context(), runs, reader)
	require.NoError(t, err)
	assert.Len(t, perms, len(runs), "one permission per distinct repository")
	require.Contains(t, perms, int64(23))
	assert.True(t, perms[23].CanRead(unit.TypeActions))
	assert.False(t, perms[23].CanWrite(unit.TypeActions))

	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 15})
	runs, _, err = FindOrgRuns(t.Context(), org, owner, false, nil, OrgRunFilter{}, db.ListOptions{ListAll: true})
	require.NoError(t, err)
	require.NoError(t, runs.LoadRepos(t.Context()))
	perms, err = OrgRunPermissions(t.Context(), runs, owner)
	require.NoError(t, err)
	assert.True(t, perms[24].CanWrite(unit.TypeActions))
}

func TestLoadOrgRunReposDropsGoneRepos(t *testing.T) {
	runIDs := orgRunsSetup(t)
	runs := actions_model.RunList{{ID: runIDs[24], RepoID: 24}, {ID: 999, RepoID: 999999}}
	runs, err := LoadOrgRunRepos(t.Context(), runs)
	require.NoError(t, err)
	assert.Equal(t, []int64{runIDs[24]}, orgRunIDs(runs))
	assert.NotNil(t, runs[0].Repo)
}
