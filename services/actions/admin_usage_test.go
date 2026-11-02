// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"fmt"
	"testing"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/timeutil"
	webhook_module "forgejo.org/modules/webhook"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
)

func TestParseUsageGroup(t *testing.T) {
	for _, g := range []string{"org", "repo", "runner"} {
		got, err := ParseUsageGroup(g)
		require.NoError(t, err)
		assert.Equal(t, UsageGroup(g), got)
	}
	for _, g := range []string{"", "user", "Org", "repo;"} {
		_, err := ParseUsageGroup(g)
		require.Error(t, err, g)
	}
}

func TestParseUsageRange(t *testing.T) {
	const now = timeutil.TimeStamp(1_800_000_000)
	day := timeutil.TimeStamp(86400)

	from, to, err := ParseUsageRange("", "", now)
	require.NoError(t, err)
	assert.Equal(t, now, to)
	assert.Equal(t, now-30*day, from)

	from, to, err = ParseUsageRange("2026-01-01", "2026-01-02", now)
	require.NoError(t, err)
	assert.Equal(t, timeutil.TimeStamp(1767225600), from)
	assert.Equal(t, timeutil.TimeStamp(1767225600+2*86400-1), to) // the end of that day

	_, _, err = ParseUsageRange("2026-01-01", "2026-01-01", now) // one day is fine
	require.NoError(t, err)
	_, _, err = ParseUsageRange("2026-01-02", "2026-01-01", now) // inverted
	require.Error(t, err)
	_, _, err = ParseUsageRange("yesterday", "", now)
	require.Error(t, err)
	_, _, err = ParseUsageRange("", "tomorrow", now)
	require.Error(t, err)
	_, _, err = ParseUsageRange("2020-01-01", "2026-01-01", now) // longer than 366 days
	require.Error(t, err)
	_, _, err = ParseUsageRange("2025-01-01", "2026-01-01", now) // 366 days at most
	require.NoError(t, err)
}

type usageRepos struct{ org, org2, personal, trashed, noActions int64 }

// usageSetup gives repo3 and repo5 (org3), repo1 (user2), repo2 (user2, trashed) an Actions unit, repo21 (org3)
// none, and returns their IDs.
func usageSetup(t *testing.T) usageRepos {
	t.Helper()
	require.NoError(t, unittest.PrepareTestDatabase())
	for _, id := range []int64{1, 2, 3, 5} {
		has, err := db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", id, unit.TypeActions).Exist(new(repo_model.RepoUnit))
		require.NoError(t, err)
		if !has {
			require.NoError(t, db.Insert(t.Context(), &repo_model.RepoUnit{RepoID: id, Type: unit.TypeActions}))
		}
	}
	_, err := db.GetEngine(t.Context()).Exec("DELETE FROM repo_unit WHERE repo_id = 32 AND type = ?", unit.TypeActions)
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 2")
	require.NoError(t, err)
	return usageRepos{org: 3, org2: 5, personal: 1, trashed: 2, noActions: 32}
}

var jobHandle int

// addUsageJob inserts a job of repoID, run by the runner of a new task (none if runnerID is 0), with the given times.
func addUsageJob(t *testing.T, repoID, runnerID int64, started, stopped, updated timeutil.TimeStamp, status actions_model.Status) {
	t.Helper()
	jobHandle++
	var repo repo_model.Repository
	_, err := db.GetEngine(t.Context()).ID(repoID).Get(&repo)
	require.NoError(t, err)
	job := &actions_model.ActionRunJob{
		RunID: 1, RepoID: repoID, OwnerID: 999 /* stale */, Name: "j", Handle: fmt.Sprintf("usage-job-%d", jobHandle),
		Status: status, Started: started, Stopped: stopped, Attempt: 1,
	}
	require.NoError(t, db.Insert(t.Context(), job))
	if runnerID != 0 {
		task := &actions_model.ActionTask{JobID: job.ID, RunnerID: runnerID, RepoID: repoID, Status: status, TokenHash: fmt.Sprintf("usage-task-%d", jobHandle)}
		require.NoError(t, db.Insert(t.Context(), task))
		_, err = db.GetEngine(t.Context()).Exec("UPDATE action_run_job SET task_id = ? WHERE id = ?", task.ID, job.ID)
		require.NoError(t, err)
	}
	_, err = db.GetEngine(t.Context()).Exec("UPDATE action_run_job SET updated = ? WHERE id = ?", updated, job.ID)
	require.NoError(t, err)
}

func usageByID(entries []UsageEntry) map[int64]UsageEntry {
	m := map[int64]UsageEntry{}
	for _, e := range entries {
		m[e.ID] = e
	}
	return m
}

func TestGetUsage(t *testing.T) {
	r := usageSetup(t)
	const from, to = timeutil.TimeStamp(10_000), timeutil.TimeStamp(20_000)
	// runner 1 live, runner 2 soft-deleted
	require.NoError(t, db.Insert(t.Context(), &actions_model.ActionRunner{ID: 901, UUID: "00000000-0000-0000-0000-000000000901", Name: "alpha", TokenHash: "usage-r1"}))
	require.NoError(t, db.Insert(t.Context(), &actions_model.ActionRunner{ID: 902, UUID: "00000000-0000-0000-0000-000000000902", Name: "beta", TokenHash: "usage-r2"}))
	_, err := db.GetEngine(t.Context()).Exec("UPDATE action_runner SET deleted = 1 WHERE id = 902")
	require.NoError(t, err)

	ok := actions_model.StatusSuccess
	bad := actions_model.StatusFailure
	addUsageJob(t, r.org, 901, 11_000, 11_600, 11_600, ok)                      // 600 s
	addUsageJob(t, r.org, 902, 12_000, 12_060, 12_060, bad)                     // 60 s, deleted runner
	addUsageJob(t, r.org2, 901, 11_000, 0, 11_000, actions_model.StatusRunning) // unfinished: no minutes
	addUsageJob(t, r.org2, 901, 15_000, 14_000, 15_000, bad)                    // stopped before started: no minutes
	addUsageJob(t, r.org2, 0, 13_000, 13_120, 13_120, ok)                       // 120 s, no runner
	addUsageJob(t, r.personal, 901, 14_000, 14_300, 14_300, ok)                 // 300 s, user-owned repo
	addUsageJob(t, r.trashed, 901, 14_000, 14_900, 14_900, ok)                  // trashed repo: hidden
	addUsageJob(t, r.noActions, 901, 14_000, 14_900, 14_900, ok)                // Actions off: hidden
	addUsageJob(t, r.org, 901, from, from+10, from+10, ok)                      // 10 s, starts exactly at from
	addUsageJob(t, r.org, 901, to, to+10, to+10, ok)                            // 10 s, starts exactly at to
	addUsageJob(t, r.org, 901, to+1, to+11, to+11, ok)                          // after the range
	addUsageJob(t, r.org, 901, from-1, from+5, from+5, ok)                      // started before from, updated inside: excluded
	addUsageJob(t, r.org, 901, from-100, from-50, from-50, ok)                  // before the range
	addUsageJob(t, r.org2, 777, 16_000, 16_030, 16_030, ok)                     // 30 s, a runner that no longer exists
	addUsageJob(t, r.org2, 778, 16_100, 16_130, 16_130, ok)                     // 30 s, another one: the same bucket

	t.Run("repo", func(t *testing.T) {
		got, err := GetUsage(t.Context(), UsageGroupRepo, from, to, nil, 100)
		require.NoError(t, err)
		m := usageByID(got)
		require.Len(t, m, 3)
		assert.EqualValues(t, 600+60+10+10, m[r.org].Seconds)
		assert.EqualValues(t, 4, m[r.org].Jobs)
		assert.EqualValues(t, 1, m[r.org].FailedJobs)
		assert.Equal(t, "org3/repo3", m[r.org].Name)
		assert.EqualValues(t, 120+60, m[r.org2].Seconds) // the unfinished and the inverted job add nothing
		assert.EqualValues(t, 300, m[r.personal].Seconds)
		assert.Equal(t, r.org, got[0].ID, "sorted by seconds, most first")
	})
	t.Run("a job that started inside the range is kept by the updated pre-filter", func(t *testing.T) {
		// updated == started: the lowest value a valid job can have
		addUsageJob(t, r.personal, 901, from+500, from+560, from+500, ok)
		got, err := GetUsage(t.Context(), UsageGroupRepo, from, to, builder.Eq{"`repository`.id": r.personal}, 100)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.EqualValues(t, 300+60, got[0].Seconds)
		_, err = db.GetEngine(t.Context()).Exec("DELETE FROM action_run_job WHERE started = ?", from+500)
		require.NoError(t, err)
	})
	t.Run("owner, by repository owner and not the stale job owner", func(t *testing.T) {
		got, err := GetUsage(t.Context(), UsageGroupOrg, from, to, nil, 100)
		require.NoError(t, err)
		m := usageByID(got)
		require.Len(t, m, 2)
		assert.EqualValues(t, 600+60+10+10+120+60, m[3].Seconds)
		assert.Equal(t, "org3", m[3].Name)
		assert.EqualValues(t, 300, m[2].Seconds)
		assert.Equal(t, "user2", m[2].Name)
	})
	t.Run("runner, with deleted runners and jobs without a runner", func(t *testing.T) {
		got, err := GetUsage(t.Context(), UsageGroupRunner, from, to, nil, 100)
		require.NoError(t, err)
		m := usageByID(got)
		assert.EqualValues(t, 600+10+10+300, m[901].Seconds)
		assert.Equal(t, "alpha", m[901].Name)
		assert.EqualValues(t, 60, m[902].Seconds)
		assert.Equal(t, "beta", m[902].Name)
		assert.EqualValues(t, 120, m[0].Seconds)
		assert.EqualValues(t, 60, m[-1].Seconds)
		assert.EqualValues(t, 2, m[-1].Jobs)
	})
	t.Run("limit", func(t *testing.T) {
		got, err := GetUsage(t.Context(), UsageGroupRepo, from, to, nil, 1)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, r.org, got[0].ID)
	})
	t.Run("token restricted to one repository", func(t *testing.T) {
		got, err := GetUsage(t.Context(), UsageGroupRepo, from, to, builder.Eq{"`repository`.id": r.personal}, 100)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, r.personal, got[0].ID)
	})
	t.Run("top repositories by failed runs", func(t *testing.T) {
		for i, repoID := range []int64{r.org2, r.org2, r.org, r.trashed, r.noActions} {
			run := &actions_model.ActionRun{
				Title: "f", RepoID: repoID, OwnerID: 999, WorkflowID: "ci.yaml", Index: int64(8000 + i), TriggerUserID: 2,
				Ref: "refs/heads/main", Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusFailure,
			}
			require.NoError(t, db.Insert(t.Context(), run))
			_, err := db.GetEngine(t.Context()).Exec("UPDATE action_run SET created = ? WHERE id = ?", from+int64ToTS(i), run.ID)
			require.NoError(t, err)
		}
		got, err := TopReposByFailures(t.Context(), from, to, nil, 10)
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, r.org2, got[0].ID)
		assert.EqualValues(t, 2, got[0].FailedRuns)
		assert.EqualValues(t, 1, got[1].FailedRuns)
	})
	_ = user_model.User{}
}

func int64ToTS(i int) timeutil.TimeStamp { return timeutil.TimeStamp(i) }

func TestFindOrgRunsAllOwners(t *testing.T) {
	r := usageSetup(t)
	_, err := db.GetEngine(t.Context()).Exec("DELETE FROM action_run")
	require.NoError(t, err)
	for i, repoID := range []int64{r.org, r.personal, r.trashed, r.noActions} {
		require.NoError(t, db.Insert(t.Context(), &actions_model.ActionRun{
			Title: "x", RepoID: repoID, OwnerID: 999, WorkflowID: "ci.yaml", Index: int64(7000 + i), TriggerUserID: 2, EventPayload: `{"big":true}`,
			Ref: "refs/heads/main", Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusSuccess,
		}))
	}
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	runs, total, err := FindOrgRuns(t.Context(), nil, admin, true, nil, OrgRunFilter{}, db.ListOptions{Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.EqualValues(t, 2, total, "trashed and no-Actions repositories are hidden; stale owner_id is ignored")
	assert.Len(t, runs, 2)
	for _, run := range runs {
		assert.Empty(t, run.EventPayload, "OmitEventPayload: the payload isn't loaded")
		var full actions_model.ActionRun
		has, err := db.GetEngine(t.Context()).ID(run.ID).Get(&full)
		require.NoError(t, err)
		require.True(t, has)
		assert.JSONEq(t, `{"big":true}`, full.EventPayload, "a normal load has it")
		assert.Equal(t, "x", run.Title)
	}

	_, total, err = FindOrgRuns(t.Context(), nil, admin, true, nil, OrgRunFilter{Repo: "user2/repo1"}, db.ListOptions{Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	_, total, _ = FindOrgRuns(t.Context(), nil, admin, true, nil, OrgRunFilter{Repo: "USER2/Repo1"}, db.ListOptions{})
	assert.EqualValues(t, 1, total)
	_, total, _ = FindOrgRuns(t.Context(), nil, admin, true, nil, OrgRunFilter{Repo: "org3/repo1"}, db.ListOptions{})
	assert.EqualValues(t, 0, total)

	_, _, err = FindOrgRuns(t.Context(), nil, admin, false, nil, OrgRunFilter{}, db.ListOptions{})
	require.Error(t, err, "no organization is for site admins only")
}

func TestFindOrgRunsNotAdminStaysInOrg(t *testing.T) {
	r := usageSetup(t)
	require.NoError(t, db.Insert(t.Context(), &actions_model.ActionRun{
		Title: "x", RepoID: r.personal, OwnerID: 3, WorkflowID: "ci.yaml", Index: 7100, TriggerUserID: 2,
		Ref: "refs/heads/main", Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusSuccess,
	}))
	org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 3})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	runs, _, err := FindOrgRuns(t.Context(), org, owner, false, nil, OrgRunFilter{}, db.ListOptions{Page: 1, PageSize: 50})
	require.NoError(t, err)
	for _, run := range runs {
		assert.NotEqual(t, r.personal, run.RepoID)
	}
}

func TestIsActiveSiteAdmin(t *testing.T) {
	assert.True(t, IsActiveSiteAdmin(&user_model.User{IsAdmin: true, IsActive: true}))
	assert.False(t, IsActiveSiteAdmin(&user_model.User{IsAdmin: true, IsActive: false}))
	assert.False(t, IsActiveSiteAdmin(&user_model.User{IsAdmin: true, IsActive: true, ProhibitLogin: true}))
	assert.False(t, IsActiveSiteAdmin(&user_model.User{IsActive: true}))
	assert.False(t, IsActiveSiteAdmin(nil))
}

// A repository in a project is named by its full path, so it differs from a root repository with the same name.
func TestUsageNamesProject(t *testing.T) {
	r := usageSetup(t)
	const from, to = timeutil.TimeStamp(10_000), timeutil.TimeStamp(20_000)
	_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET name = 'repo3', lower_name = 'repo3', group_id = 7, group_name = 'payments' WHERE id = ?", r.org2)
	require.NoError(t, err)
	addUsageJob(t, r.org, 0, 11_000, 11_100, 11_100, actions_model.StatusSuccess)
	addUsageJob(t, r.org2, 0, 11_000, 11_200, 11_200, actions_model.StatusSuccess)
	for i, repoID := range []int64{r.org, r.org2} {
		run := &actions_model.ActionRun{
			Title: "f", RepoID: repoID, OwnerID: 999, WorkflowID: "ci.yaml", Index: int64(9000 + i), TriggerUserID: 2,
			Ref: "refs/heads/main", Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: actions_model.StatusFailure,
		}
		require.NoError(t, db.Insert(t.Context(), run))
		_, err := db.GetEngine(t.Context()).Exec("UPDATE action_run SET created = ? WHERE id = ?", from+10, run.ID)
		require.NoError(t, err)
	}

	usage, err := GetUsage(t.Context(), UsageGroupRepo, from, to, nil, 100)
	require.NoError(t, err)
	m := usageByID(usage)
	assert.Equal(t, "org3/repo3", m[r.org].Name)
	assert.Equal(t, "org3/payments/repo3", m[r.org2].Name)

	top, err := TopReposByFailures(t.Context(), from, to, nil, 10)
	require.NoError(t, err)
	m = usageByID(top)
	assert.Equal(t, "org3/repo3", m[r.org].Name)
	assert.Equal(t, "org3/payments/repo3", m[r.org2].Name)

	byOrg, err := GetUsage(t.Context(), UsageGroupOrg, from, to, nil, 100)
	require.NoError(t, err)
	assert.Equal(t, "org3", usageByID(byOrg)[3].Name)
}
