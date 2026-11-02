// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"fmt"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/timeutil"
	webhook_module "forgejo.org/modules/webhook"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var overviewSeq int64

// overviewSetup leaves org3 with Actions on and no runs or jobs, and returns it with the mocked current time.
// repo3 (private, default branch main) and repo5 (private) belong to org3; repo1 belongs to user2.
func overviewSetup(t *testing.T) (*organization.Organization, timeutil.TimeStamp) {
	t.Helper()
	orgRunsSetup(t)
	e := db.GetEngine(t.Context())
	for _, q := range []string{"DELETE FROM action_run", "DELETE FROM action_run_job", "DELETE FROM action_runner", "UPDATE repository SET default_branch = 'main' WHERE id = 3"} {
		_, err := e.Exec(q)
		require.NoError(t, err)
	}
	now := time.Unix(1_800_000_000, 0)
	timeutil.MockSet(now)
	t.Cleanup(timeutil.MockUnset)
	return unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 3}), timeutil.TimeStamp(now.Unix())
}

// overviewRun inserts a run of repoID owned (in action_run.owner_id) by ownerID, created at the given time.
func overviewRun(t *testing.T, repoID, ownerID int64, workflow, ref string, status actions_model.Status, created timeutil.TimeStamp) *actions_model.ActionRun {
	t.Helper()
	overviewSeq++
	run := &actions_model.ActionRun{
		Title: workflow, RepoID: repoID, OwnerID: ownerID, WorkflowID: workflow, Index: overviewSeq, TriggerUserID: 2, Ref: ref,
		Event: webhook_module.HookEventPush, TriggerEvent: "push", Status: status,
	}
	require.NoError(t, db.Insert(t.Context(), run))
	_, err := db.GetEngine(t.Context()).Exec("UPDATE action_run SET created = ? WHERE id = ?", created, run.ID)
	require.NoError(t, err)
	return run
}

// overviewJob inserts a job, created and started at the given times (started 0 = not picked up).
func overviewJob(t *testing.T, run *actions_model.ActionRun, name string, status actions_model.Status, runsOn []string, created, started timeutil.TimeStamp, attempt int64) *actions_model.ActionRunJob {
	t.Helper()
	overviewSeq++
	job := &actions_model.ActionRunJob{
		RunID: run.ID, RepoID: run.RepoID, OwnerID: run.OwnerID, Name: name, Handle: fmt.Sprintf("handle-%d", overviewSeq),
		JobID: actions_model.JobIdentifier(name), RunsOn: runsOn, Status: status, Attempt: attempt,
	}
	require.NoError(t, db.Insert(t.Context(), job))
	_, err := db.GetEngine(t.Context()).Exec("UPDATE action_run_job SET created = ?, started = ? WHERE id = ?", created, started, job.ID)
	require.NoError(t, err)
	return job
}

func overviewRunner(t *testing.T, ownerID, repoID int64, labels []string, lastOnline timeutil.TimeStamp) {
	t.Helper()
	overviewSeq++
	require.NoError(t, db.Insert(t.Context(), &actions_model.ActionRunner{
		UUID: fmt.Sprintf("00000000-0000-0000-0000-%012d", overviewSeq), Name: "r", TokenHash: fmt.Sprintf("hash%d", overviewSeq),
		OwnerID: ownerID, RepoID: repoID, AgentLabels: labels, LastOnline: lastOnline,
	}))
}

func TestOrgOverviewCards(t *testing.T) {
	org, now := overviewSetup(t)
	day, week := timeutil.TimeStamp(24*3600), timeutil.TimeStamp(7*24*3600)
	st := actions_model.StatusSuccess
	overviewRun(t, 3, 3, "a.yaml", "refs/heads/main", st, now-3600)
	overviewRun(t, 3, 3, "a.yaml", "refs/heads/main", actions_model.StatusFailure, now-day+10)          // 24h, edge inside
	overviewRun(t, 3, 3, "a.yaml", "refs/heads/main", actions_model.StatusFailure, now-day-10)          // 7d only
	overviewRun(t, 3, 3, "a.yaml", "refs/heads/main", st, now-week+10)                                  // 7d, edge inside
	overviewRun(t, 3, 3, "a.yaml", "refs/heads/main", st, now-week-10)                                  // too old
	overviewRun(t, 3, 3, "a.yaml", "refs/heads/main", actions_model.StatusCancelled, now-3600)          // counted, not finished
	running := overviewRun(t, 5, 3, "a.yaml", "refs/heads/main", actions_model.StatusRunning, now-3600) // counted, running
	overviewRun(t, 1, 3, "a.yaml", "refs/heads/main", actions_model.StatusFailure, now-3600)            // repo1 was transferred out: stale owner_id
	foreign := overviewRun(t, 1, 3, "a.yaml", "refs/heads/main", actions_model.StatusWaiting, now-3600)

	w := actions_model.StatusWaiting
	overviewJob(t, running, "q1", w, []string{"x"}, now-50, 0, 0)
	overviewJob(t, running, "q2", w, []string{"x"}, now-500, 0, 0)
	overviewJob(t, foreign, "q3", w, []string{"x"}, now-50, 0, 0)                                            // transferred out
	overviewJob(t, running, "s1", actions_model.StatusRunning, []string{"x"}, now-100, now-40, 1)            // waited 60s
	overviewJob(t, running, "s2", actions_model.StatusRunning, []string{"x"}, now-200, now-100, 1)           // waited 100s
	overviewJob(t, running, "s3", actions_model.StatusRunning, []string{"x"}, now-5000, now-10, 2)           // re-run: not a sample
	overviewJob(t, running, "s4", actions_model.StatusSuccess, []string{"x"}, now-week-500, now-week-300, 1) // too old
	overviewJob(t, foreign, "s5", actions_model.StatusSuccess, []string{"x"}, now-900, now-100, 1)           // transferred out

	o, err := GetOrgOverview(t.Context(), org, nil, true, nil, now)
	require.NoError(t, err)
	assert.EqualValues(t, 4, o.Runs24h) // success, failure edge, cancelled, running
	assert.EqualValues(t, 6, o.Runs7d)
	assert.EqualValues(t, 4, o.Finished7d)
	assert.EqualValues(t, 2, o.Failed7d)
	assert.EqualValues(t, 1, o.Running)
	assert.EqualValues(t, 2, o.Queued)
	assert.True(t, o.HasQueueSample)
	assert.Equal(t, 80*time.Second, o.AvgQueue)

	// nothing at all: no sample, no division by zero
	_, err = db.GetEngine(t.Context()).Exec("DELETE FROM action_run_job")
	require.NoError(t, err)
	o, err = GetOrgOverview(t.Context(), org, nil, true, nil, now)
	require.NoError(t, err)
	assert.False(t, o.HasQueueSample)
}

// The overview shows what the runs list shows, for every user.
func TestOrgOverviewParity(t *testing.T) {
	orgRunsSetup(t)
	now := timeutil.TimeStampNow()
	var users []*user_model.User
	require.NoError(t, db.GetEngine(t.Context()).Where("type = ?", user_model.UserTypeIndividual).Find(&users))
	for _, orgID := range []int64{3, 17} {
		org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: orgID})
		for _, doer := range users {
			_, total, err := FindOrgRuns(t.Context(), org, doer, doer.IsAdmin, nil, OrgRunFilter{}, db.ListOptions{ListAll: true})
			require.NoError(t, err)
			o, err := GetOrgOverview(t.Context(), org, doer, doer.IsAdmin, nil, now+1)
			require.NoError(t, err)
			assert.Equal(t, total, o.Runs7d, "org %d, user %s", orgID, doer.Name)
		}
	}

	// a trashed repo and a repo without the Actions unit drop out of the counts
	org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 3})
	before, err := GetOrgOverview(t.Context(), org, nil, true, nil, now+1)
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 3")
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Exec("DELETE FROM repo_unit WHERE repo_id = 5 AND type = ?", unit.TypeActions)
	require.NoError(t, err)
	after, err := GetOrgOverview(t.Context(), org, nil, true, nil, now+1)
	require.NoError(t, err)
	assert.Equal(t, before.Runs7d-2, after.Runs7d)
	_, n, err := FindOrgFailingNow(t.Context(), org, nil, true, nil, 50)
	require.NoError(t, err)
	assert.Zero(t, n)
}

func TestOrgFailingNow(t *testing.T) {
	org, now := overviewSetup(t)
	main, fail, ok := "refs/heads/main", actions_model.StatusFailure, actions_model.StatusSuccess
	overviewRun(t, 3, 3, "healed.yaml", main, fail, now-300)
	overviewRun(t, 3, 3, "healed.yaml", main, ok, now-200) // a later success removes it
	overviewRun(t, 3, 3, "broken.yaml", main, ok, now-300)
	broken := overviewRun(t, 3, 3, "broken.yaml", main, fail, now-200)
	overviewRun(t, 3, 3, "cancelled.yaml", main, fail, now-300)
	cancelled := overviewRun(t, 3, 3, "cancelled.yaml", main, actions_model.StatusCancelled, now-200) // does not hide it
	_ = cancelled
	overviewRun(t, 3, 3, "dev.yaml", "refs/heads/dev", fail, now-100)  // not the default branch
	overviewRun(t, 3, 3, "pr.yaml", "refs/pull/1/head", fail, now-100) // not a branch
	overviewRun(t, 5, 3, "nodefault.yaml", main, fail, now-100)        // repo5: default branch is empty
	overviewRun(t, 1, 3, "moved.yaml", main, fail, now-100)            // transferred out
	_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET default_branch = '' WHERE id = 5")
	require.NoError(t, err)

	runs, total, err := FindOrgFailingNow(t.Context(), org, nil, true, nil, 50)
	require.NoError(t, err)
	var names []string
	for _, r := range runs {
		names = append(names, r.WorkflowID)
		assert.NotNil(t, r.Repo)
	}
	assert.Equal(t, []string{"cancelled.yaml", "broken.yaml"}, names) // newest first
	assert.EqualValues(t, 2, total)
	assert.Equal(t, broken.ID, runs[1].ID)

	// the limit only cuts the list, not the total
	runs, total, err = FindOrgFailingNow(t.Context(), org, nil, true, nil, 1)
	require.NoError(t, err)
	assert.Len(t, runs, 1)
	assert.EqualValues(t, 2, total)

	// a user who can't read repo3 sees nothing
	nobody := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8})
	runs, total, err = FindOrgFailingNow(t.Context(), org, nobody, false, nil, 50)
	require.NoError(t, err)
	assert.Empty(t, runs)
	assert.Zero(t, total)
}

func TestOrgQueue(t *testing.T) {
	org, now := overviewSetup(t)
	w := actions_model.StatusWaiting
	r3 := overviewRun(t, 3, 3, "a.yaml", "refs/heads/main", w, now-1000)
	r5 := overviewRun(t, 5, 3, "a.yaml", "refs/heads/main", w, now-1000)
	moved := overviewRun(t, 1, 3, "a.yaml", "refs/heads/main", w, now-1000)
	overviewJob(t, r3, "global", w, []string{"linux"}, now-900, 0, 0)
	overviewJob(t, r3, "nolabel", w, []string{"gpu"}, now-800, 0, 0)
	overviewJob(t, r3, "offline", w, []string{"arm"}, now-700, 0, 0)
	overviewJob(t, r3, "org", w, []string{"mac"}, now-600, 0, 0)
	overviewJob(t, r3, "otherrepo", w, []string{"r5only"}, now-500, 0, 0) // runner of repo5
	overviewJob(t, r5, "ownrepo", w, []string{"r5only"}, now-400, 0, 0)
	overviewJob(t, r3, "otherorg", w, []string{"o2"}, now-300, 0, 0) // runner of user2
	overviewJob(t, r3, "subset", w, []string{"linux", "docker"}, now-200, 0, 0)
	overviewJob(t, r3, "taken", w, []string{"linux"}, now-100, 0, 0)
	overviewJob(t, moved, "moved", w, []string{"linux"}, now-100, 0, 0) // transferred out
	overviewJob(t, r3, "running", actions_model.StatusRunning, []string{"linux"}, now-100, now-50, 1)
	_, err := db.GetEngine(t.Context()).Exec("UPDATE action_run_job SET task_id = 7 WHERE name = 'taken'")
	require.NoError(t, err)

	overviewRunner(t, 0, 0, []string{"linux", "docker"}, now-10) // global
	overviewRunner(t, 0, 0, []string{"arm"}, now-120)            // offline
	overviewRunner(t, 3, 0, []string{"mac"}, now-10)             // org3
	overviewRunner(t, 0, 5, []string{"r5only"}, now-10)          // repo5
	overviewRunner(t, 2, 0, []string{"o2"}, now-10)              // user2

	jobs, total, err := FindOrgQueue(t.Context(), org, nil, true, nil, 50, now)
	require.NoError(t, err)
	got := map[string]bool{}
	var order []string
	for _, j := range jobs {
		got[j.Job.Name] = j.HasRunner
		order = append(order, j.Job.Name)
		assert.NotNil(t, j.Repo)
		assert.NotNil(t, j.Run)
	}
	assert.Equal(t, map[string]bool{
		"global": true, "nolabel": false, "offline": false, "org": true, "otherrepo": false, "ownrepo": true, "otherorg": false, "subset": true,
	}, got)
	assert.Equal(t, "global", order[0], "oldest first")
	assert.EqualValues(t, 8, total)

	jobs, total, err = FindOrgQueue(t.Context(), org, nil, true, nil, 2, now)
	require.NoError(t, err)
	assert.Len(t, jobs, 2)
	assert.EqualValues(t, 8, total)

	// a user who can't read the repositories sees no job (and so no runner)
	nobody := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8})
	jobs, total, err = FindOrgQueue(t.Context(), org, nobody, false, nil, 50, now)
	require.NoError(t, err)
	assert.Empty(t, jobs)
	assert.Zero(t, total)
}
