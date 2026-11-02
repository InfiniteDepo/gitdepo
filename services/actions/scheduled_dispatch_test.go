// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"math"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckScheduleTime(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	timeutil.MockSet(now)
	defer timeutil.MockUnset()
	defer test.MockVariableValue(&setting.Actions.MaxDelayedRunDays, 30)()

	require.NoError(t, CheckScheduleTime(now.Add(time.Minute)))
	require.NoError(t, CheckScheduleTime(now.AddDate(0, 0, 30)))
	require.ErrorIs(t, CheckScheduleTime(now), ErrScheduleInPast)
	require.ErrorIs(t, CheckScheduleTime(now.Add(-time.Hour)), ErrScheduleInPast)
	require.ErrorIs(t, CheckScheduleTime(now.AddDate(0, 0, 30).Add(time.Second)), ErrScheduleTooFar)
	require.ErrorIs(t, ErrScheduleTooFar, util.ErrInvalidArgument)

	setting.Actions.MaxDelayedRunDays = math.MaxInt
	require.NoError(t, CheckScheduleTime(now.Add(time.Minute)))
	require.ErrorIs(t, CheckScheduleTime(time.Unix(1<<62, 0)), ErrScheduleTooFar)

	setting.Actions.MaxDelayedRunDays = 0
	require.ErrorIs(t, CheckScheduleTime(now.Add(time.Minute)), ErrScheduleDisabled)
}

func TestScheduleDispatchLimit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Actions.MaxDelayedRunDays, 30)()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	for range maxPendingScheduledDispatches {
		require.NoError(t, actions_model.InsertScheduledDispatch(t.Context(), &actions_model.ActionScheduledDispatch{RepoID: repo.ID, WorkflowID: "a.yml", Ref: "refs/heads/main", DoerID: doer.ID, RunAt: 1}))
	}
	_, err := ScheduleDispatch(t.Context(), repo, doer, &Workflow{WorkflowID: "a.yml"}, nil, time.Now().Add(time.Hour))
	require.ErrorIs(t, err, ErrScheduleLimit)

	_, err = ScheduleDispatch(t.Context(), repo, user_model.NewActionsUser(), &Workflow{WorkflowID: "a.yml"}, nil, time.Now().Add(time.Hour))
	require.ErrorIs(t, err, util.ErrPermissionDenied)
}

// The checks that need no git repository: whatever the row stores, the due job starts nothing and cancels with a code
func TestStartDueScheduledDispatchesCancels(t *testing.T) {
	defer test.MockVariableValue(&setting.Actions.MaxDelayedRunDays, 30)()
	exec := func(t *testing.T, query string, args ...any) {
		t.Helper()
		_, err := db.GetEngine(t.Context()).Exec(append([]any{query}, args...)...)
		require.NoError(t, err)
	}
	cases := []struct {
		name   string
		repoID int64
		doerID int64
		prep   func(t *testing.T)
		reason string
	}{
		{"repo missing", 999999, 2, nil, "repo_missing"},
		{"repo trashed", 1, 2, func(t *testing.T) { exec(t, "UPDATE repository SET trashed_unix = 1 WHERE id = 1") }, "repo_missing"},
		{"doer missing", 1, 999999, nil, "doer_missing"},
		{"doer ghost", 1, -1, nil, "doer_missing"},
		{"doer prohibited", 1, 2, func(t *testing.T) { exec(t, "UPDATE `user` SET prohibit_login = ? WHERE id = 2", true) }, "doer_disabled"},
		{"doer inactive", 1, 2, func(t *testing.T) { exec(t, "UPDATE `user` SET is_active = ? WHERE id = 2", false) }, "doer_disabled"},
		{"repo archived", 1, 2, func(t *testing.T) { exec(t, "UPDATE repository SET is_archived = ? WHERE id = 1", true) }, "repo_archived"},
		{"actions unit off", 1, 2, func(t *testing.T) { exec(t, "DELETE FROM repo_unit WHERE repo_id = 1 AND type = ?", unit.TypeActions) }, "actions_disabled"},
		{"org turns actions off", 3, 2, func(t *testing.T) {
			exec(t, "INSERT INTO repo_unit (repo_id, type, config, created_unix) VALUES (3, ?, '{}', 1)", unit.TypeActions)
			unittest.AssertSuccessfulInsert(t, &repo_model.OrgUnit{OrgID: 3, Type: unit.TypeActions, Disabled: true})
		}, "actions_disabled"},
		{"write permission lost", 1, 5, nil, "no_permission"}, // user 5 has no access to user2/repo1's Actions
		{"read only", 1, 4, nil, "no_permission"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.NoError(t, unittest.PrepareTestDatabase())
			if c.prep != nil {
				c.prep(t)
				defer db.DeleteAllRecords("org_unit")
			}
			now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
			timeutil.MockSet(now.Add(-time.Hour))
			sd := &actions_model.ActionScheduledDispatch{RepoID: c.repoID, WorkflowID: "a.yml", Ref: "refs/heads/master", Inputs: "{}", DoerID: c.doerID, RunAt: timeutil.TimeStamp(now.Unix())}
			require.NoError(t, actions_model.InsertScheduledDispatch(t.Context(), sd))
			runs := unittest.GetCount(t, &actions_model.ActionRun{})

			// before the time nothing happens
			require.NoError(t, StartDueScheduledDispatches(t.Context()))
			unittest.AssertExistsAndLoadBean(t, &actions_model.ActionScheduledDispatch{ID: sd.ID, Status: actions_model.ScheduledDispatchPending})

			timeutil.MockSet(now)
			defer timeutil.MockUnset()
			require.NoError(t, StartDueScheduledDispatches(t.Context()))
			unittest.AssertExistsAndLoadBean(t, &actions_model.ActionScheduledDispatch{ID: sd.ID, Status: actions_model.ScheduledDispatchCancelled, CancelReason: c.reason})
			assert.Equal(t, runs, unittest.GetCount(t, &actions_model.ActionRun{}))

			// a second pass leaves the cancelled row alone
			require.NoError(t, StartDueScheduledDispatches(t.Context()))
			unittest.AssertExistsAndLoadBean(t, &actions_model.ActionScheduledDispatch{ID: sd.ID, Status: actions_model.ScheduledDispatchCancelled, CancelReason: c.reason})
		})
	}
}

// A row that is overdue by more than an hour (the server was down) is cancelled, not started late
func TestStartDueScheduledDispatchesMissed(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	timeutil.MockSet(now)
	defer timeutil.MockUnset()
	runs := unittest.GetCount(t, &actions_model.ActionRun{})

	late := &actions_model.ActionScheduledDispatch{RepoID: 1, WorkflowID: "a.yml", Ref: "refs/heads/master", Inputs: `{"a":"b"}`, DoerID: 2, RunAt: timeutil.TimeStamp(now.Add(-61 * time.Minute).Unix())}
	require.NoError(t, actions_model.InsertScheduledDispatch(t.Context(), late))
	require.NoError(t, StartDueScheduledDispatches(t.Context()))

	got := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionScheduledDispatch{ID: late.ID, Status: actions_model.ScheduledDispatchCancelled, CancelReason: "missed"})
	assert.Empty(t, got.Inputs, "the inputs are dropped with the cancellation")
	assert.Equal(t, runs, unittest.GetCount(t, &actions_model.ActionRun{}))
}

func TestChangeScheduledRunAt(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	timeutil.MockSet(now)
	defer timeutil.MockUnset()
	defer test.MockVariableValue(&setting.Actions.MaxDelayedRunDays, 30)()

	sd := &actions_model.ActionScheduledDispatch{RepoID: 1, WorkflowID: "a.yml", Ref: "refs/heads/master", Inputs: "{}", DoerID: 2, RunAt: timeutil.TimeStamp(now.Add(time.Hour).Unix())}
	require.NoError(t, actions_model.InsertScheduledDispatch(t.Context(), sd))
	runAt := func() timeutil.TimeStamp {
		return unittest.AssertExistsAndLoadBean(t, &actions_model.ActionScheduledDispatch{ID: sd.ID}).RunAt
	}

	require.NoError(t, ChangeScheduledRunAt(t.Context(), 1, sd.ID, now.Add(2*time.Hour)))
	assert.EqualValues(t, now.Add(2*time.Hour).Unix(), runAt())

	// the window is checked again, and a refused change leaves the row alone
	require.ErrorIs(t, ChangeScheduledRunAt(t.Context(), 1, sd.ID, now), ErrScheduleInPast)
	require.ErrorIs(t, ChangeScheduledRunAt(t.Context(), 1, sd.ID, now.AddDate(0, 0, 31)), ErrScheduleTooFar)
	require.ErrorIs(t, ChangeScheduledRunAt(t.Context(), 1, sd.ID, time.Unix(1<<62, 0)), ErrScheduleTooFar)
	assert.EqualValues(t, now.Add(2*time.Hour).Unix(), runAt())
	setting.Actions.MaxDelayedRunDays = 0
	require.ErrorIs(t, ChangeScheduledRunAt(t.Context(), 1, sd.ID, now.Add(time.Hour)), ErrScheduleDisabled)
	setting.Actions.MaxDelayedRunDays = 30

	// other repository, and a row that is no longer pending
	require.ErrorIs(t, ChangeScheduledRunAt(t.Context(), 2, sd.ID, now.Add(time.Hour)), actions_model.ErrScheduledDispatchNotFound)
	_, err := db.GetEngine(t.Context()).ID(sd.ID).Cols("status").Update(&actions_model.ActionScheduledDispatch{Status: actions_model.ScheduledDispatchCancelled})
	require.NoError(t, err)
	require.ErrorIs(t, ChangeScheduledRunAt(t.Context(), 1, sd.ID, now.Add(time.Hour)), actions_model.ErrScheduledDispatchNotFound)
}
