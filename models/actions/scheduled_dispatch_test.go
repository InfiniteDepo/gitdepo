// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"sync"
	"testing"
	"time"

	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newScheduledDispatch(t *testing.T, repoID int64, runAt timeutil.TimeStamp) *ActionScheduledDispatch {
	t.Helper()
	sd := &ActionScheduledDispatch{RepoID: repoID, WorkflowID: "a.yml", Ref: "main", Inputs: `{"k":"v"}`, DoerID: 2, RunAt: runAt}
	require.NoError(t, InsertScheduledDispatch(t.Context(), sd))
	return sd
}

// cancelScheduledDispatch makes a cancelled row the way the due job does: claimed first
func cancelScheduledDispatch(t *testing.T, id int64, reason string) {
	t.Helper()
	_, err := db.GetEngine(t.Context()).ID(id).Cols("status").Update(&ActionScheduledDispatch{Status: ScheduledDispatchClaimed})
	require.NoError(t, err)
	require.NoError(t, CancelClaimedScheduledDispatch(t.Context(), id, reason))
}

func TestScheduledDispatchCRUD(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()

	a := newScheduledDispatch(t, 1, 100)
	b := newScheduledDispatch(t, 1, 200)
	newScheduledDispatch(t, 2, 300)

	list, total, err := ListScheduledDispatches(ctx, 1, db.ListOptions{})
	require.NoError(t, err)
	assert.EqualValues(t, 2, total)
	require.Len(t, list, 2)
	assert.Equal(t, a.ID, list[0].ID, "ordered by time")

	n, err := CountPendingScheduledDispatches(ctx, 1)
	require.NoError(t, err)
	assert.EqualValues(t, 2, n)

	_, err = GetScheduledDispatch(ctx, 2, a.ID)
	require.ErrorIs(t, err, ErrScheduledDispatchNotFound, "ids are scoped by repository")
	got, err := GetScheduledDispatch(ctx, 1, a.ID)
	require.NoError(t, err)
	assert.JSONEq(t, `{"k":"v"}`, got.Inputs)

	require.NoError(t, UpdateScheduledDispatchRunAt(ctx, 1, a.ID, 500))
	got, err = GetScheduledDispatch(ctx, 1, a.ID)
	require.NoError(t, err)
	assert.EqualValues(t, 500, got.RunAt)
	require.ErrorIs(t, UpdateScheduledDispatchRunAt(ctx, 2, a.ID, 600), ErrScheduledDispatchNotFound)

	cancelScheduledDispatch(t, b.ID, "no_permission")
	require.ErrorIs(t, UpdateScheduledDispatchRunAt(ctx, 1, b.ID, 600), ErrScheduledDispatchNotFound, "only a pending row changes")
	n, err = CountPendingScheduledDispatches(ctx, 1)
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	got, err = GetScheduledDispatch(ctx, 1, b.ID)
	require.NoError(t, err)
	assert.Equal(t, ScheduledDispatchCancelled, got.Status)
	assert.Equal(t, "no_permission", got.CancelReason)

	require.ErrorIs(t, DeleteScheduledDispatch(ctx, 2, b.ID), ErrScheduledDispatchNotFound)
	require.NoError(t, DeleteScheduledDispatch(ctx, 1, b.ID))

	require.NoError(t, DeleteScheduledDispatch(ctx, 1, a.ID))
	_, total, err = ListScheduledDispatches(ctx, 1, db.ListOptions{})
	require.NoError(t, err)
	assert.Zero(t, total)
	_, total, err = ListScheduledDispatches(ctx, 2, db.ListOptions{})
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
}

func TestTakeDueScheduledDispatch(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	first := newScheduledDispatch(t, 1, 100)
	second := newScheduledDispatch(t, 1, 150)
	newScheduledDispatch(t, 1, 300)

	sd, err := TakeDueScheduledDispatch(ctx, 99)
	require.NoError(t, err)
	assert.Nil(t, sd)

	// one row per call, oldest first
	sd, err = TakeDueScheduledDispatch(ctx, 200)
	require.NoError(t, err)
	require.NotNil(t, sd)
	assert.Equal(t, first.ID, sd.ID)
	unittest.AssertExistsAndLoadBean(t, &ActionScheduledDispatch{ID: second.ID, Status: ScheduledDispatchPending})

	sd, err = TakeDueScheduledDispatch(ctx, 200)
	require.NoError(t, err)
	require.NotNil(t, sd)
	assert.Equal(t, second.ID, sd.ID)

	sd, err = TakeDueScheduledDispatch(ctx, 200)
	require.NoError(t, err)
	assert.Nil(t, sd, "a row is returned once")

	// claimed rows can't be cancelled or moved by a user
	require.ErrorIs(t, UpdateScheduledDispatchRunAt(ctx, 1, first.ID, 5), ErrScheduledDispatchNotFound)
}

func TestScheduledDispatchCancelClearsInputs(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()

	pending := newScheduledDispatch(t, 1, 100)
	cancelScheduledDispatch(t, pending.ID, "no_permission")
	got, err := GetScheduledDispatch(ctx, 1, pending.ID)
	require.NoError(t, err)
	assert.Empty(t, got.Inputs)

	claimed := newScheduledDispatch(t, 1, 100)
	taken, err := TakeDueScheduledDispatch(ctx, 200)
	require.NoError(t, err)
	require.Equal(t, claimed.ID, taken.ID)
	require.NoError(t, CancelClaimedScheduledDispatch(ctx, claimed.ID, "ref_changed"))
	got, err = GetScheduledDispatch(ctx, 1, claimed.ID)
	require.NoError(t, err)
	assert.Empty(t, got.Inputs)
	assert.Equal(t, "ref_changed", got.CancelReason)

	// only the fixed codes are stored, whatever the caller passes
	other := newScheduledDispatch(t, 1, 100)
	cancelScheduledDispatch(t, other.ID, "../../etc"+string(make([]byte, 300)))
	got, err = GetScheduledDispatch(ctx, 1, other.ID)
	require.NoError(t, err)
	assert.Equal(t, "internal_error", got.CancelReason)
}

func TestTakeDueScheduledDispatchesConcurrent(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	for range 5 {
		newScheduledDispatch(t, 1, 100)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	seen := map[int64]int{}
	var errs []error
	for range 4 {
		wg.Go(func() {
			for {
				sd, err := TakeDueScheduledDispatch(t.Context(), 200)
				mu.Lock()
				errs = append(errs, err)
				if sd != nil {
					seen[sd.ID]++
				}
				mu.Unlock()
				if sd == nil || err != nil {
					return
				}
			}
		})
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	assert.Len(t, seen, 5)
	for _, c := range seen {
		assert.Equal(t, 1, c)
	}
}

func TestCleanupOldScheduledDispatches(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	now := timeutil.TimeStampNow()
	age := func(sd *ActionScheduledDispatch, d time.Duration) {
		// xorm stamps `updated` with the real clock, so backdate it
		_, err := db.GetEngine(ctx).Exec("UPDATE action_scheduled_dispatch SET updated = ? WHERE id = ?", int64(now)-int64(d.Seconds()), sd.ID)
		require.NoError(t, err)
	}
	oldCancelled := newScheduledDispatch(t, 1, 100)
	cancelScheduledDispatch(t, oldCancelled.ID, "x")
	age(oldCancelled, 8*24*time.Hour)
	recentCancelled := newScheduledDispatch(t, 1, 100)
	cancelScheduledDispatch(t, recentCancelled.ID, "x")
	age(recentCancelled, time.Hour)
	staleClaimed := newScheduledDispatch(t, 1, 100)
	freshClaimed := newScheduledDispatch(t, 1, 100)
	for range 2 {
		_, err := TakeDueScheduledDispatch(ctx, 200)
		require.NoError(t, err)
	}
	age(staleClaimed, time.Hour)
	age(freshClaimed, 2*time.Minute)

	require.NoError(t, CleanupOldScheduledDispatches(ctx, now))

	_, err := GetScheduledDispatch(ctx, 1, oldCancelled.ID)
	require.ErrorIs(t, err, ErrScheduledDispatchNotFound)
	got, err := GetScheduledDispatch(ctx, 1, staleClaimed.ID)
	require.NoError(t, err)
	assert.Equal(t, ScheduledDispatchCancelled, got.Status)
	assert.Equal(t, "interrupted", got.CancelReason)
	assert.Empty(t, got.Inputs)
	unittest.AssertExistsAndLoadBean(t, &ActionScheduledDispatch{ID: freshClaimed.ID, Status: ScheduledDispatchClaimed})
	_, err = GetScheduledDispatch(ctx, 1, recentCancelled.ID)
	require.NoError(t, err)
}
