// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"slices"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func markedIDs(t *testing.T) []int64 {
	t.Helper()
	var ids []int64
	require.NoError(t, db.GetEngine(t.Context()).Table("secret_scan").Select("repo_id").Where("requeue > 0").OrderBy("repo_id").Find(&ids))
	return ids
}

func collectRequeued(t *testing.T) []int64 {
	t.Helper()
	var got []int64
	require.NoError(t, requeueMarked(t.Context(), func(id int64) { got = append(got, id) }))
	slices.Sort(got)
	return got
}

// Turning scanning on marks the repositories that were scanned before: the organization's (or all), not the ones whose
// own switch is off, not the trashed ones, and the mark is queued across more than one batch.
func TestRequeueMarked(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	// org3 owns repositories 3, 5 and 32; user2 owns 1
	for _, id := range []int64{1, 3, 5, 32} {
		_, err := db.GetEngine(ctx).Insert(&secretscan_model.Scan{RepoID: id, Kind: secretscan_model.KindRepo, Status: secretscan_model.StatusOK})
		require.NoError(t, err)
	}
	mark := func(orgID int64) []int64 {
		t.Helper()
		_, err := db.GetEngine(ctx).Exec("UPDATE secret_scan SET requeue = 0")
		require.NoError(t, err)
		require.NoError(t, secretscan_model.MarkRequeue(ctx, orgID))
		return markedIDs(t)
	}
	assert.Equal(t, []int64{5, 32}, mark(3), "repository 3 is still being migrated in the fixtures")
	_, err := db.GetEngine(ctx).Exec("UPDATE repository SET status = 0 WHERE id = 3")
	require.NoError(t, err)
	assert.Equal(t, []int64{3, 5, 32}, mark(3), "the organization's repositories only")
	assert.Equal(t, []int64{3, 5, 32}, collectRequeued(t))
	assert.Equal(t, []int64{1, 3, 5, 32}, mark(0))

	defer test.MockVariableValue(&requeueBatch, 1)()
	assert.Equal(t, []int64{1, 3, 5, 32}, collectRequeued(t), "more than one batch")

	_, err = db.GetEngine(ctx).Exec("UPDATE repository SET secret_scanning_disabled = ? WHERE id = 5", true)
	require.NoError(t, err)
	assert.Equal(t, []int64{1, 3, 32}, collectRequeued(t), "a repository that turned it off since is left out")
	assert.Equal(t, []int64{1, 3, 32}, mark(0), "and is not marked")

	_, err = db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 32")
	require.NoError(t, err)
	assert.Equal(t, []int64{1, 3}, mark(0), "a trashed repository is left out")

	require.NoError(t, secretscan_model.ClearRequeue(ctx, 1, 0))
	assert.Equal(t, []int64{1, 3}, collectRequeued(t), "a clear with a stale counter keeps the mark")
	require.NoError(t, secretscan_model.ClearRequeue(ctx, 1, 1))
	assert.Equal(t, []int64{3}, collectRequeued(t), "the scan took repository 1")

	_, err = db.GetEngine(ctx).Exec("DELETE FROM secret_scan WHERE repo_id = 3")
	require.NoError(t, err)
	assert.Empty(t, mark(0)[1:], "a repository that was never scanned is the cron task's, not marked")
}

// The mark is set by the save, survives a process that stops before it queued anything, is queued by the cron task
// and cleared by the scan.
func TestRequeueMarkSurvivesARestart(t *testing.T) {
	repo := enable(t)
	q := mockQueue(t)
	ctx := audit_model.WithSystem(t.Context(), "test")
	w := newWork(t, repo)
	w.commit(map[string]string{"a.txt": "nothing here\n"}, "Dev", "dev@example.com")
	w.pushDefault()
	require.NoError(t, Scan(ctx, repo.ID))
	require.NoError(t, secretscan_model.ClearRequeue(ctx, repo.ID, scanOf(t, repo.ID, secretscan_model.KindRepo).Requeue))
	require.Empty(t, markedIDs(t))
	_, err := db.GetEngine(ctx).Exec("UPDATE repository SET secret_scanning_disabled = ? WHERE id = ?", false, repo.ID)
	require.NoError(t, err)

	// the save runs and the process stops before the background queue did anything
	defer test.MockVariableValue(&requeue, func() {})()
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	_, err = SaveSwitches(ctx, doer, false, false, true)
	require.NoError(t, err)
	_, err = SaveSwitches(ctx, doer, true, false, true)
	require.NoError(t, err)
	assert.Contains(t, markedIDs(t), repo.ID, "the save marked the scanned repository")

	// after the restart, the cron task queues it
	require.NoError(t, EnqueueUnscanned(ctx))
	has, err := q.Has(repo.ID)
	require.NoError(t, err)
	assert.True(t, has, "queued by the cron task")

	// the scan takes the row and clears the mark
	require.NoError(t, Scan(ctx, repo.ID))
	assert.NotContains(t, markedIDs(t), repo.ID)
	assert.Zero(t, scanOf(t, repo.ID, secretscan_model.KindRepo).Requeue)
}

// After a restart every marked repository is queued by the startup run and by the cron task, not 500 per run; and a
// slice that fails keeps the mark, one that writes its state takes it.
func TestRequeueAfterRestart(t *testing.T) {
	repo := enable(t)
	q := mockQueue(t)
	ctx := audit_model.WithSystem(t.Context(), "test")
	for _, id := range []int64{2, 3, 4} {
		_, err := db.GetEngine(ctx).Exec("UPDATE repository SET status = 0 WHERE id = ?", id)
		require.NoError(t, err)
	}
	w := newWork(t, repo)
	w.commit(map[string]string{"a.txt": "nothing here\n"})
	w.pushDefault()
	require.NoError(t, Scan(ctx, repo.ID))
	for _, id := range []int64{2, 3, 4} {
		require.NoError(t, secretscan_model.Save(ctx, nil, &secretscan_model.Scan{RepoID: id, Kind: secretscan_model.KindRepo, ScannedTips: "[]", Status: secretscan_model.StatusOK}))
	}
	require.NoError(t, secretscan_model.MarkRequeue(ctx, 0))
	marked := markedIDs(t)
	require.GreaterOrEqual(t, len(marked), 4)
	queued := func() (n int) {
		for _, id := range marked {
			if has, err := q.Has(id); err == nil && has {
				n++
			}
		}
		require.NoError(t, q.RemoveAllItems(ctx))
		return n
	}

	// the startup run (a process of its own, as at start) queues them all, a batch at a time
	defer test.MockVariableValue(&requeueBatch, 2)()
	startRequeue()
	require.Eventually(t, func() bool {
		for _, id := range marked {
			if has, _ := q.Has(id); !has {
				return false
			}
		}
		return true
	}, 10*time.Second, 20*time.Millisecond, "every marked repository is queued at start")
	queued()

	// the cron task queues all of them too, whatever its own limit of repositories per run
	require.NoError(t, EnqueueUnscanned(ctx))
	assert.Equal(t, len(marked), queued())

	// a failing slice leaves the mark; the scan that writes its state takes it
	w.commit(map[string]string{"b.env": "T=" + token("fails") + "\n"})
	w.pushDefault()
	restore := test.MockVariableValue(&scanContent, func(*secretdetection.Detector, []byte) ([]secretdetection.Finding, bool) { panic("boom") })
	require.NoError(t, Scan(ctx, repo.ID))
	restore()
	assert.Equal(t, secretscan_model.StatusFailed, scanOf(t, repo.ID, secretscan_model.KindRepo).Status)
	assert.Contains(t, markedIDs(t), repo.ID, "a failed slice keeps the mark")
	_, err := db.GetEngine(ctx).Exec("UPDATE secret_scan SET retry_unix = 0, fail_count = 0 WHERE repo_id = ?", repo.ID)
	require.NoError(t, err)
	require.NoError(t, Scan(ctx, repo.ID))
	assert.NotContains(t, markedIDs(t), repo.ID, "the slice that wrote its state took the mark")
}

// Only a change that turns scanning on for repositories marks them and asks for the queue; unlocking an organization that stays on,
// turning it off and a save without a change don't.
func TestOrgSwitchRequeues(t *testing.T) {
	unittest.PrepareTestEnv(t)
	var asked []int64
	defer test.MockVariableValue(&requeue, func() { asked = append(asked, 3) })()
	ctx := audit_model.WithSystem(t.Context(), "test")
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})

	step := func(on, locked bool, want []int64, msg string) {
		t.Helper()
		asked = nil
		require.NoError(t, SetOrgSwitch(ctx, org, on, locked))
		assert.Equal(t, want, asked, msg)
	}
	step(true, false, nil, "no change")
	step(false, false, nil, "off")
	step(true, false, []int64{3}, "off to on")
	step(true, true, []int64{3}, "locking on turns it on in repositories that turned it off")
	step(true, false, nil, "unlocking an organization that stays on")
	step(false, true, nil, "locked off")
	step(true, true, []int64{3}, "locked off to locked on")
}

// The rows of the two site settings are created before they are locked: on PostgreSQL and MySQL a row that doesn't
// exist can't be locked, so two first saves could both read "not stored" and the later one would win silently.
func TestSaveCreatesTheSettingRowsToLock(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := audit_model.WithSystem(t.Context(), "test")
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	count := func() int64 {
		n, err := db.GetEngine(ctx).Table("system_setting").In("setting_key", "secret_scanning.enabled", "secret_scanning.config").Count()
		require.NoError(t, err)
		return n
	}
	_, err := db.GetEngine(ctx).Exec("DELETE FROM system_setting WHERE setting_key IN ('secret_scanning.enabled', 'secret_scanning.config')")
	require.NoError(t, err)
	require.Zero(t, count())
	changed, err := SaveLimits(ctx, doer, map[string]int64{})
	require.NoError(t, err)
	assert.False(t, changed, "nothing to store")
	assert.EqualValues(t, 2, count(), "both rows exist (empty) after the save that locked them")
	changed, err = SaveLimits(ctx, doer, map[string]int64{"max_alerts_per_repo": 500})
	require.NoError(t, err)
	assert.True(t, changed)
}
