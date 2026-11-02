// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AC3: "delete runs older than" is limited to the repository, to completed runs that are not kept, and to 100 runs.
func TestDeleteOldRuns(t *testing.T) {
	doer := &user_model.User{ID: 2}
	nextID := int64(800000)
	// a run of repo 4 or 1 created `days` days ago
	insert := func(t *testing.T, repoID, days int64, status actions_model.Status, ref string, keep bool) int64 {
		t.Helper()
		nextID++
		unittest.AssertSuccessfulInsert(t, &actions_model.ActionRun{ID: nextID, Index: nextID, RepoID: repoID, OwnerID: 2, Ref: ref, WorkflowID: "a.yaml", Status: status, Keep: keep})
		_, err := db.GetEngine(t.Context()).Exec("UPDATE action_run SET created = ? WHERE id = ?", timeutil.TimeStampNow().AddDuration(-time.Duration(days)*24*time.Hour), nextID)
		require.NoError(t, err)
		return nextID
	}
	exists := func(id int64) bool {
		has, err := db.GetEngine(t.Context()).ID(id).Exist(new(actions_model.ActionRun))
		require.NoError(t, err)
		return has
	}
	repo := func(id int64) *repo_model.Repository {
		return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: id})
	}

	t.Run("Deletes what is old, done and not kept, in this repository only", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		_, err := db.GetEngine(t.Context()).Exec("DELETE FROM action_run WHERE repo_id = 4") // the fixture runs
		require.NoError(t, err)
		old := insert(t, 4, 40, actions_model.StatusSuccess, "refs/heads/feature", false)
		oldFailed := insert(t, 4, 35, actions_model.StatusFailure, "refs/heads/feature", false)
		recent := insert(t, 4, 5, actions_model.StatusSuccess, "refs/heads/feature", false)
		kept := insert(t, 4, 40, actions_model.StatusSuccess, "refs/heads/feature", true)
		running := insert(t, 4, 40, actions_model.StatusRunning, "refs/heads/feature", false)
		waiting := insert(t, 4, 40, actions_model.StatusWaiting, "refs/heads/feature", false)
		otherRepo := insert(t, 1, 40, actions_model.StatusSuccess, "refs/heads/feature", false)
		// the latest run of the workflow on the default branch is spared
		latest := insert(t, 4, 50, actions_model.StatusSuccess, "refs/heads/master", false)

		count, err := CountOldRuns(t.Context(), repo(4), 30)
		require.NoError(t, err)
		assert.EqualValues(t, 2, count) // old and oldFailed
		deleted, more, err := DeleteOldRuns(t.Context(), doer, repo(4), 30)
		require.NoError(t, err)
		assert.False(t, more)
		assert.EqualValues(t, count, deleted)

		assert.False(t, exists(old))
		assert.False(t, exists(oldFailed))
		assert.True(t, exists(recent))
		assert.True(t, exists(kept))
		assert.True(t, exists(running))
		assert.True(t, exists(waiting))
		assert.True(t, exists(otherRepo))
		assert.True(t, exists(latest))

		after, err := CountOldRuns(t.Context(), repo(4), 30)
		require.NoError(t, err)
		assert.Zero(t, after)
	})

	t.Run("At most 100 runs, and it says whether more are left", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		// the fixture runs are older than anything: start from nothing
		_, err := db.GetEngine(t.Context()).Exec("DELETE FROM action_run WHERE repo_id = 4")
		require.NoError(t, err)
		var ids []int64
		for range MaxDeleteOldRuns + 20 {
			ids = append(ids, insert(t, 4, 40, actions_model.StatusSuccess, "refs/heads/feature", false))
		}

		deleted, more, err := DeleteOldRuns(t.Context(), doer, repo(4), 30)
		require.NoError(t, err)
		assert.Equal(t, MaxDeleteOldRuns, deleted)
		assert.True(t, more)
		assert.False(t, exists(ids[0]))
		assert.False(t, exists(ids[MaxDeleteOldRuns-1]))
		assert.True(t, exists(ids[MaxDeleteOldRuns]))

		deleted, more, err = DeleteOldRuns(t.Context(), doer, repo(4), 30)
		require.NoError(t, err)
		assert.Equal(t, 20, deleted)
		assert.False(t, more)

		// exactly 100 left: no more
		for range MaxDeleteOldRuns {
			insert(t, 4, 40, actions_model.StatusSuccess, "refs/heads/feature", false)
		}
		deleted, more, err = DeleteOldRuns(t.Context(), doer, repo(4), 30)
		require.NoError(t, err)
		assert.Equal(t, MaxDeleteOldRuns, deleted)
		assert.False(t, more)
	})

	t.Run("A run whose job is still running is skipped, the others go", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		_, err := db.GetEngine(t.Context()).Exec("DELETE FROM action_run WHERE repo_id = 4")
		require.NoError(t, err)
		stuck := insert(t, 4, 40, actions_model.StatusSuccess, "refs/heads/feature", false)
		unittest.AssertSuccessfulInsert(t, &actions_model.ActionRunJob{ID: stuck, Handle: "stuck", RunID: stuck, RepoID: 4, OwnerID: 2, Status: actions_model.StatusRunning})
		fine := insert(t, 4, 40, actions_model.StatusSuccess, "refs/heads/feature", false)

		deleted, _, err := DeleteOldRuns(t.Context(), doer, repo(4), 30)
		require.NoError(t, err)
		assert.Equal(t, 1, deleted)
		assert.True(t, exists(stuck))
		assert.False(t, exists(fine))
	})
}
