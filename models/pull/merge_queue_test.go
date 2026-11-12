// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull_test

import (
	"fmt"
	"testing"

	pull_model "forgejo.org/models/pull"
	"forgejo.org/models/unittest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeQueueEntries(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()

	add := func(pullID int64, branch string) *pull_model.MergeQueueEntry {
		e := &pull_model.MergeQueueEntry{RepoID: 1, BaseBranch: branch, PullID: pullID, MergeStyle: "merge", HeadCommitID: "h", EnqueuedByID: 2}
		require.NoError(t, pull_model.AddToMergeQueue(ctx, e))
		return e
	}
	a, b := add(1, "main"), add(2, "main")
	other := add(3, "main/x")
	assert.Equal(t, int64(1), a.Position)
	assert.Equal(t, int64(2), b.Position)
	assert.Equal(t, int64(1), other.Position)
	assert.Equal(t, fmt.Sprintf("merge-queue/main/x/%d", other.ID), other.TempBranch())

	err := pull_model.AddToMergeQueue(ctx, &pull_model.MergeQueueEntry{RepoID: 1, BaseBranch: "main", PullID: 1, MergeStyle: "merge", HeadCommitID: "h", EnqueuedByID: 2})
	require.ErrorAs(t, err, &pull_model.ErrAlreadyInMergeQueue{})

	queue, err := pull_model.FindMergeQueue(ctx, 1, "main")
	require.NoError(t, err)
	require.Len(t, queue, 2)
	assert.Equal(t, a.ID, queue[0].ID)

	// only a waiting entry starts a build
	started, err := pull_model.StartMergeQueueBuild(ctx, a.ID, "base", "temp", "squash")
	require.NoError(t, err)
	assert.True(t, started)
	started, err = pull_model.StartMergeQueueBuild(ctx, a.ID, "base2", "temp2", "merge")
	require.NoError(t, err)
	assert.False(t, started)

	keys, err := pull_model.FindMergeQueueKeysByTempCommit(ctx, 1, "temp")
	require.NoError(t, err)
	assert.Equal(t, []pull_model.MergeQueueKey{{RepoID: 1, BaseBranch: "main"}}, keys)

	require.NoError(t, pull_model.ResetMergeQueueBuilds(ctx, []int64{a.ID}))
	e, err := pull_model.GetMergeQueueEntryByPullID(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, pull_model.MergeQueueWaiting, e.Status)
	assert.Empty(t, e.TempCommitID)

	deleted, err := pull_model.DeleteMergeQueueEntry(ctx, a.ID)
	require.NoError(t, err)
	assert.True(t, deleted)
	deleted, err = pull_model.DeleteMergeQueueEntry(ctx, a.ID)
	require.NoError(t, err)
	assert.False(t, deleted)
	e, err = pull_model.GetMergeQueueEntryByPullID(ctx, 1)
	require.NoError(t, err)
	assert.Nil(t, e)

	// the next one goes after the last, not into the gap
	c := add(1, "main")
	assert.Equal(t, int64(3), c.Position)
}
