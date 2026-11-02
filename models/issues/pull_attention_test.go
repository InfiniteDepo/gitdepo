// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package issues_test

import (
	"testing"

	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/unittest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPullAttention(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()

	// issue 2 is pull request 1
	require.NoError(t, issues_model.AddPullAttention(ctx, 2, []int64{4, 5}, 1, issues_model.AttentionReviewRequested, ""))
	// adding again updates why the user is in the set
	require.NoError(t, issues_model.AddPullAttention(ctx, 2, []int64{4}, 2, issues_model.AttentionManual, "please look"))
	unittest.AssertCount(t, &issues_model.PullAttention{IssueID: 2}, 2)
	row := unittest.AssertExistsAndLoadBean(t, &issues_model.PullAttention{IssueID: 2, UserID: 4})
	assert.Equal(t, issues_model.AttentionManual, row.Kind)
	assert.EqualValues(t, 2, row.DoerID)
	assert.Equal(t, "please look", row.Reason)

	ids, err := issues_model.GetPullAttentionUserIDs(ctx, 2)
	require.NoError(t, err)
	assert.ElementsMatch(t, []int64{4, 5}, ids)

	// a row of a user that no longer exists is skipped, and an unknown doer is the ghost
	require.NoError(t, db.Insert(ctx, &issues_model.PullAttention{IssueID: 2, UserID: 99999, DoerID: 99998}))
	require.NoError(t, issues_model.AddPullAttention(ctx, 3, []int64{2}, 99998, issues_model.AttentionReviewed, ""))
	issues, err := issues_model.GetIssuesByIDs(ctx, []int64{1, 2, 3})
	require.NoError(t, err)
	sets, err := issues.LoadPullAttention(ctx)
	require.NoError(t, err)
	require.Len(t, sets[2], 2)
	assert.Equal(t, "user4", sets[2][0].User.Name)
	assert.Equal(t, "user2", sets[2][0].Doer.Name)
	assert.Equal(t, "user5", sets[2][1].User.Name)
	require.Len(t, sets[3], 1)
	assert.True(t, sets[3][0].Doer.IsGhost())
	assert.NotContains(t, sets, int64(1)) // an issue, not a pull request

	n, err := issues_model.RemovePullAttention(ctx, 2, 4)
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	unittest.AssertNotExistsBean(t, &issues_model.PullAttention{IssueID: 2, UserID: 4})
	n, err = issues_model.ClearPullAttention(ctx, 2)
	require.NoError(t, err)
	assert.EqualValues(t, 2, n)
	unittest.AssertCount(t, &issues_model.PullAttention{IssueID: 2}, 0)
	unittest.AssertCount(t, &issues_model.PullAttention{IssueID: 3}, 1)
}
