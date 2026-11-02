// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package issues_test

import (
	"testing"

	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/structs"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The AllPublic OR (org project boards) must not bring back what an organization's two-factor requirement hides.
func TestIssuesTwoFactorRequired(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	ids := func() []int64 {
		issues, err := issues_model.Issues(ctx, &issues_model.IssuesOptions{User: user2, AllPublic: true, IsPull: optional.Some(false)})
		require.NoError(t, err)
		var ids []int64
		for _, issue := range issues {
			ids = append(ids, issue.ID)
		}
		return ids
	}
	// org3 owned by user 2: repo3 (issue 6), repo5 (issue 15) private, repo21 (issues 16, 17) public
	assert.Subset(t, ids(), []int64{6, 15, 16, 17})

	// a private-visibility org that requires 2FA, and user 2 has none
	_, err := db.GetEngine(ctx).ID(3).Cols("require_two_factor", "visibility").Update(&user_model.User{RequireTwoFactor: true, Visibility: structs.VisibleTypePrivate})
	require.NoError(t, err)
	got := ids()
	for _, id := range []int64{6, 15, 16, 17} {
		assert.NotContains(t, got, id)
	}
}

// The event stream sends each user only the stopwatches they still see.
func TestGetUIDsAndStopwatchTwoFactorRequired(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	// user 4 writes repo3 (issue 6) through team1
	require.NoError(t, db.Insert(ctx, &issues_model.Stopwatch{UserID: 4, IssueID: 6}))
	issueIDs := func() []int64 {
		sws, err := issues_model.GetUIDsAndStopwatch(ctx)
		require.NoError(t, err)
		var ids []int64
		for _, sw := range sws[4] {
			ids = append(ids, sw.IssueID)
		}
		return ids
	}
	assert.Contains(t, issueIDs(), int64(6))
	_, err := db.GetEngine(ctx).ID(3).Cols("require_two_factor").Update(&user_model.User{RequireTwoFactor: true})
	require.NoError(t, err)
	assert.NotContains(t, issueIDs(), int64(6))
}
