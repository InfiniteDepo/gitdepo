// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import (
	"fmt"
	"slices"
	"testing"

	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// insertPull adds a pull request merged now to the repository, reviewed by reviewer if not 0.
func insertPull(t *testing.T, repoID, poster, reviewer int64) {
	t.Helper()
	ctx := db.DefaultContext
	issue := &issues_model.Issue{RepoID: repoID, Index: 1000 + repoID*10 + int64(len(rowsOf(t, repoID))), PosterID: poster, Title: fmt.Sprintf("metrics %d", repoID), IsPull: true}
	require.NoError(t, db.Insert(ctx, issue))
	require.NoError(t, db.Insert(ctx, &issues_model.PullRequest{IssueID: issue.ID, BaseRepoID: repoID, HeadRepoID: repoID, HasMerged: true, CommitsAhead: 2}))
	if reviewer != 0 {
		require.NoError(t, db.Insert(ctx, &issues_model.Comment{Type: issues_model.CommentTypeReview, PosterID: reviewer, IssueID: issue.ID}))
	}
}

func rowsOf(t *testing.T, repoID int64) []*issues_model.Issue {
	var issues []*issues_model.Issue
	require.NoError(t, db.GetEngine(db.DefaultContext).Where("repo_id = ? AND `index` > 1000", repoID).Find(&issues))
	return issues
}

func repoNames(r *Report) []string {
	var names []string
	for _, row := range r.Rows {
		names = append(names, row.OwnerName+"/"+row.RepoName)
	}
	slices.Sort(names)
	return names
}

func TestReports(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	insertPull(t, 3, 2, 4)
	insertPull(t, 5, 2, 4)
	insertPull(t, 32, 2, 4) // no pull request unit
	insertPull(t, 1, 2, 4)
	insertPull(t, 1, 2, 2) // reviewed by the author
	now := timeutil.TimeStampNow() + 10

	t.Run("repo", func(t *testing.T) {
		r, err := RepoReport(ctx, 1, 30, true, now)
		require.NoError(t, err)
		assert.Equal(t, []string{"user2/repo1", "user2/repo1"}, repoNames(r))
		assert.Equal(t, 2, r.Merged)
		assert.Equal(t, Stat{N: 2, Median: 2, P85: 2}, r.Commits)
		assert.Equal(t, 1, r.FirstReview.N)
		assert.EqualValues(t, 1, r.Reviews, "the author's review doesn't count")
		assert.EqualValues(t, 1, r.ReviewerCount)
		require.Len(t, r.Reviewers, 1)
		assert.Equal(t, "user4", r.Reviewers[0].User.Name)
		assert.False(t, r.Truncated)

		r, err = RepoReport(ctx, 1, 30, false, now)
		require.NoError(t, err)
		assert.Empty(t, r.Reviewers)
		assert.EqualValues(t, 1, r.ReviewerCount)
	})

	t.Run("org", func(t *testing.T) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
		r, err := OrgReport(ctx, 3, user2, false, 30, false, now)
		require.NoError(t, err)
		assert.Equal(t, []string{"org3/repo3", "org3/repo5"}, repoNames(r))
		assert.EqualValues(t, 2, r.Reviews)

		r, err = OrgReport(ctx, 3, user4, false, 30, false, now)
		require.NoError(t, err)
		assert.Equal(t, []string{"org3/repo3"}, repoNames(r))
		assert.EqualValues(t, 1, r.Reviews)

		r, err = OrgReport(ctx, 3, user4, true, 30, false, now)
		require.NoError(t, err)
		assert.Equal(t, []string{"org3/repo3", "org3/repo5"}, repoNames(r), "a site admin sees every repository with the unit")
	})

	t.Run("truncated", func(t *testing.T) {
		defer test.MockVariableValue(&MaxPRs, 1)()
		r, err := RepoReport(ctx, 1, 30, false, now)
		require.NoError(t, err)
		assert.True(t, r.Truncated)
		assert.Len(t, r.Rows, 1)
	})
}
