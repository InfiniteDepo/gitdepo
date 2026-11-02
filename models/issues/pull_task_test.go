// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package issues_test

import (
	"testing"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPullTask(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{IssueID: 2})
	require.NoError(t, pr.LoadIssue(db.DefaultContext))
	issue := pr.Issue
	require.NoError(t, issue.LoadRepo(db.DefaultContext))
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	pb := &git_model.ProtectedBranch{}

	// comments a task can't be created from: of a pending review (4), of another issue (8),
	// and not a comment
	for _, commentID := range []int64{4, 8, 99999} {
		_, err := issues_model.CreatePullTask(db.DefaultContext, doer, issue, "nope", commentID)
		require.ErrorIs(t, err, issues_model.ErrPullTaskNotExist, commentID)
	}

	task, err := issues_model.CreatePullTask(db.DefaultContext, doer, issue, "add a test", 5)
	require.NoError(t, err)
	assert.Equal(t, issue.PosterID, task.AssigneeID)
	assert.Equal(t, doer.ID, task.Creator.ID)

	assert.False(t, issues_model.MergeBlockedByIncompleteTasks(db.DefaultContext, pb, pr))
	pb.BlockOnIncompleteTasks = true
	assert.True(t, issues_model.MergeBlockedByIncompleteTasks(db.DefaultContext, pb, pr))

	require.NoError(t, issues_model.SetPullTaskDone(db.DefaultContext, doer, issue, task, true))
	assert.False(t, issues_model.MergeBlockedByIncompleteTasks(db.DefaultContext, pb, pr))
	require.NoError(t, issues_model.SetPullTaskDone(db.DefaultContext, doer, issue, task, true)) // no-op
	unittest.AssertCount(t, &issues_model.Comment{IssueID: issue.ID, Type: issues_model.CommentTypePullTaskDone}, 1)

	_, err = issues_model.GetPullTaskByID(db.DefaultContext, 3, task.ID)
	require.ErrorIs(t, err, issues_model.ErrPullTaskNotExist)

	require.NoError(t, issues_model.DeletePullTask(db.DefaultContext, doer, issue, task))
	unittest.AssertNotExistsBean(t, &issues_model.PullTask{ID: task.ID})
	unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: issue.ID, Type: issues_model.CommentTypePullTaskDeleted, Content: "add a test"})
}
