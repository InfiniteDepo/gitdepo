// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"testing"

	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/require"
)

func TestAttentionTeamRequestAddsNobody(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 2})
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	member := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	n := &attentionNotifier{}

	// a team request reaches the notifier once per member, with the team in the comment
	n.PullRequestReviewRequest(t.Context(), doer, issue, member, true, &issues_model.Comment{AssigneeID: member.ID, AssigneeTeamID: 1})
	unittest.AssertNotExistsBean(t, &issues_model.PullAttention{IssueID: issue.ID})

	n.PullRequestReviewRequest(t.Context(), doer, issue, member, true, &issues_model.Comment{AssigneeID: member.ID})
	unittest.AssertExistsAndLoadBean(t, &issues_model.PullAttention{IssueID: issue.ID, UserID: member.ID})
}
