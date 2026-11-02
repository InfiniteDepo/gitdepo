// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull_test

import (
	"testing"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	pull_service "forgejo.org/services/pull"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type approvalFixture struct {
	pb *git_model.ProtectedBranch
	pr *issues_model.PullRequest
}

// repo1 is owned by user2; the PR (issue 2) is authored by the site admin user1.
// user4 is a writer, user5 has no access at all.
func newApprovalFixture(t *testing.T, rules ...*git_model.ApprovalRule) *approvalFixture {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 1})
	require.NoError(t, pr.LoadIssue(ctx))
	require.NoError(t, pr.LoadBaseRepo(ctx))
	_, err := db.GetEngine(ctx).Insert(&access_model.Access{UserID: 4, RepoID: pr.BaseRepoID, Mode: perm.AccessModeWrite})
	require.NoError(t, err)
	pb := &git_model.ProtectedBranch{RepoID: pr.BaseRepoID, RuleName: "approval-rules"}
	require.NoError(t, git_model.UpdateProtectBranch(ctx, pr.BaseRepo, pb, git_model.WhitelistOptions{}))
	require.NoError(t, git_model.SetApprovalRules(ctx, pr.BaseRepo, pb.ID, rules))
	return &approvalFixture{pb, pr}
}

func (f *approvalFixture) review(t *testing.T, userID int64, typ issues_model.ReviewType, stale bool) *issues_model.Review {
	r, err := issues_model.CreateReview(t.Context(), issues_model.CreateReviewOptions{
		Issue:    f.pr.Issue,
		Reviewer: &user_model.User{ID: userID},
		Type:     typ,
		Stale:    stale,
	})
	require.NoError(t, err)
	return r
}

func (f *approvalFixture) granted(t *testing.T) map[string]int64 {
	statuses, err := pull_service.EvaluateApprovalRules(t.Context(), f.pb, f.pr)
	require.NoError(t, err)
	granted := map[string]int64{}
	for _, s := range statuses {
		granted[s.Name] = s.Granted
		assert.Equal(t, s.Granted >= s.Required, s.Satisfied, s.Name)
	}
	return granted
}

func rule(name string, userIDs ...int64) *git_model.ApprovalRule {
	return &git_model.ApprovalRule{Name: name, RequiredCount: 1, UserIDs: userIDs}
}

// AC3/AC11: eligible users only, author excluded, stale and dismissed approvals ignored, latest review wins.
func TestEvaluateApprovalRulesCounting(t *testing.T) {
	f := newApprovalFixture(t, rule("Security", 1, 2, 4, 5))
	approve := issues_model.ReviewTypeApprove

	assert.Equal(t, map[string]int64{"Security": 0}, f.granted(t))

	f.review(t, 1, approve, false) // the PR author never counts
	f.review(t, 5, approve, false) // listed but has no write access
	f.review(t, 99999, approve, false)
	assert.Equal(t, map[string]int64{"Security": 0}, f.granted(t), "author, non-writer and deleted user are not eligible, and don't fail the evaluation")

	f.review(t, 4, approve, false)
	assert.Equal(t, map[string]int64{"Security": 1}, f.granted(t))

	f.review(t, 4, issues_model.ReviewTypeReject, false)
	assert.Equal(t, map[string]int64{"Security": 0}, f.granted(t), "a later rejection replaces the approval")
	f.review(t, 4, issues_model.ReviewTypeComment, false)
	assert.Equal(t, map[string]int64{"Security": 0}, f.granted(t))

	f.review(t, 2, approve, true)
	assert.Equal(t, map[string]int64{"Security": 1}, f.granted(t), "stale approvals count unless IgnoreStaleApprovals")
	f.pb.IgnoreStaleApprovals = true
	assert.Equal(t, map[string]int64{"Security": 0}, f.granted(t))
	f.pb.IgnoreStaleApprovals = false

	_, err := db.GetEngine(t.Context()).Where("reviewer_id = 2").Cols("dismissed").Update(&issues_model.Review{Dismissed: true})
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{"Security": 0}, f.granted(t))

	f.review(t, 4, approve, false)
	_, err = db.GetEngine(t.Context()).ID(4).Cols("prohibit_login").Update(&user_model.User{ProhibitLogin: true})
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{"Security": 0}, f.granted(t), "users that can't log in don't count")
}

// AC5: every rule needs approvers eligible for it, one approver can serve several rules.
func TestEvaluateApprovalRulesSeveralRules(t *testing.T) {
	f := newApprovalFixture(t, rule("Backend", 2), rule("Security", 4), rule("Also user2", 2))

	f.review(t, 2, issues_model.ReviewTypeApprove, false)
	assert.Equal(t, map[string]int64{"Backend": 1, "Security": 0, "Also user2": 1}, f.granted(t))
	f.review(t, 4, issues_model.ReviewTypeApprove, false)
	assert.Equal(t, map[string]int64{"Backend": 1, "Security": 1, "Also user2": 1}, f.granted(t))
}

// AC2: the merge check names the first unsatisfied rule and nothing is checked without rules.
func TestCheckPullBranchProtectionsApprovalRules(t *testing.T) {
	f := newApprovalFixture(t, rule("Security", 4))
	f.pb.RuleName = "master"
	require.NoError(t, git_model.UpdateProtectBranch(t.Context(), f.pr.BaseRepo, f.pb, git_model.WhitelistOptions{}))
	f.pr.BaseBranch = "master"

	_, err := pull_service.CheckPullBranchProtections(t.Context(), f.pr, true, nil)
	require.ErrorContains(t, err, `Security`)
	f.review(t, 4, issues_model.ReviewTypeApprove, false)
	_, err = pull_service.CheckPullBranchProtections(t.Context(), f.pr, true, nil)
	require.NoError(t, err)
}

// AC7: a protection without approval rules evaluates to nothing.
func TestEvaluateApprovalRulesNone(t *testing.T) {
	f := newApprovalFixture(t)
	statuses, err := pull_service.EvaluateApprovalRules(t.Context(), f.pb, f.pr)
	require.NoError(t, err)
	assert.Empty(t, statuses)
}

// AC3: IgnoreStaleApprovals and dismissals apply to every rule.
func TestEvaluateApprovalRulesStalePerRule(t *testing.T) {
	f := newApprovalFixture(t, rule("Backend", 2), rule("Security", 4))
	f.review(t, 2, issues_model.ReviewTypeApprove, true)
	f.review(t, 4, issues_model.ReviewTypeApprove, false)
	assert.Equal(t, map[string]int64{"Backend": 1, "Security": 1}, f.granted(t))

	f.pb.IgnoreStaleApprovals = true
	assert.Equal(t, map[string]int64{"Backend": 0, "Security": 1}, f.granted(t), "only the stale approval of user2 is ignored")

	_, err := db.GetEngine(t.Context()).Where("reviewer_id = 4").Cols("dismissed").Update(&issues_model.Review{Dismissed: true})
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{"Backend": 0, "Security": 0}, f.granted(t))
}
