// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull_test

import (
	"testing"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	pull_service "forgejo.org/services/pull"

	"github.com/stretchr/testify/require"
)

// A merge has to pass the repository, project and organization rules: one level allowing it doesn't lift another.
func TestCheckPullBranchProtectionsProjectRule(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: 3, BaseBranch: "master"})
	require.NoError(t, pr.LoadIssue(ctx))
	require.NoError(t, pr.LoadBaseRepo(ctx))
	group, err := repo_model.CreateRepoGroup(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}), "pay", "")
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).ID(3).Cols("group_id").Update(&repo_model.Repository{GroupID: group.ID})
	require.NoError(t, err)

	require.NoError(t, git_model.UpdateProtectBranch(ctx, pr.BaseRepo, &git_model.ProtectedBranch{RepoID: 3, RuleName: "master"}, git_model.WhitelistOptions{}))
	projRule := &git_model.ProtectedBranch{RuleName: "mas*", RequiredApprovals: 1}
	require.NoError(t, git_model.UpdateOrgProtectBranch(ctx, 3, group.ID, projRule, git_model.WhitelistOptions{}, nil))
	_, err = pull_service.CheckPullBranchProtections(ctx, pr, true, nil)
	require.ErrorContains(t, err, "approvals", "the project rule binds although the repository rule allows the merge")

	projRule.RequiredApprovals = 0
	require.NoError(t, git_model.UpdateOrgProtectBranch(ctx, 3, group.ID, projRule, git_model.WhitelistOptions{}, nil))
	orgRule := &git_model.ProtectedBranch{RuleName: "master", RequiredApprovals: 1}
	require.NoError(t, git_model.UpdateOrgProtectBranch(ctx, 3, 0, orgRule, git_model.WhitelistOptions{}, nil))
	_, err = pull_service.CheckPullBranchProtections(ctx, pr, true, nil)
	require.ErrorContains(t, err, "approvals", "the organization rule binds although the project rule allows the merge")

	orgRule.RequiredApprovals = 0
	require.NoError(t, git_model.UpdateOrgProtectBranch(ctx, 3, 0, orgRule, git_model.WhitelistOptions{}, nil))
	_, err = pull_service.CheckPullBranchProtections(ctx, pr, true, nil)
	require.NoError(t, err)
}
