// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"sync"
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A ref gets the first matching rule of each level, whatever kind (plain or glob) the other levels' rules are.
func TestProtectedBranchRulesGetMatchedLevels(t *testing.T) {
	repoMain := &ProtectedBranch{RuleName: "main", RepoID: 1}
	projMain := &ProtectedBranch{RuleName: "main", OrgID: 3, GroupID: 1}
	projGlob := &ProtectedBranch{RuleName: "*", OrgID: 3, GroupID: 1}
	orgMain := &ProtectedBranch{RuleName: "main", OrgID: 3}
	orgGlob := &ProtectedBranch{RuleName: "*", OrgID: 3}

	for name, c := range map[string]struct {
		rules    ProtectedBranchRules
		expected []*ProtectedBranch
	}{
		"project glob, org plain": {ProtectedBranchRules{orgMain, projGlob}, []*ProtectedBranch{projGlob, orgMain}},
		"project plain, org glob": {ProtectedBranchRules{orgGlob, projMain}, []*ProtectedBranch{projMain, orgGlob}},
		"three levels":            {ProtectedBranchRules{orgGlob, orgMain, projGlob, projMain, repoMain}, []*ProtectedBranch{repoMain, projMain, orgMain}},
		"project only":            {ProtectedBranchRules{projGlob, projMain}, []*ProtectedBranch{projMain}},
		"repo and project glob":   {ProtectedBranchRules{projGlob, repoMain}, []*ProtectedBranch{repoMain, projGlob}},
	} {
		t.Run(name, func(t *testing.T) {
			c.rules.sort()
			assert.Equal(t, ProtectedBranchRules(c.expected), c.rules.GetMatched("main"))
		})
	}
}

func createProjectRule(t *testing.T, orgID, groupID int64, name string) *ProtectedBranch {
	t.Helper()
	rule := &ProtectedBranch{RuleName: name}
	require.NoError(t, UpdateOrgProtectBranch(db.DefaultContext, orgID, groupID, rule, WhitelistOptions{}, nil))
	return rule
}

func createProject(t *testing.T, ownerID int64, name string) *repo_model.RepoGroup {
	t.Helper()
	group, err := repo_model.CreateRepoGroup(db.DefaultContext, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: ownerID}), name, "")
	require.NoError(t, err)
	return group
}

func moveToProject(t *testing.T, repoID, groupID int64) {
	t.Helper()
	_, err := db.GetEngine(db.DefaultContext).ID(repoID).Cols("group_id").Update(&repo_model.Repository{GroupID: groupID})
	require.NoError(t, err)
}

// Project rules apply to the repositories of their project only, together with the repository and organization
// rules, and follow a repository that moves.
func TestProjectRulesApply(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	pay, web := createProject(t, 3, "pay"), createProject(t, 3, "web")
	createOrgRule(t, 3, "master")
	payRule := createProjectRule(t, 3, pay.ID, "master")
	createProjectRule(t, 3, web.ID, "mas*")
	moveToProject(t, 3, pay.ID)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	require.NoError(t, UpdateProtectBranch(ctx, repo, &ProtectedBranch{RepoID: 3, RuleName: "master"}, WhitelistOptions{}))

	rules, err := GetMatchedProtectedBranchRules(ctx, 3, "master")
	require.NoError(t, err)
	require.Len(t, rules, 3)
	assert.EqualValues(t, 3, rules[0].RepoID)
	assert.Equal(t, payRule.ID, rules[1].ID)
	assert.Zero(t, rules[2].GroupID)
	for _, rule := range rules[1:] {
		assert.EqualValues(t, 3, rule.Repo.ID, "the repository being checked is set on every organization and project rule")
	}

	t.Run("RootRepository", func(t *testing.T) {
		rules, err := GetMatchedProtectedBranchRules(ctx, 5, "master")
		require.NoError(t, err)
		require.Len(t, rules, 1)
		assert.Zero(t, rules[0].GroupID)
	})

	t.Run("Move", func(t *testing.T) {
		moveToProject(t, 3, web.ID)
		rules, err := GetMatchedProtectedBranchRules(ctx, 3, "master")
		require.NoError(t, err)
		assert.Equal(t, []string{"master", "mas*", "master"}, ruleNames(rules))
		assert.Equal(t, web.ID, rules[1].GroupID)
	})
}

// No organization reader sees a project rule and no project reader sees the organization's or another project's
// rule, even with the same name.
func TestProjectRulesFailClosed(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	pay, web := createProject(t, 3, "pay"), createProject(t, 3, "web")
	orgRule := createOrgRule(t, 3, "main")
	payRule := createProjectRule(t, 3, pay.ID, "main")

	rules, err := FindOrgProtectedBranchRules(ctx, 3, 0)
	require.NoError(t, err)
	assert.Equal(t, []int64{orgRule.ID}, []int64{rules[0].ID})
	assert.Len(t, rules, 1)
	rules, err = FindOrgProtectedBranchRules(ctx, 3, pay.ID)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, payRule.ID, rules[0].ID)
	rules, err = FindOrgProtectedBranchRules(ctx, 3, web.ID)
	require.NoError(t, err)
	assert.Empty(t, rules)

	byName, err := GetOrgProtectedBranchRuleByName(ctx, 3, 0, "main")
	require.NoError(t, err)
	assert.Equal(t, orgRule.ID, byName.ID)
	byName, err = GetOrgProtectedBranchRuleByName(ctx, 3, web.ID, "main")
	require.NoError(t, err)
	assert.Nil(t, byName)

	for _, groupID := range []int64{0, web.ID} {
		byID, err := GetOrgProtectedBranchRuleByID(ctx, 3, groupID, payRule.ID)
		require.NoError(t, err)
		assert.Nil(t, byID)
		require.ErrorIs(t, DeleteOrgProtectedBranch(ctx, 3, groupID, payRule.ID), util.ErrNotExist)
		require.ErrorIs(t, UpdateOrgProtectBranch(ctx, 3, groupID, &ProtectedBranch{ID: payRule.ID, RuleName: "taken"}, WhitelistOptions{}, nil), util.ErrNotExist)
	}
	byID, err := GetOrgProtectedBranchRuleByID(ctx, 3, pay.ID, orgRule.ID)
	require.NoError(t, err)
	assert.Nil(t, byID)
	unittest.AssertExistsAndLoadBean(t, &ProtectedBranch{ID: payRule.ID, OrgID: 3, GroupID: pay.ID, RuleName: "main"})
}

// A project rule needs a project of the organization, covers the whole project and allows no deploy keys.
func TestUpdateProjectRuleValidation(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	pay := createProject(t, 3, "pay")
	other := createProject(t, 7, "other")

	require.ErrorIs(t, UpdateOrgProtectBranch(ctx, 3, other.ID, &ProtectedBranch{RuleName: "x"}, WhitelistOptions{}, nil), util.ErrNotExist)
	require.ErrorIs(t, UpdateOrgProtectBranch(ctx, 3, 99999, &ProtectedBranch{RuleName: "x"}, WhitelistOptions{}, nil), util.ErrNotExist)
	require.ErrorIs(t, UpdateOrgProtectBranch(ctx, 3, pay.ID, &ProtectedBranch{RuleName: "x"}, WhitelistOptions{}, []int64{3}), util.ErrInvalidArgument)
	require.ErrorIs(t, UpdateOrgProtectBranch(ctx, 3, pay.ID, &ProtectedBranch{RuleName: "x", ApplyToSelectedRepos: true}, WhitelistOptions{}, nil), util.ErrInvalidArgument)
	require.ErrorIs(t, UpdateOrgProtectBranch(ctx, 3, pay.ID, &ProtectedBranch{RuleName: "x"}, WhitelistOptions{DeployKeyIDs: []int64{1}}, nil), util.ErrInvalidArgument)
	unittest.AssertNotExistsBean(t, &ProtectedBranch{RuleName: "x"})

	// the same name in the organization and in a project, but only once per project
	createOrgRule(t, 3, "x")
	createProjectRule(t, 3, pay.ID, "x")
	require.Error(t, UpdateOrgProtectBranch(ctx, 3, pay.ID, &ProtectedBranch{RuleName: "x"}, WhitelistOptions{}, nil))
}

// Deleting a project removes its rules, deleting the organization removes every rule of it, and the doctor finds
// project rules whose project is gone or belongs to another organization.
func TestProjectRulesCleanup(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	pay, web := createProject(t, 3, "pay"), createProject(t, 3, "web")
	orgRule := createOrgRule(t, 3, "main")
	payRule := createProjectRule(t, 3, pay.ID, "main")
	_, err := db.GetEngine(ctx).Insert(&ApprovalRule{ProtectedBranchID: payRule.ID, Name: "a"})
	require.NoError(t, err)

	require.NoError(t, repo_model.DeleteRepoGroup(ctx, pay))
	unittest.AssertNotExistsBean(t, &ProtectedBranch{ID: payRule.ID})
	unittest.AssertNotExistsBean(t, &ApprovalRule{ProtectedBranchID: payRule.ID})
	unittest.AssertExistsAndLoadBean(t, &ProtectedBranch{ID: orgRule.ID})

	other := createProject(t, 7, "other")
	orphans := []*ProtectedBranch{{OrgID: 3, GroupID: 99999, RuleName: "gone"}, {OrgID: 3, GroupID: other.ID, RuleName: "cross"}}
	for _, rule := range orphans {
		_, err := db.GetEngine(ctx).Insert(rule)
		require.NoError(t, err)
	}
	n, err := CountOrphanedProtectedBranches(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 2, n)

	webRule := createProjectRule(t, 3, web.ID, "main")
	require.NoError(t, DeleteOrgProtectedBranches(ctx, 3))
	for _, id := range []int64{orgRule.ID, webRule.ID, orphans[0].ID, orphans[1].ID} {
		unittest.AssertNotExistsBean(t, &ProtectedBranch{ID: id})
	}
}

// A rule saved while its project is deleted is either refused or deleted with the project, never left behind.
func TestProjectRuleDeleteRace(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	for range 5 {
		group := createProject(t, 3, "race")
		var wg sync.WaitGroup
		wg.Add(2)
		var saveErr, deleteErr error
		go func() {
			defer wg.Done()
			saveErr = UpdateOrgProtectBranch(db.DefaultContext, 3, group.ID, &ProtectedBranch{RuleName: "main"}, WhitelistOptions{}, nil)
		}()
		go func() { defer wg.Done(); deleteErr = repo_model.DeleteRepoGroup(db.DefaultContext, group) }()
		wg.Wait()
		require.NoError(t, deleteErr)
		if saveErr != nil {
			require.ErrorIs(t, saveErr, util.ErrNotExist)
		}
		n, err := CountOrphanedProtectedBranches(db.DefaultContext)
		require.NoError(t, err)
		require.Zero(t, n)
	}
}

// Only acting organization owners may skip a project rule without "apply to admins"; repository admins never.
func TestProjectRuleAdminExempt(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	rule := createProjectRule(t, 3, createProject(t, 3, "pay").ID, "main")
	for userID, exempt := range map[int64]bool{2: true, 4: false, 28: false} { // owner, team member, admin team member
		got, err := rule.IsAdminExempt(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: userID}), true)
		require.NoError(t, err)
		assert.Equal(t, exempt, got, "user %d", userID)
	}
	rule.ApplyToAdmins = true
	got, err := rule.IsAdminExempt(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), true)
	require.NoError(t, err)
	assert.False(t, got)
}
