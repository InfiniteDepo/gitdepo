// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ruleNames(rules ProtectedBranchRules) []string {
	names := []string{}
	for _, rule := range rules {
		names = append(names, rule.RuleName)
	}
	return names
}

// AC11: combining rules, a ref gets the first matching repository rule and the first matching organization rule.
func TestProtectedBranchRulesGetMatched(t *testing.T) {
	repoMain := &ProtectedBranch{RuleName: "main", RepoID: 1}
	repoGlob := &ProtectedBranch{RuleName: "*", RepoID: 1}
	orgMain := &ProtectedBranch{RuleName: "main", OrgID: 3}
	orgGlob := &ProtectedBranch{RuleName: "*", OrgID: 3}

	for name, c := range map[string]struct {
		rules    ProtectedBranchRules
		expected []*ProtectedBranch
	}{
		"repo only": {ProtectedBranchRules{repoGlob, repoMain}, []*ProtectedBranch{repoMain}},
		"org only":  {ProtectedBranchRules{orgGlob, orgMain}, []*ProtectedBranch{orgMain}},
		"both":      {ProtectedBranchRules{orgGlob, orgMain, repoGlob, repoMain}, []*ProtectedBranch{repoMain, orgMain}},
		"org glob":  {ProtectedBranchRules{orgGlob, repoMain}, []*ProtectedBranch{repoMain, orgGlob}},
		"none":      {ProtectedBranchRules{&ProtectedBranch{RuleName: "dev", RepoID: 1}}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			c.rules.sort()
			assert.Equal(t, ProtectedBranchRules(c.expected), c.rules.GetMatched("main"))
		})
	}
}

func createOrgRule(t *testing.T, orgID int64, name string, repoIDs ...int64) *ProtectedBranch {
	t.Helper()
	rule := &ProtectedBranch{RuleName: name, ApplyToSelectedRepos: len(repoIDs) > 0}
	require.NoError(t, UpdateOrgProtectBranch(db.DefaultContext, orgID, 0, rule, WhitelistOptions{}, repoIDs))
	return rule
}

// AC2, AC5, AC11: organization rules apply to every repository of the organization, including new and
// transferred ones, or to the selected repositories only.
func TestFindProtectedBranchRulesForRepo(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	createOrgRule(t, 3, "master")
	createOrgRule(t, 3, "release/*", 5)

	rules, err := GetMatchedProtectedBranchRules(ctx, 3, "master")
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.EqualValues(t, 3, rules[0].OrgID)
	assert.EqualValues(t, 3, rules[0].Repo.ID, "the repository being checked is set on organization rules")

	t.Run("NotOtherOwners", func(t *testing.T) {
		rules, err := GetMatchedProtectedBranchRules(ctx, 1, "master")
		require.NoError(t, err)
		assert.Empty(t, rules)
	})

	t.Run("BothLevels", func(t *testing.T) {
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
		require.NoError(t, UpdateProtectBranch(ctx, repo, &ProtectedBranch{RepoID: 3, RuleName: "master"}, WhitelistOptions{}))
		rules, err := GetMatchedProtectedBranchRules(ctx, 3, "master")
		require.NoError(t, err)
		require.Len(t, rules, 2)
		assert.EqualValues(t, 3, rules[0].RepoID)
		assert.EqualValues(t, 3, rules[1].OrgID)

		first, err := GetFirstMatchProtectedBranchRule(ctx, 3, "master")
		require.NoError(t, err)
		assert.Equal(t, rules[0].ID, first.ID)
	})

	t.Run("SelectedRepos", func(t *testing.T) {
		rules, err := GetMatchedProtectedBranchRules(ctx, 5, "release/1")
		require.NoError(t, err)
		assert.Equal(t, []string{"release/*"}, ruleNames(rules))

		rules, err = GetMatchedProtectedBranchRules(ctx, 3, "release/1")
		require.NoError(t, err)
		assert.Empty(t, rules)
	})

	t.Run("ScopeEdit", func(t *testing.T) {
		rule, err := GetOrgProtectedBranchRuleByName(ctx, 3, 0, "release/*")
		require.NoError(t, err)
		rule.ApplyToSelectedRepos = false
		require.NoError(t, UpdateOrgProtectBranch(ctx, 3, 0, rule, WhitelistOptions{}, nil))
		protected, err := IsBranchProtected(ctx, 3, "release/1")
		require.NoError(t, err)
		assert.True(t, protected)
	})

	t.Run("Transfer", func(t *testing.T) {
		_, err := db.GetEngine(ctx).ID(3).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 2})
		require.NoError(t, err)
		rules, err := GetMatchedProtectedBranchRules(ctx, 3, "master")
		require.NoError(t, err)
		assert.Len(t, rules, 1, "only the repository rule is left")
		assert.EqualValues(t, 0, rules[0].OrgID)
	})
}

// AC13: organization rules only reference the organization's users, teams and repositories, and no deploy keys.
func TestUpdateOrgProtectBranchValidation(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	for name, c := range map[string]struct {
		opts    WhitelistOptions
		repoIDs []int64
	}{
		"non-member user":     {opts: WhitelistOptions{MergeUserIDs: []int64{5}}},
		"other org's team":    {opts: WhitelistOptions{TeamIDs: []int64{3}}},
		"other owner's repo":  {repoIDs: []int64{1}},
		"deploy key":          {opts: WhitelistOptions{DeleteDeployKeyIDs: []int64{1}}},
		"approval rule users": {opts: WhitelistOptions{ApprovalRules: []*ApprovalRule{{Name: "a", RequiredCount: 1, UserIDs: []int64{5}}}}},
	} {
		t.Run(name, func(t *testing.T) {
			err := UpdateOrgProtectBranch(db.DefaultContext, 3, 0, &ProtectedBranch{RuleName: "x"}, c.opts, c.repoIDs)
			require.ErrorIs(t, err, util.ErrInvalidArgument)
		})
	}

	rule := &ProtectedBranch{RuleName: "x", EnableWhitelist: true}
	require.NoError(t, UpdateOrgProtectBranch(db.DefaultContext, 3, 0, rule, WhitelistOptions{UserIDs: []int64{4}, TeamIDs: []int64{2}}, []int64{3, 5}))
	assert.Equal(t, []int64{4}, rule.WhitelistUserIDs)
	ids, err := GetOrgProtectedBranchRuleRepoIDs(db.DefaultContext, rule.ID)
	require.NoError(t, err)
	assert.Equal(t, []int64{3, 5}, ids)
}

// Organization rules are only reachable through their own organization.
func TestOrgRuleScopedToOrg(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	rule := createOrgRule(t, 3, "master", 3)

	other, err := GetOrgProtectedBranchRuleByName(ctx, 7, 0, "master")
	require.NoError(t, err)
	assert.Nil(t, other)

	require.ErrorIs(t, DeleteOrgProtectedBranch(ctx, 7, 0, rule.ID), util.ErrNotExist)
	require.ErrorIs(t, UpdateOrgProtectBranch(ctx, 7, 0, &ProtectedBranch{ID: rule.ID, RuleName: "taken"}, WhitelistOptions{}, nil), util.ErrNotExist)
	unittest.AssertExistsAndLoadBean(t, &ProtectedBranch{ID: rule.ID, OrgID: 3, RuleName: "master"})
	unittest.AssertExistsAndLoadBean(t, &ProtectedBranchRepo{ProtectedBranchID: rule.ID, RepoID: 3})

	// the repository functions never see organization rules
	byID, err := GetProtectedBranchRuleByID(ctx, 3, rule.ID)
	require.NoError(t, err)
	assert.Nil(t, byID)

	require.NoError(t, DeleteOrgProtectedBranch(ctx, 3, 0, rule.ID))
	unittest.AssertNotExistsBean(t, &ProtectedBranch{ID: rule.ID})
	unittest.AssertNotExistsBean(t, &ProtectedBranchRepo{ProtectedBranchID: rule.ID})
}

// An organization rule without the repository being checked fails instead of loading repository 0.
func TestOrgRuleNeedsRepo(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	rule := createOrgRule(t, 3, "master")
	require.Error(t, rule.LoadRepo(db.DefaultContext))
	_, err := IsUserOfficialReviewer(db.DefaultContext, rule, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}))
	require.Error(t, err)
}

// The doctor removes rules whose repository or organization is gone and keeps the others.
func TestDeleteOrphanedProtectedBranches(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	kept := createOrgRule(t, 3, "master")
	orphans := []*ProtectedBranch{{RepoID: 99999, RuleName: "main"}, {OrgID: 99999, RuleName: "main"}, {OrgID: 2, RuleName: "main"}}
	for _, rule := range orphans {
		_, err := db.GetEngine(ctx).Insert(rule)
		require.NoError(t, err)
		_, err = db.GetEngine(ctx).Insert(&ApprovalRule{ProtectedBranchID: rule.ID, Name: "a"})
		require.NoError(t, err)
	}

	n, err := CountOrphanedProtectedBranches(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 3, n, "a rule of a user is an orphan too")

	require.NoError(t, DeleteOrphanedProtectedBranches(ctx))
	unittest.AssertExistsAndLoadBean(t, &ProtectedBranch{ID: kept.ID})
	for _, rule := range orphans {
		unittest.AssertNotExistsBean(t, &ProtectedBranch{ID: rule.ID})
		unittest.AssertNotExistsBean(t, &ApprovalRule{ProtectedBranchID: rule.ID})
	}
	n, err = CountOrphanedProtectedBranches(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
}

// must-fix 10: each rule checks the changed files against its own protected file patterns.
func TestChangedProtectedFiles(t *testing.T) {
	files := []string{"a.txt", "docs/b.md"}
	assert.Equal(t, []string{"docs/b.md"}, (&ProtectedBranch{ProtectedFilePatterns: "docs/*.md"}).ChangedProtectedFiles(files))
	assert.Empty(t, (&ProtectedBranch{ProtectedFilePatterns: "c.txt"}).ChangedProtectedFiles(files))
	assert.Empty(t, (&ProtectedBranch{}).ChangedProtectedFiles(files))
	assert.True(t, (&ProtectedBranch{ProtectedFilePatterns: "docs/*.md"}).MergeBlockedByProtectedFiles([]string{"docs/b.md"}))
}
