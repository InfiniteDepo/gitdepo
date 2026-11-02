// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git_test

import (
	"fmt"
	"testing"

	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AC4: a rule without paths always applies, a rule with paths applies only to a matching file.
func TestApprovalRuleAppliesTo(t *testing.T) {
	for _, c := range []struct {
		patterns string
		files    []string
		applies  bool
	}{
		{"", nil, true},
		{"", []string{"a.txt"}, true},
		{"db/migrations/**", []string{"db/migrations/v1/a.sql"}, true},
		{"db/migrations/**", []string{"src/main.go"}, false},
		{"db/migrations/**", nil, false},
		{"*.sql;docs/**", []string{"docs/a/b.md"}, true},
		{"*.sql", []string{"db/a.sql"}, false}, // `*` doesn't cross '/'
		{"DB/**", []string{"db/a.sql"}, true},  // case-insensitive, like protected files
		{" ; ", []string{"src/main.go"}, true}, // patterns that compile to nothing apply
	} {
		r := &git_model.ApprovalRule{PathPatterns: c.patterns}
		assert.Equal(t, c.applies, r.AppliesTo(c.files), "%q %v", c.patterns, c.files)
	}
}

// AC1/AC14: rules are stored per protected branch and validated.
func TestSetApprovalRules(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	pb := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "approval-rules"}
	require.NoError(t, git_model.UpdateProtectBranch(t.Context(), repo, pb, git_model.WhitelistOptions{}))

	valid := &git_model.ApprovalRule{Name: "Security", RequiredCount: 1, UserIDs: []int64{user2.ID}}
	require.NoError(t, git_model.SetApprovalRules(t.Context(), repo, pb.ID, []*git_model.ApprovalRule{valid}))
	rules, err := git_model.GetApprovalRules(t.Context(), pb.ID)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "Security", rules[0].Name)
	assert.Equal(t, []int64{user2.ID}, rules[0].UserIDs)

	for name, bad := range map[string]*git_model.ApprovalRule{
		"count":  {Name: "A", RequiredCount: 0, UserIDs: []int64{user2.ID}},
		"name":   {Name: " ", RequiredCount: 1, UserIDs: []int64{user2.ID}},
		"nobody": {Name: "A", RequiredCount: 1},
		"glob":   {Name: "A", RequiredCount: 1, UserIDs: []int64{user2.ID}, PathPatterns: "[a"},
	} {
		err := git_model.SetApprovalRules(t.Context(), repo, pb.ID, []*git_model.ApprovalRule{bad})
		require.ErrorIs(t, err, util.ErrInvalidArgument, name)
	}
	// code owners can stand in for the approver list
	require.NoError(t, git_model.SetApprovalRules(t.Context(), repo, pb.ID, []*git_model.ApprovalRule{{Name: "Owners", RequiredCount: 1, RequireCodeOwners: true}}))

	// duplicate names and more than MaxApprovalRules
	dup := []*git_model.ApprovalRule{valid, valid}
	require.ErrorIs(t, git_model.SetApprovalRules(t.Context(), repo, pb.ID, dup), util.ErrInvalidArgument)
	var many []*git_model.ApprovalRule
	for i := range git_model.MaxApprovalRules + 1 {
		many = append(many, &git_model.ApprovalRule{Name: fmt.Sprintf("r%d", i), RequiredCount: 1, UserIDs: []int64{user2.ID}})
	}
	require.ErrorIs(t, git_model.SetApprovalRules(t.Context(), repo, pb.ID, many), util.ErrInvalidArgument)

	// a failed save keeps the previous rules; deleting the protection removes them
	rules, err = git_model.GetApprovalRules(t.Context(), pb.ID)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "Owners", rules[0].Name)
	require.NoError(t, git_model.DeleteProtectedBranch(t.Context(), repo, pb.ID))
	rules, err = git_model.GetApprovalRules(t.Context(), pb.ID)
	require.NoError(t, err)
	assert.Empty(t, rules)
}
