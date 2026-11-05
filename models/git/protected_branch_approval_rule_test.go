// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/util"

	"github.com/gobwas/glob"
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

func TestApprovalRuleMatchesSourceBranch(t *testing.T) {
	for _, c := range []struct {
		pattern, branch string
		matches         bool
	}{
		{"", "anything", true},
		{"feature/*", "feature/a", true},
		{"feature/*", "feature/a/b", false}, // `*` doesn't cross '/'
		{"feature/**", "feature/a/b", true},
		{"feature/*", "bugfix/a", false},
		{"feature/*", "Feature/a", false}, // branch names are case-sensitive
		{"[a", "a", false},                // a pattern that can't compile matches nothing: it only limits requests
		{"user5/*", "user5/topic", true},  // AGit pull requests are stored as "<pusher>/<topic>"
		{"feature/*", "user5/feature/x", false},
		{strings.Repeat("*aa", 16) + "*c", "aaa", false}, // beyond the limits: nobody is asked
	} {
		r := &git_model.ApprovalRule{SourceBranchPattern: c.pattern}
		assert.Equal(t, c.matches, r.MatchesSourceBranch(c.branch), "%q %q", c.pattern, c.branch)
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
		"count":            {Name: "A", RequiredCount: 0, UserIDs: []int64{user2.ID}},
		"name":             {Name: " ", RequiredCount: 1, UserIDs: []int64{user2.ID}},
		"nobody":           {Name: "A", RequiredCount: 1},
		"glob":             {Name: "A", RequiredCount: 1, UserIDs: []int64{user2.ID}, PathPatterns: "[a"},
		"negative":         {Name: "A", RequiredCount: -1, RequestReviews: true, UserIDs: []int64{user2.ID}},
		"source glob":      {Name: "A", RequiredCount: 0, RequestReviews: true, UserIDs: []int64{user2.ID}, SourceBranchPattern: "[a"},
		"source too long":  {Name: "A", RequiredCount: 1, RequestReviews: true, UserIDs: []int64{user2.ID}, SourceBranchPattern: strings.Repeat("a", 256)},
		"request no users": {Name: "A", RequiredCount: 0, RequestReviews: true},
	} {
		err := git_model.SetApprovalRules(t.Context(), repo, pb.ID, []*git_model.ApprovalRule{bad})
		require.ErrorIs(t, err, util.ErrInvalidArgument, name)
	}
	// 0 approvals is a request-only rule
	require.ErrorIs(t, git_model.SetApprovalRules(t.Context(), repo, pb.ID, []*git_model.ApprovalRule{{Name: "Ask", RequestReviews: true, RequireCodeOwners: true, UserIDs: []int64{user2.ID}}}), util.ErrInvalidArgument)
	require.NoError(t, git_model.SetApprovalRules(t.Context(), repo, pb.ID, []*git_model.ApprovalRule{{Name: "Ask", RequiredCount: 0, RequestReviews: true, SourceBranchPattern: "feature/*", UserIDs: []int64{user2.ID}}}))
	rules, err = git_model.GetApprovalRules(t.Context(), pb.ID)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.True(t, rules[0].RequestReviews)
	assert.Equal(t, "feature/*", rules[0].SourceBranchPattern)
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

func TestValidateGlobPattern(t *testing.T) {
	for _, ok := range []string{"", "feature/*", "release/**", "src/**/*.go", "{docs,api}/**", "docs/**", "a?b", strings.Repeat("a", 255)} {
		require.NoError(t, git_model.ValidateGlobPattern(ok, '.', '/'), "%q", ok)
	}
	for name, bad := range map[string]string{
		"compile":     "[a",
		"too long":    strings.Repeat("a", 256),
		"wildcards":   strings.Repeat("*a", 7) + "*b",
		"alternation": "{a,b}/{c,d}/{e,f}/{g,h}",
		"nested":      "{a,{b,c}}",
		"nul":         "a\x00b",
		"newline":     "a\nb",
		"c1":          "a\u0085b",
		"bidi":        "a\u202eb",
	} {
		require.ErrorIs(t, git_model.ValidateGlobPattern(bad, '.', '/'), util.ErrInvalidArgument, name)
	}
}

// Matching a glob with many wildcards takes polynomial time of a high degree in the length of the name; the limits
// refuse such patterns, and what they allow stays fast.
func TestGlobPatternComplexityBound(t *testing.T) {
	name := strings.Repeat("a", 250) + "x"
	slow := strings.Repeat("*aa", 14) + "*c"
	require.Error(t, git_model.ValidateGlobPattern(slow, '/'), "refused when saved")

	g := glob.MustCompile(slow, '/')
	start := time.Now()
	g.Match(name)
	t.Logf("without the limit, %d wildcards against %d characters take %v", 15, len(name), time.Since(start))

	worst := strings.Repeat("*aa", 6)
	require.NoError(t, git_model.ValidateGlobPattern(worst, '/'))
	start = time.Now()
	glob.MustCompile(worst, '/').Match(name)
	assert.Less(t, time.Since(start), 100*time.Millisecond)

	// a stored pattern beyond the limits fails closed
	r := &git_model.ApprovalRule{PathPatterns: slow}
	assert.True(t, r.AppliesTo([]string{"unrelated.txt"}))
	assert.False(t, (&git_model.ApprovalRule{SourceBranchPattern: slow}).MatchesSourceBranch(name))
}
