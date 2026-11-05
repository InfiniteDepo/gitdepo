// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"forgejo.org/models/db"
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
		// `**` as a whole segment also matches no directory
		{"docs/**/README.md", []string{"docs/README.md"}, true},
		{"docs/**/README.md", []string{"docs/a/b/README.md"}, true},
		{"**/x.go", []string{"x.go"}, true},
		{"src/**/*.go", []string{"src/x.go"}, true},
	} {
		r := &git_model.ApprovalRule{PathPatterns: c.patterns}
		assert.Equal(t, c.applies, r.AppliesTo(git_model.NewPathMatchBudget(), c.files), "%q %v", c.patterns, c.files)
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
		"101 paths":        {Name: "A", RequiredCount: 1, UserIDs: []int64{user2.ID}, PathPatterns: strings.Repeat("a;", 100) + "a"},
		"path bytes":       {Name: "A", RequiredCount: 1, UserIDs: []int64{user2.ID}, PathPatterns: strings.Repeat("a", 200) + strings.Repeat(";"+strings.Repeat("a", 200), 40)},
	} {
		err := git_model.SetApprovalRules(t.Context(), repo, pb.ID, []*git_model.ApprovalRule{bad})
		require.ErrorIs(t, err, util.ErrInvalidArgument, name)
	}
	// 100 path patterns and 8 KiB of them are allowed
	require.NoError(t, git_model.SetApprovalRules(t.Context(), repo, pb.ID, []*git_model.ApprovalRule{{Name: "Paths", RequiredCount: 1, UserIDs: []int64{user2.ID}, PathPatterns: strings.Repeat("a;", 99) + "a"}}))
	require.NoError(t, git_model.SetApprovalRules(t.Context(), repo, pb.ID, []*git_model.ApprovalRule{{Name: "Paths", RequiredCount: 1, UserIDs: []int64{user2.ID}, PathPatterns: strings.Repeat("a", 200) + strings.Repeat(";"+strings.Repeat("a", 200), 39)}}))
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

// A user in very many teams must not make the lookup fail: the IDs are matched in chunks, and an ID that is only
// part of another one matches nothing.
func TestFindApprovalRulesListingManyTeams(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	rule := &git_model.ProtectedBranch{RepoID: 1, RuleName: "listing"}
	require.NoError(t, db.Insert(ctx, rule))
	require.NoError(t, db.Insert(ctx, &git_model.ApprovalRule{ProtectedBranchID: rule.ID, Name: "Teams", RequiredCount: 1, TeamIDs: []int64{250, 15}, UserIDs: []int64{77}}))

	teams := make([]int64, 400)
	for i := range teams {
		teams[i] = int64(1000 + i)
	}
	found, err := git_model.FindApprovalRulesListing(ctx, nil, teams)
	require.NoError(t, err)
	assert.Empty(t, found)

	found, err = git_model.FindApprovalRulesListing(ctx, []int64{1}, append(teams, 250))
	require.NoError(t, err)
	require.Len(t, found, 1, "found through the team, once, though the chunks repeat nothing")
	assert.Equal(t, "Teams", found[0].Name)

	found, err = git_model.FindApprovalRulesListing(ctx, []int64{7, 5}, []int64{25})
	require.NoError(t, err)
	assert.Empty(t, found, "7 is not 77, 25 is not 250 or 15")
	found, err = git_model.FindApprovalRulesListing(ctx, nil, nil)
	require.NoError(t, err)
	assert.Empty(t, found)
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
		"unmatched":   "}{a,{b,c}}",
		"unmatched 2": "a}",
		"nul":         "a\x00b",
		"newline":     "a\nb",
		"c1":          "a\u0085b",
		"bidi":        "a\u202eb",
	} {
		require.ErrorIs(t, git_model.ValidateGlobPattern(bad, '.', '/'), util.ErrInvalidArgument, name)
	}
}

// Approval-rule patterns use linear-time matching: patterns within the limits stay fast against long path and
// source branch names that end in the pattern's last character, and a stored pattern beyond the limits fails closed.
func TestGlobPatternLinearTime(t *testing.T) {
	for _, p := range []string{"*/*/*/*/*/*x", "**/*/*/*/*x", "*/*/*/*x"} {
		require.NoError(t, git_model.ValidateGlobPattern(p, '.', '/'))
		assert.True(t, (&git_model.ApprovalRule{PathPatterns: p}).AppliesTo(git_model.NewPathMatchBudget(), []string{strings.ReplaceAll(p, "*", "a")}))
		assert.True(t, (&git_model.ApprovalRule{SourceBranchPattern: p}).MatchesSourceBranch(strings.ReplaceAll(p, "*", "a")))
		name := strings.Repeat("a/", 600) + "x"
		start := time.Now()
		(&git_model.ApprovalRule{PathPatterns: p}).AppliesTo(git_model.NewPathMatchBudget(), []string{name})
		(&git_model.ApprovalRule{SourceBranchPattern: p}).MatchesSourceBranch(name)
		assert.Less(t, time.Since(start), 5*slowdown*time.Millisecond, "%q against %d bytes", p, len(name))
	}

	slow := strings.Repeat("*aa", 14) + "*c"
	require.Error(t, git_model.ValidateGlobPattern(slow, '/'), "refused when saved")
	assert.True(t, (&git_model.ApprovalRule{PathPatterns: slow}).AppliesTo(git_model.NewPathMatchBudget(), []string{"unrelated.txt"}))
	assert.False(t, (&git_model.ApprovalRule{SourceBranchPattern: slow}).MatchesSourceBranch(strings.Repeat("a", 250)+"c"))
}

// The work of approval-rule path matching is bounded: 100 patterns against 2000 changed files of 4 KiB are not
// matched, the rule applies (fails closed) and asks nobody (MatchesPaths isn't decided); a stored rule beyond the
// pattern caps applies too.
func TestApprovalRulePathMatchingBound(t *testing.T) {
	patterns := make([]string, 100)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("**/a*b*c%d/**", i)
	}
	files := make([]string, 2000)
	for i := range files {
		files[i] = strings.Repeat("ab/", 1365) + fmt.Sprint(i)
	}
	r := &git_model.ApprovalRule{PathPatterns: strings.Join(patterns, ";")}
	start := time.Now()
	assert.True(t, r.AppliesTo(git_model.NewPathMatchBudget(), files))
	_, decided := r.MatchesPaths(git_model.NewPathMatchBudget(), files)
	assert.False(t, decided)
	assert.Less(t, time.Since(start), 50*slowdown*time.Millisecond)

	// within the bound the files are matched
	matches, decided := r.MatchesPaths(git_model.NewPathMatchBudget(), []string{"src/x/a1b2c7/y.go", "README.md"})
	assert.True(t, matches && decided)
	matches, decided = r.MatchesPaths(git_model.NewPathMatchBudget(), []string{"README.md"})
	assert.True(t, !matches && decided)
	assert.False(t, r.AppliesTo(git_model.NewPathMatchBudget(), []string{"README.md"}))

	for _, stored := range []string{strings.Repeat("a;", 100) + "a", strings.Repeat("a", 8<<10+1)} {
		r := &git_model.ApprovalRule{PathPatterns: stored}
		assert.True(t, r.AppliesTo(git_model.NewPathMatchBudget(), []string{"unrelated.txt"}))
		_, decided := r.MatchesPaths(git_model.NewPathMatchBudget(), []string{"unrelated.txt"})
		assert.False(t, decided)
	}
}

// One budget is shared by every rule of an evaluation: 60 rules of 100 patterns (20 per level, three levels) against
// 20 files of 4 KiB take at most the work of one budget, and the rules beyond it fail closed.
func TestApprovalRulePathMatchingSharedBudget(t *testing.T) {
	patterns := make([]string, 100)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("**/a*b*c%d/**", i)
	}
	files := make([]string, 20)
	for i := range files {
		files[i] = strings.Repeat("ab/", 1365) + fmt.Sprint(i)
	}
	budget := git_model.NewPathMatchBudget()
	undecided := 0
	start := time.Now()
	for range 60 {
		r := &git_model.ApprovalRule{PathPatterns: strings.Join(patterns, ";")}
		if _, decided := r.MatchesPaths(budget, files); !decided {
			undecided++
			assert.True(t, r.AppliesTo(budget, files), "fails closed")
		}
	}
	// 20 files of 4 KiB against 100 patterns is about 8 Mi / 1 of the budget: only the first rule fits
	assert.Equal(t, 59, undecided)
	// about 0.3 s; without the shared budget it was about 13 s
	assert.Less(t, time.Since(start), 3*slowdown*time.Second)

	// a rule that fits in what is left is still matched
	small := &git_model.ApprovalRule{PathPatterns: "docs/**"}
	matches, decided := small.MatchesPaths(budget, []string{"docs/a.md"})
	assert.True(t, matches && decided)
}
