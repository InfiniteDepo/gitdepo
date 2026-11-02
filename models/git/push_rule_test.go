// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git_test

import (
	"strings"
	"testing"
	"time"

	git_model "forgejo.org/models/git"
	"forgejo.org/models/unittest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPushRuleCompile(t *testing.T) {
	for _, rule := range []git_model.PushRule{
		{CommitMessageRegex: "("},
		{CommitMessageBannedRegex: strings.Repeat("a", git_model.PushRuleMaxPatternLength+1)},
		{BranchNameRegex: "["},
		{BannedFilePatterns: "ok;[a"},
		{BannedFilePatterns: strings.Repeat("a", git_model.PushRuleMaxPatternLength+1)},
		{MaxFileSizeMB: -1},
	} {
		require.Error(t, rule.Compile(), "%+v", rule)
	}

	rule := git_model.PushRule{CommitMessageRegex: "^ABC-", BannedFilePatterns: " *.EXE ; id_rsa;secrets/**;"}
	require.NoError(t, rule.Compile())
	assert.True(t, rule.CommitMessageRe.MatchString("ABC-1 x"))
	assert.Nil(t, rule.BranchNameRe)
	for _, p := range []string{"a.exe", "sub/dir/x.tar.exe", "A/B/ID_RSA", "secrets/a/b"} {
		assert.True(t, rule.IsBannedFile(p), p)
	}
	for _, p := range []string{"exe", "id_rsa.pub", "a/secrets/b", "x.exe/readme"} {
		assert.False(t, rule.IsBannedFile(p), p)
	}
}

func TestPushRuleUpsert(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	rule, err := git_model.GetPushRule(t.Context(), 1)
	require.NoError(t, err)
	assert.Nil(t, rule)

	require.NoError(t, git_model.UpsertPushRule(t.Context(), &git_model.PushRule{RepoID: 1, BranchNameRegex: "^a", MaxFileSizeMB: 2}))
	require.NoError(t, git_model.UpsertPushRule(t.Context(), &git_model.PushRule{RepoID: 1, CommitMessageRegex: "^b"}))
	rule, err = git_model.GetPushRule(t.Context(), 1)
	require.NoError(t, err)
	assert.Equal(t, "^b", rule.CommitMessageRegex)
	assert.Empty(t, rule.BranchNameRegex)
	assert.Zero(t, rule.MaxFileSizeMB)
	unittest.AssertCount(t, &git_model.PushRule{}, 1)
}

func TestPushRulePRTitle(t *testing.T) {
	for _, rule := range []git_model.PushRule{
		{PRTitleRegex: "("},
		{PRTitleBannedRegex: strings.Repeat("a", git_model.PushRuleMaxPatternLength+1)},
		{PRTitleBranches: "main;[a"},
		{PRTitleBranches: strings.Repeat("a", git_model.PushRuleMaxPatternLength+1)},
		{PRTitleMessage: strings.Repeat("a", git_model.PushRuleMaxPRTitleMessageLength+1)},
	} {
		require.Error(t, rule.Compile(), "%+v", rule)
	}

	var empty git_model.PushRule
	require.NoError(t, empty.Compile())
	require.NoError(t, empty.CheckPRTitle("main", "anything", false))

	rule := git_model.PushRule{PRTitleRegex: "^[A-Z]+-\\d+ ", PRTitleBannedRegex: "^WIP", PRTitleMessage: "use KEY-1 prefix"}
	require.NoError(t, rule.Compile())
	require.NoError(t, rule.CheckPRTitle("main", "ABC-1 fix", false))
	err := rule.CheckPRTitle("main", "fix", false)
	require.ErrorAs(t, err, new(*git_model.ErrPRTitleRule))
	assert.True(t, git_model.IsErrPRTitleRule(err))
	assert.Equal(t, "use KEY-1 prefix", err.(*git_model.ErrPRTitleRule).Message)
	// a draft skips must-match, never must-not-match
	require.NoError(t, rule.CheckPRTitle("main", "fix", true))
	require.Error(t, rule.CheckPRTitle("main", "WIP: ABC-1 fix", true))

	// the filter is case sensitive and limits the checked base branches
	rule = git_model.PushRule{PRTitleRegex: "^ok", PRTitleBranches: "main; release/*"}
	require.NoError(t, rule.Compile())
	require.Error(t, rule.CheckPRTitle("main", "bad", false))
	require.Error(t, rule.CheckPRTitle("release/1.0", "bad", false))
	require.NoError(t, rule.CheckPRTitle("develop", "bad", false))
	require.NoError(t, rule.CheckPRTitle("Main", "bad", false))
}

func TestPushRulePRTitleWorstCasePattern(t *testing.T) {
	// Go's regexp is linear time and refuses programs that are too large, so the 1024 cap is enough:
	// a pattern is either rejected at save time or cheap to match.
	for _, pattern := range []string{`\pL{1000}`, `(\pL{1000}){1000}`, `((a{1000}){1000}){1000}`} {
		rule := git_model.PushRule{PRTitleRegex: pattern}
		if err := rule.Compile(); err != nil {
			continue
		}
		start := time.Now()
		require.Error(t, rule.CheckPRTitle("main", strings.Repeat("a", 255), false))
		assert.Less(t, time.Since(start), time.Second, pattern)
	}
}

func TestPushRuleCompilePRTitleOnly(t *testing.T) {
	// the merge box compiles only the title fields, a broken commit message regex is not its business
	rule := git_model.PushRule{CommitMessageRegex: "(", PRTitleRegex: "^a"}
	require.NoError(t, rule.CompilePRTitle())
	require.Error(t, rule.Compile())
	assert.Nil(t, rule.CommitMessageRe)
}
