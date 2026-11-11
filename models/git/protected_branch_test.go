// Copyright 2022 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package git

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBranchRuleMatch(t *testing.T) {
	kases := []struct {
		Rule          string
		BranchName    string
		ExpectedMatch bool
	}{
		{
			Rule:          "release/*",
			BranchName:    "release/v1.17",
			ExpectedMatch: true,
		},
		{
			Rule:          "release/**/v1.17",
			BranchName:    "release/test/v1.17",
			ExpectedMatch: true,
		},
		{
			Rule:          "release/**/v1.17",
			BranchName:    "release/test/1/v1.17",
			ExpectedMatch: true,
		},
		{
			Rule:          "release/*/v1.17",
			BranchName:    "release/test/1/v1.17",
			ExpectedMatch: false,
		},
		{
			Rule:          "release/v*",
			BranchName:    "release/v1.16",
			ExpectedMatch: true,
		},
		{
			Rule:          "*",
			BranchName:    "release/v1.16",
			ExpectedMatch: false,
		},
		{
			Rule:          "**",
			BranchName:    "release/v1.16",
			ExpectedMatch: true,
		},
		{
			Rule:          "main",
			BranchName:    "main",
			ExpectedMatch: true,
		},
		{
			Rule:          "master",
			BranchName:    "main",
			ExpectedMatch: false,
		},
	}

	for _, kase := range kases {
		pb := ProtectedBranch{RuleName: kase.Rule}
		assert.Equal(t, kase.ExpectedMatch, pb.Match(kase.BranchName), "%s - %s", kase.BranchName, kase.Rule)
	}
}

func TestCanDeployKeyPush(t *testing.T) {
	cases := []struct {
		name    string
		rule    ProtectedBranch
		keyID   int64
		allowed bool
	}{
		{"push disabled", ProtectedBranch{CanPush: false}, 1, false},
		{"push enabled without allow-list", ProtectedBranch{CanPush: true}, 1, true},
		{"allow-list without deploy keys", ProtectedBranch{CanPush: true, EnableWhitelist: true}, 1, false},
		{"allow-list with all deploy keys", ProtectedBranch{CanPush: true, EnableWhitelist: true, WhitelistDeployKeys: true}, 1, true},
		{"allow-list with listed key", ProtectedBranch{CanPush: true, EnableWhitelist: true, WhitelistDeployKeyIDs: []int64{1, 2}}, 2, true},
		{"allow-list with unlisted key", ProtectedBranch{CanPush: true, EnableWhitelist: true, WhitelistDeployKeyIDs: []int64{1, 2}}, 3, false},
		{"listed key but push disabled", ProtectedBranch{CanPush: false, EnableWhitelist: true, WhitelistDeployKeyIDs: []int64{1}}, 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.allowed, c.rule.CanDeployKeyPush(c.keyID))
		})
	}
}

func TestValidateMergeQueue(t *testing.T) {
	for _, tc := range []struct {
		pb ProtectedBranch
		ok bool
	}{
		{ProtectedBranch{}, true},
		{ProtectedBranch{MergeQueueMergeStyle: "squash", MergeQueueBuildConcurrency: 100, MergeQueueMinGroupSize: 3, MergeQueueMaxGroupSize: 3, MergeQueueWaitMinutes: 1440, MergeQueueCheckTimeoutMinutes: 1440}, true},
		{ProtectedBranch{MergeQueueMergeStyle: "fast-forward-only"}, false},
		{ProtectedBranch{MergeQueueMergeStyle: "manually-merged"}, false},
		{ProtectedBranch{MergeQueueBuildConcurrency: 101}, false},
		{ProtectedBranch{MergeQueueBuildConcurrency: -1}, false},
		{ProtectedBranch{MergeQueueMinGroupSize: 6}, false}, // above the default maximum
		{ProtectedBranch{MergeQueueMinGroupSize: 4, MergeQueueMaxGroupSize: 3}, false},
		{ProtectedBranch{MergeQueueMinGroupSize: 3, MergeQueueMaxGroupSize: 10, MergeQueueBuildConcurrency: 2}, false}, // never that many passed at once
		{ProtectedBranch{MergeQueueMaxGroupSize: 5, MergeQueueBuildConcurrency: 2}, false},
		{ProtectedBranch{MergeQueueBuildConcurrency: 2}, true}, // the default maximum is capped at it
		{ProtectedBranch{MergeQueueWaitMinutes: 1441}, false},
		{ProtectedBranch{MergeQueueCheckTimeoutMinutes: 1441}, false},
	} {
		err := tc.pb.ValidateMergeQueue()
		if tc.ok {
			require.NoError(t, err, "%+v", tc.pb)
		} else {
			require.ErrorIs(t, err, ErrInvalidMergeQueueConfig, "%+v", tc.pb)
		}
	}
	var cfgErr *MergeQueueConfigError
	require.ErrorAs(t, (&ProtectedBranch{MergeQueueMaxGroupSize: 5, MergeQueueBuildConcurrency: 2}).ValidateMergeQueue(), &cfgErr)
	assert.Equal(t, "max_group_size", cfgErr.Field)
	assert.Equal(t, 2, (&ProtectedBranch{MergeQueueBuildConcurrency: 2}).MergeQueueConfig().MaxGroupSize)
}

// a rule name is a glob a repository admin writes and every push matches: it takes linear time (red team #645)
func TestBranchRuleMatchIsLinear(t *testing.T) {
	rule := &ProtectedBranch{RuleName: strings.Repeat("{a,aa}*", 20) + "b"}
	start := time.Now()
	rule.Match(strings.Repeat("ab", 50) + "c")
	assert.Less(t, time.Since(start), 100*time.Millisecond)
}
