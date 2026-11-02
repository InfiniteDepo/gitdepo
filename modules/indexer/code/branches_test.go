// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package code

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// AC2: the default branch is always first, patterns expand to the most recent
// matches, and the limit caps the whole list including the default branch.
func TestSelectBranches(t *testing.T) {
	branches := []BranchInfo{
		{Name: "main", CommitTime: 1},
		{Name: "develop", CommitTime: 50},
		{Name: "release/1.0", CommitTime: 10},
		{Name: "release/2.0", CommitTime: 30},
		{Name: "release/3.0", CommitTime: 20},
		{Name: "feature/x", CommitTime: 99},
	}

	assert.Equal(t, []string{"main"}, selectBranches("main", nil, branches, 5))
	assert.Equal(t, []string{"main", "develop"}, selectBranches("main", []string{"develop"}, branches, 5))
	// newest first: release/2.0 (30), release/3.0 (20)
	assert.Equal(t, []string{"main", "release/2.0", "release/3.0"}, selectBranches("main", []string{"release/*"}, branches, 3))
	// a pattern matching the default branch doesn't duplicate it
	assert.Equal(t, []string{"main", "develop"}, selectBranches("main", []string{"main", "develop"}, branches, 5))
	// limit counts the default branch
	assert.Equal(t, []string{"main"}, selectBranches("main", []string{"release/*"}, branches, 1))
	// '*' does not cross '/'
	assert.Equal(t, []string{"main", "develop"}, selectBranches("main", []string{"*"}, branches, 2))
	// unknown patterns match nothing
	assert.Equal(t, []string{"main"}, selectBranches("main", []string{"nope/*"}, branches, 5))
}

// Push/delete trigger: only the default branch or a pattern match qualifies.
func TestIsIndexedBranchName(t *testing.T) {
	patterns := []string{"develop", "release/*"}
	assert.True(t, isIndexedBranchName("main", patterns, "main"))
	assert.True(t, isIndexedBranchName("main", patterns, "develop"))
	assert.True(t, isIndexedBranchName("main", patterns, "release/1.0"))
	assert.False(t, isIndexedBranchName("main", patterns, "feature/x"))
	assert.False(t, isIndexedBranchName("main", nil, "develop"))
	// a pattern that compiles but panics in glob's Match counts as no match
	assert.NotPanics(t, func() { assert.False(t, isIndexedBranchName("main", []string{"?a{}{,*"}, "xa")) })
}
