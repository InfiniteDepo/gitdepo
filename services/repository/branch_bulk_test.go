// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"strings"
	"testing"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBranchFilterValidate(t *testing.T) {
	for _, ok := range []BranchFilter{{}, {State: BranchMerged}, {State: BranchNotMerged, Into: MergedIntoDefault}, {StaleDays: 1}, {StaleDays: 3650}, {Into: MergedIntoDev}} {
		require.NoError(t, ok.Validate(), "%+v", ok)
	}
	for _, bad := range []BranchFilter{{State: "yes"}, {Into: "main"}, {StaleDays: -1}, {StaleDays: 3651}} {
		require.ErrorIs(t, bad.Validate(), util.ErrInvalidArgument, "%+v", bad)
	}
	assert.False(t, BranchFilter{Keyword: "x", Type: "Feature", Untyped: true}.IsSet())
	assert.True(t, BranchFilter{StaleDays: 1}.IsSet())
	assert.True(t, BranchFilter{PushedBy: "a"}.IsSet())
	assert.True(t, BranchFilter{Deleted: true}.IsSet())
}

func TestCheckSelectedBranchNames(t *testing.T) {
	got, err := CheckSelectedBranchNames([]string{"b", "a", "b"}, 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, got) // duplicates count once
	for _, bad := range [][]string{nil, {"a", "b", "c"}, {""}, {"a..b"}, {"x/"}, {"HEAD"}, {"refs/heads/x"}, {strings.Repeat("x", 256)}} {
		_, err := CheckSelectedBranchNames(bad, 2)
		require.ErrorIs(t, err, util.ErrInvalidArgument, "%q", bad)
	}
}

// merged and not merged are the two halves of the branches: one git walk each, exact names.
func TestBranchesMergedInto(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
	require.NoError(t, err)
	defer gitRepo.Close()

	merged, err := branchesMergedInto(t.Context(), repo, gitRepo, repo.DefaultBranch, true)
	require.NoError(t, err)
	notMerged, err := branchesMergedInto(t.Context(), repo, gitRepo, repo.DefaultBranch, false)
	require.NoError(t, err)
	all, _, err := gitRepo.GetBranchNames(0, 0)
	require.NoError(t, err)
	assert.Contains(t, merged, repo.DefaultBranch)
	assert.NotContains(t, notMerged, repo.DefaultBranch)
	assert.ElementsMatch(t, all, append(append([]string{}, merged...), notMerged...))

	// a branch that doesn't exist matches nothing, either way
	none, err := branchesMergedInto(t.Context(), repo, gitRepo, "no-such-branch", true)
	require.NoError(t, err)
	assert.Empty(t, none)
}
