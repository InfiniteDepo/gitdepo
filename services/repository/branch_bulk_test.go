// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
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
	assert.ElementsMatch(t, all, slices.Concat(slices.Collect(maps.Keys(merged)), slices.Collect(maps.Keys(notMerged))))
	for name, sha := range merged { // the tip git walked is what the filter reports
		tip, err := gitRepo.GetBranchCommitID(name)
		require.NoError(t, err)
		assert.Equal(t, tip, sha)
	}

	// a branch that doesn't exist matches nothing, either way
	none, err := branchesMergedInto(t.Context(), repo, gitRepo, "no-such-branch", true)
	require.NoError(t, err)
	assert.Empty(t, none)
}

// The merged set is intersected in Go: more names than a statement can bind (SQLite: 32766) work, and a row counts
// only at the tip git walked, compared exactly (a name differing in case, or a branch pushed since, doesn't match).
func TestBranchQueryMergedSetBeyondBindLimit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	const n = 33000
	merged := map[string]string{}
	rows := make([]*git_model.Branch, 0, n)
	for i := range n {
		name, sha := fmt.Sprintf("bulk-%d", i), fmt.Sprintf("%040x", i+1)
		merged[name] = sha
		rows = append(rows, &git_model.Branch{RepoID: repo.ID, Name: name, CommitID: sha})
	}
	for chunk := range slices.Chunk(rows, 1000) {
		_, err := db.GetEngine(t.Context()).Insert(chunk)
		require.NoError(t, err)
	}
	moved := rows[7] // pushed since the walk
	merged[moved.Name] = fmt.Sprintf("%040x", 999999)
	merged["BULK-8"] = rows[8].CommitID // another name by case: no row of it, and no match for bulk-8's row either
	delete(merged, rows[9].Name)

	q := BranchQuery{Cond: builder.NewCond(), Merged: merged}
	got, err := q.rows(t.Context(), repo)
	require.NoError(t, err)
	assert.Len(t, got, n-2)
	for _, b := range got {
		assert.NotContains(t, []string{moved.Name, rows[9].Name}, b.Name)
	}

	pageQuery, total, err := q.Page(t.Context(), repo, 2, 50)
	require.NoError(t, err)
	assert.EqualValues(t, n-2, total)
	page, err := db.Find[git_model.Branch](t.Context(), git_model.FindBranchOptions{RepoID: repo.ID, Cond: pageQuery.Cond, ListOptions: db.ListOptionsAll})
	require.NoError(t, err)
	assert.Len(t, page, 50)
}
