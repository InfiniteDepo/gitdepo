// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package code

import (
	"context"
	"testing"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/git"
	"forgejo.org/modules/indexer/code/internal"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// branchRecorder is an indexer that indexes whole repos, and records how it is called.
type branchRecorder struct {
	internal.Indexer
	indexed  int
	rebuilds [][]internal.BranchFiles
}

func (r *branchRecorder) Index(context.Context, *repo_model.Repository, string, string, bool, *internal.RepoChanges) error {
	r.indexed++
	return nil
}

func (r *branchRecorder) IndexBranches(_ context.Context, _ *repo_model.Repository, _ string, branches []internal.BranchFiles) error {
	r.rebuilds = append(r.rebuilds, branches)
	return nil
}

func (r *branchRecorder) DeleteBranch(context.Context, int64, string) error { return nil }

func setPatterns(t *testing.T, repoID int64, patterns ...string) {
	t.Helper()
	_, err := db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", repoID, unit.TypeCode).Cols("config").
		Update(&repo_model.RepoUnit{Config: &repo_model.CodeConfig{IndexedBranches: patterns}})
	require.NoError(t, err)
}

func names(branches []internal.BranchFiles) []string {
	out := make([]string, 0, len(branches))
	for _, b := range branches {
		out = append(out, b.Name)
	}
	return out
}

// Z1/AC3: an indexer that indexes whole repos gets one call with the default branch first, once
// extra branches are wanted or stored; a repo with only the default branch keeps the delta path.
func TestIndexBranchIndexer(t *testing.T) {
	unittest.PrepareTestEnv(t)
	rec := &branchRecorder{Indexer: internal.NewDummyIndexer()}
	const repoID = 1

	require.NoError(t, index(git.DefaultContext, rec, repoID))
	assert.Equal(t, 1, rec.indexed)
	assert.Empty(t, rec.rebuilds)

	// a wanted branch: rebuilt once with default + branch, and not again while nothing changed
	setPatterns(t, repoID, "branch2")
	require.NoError(t, index(git.DefaultContext, rec, repoID))
	require.Len(t, rec.rebuilds, 1)
	assert.Equal(t, []string{"master", "branch2"}, names(rec.rebuilds[0]))
	assert.NotEmpty(t, rec.rebuilds[0][0].Files, "default branch files")
	assert.NotEmpty(t, rec.rebuilds[0][1].Files, "branch files")
	stored, err := repo_model.GetIndexerBranches(t.Context(), repoID)
	require.NoError(t, err)
	assert.Contains(t, stored, "branch2")

	require.NoError(t, index(git.DefaultContext, rec, repoID))
	assert.Len(t, rec.rebuilds, 1)
	assert.Equal(t, 1, rec.indexed)

	// patterns removed: a rebuild with the default branch only drops the branch
	setPatterns(t, repoID)
	require.NoError(t, index(git.DefaultContext, rec, repoID))
	require.Len(t, rec.rebuilds, 2)
	assert.Equal(t, []string{"master"}, names(rec.rebuilds[1]))
	stored, err = repo_model.GetIndexerBranches(t.Context(), repoID)
	require.NoError(t, err)
	assert.Empty(t, stored)

	// and back to the delta path
	require.NoError(t, index(git.DefaultContext, rec, repoID))
	assert.Len(t, rec.rebuilds, 2)
}

// N2: a branch named HEAD is never indexed, it would be the default branch for zoekt.
func TestExpandIndexedBranchesSkipsHEAD(t *testing.T) {
	unittest.PrepareTestEnv(t)
	repo, err := repo_model.GetRepositoryByID(t.Context(), 1)
	require.NoError(t, err)
	require.NoError(t, git_model.AddBranches(t.Context(), []*git_model.Branch{{RepoID: 1, Name: "HEAD", CommitID: "985f0301dba5e7b34be866819cd15ad3d8f508ee"}}))
	setPatterns(t, 1, "*")

	repo.Units = nil
	wanted, err := expandIndexedBranches(t.Context(), repo)
	require.NoError(t, err)
	for _, b := range wanted {
		assert.NotEqual(t, "HEAD", b.Name)
	}
	assert.NotEmpty(t, wanted)
}
