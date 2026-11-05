// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A name that makes git die (`master@{99}` is a reflog entry that does not exist, which git dies on) must give the caller an error,
// not a request that waits forever.
func TestCatFileBatchCheckGitDies(t *testing.T) {
	repo, err := OpenRepository(t.Context(), filepath.Join(testReposDir, "repo1_bare"))
	require.NoError(t, err)
	defer repo.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = repo.IsReferenceExist("master@{99}")
		_, err := repo.GetRefCommitID("master@{99}")
		assert.Error(t, err)
		assert.False(t, repo.IsObjectExist("master@{99}"))
		// the repository still answers afterwards
		assert.True(t, repo.IsBranchExist("master"))
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the request waits for a git process that died")
	}
}

// A branch or tag exists only under its own full name: a tag called `refs/heads/x` doesn't make a branch `x`, nor a
// branch called `refs/tags/y` a tag `y`, which a lookup by name (cat-file) resolved.
func TestIsBranchTagExistExact(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, exec.Command("git", "clone", "-q", "--bare", filepath.Join(testReposDir, "repo1_bare"), dir).Run())
	repo, err := OpenRepository(t.Context(), dir)
	require.NoError(t, err)
	defer repo.Close()
	id, err := repo.GetRefCommitID("refs/heads/master")
	require.NoError(t, err)
	require.NoError(t, repo.SetReference("refs/tags/refs/heads/x", id))
	require.NoError(t, repo.SetReference("refs/heads/refs/tags/y", id))

	assert.False(t, repo.IsBranchExist("x"))
	assert.False(t, repo.IsTagExist("y"))
	assert.True(t, repo.IsBranchExist("refs/tags/y"))
	assert.True(t, repo.IsTagExist("refs/heads/x"))
	assert.True(t, repo.IsBranchExist("master"))
	assert.False(t, repo.IsTagExist("master"))
	assert.False(t, repo.IsExactRefExist("master"), "a full name only")

	ref, err := repo.ExpandRef("x")
	require.Error(t, err)
	assert.Empty(t, ref)
}

func TestIsReservedRefName(t *testing.T) {
	for name, want := range map[string]bool{"HEAD": true, "refs/heads/x": true, "refs/x": true, "main": false, "heads/x": false, "HEAD2": false, "x/refs/y": false} {
		assert.Equal(t, want, IsReservedRefName(name), name)
	}
}

// A lookup chain (the segments of a URL path) starts no git process for a name that is missing, and one for the hit.
func TestExactRefLookupProcesses(t *testing.T) {
	repo, err := OpenRepository(t.Context(), filepath.Join(testReposDir, "repo1_bare"))
	require.NoError(t, err)
	defer repo.Close()
	assert.True(t, repo.IsBranchExist("master")) // starts the shared batch process

	trace := filepath.Join(t.TempDir(), "trace")
	t.Setenv("GIT_TRACE", trace)
	for range 50 {
		assert.False(t, repo.IsBranchExist("a/a/a/a"))
		assert.False(t, repo.IsTagExist("a/a/a/a"))
	}
	data, _ := os.ReadFile(trace)
	assert.NotContains(t, string(data), "show-ref", "missing names are answered by the batch process")

	assert.True(t, repo.IsBranchExist("master"))
	data, err = os.ReadFile(trace)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(data), "git show-ref"), "the hit is confirmed once")

	id, ok, err := repo.GetExactRefCommitID("refs/heads/master")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Len(t, id, 40)
	_, ok, err = repo.GetExactRefCommitID("refs/heads/nope")
	require.NoError(t, err)
	assert.False(t, ok)
}
