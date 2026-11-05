// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"path/filepath"
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
