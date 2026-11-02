// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package mirror

import (
	"context"
	"strings"
	"testing"
	"time"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/git"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddFetchArgs(t *testing.T) {
	// no filters: exactly what the mirror always ran
	cmd := git.NewCommand(context.Background())
	addFetchArgs(cmd, &repo_model.Mirror{EnablePrune: true}, nil)
	assert.True(t, strings.HasSuffix(cmd.String(), "fetch --prune --tags origin"), cmd.String())
	cmd = git.NewCommand(context.Background())
	addFetchArgs(cmd, &repo_model.Mirror{}, nil)
	assert.True(t, strings.HasSuffix(cmd.String(), "fetch --tags origin"), cmd.String())

	// filters: explicit refspecs after `--`, no automatic tags
	cmd = git.NewCommand(context.Background())
	m := &repo_model.Mirror{EnablePrune: true, BranchFilter: "main"}
	specs, err := m.RefSpecs(nil)
	require.NoError(t, err)
	addFetchArgs(cmd, m, specs)
	assert.True(t, strings.HasSuffix(cmd.String(), "fetch --prune --no-tags origin -- +refs/heads/main:refs/heads/main +refs/tags/*:refs/tags/*"), cmd.String())
}

func TestAddLsRemoteArgs(t *testing.T) {
	cmd := git.NewCommand(context.Background())
	addLsRemoteArgs(cmd, &repo_model.Mirror{BranchFilter: "main,release/*,dev", TagFilter: "v1"})
	assert.True(t, strings.HasSuffix(cmd.String(), "ls-remote --symref -- origin HEAD refs/heads/main refs/heads/dev refs/tags/v1"), cmd.String())
	cmd = git.NewCommand(context.Background())
	addLsRemoteArgs(cmd, &repo_model.Mirror{BranchFilter: "release/*"})
	assert.True(t, strings.HasSuffix(cmd.String(), "ls-remote --symref -- origin HEAD"), cmd.String())
}

// A request queued while a sync of the same repository runs waits for it (repack/prune must not overlap a fetch) and
// then loads the mirror, so it sees what was saved meanwhile.
func TestSyncPullMirrorWaitsForRunningSync(t *testing.T) {
	unlock := pullSyncLocks.Lock("424242")
	done := make(chan struct{})
	go func() {
		defer close(done)
		SyncPullMirror(context.Background(), 424242)
	}()
	select {
	case <-done:
		t.Fatal("the second sync ran while the first one held the lock")
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the second sync never ran")
	}
}

func TestFilterErrorFor(t *testing.T) {
	m := &repo_model.Mirror{BranchFilter: "main,release/*"}
	assert.Empty(t, filterErrorFor(m, ""))
	assert.Empty(t, filterErrorFor(m, "release/1"))
	assert.Equal(t, "dev", filterErrorFor(m, "dev"))
	assert.Equal(t, "dev", filterErrorFor(m, "de\nv\x00"))
	assert.Len(t, []rune(filterErrorFor(m, strings.Repeat("é", 300))), 255)
	assert.Empty(t, filterErrorFor(&repo_model.Mirror{}, "dev"))
}

func TestCappedWriter(t *testing.T) {
	w := &cappedWriter{}
	n, err := w.Write([]byte(strings.Repeat("a", maxLsRemoteOutput+10)))
	require.NoError(t, err)
	assert.Equal(t, maxLsRemoteOutput+10, n)
	assert.Equal(t, maxLsRemoteOutput, w.Len())
	assert.True(t, w.truncated)

	w = &cappedWriter{}
	_, _ = w.Write([]byte(strings.Repeat("a", maxLsRemoteOutput)))
	assert.False(t, w.truncated, "exactly the limit isn't truncated")
	_, _ = w.Write([]byte("b"))
	assert.True(t, w.truncated)
}
