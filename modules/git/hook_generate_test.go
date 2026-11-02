// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitDelegateHooks(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "hooks", "update.d", "gitea")
	require.NoError(t, os.MkdirAll(filepath.Dir(stale), 0o755))
	require.NoError(t, os.WriteFile(stale, []byte("#!/bin/sh\n"), 0o755))

	require.NoError(t, InitDelegateHooks(dir))

	for _, name := range []string{"pre-receive", "update", "post-receive", "proc-receive"} {
		assert.FileExists(t, filepath.Join(dir, "hooks", name))
	}
	assert.FileExists(t, filepath.Join(dir, "hooks", "pre-receive.d", "gitea"))
	assert.FileExists(t, filepath.Join(dir, "hooks", "post-receive.d", "gitea"))
	for _, path := range []string{"pre-receive.d/gitea", "post-receive.d/gitea", "proc-receive"} {
		content, err := os.ReadFile(filepath.Join(dir, "hooks", path))
		require.NoError(t, err)
		assert.Contains(t, string(content), "\n"+hookEnv+" ", path)
	}
	// the update hook of the binary does nothing, so a push doesn't start it (and an old one is removed)
	assert.NoFileExists(t, stale)
	assert.DirExists(t, filepath.Join(dir, "hooks", "update.d"))
}
