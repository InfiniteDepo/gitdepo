// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"forgejo.org/modules/process"
	"forgejo.org/modules/setting"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
)

// A background process (the async TestPullRequest after a push) may still run git in the repository root when a
// test returns: the test's cleanup must cancel it and wait for it before the root is removed (#511).
func TestPrepareTestEnvWaitsForProcessesBeforeRemovingRepoRoot(t *testing.T) {
	var root string
	var existedWhenDone bool
	finished := make(chan struct{})

	t.Run("test", func(t *testing.T) {
		defer tests.PrepareTestEnv(t)()
		root = setting.RepoRootPath

		ctx, _, done := process.GetManager().AddContext(context.Background(), "background work in the repository root")
		go func() {
			defer close(finished)
			defer done()
			<-ctx.Done()
			time.Sleep(200 * time.Millisecond) // winding down: git still writes below the root
			_, err := os.Stat(root)
			existedWhenDone = err == nil
		}()
	})

	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the background process was not cancelled")
	}
	assert.True(t, existedWhenDone, "the repository root was removed while a background process still ran")
}
