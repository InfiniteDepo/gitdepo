// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package branchworkflow

import (
	"strings"
	"testing"
	"time"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Red team #645 (regression): a repository admin (any user, in their own repository) stores an exception pattern that
// NormalizeBranchingModel accepts and whose match against a branch name is exponential. Every new branch name the
// model checks (push hook, web/API create and rename, the issue page suggestion) runs it on a server goroutine.
func TestRT645ExceptionGlobBlowup(t *testing.T) {
	pattern := strings.Repeat("{a,aa}*", 16) + "b" // 113 bytes, under maxExceptionLen
	m, err := NormalizeBranchingModel(&repo_model.BranchingModel{
		ReleasePrefixes: []string{"release/"}, RequireBranchType: true, BranchExceptions: []string{pattern},
	})
	require.NoError(t, err, "the pattern is accepted on save")
	repo := &repo_model.Repository{DefaultBranch: "main"}
	start := time.Now()
	namingAllows(repo, EffectiveModel{Model: *m}, strings.Repeat("ab", 125))
	took := time.Since(start)
	t.Logf("one namingAllows call took %v", took)
	assert.Less(t, took, 100*time.Millisecond, "DoS: one branch-name check of a 113-byte exception is unbounded (x4 per two more groups, 255 bytes allowed)")
}

// MergeForwardBranchName is allowed under a required type for the targets merge forward steps into (the development
// or production branch, a versioned release branch) and nothing else under automerge/.
func TestNamingAllowsMergeForwardBranch(t *testing.T) {
	repo := &repo_model.Repository{DefaultBranch: "main"}
	e := EffectiveModel{Model: repo_model.BranchingModel{
		DevelopmentBranch: "develop", ProductionBranch: "prod", ReleasePrefixes: []string{"release/"},
		RequireBranchType: true, MergeForward: true,
	}}
	for _, target := range []string{"develop", "prod", "release/1.2", "release/10"} {
		assert.True(t, namingAllows(repo, e, MergeForwardBranchName(7, target)), target)
	}
	for _, name := range []string{
		"automerge/pr-7/feature/x", "automerge/pr-7/release/", "automerge/pr-7/release/x", "automerge/pr-x/develop", "automerge/pr-/develop",
		"automerge/pr-7/", "automerge/pr-7", "automerge/develop", "automerge/pr-7/develop/extra", "xautomerge/pr-7/develop", "Automerge/pr-7/develop",
	} {
		assert.False(t, namingAllows(repo, e, name), name)
	}
	e.Model.MergeForward = false
	assert.False(t, namingAllows(repo, e, MergeForwardBranchName(7, "develop")), "only while merge forward is on")
}

func TestBinaryOperand(t *testing.T) {
	defer test.MockVariableValue(&setting.Database.Type, setting.DatabaseType("mysql"))()
	assert.Equal(t, "BINARY name", binary("name"))
	defer test.MockVariableValue(&setting.Database.Type, setting.DatabaseType("sqlite3"))()
	assert.Equal(t, "name", binary("name"))
}
