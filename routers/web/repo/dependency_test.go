// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"fmt"
	"testing"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/services/contexttest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The "no lock file" hint groups the manifests by ecosystem and by the lock file above them that doesn't list
// them, and names at most maxHintPaths of them.
func TestUnpinnedManifests(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx, _ := contexttest.MockContext(t, "/user2/repo1/activity/dependencies")
	manifests := []repo_model.DependencyFacet{{Value: "package-lock.json"}, {Value: "Gemfile.lock"}}
	for i := range 12 {
		manifests = append(manifests, repo_model.DependencyFacet{Value: fmt.Sprintf("templates/t%02d/package.json", i)})
	}
	manifests = append(manifests, repo_model.DependencyFacet{Value: "ruby/Gemfile"}, repo_model.DependencyFacet{Value: "py/pyproject.toml"})
	groups := unpinnedManifests(ctx, manifests)
	require.Len(t, groups, 3)
	assert.Equal(t, "package-lock.json", groups[0].Outside, "not among the projects of the lock above them")
	assert.Len(t, groups[0].Paths, maxHintPaths)
	assert.Equal(t, 12, groups[0].Count)
	assert.Equal(t, 2, groups[0].More)
	assert.Empty(t, groups[1].Outside, "a Gemfile.lock covers only the Gemfile next to it")
	assert.Equal(t, []string{"ruby/Gemfile"}, groups[1].Paths)
	assert.True(t, groups[2].PyPI)
}
