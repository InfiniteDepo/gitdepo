// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package branchworkflow

import (
	"strings"
	"testing"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVersion(t *testing.T) {
	for in, want := range map[string][]uint64{
		"1":          {1},
		"1.9":        {1, 9},
		"v1.10":      {1, 10},
		"2.0.3":      {2, 0, 3},
		"01.2":       {1, 2},
		"next":       nil,
		"":           nil,
		"v":          nil,
		"1..2":       nil,
		"1.2-rc1":    nil,
		"1.2.":       nil,
		"-1":         nil,
		"1.x":        nil,
		"V1.2":       nil,
		"1234567890": nil, // more than 9 digits
	} {
		got, ok := parseVersion(in)
		assert.Equal(t, want != nil, ok, in)
		assert.Equal(t, want, got, in)
	}
}

func TestBuildChain(t *testing.T) {
	m := repo_model.BranchingModel{ReleasePrefixes: []string{"release/", "hotfix/", "release/v"}}
	branches := []string{"main", "develop", "release/2.0", "release/1.10", "release/1.9", "release/next", "hotfix/1.9", "release/v1.9.1", "feature/x", "hotfix/"}
	c := BuildChain(m, "develop", branches)
	assert.Equal(t, "develop", c.Development)
	assert.False(t, c.DevelopmentMissing)
	// release/v1.9.1 belongs to the longer prefix "release/v", and 1.9 of release/ comes before 1.9 of hotfix/
	assert.Equal(t, []string{"release/1.9", "hotfix/1.9", "release/v1.9.1", "release/1.10", "release/2.0"}, c.Releases)
	assert.Equal(t, []string{"hotfix/", "release/next"}, c.Ignored)

	assert.Equal(t, []string{"release/1.10", "release/2.0", "develop"}, c.Forward("release/v1.9.1"))
	assert.Equal(t, []string{"develop"}, c.Forward("release/2.0"))
	assert.Empty(t, c.Forward("develop"))
	assert.Empty(t, c.Forward("release/next"))

	// the development branch is never a release branch, even with a release prefix
	c = BuildChain(m, "release/2.0", branches)
	assert.NotContains(t, c.Releases, "release/2.0")
	assert.True(t, BuildChain(m, "trunk", branches).DevelopmentMissing)

	assert.Empty(t, BuildChain(repo_model.BranchingModel{}, "main", branches).Releases)

	// the production branch is merged into the development branch only
	c = BuildChain(repo_model.BranchingModel{ReleasePrefixes: []string{"release/"}, ProductionBranch: "main"}, "develop", branches)
	assert.Equal(t, []string{"develop"}, c.Forward("main"))
	assert.False(t, c.ProductionMissing)
	c = BuildChain(repo_model.BranchingModel{ProductionBranch: "prod"}, "develop", branches)
	assert.True(t, c.ProductionMissing)
	assert.Empty(t, c.Forward("prod"))
	assert.Empty(t, BuildChain(repo_model.BranchingModel{ProductionBranch: "develop"}, "develop", branches).Forward("develop"))
}

func TestNormalizeBranchingModel(t *testing.T) {
	m, err := NormalizeBranchingModel(&repo_model.BranchingModel{DevelopmentBranch: " develop ", ReleasePrefixes: []string{" release/", "", "release/", "hotfix-"}})
	require.NoError(t, err)
	assert.Equal(t, &repo_model.BranchingModel{DevelopmentBranch: "develop", ReleasePrefixes: []string{"release/", "hotfix-"}}, m)

	for _, bad := range []*repo_model.BranchingModel{
		{DevelopmentBranch: "bad..name"},
		{ReleasePrefixes: []string{"rel ease/"}},
		{ReleasePrefixes: []string{"a,b/"}},
		{ReleasePrefixes: []string{"/release"}},
		{DevelopmentBranch: strings.Repeat("d", 256)},
		{ProductionBranch: "bad..name"},
		{DevelopmentBranch: "main", ProductionBranch: "main"},
	} {
		_, err := NormalizeBranchingModel(bad)
		_, ok := IsInvalidBranchingModel(err)
		assert.True(t, ok, "%v", bad)
	}
	_, err = NormalizeBranchingModel(&repo_model.BranchingModel{ReleasePrefixes: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"}})
	require.ErrorIs(t, err, ErrTooManyReleasePrefixes)
}

func TestResolveModel(t *testing.T) {
	org := &repo_model.BranchingModel{ReleasePrefixes: []string{"release/"}}
	own := &repo_model.BranchingModel{ReleasePrefixes: []string{"rel-"}}

	e := ResolveModel(nil, false, nil)
	assert.Equal(t, SourceNone, e.Source)
	assert.Empty(t, e.Model.ReleasePrefixes)

	e = ResolveModel(org, false, nil)
	assert.Equal(t, SourceOrg, e.Source)
	assert.Equal(t, *org, e.Model)

	e = ResolveModel(org, false, own)
	assert.Equal(t, SourceRepo, e.Source)
	assert.Equal(t, *own, e.Model)

	e = ResolveModel(org, true, own)
	assert.Equal(t, SourceOrg, e.Source)
	assert.True(t, e.Locked)
	assert.Equal(t, *org, e.Model)
	assert.Equal(t, own, e.Configured)
}

func TestSetOrgAndRepoModel(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	orgModel := &repo_model.BranchingModel{DevelopmentBranch: "develop", ReleasePrefixes: []string{"release/"}}

	require.ErrorIs(t, SetOrgModel(t.Context(), org, nil, true), ErrLockWithoutValue)
	require.ErrorIs(t, SetOrgModel(t.Context(), org, &repo_model.BranchingModel{DevelopmentBranch: "develop"}, true), ErrLockWithoutValue)

	require.NoError(t, SetOrgModel(t.Context(), org, orgModel, false))
	eff, err := GetEffectiveModel(t.Context(), repo)
	require.NoError(t, err)
	assert.Equal(t, SourceOrg, eff.Source)
	assert.Equal(t, org.Name, eff.SetBy)
	assert.Equal(t, "develop", eff.DevelopmentBranch(repo))

	own := &repo_model.BranchingModel{ReleasePrefixes: []string{"rel-"}}
	require.NoError(t, SetRepoModel(t.Context(), repo, own))
	repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	eff, err = GetEffectiveModel(t.Context(), repo)
	require.NoError(t, err)
	assert.Equal(t, SourceRepo, eff.Source)
	assert.Equal(t, own, eff.Configured)
	assert.Equal(t, repo.DefaultBranch, eff.DevelopmentBranch(repo))

	require.NoError(t, SetOrgModel(t.Context(), org, orgModel, true))
	eff, err = GetEffectiveModel(t.Context(), repo)
	require.NoError(t, err)
	assert.True(t, eff.Locked)
	assert.Equal(t, *orgModel, eff.Model)
	require.ErrorIs(t, SetRepoModel(t.Context(), repo, nil), ErrLocked)

	// unlocking brings the repository's own model back; removing the org's leaves it as it is
	require.NoError(t, SetOrgModel(t.Context(), org, nil, false))
	eff, err = GetEffectiveModel(t.Context(), repo)
	require.NoError(t, err)
	assert.Equal(t, SourceRepo, eff.Source)

	require.NoError(t, SetRepoModel(t.Context(), repo, nil))
	repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	eff, err = GetEffectiveModel(t.Context(), repo)
	require.NoError(t, err)
	assert.Equal(t, SourceNone, eff.Source)
	assert.Nil(t, eff.Configured)
}
