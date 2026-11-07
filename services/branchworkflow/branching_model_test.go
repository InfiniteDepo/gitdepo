// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package branchworkflow

import (
	"fmt"
	"strings"
	"testing"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
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

func TestNormalizeBranchTypes(t *testing.T) {
	feature := repo_model.BranchType{Name: " Feature ", Prefix: " feature/ ", Base: repo_model.BranchTypeBaseDevelopment, BaseBranch: "ignored"}
	m, err := NormalizeBranchingModel(&repo_model.BranchingModel{
		DefaultPRTarget: " staging ",
		Types: []repo_model.BranchType{
			feature,
			{Name: "Chore", Prefix: "chore/", Base: repo_model.BranchTypeBaseBranch, BaseBranch: " next ", Off: true},
			{Name: "Hotfix", Prefix: "hotfix/", Base: repo_model.BranchTypeBaseProduction},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "staging", m.DefaultPRTarget)
	assert.Equal(t, []repo_model.BranchType{
		{Name: "Feature", Prefix: "feature/", Base: repo_model.BranchTypeBaseDevelopment},
		{Name: "Chore", Prefix: "chore/", Base: repo_model.BranchTypeBaseBranch, BaseBranch: "next", Off: true},
		{Name: "Hotfix", Prefix: "hotfix/", Base: repo_model.BranchTypeBaseProduction},
	}, m.Types)

	ok := repo_model.BranchType{Name: "A", Prefix: "a/", Base: repo_model.BranchTypeBaseDevelopment}
	with := func(f func(*repo_model.BranchType)) *repo_model.BranchingModel {
		t := ok
		f(&t)
		return &repo_model.BranchingModel{Types: []repo_model.BranchType{t}}
	}
	for name, bad := range map[string]*repo_model.BranchingModel{
		"empty name":         with(func(b *repo_model.BranchType) { b.Name = " " }),
		"long name":          with(func(b *repo_model.BranchType) { b.Name = strings.Repeat("n", 51) }),
		"control in name":    with(func(b *repo_model.BranchType) { b.Name = "a\nb" }),
		"invalid utf-8":      with(func(b *repo_model.BranchType) { b.Name = "a\xffb" }),
		"empty prefix":       with(func(b *repo_model.BranchType) { b.Prefix = "" }),
		"long prefix":        with(func(b *repo_model.BranchType) { b.Prefix = strings.Repeat("p", 101) }),
		"comma in prefix":    with(func(b *repo_model.BranchType) { b.Prefix = "a,b/" }),
		"invalid prefix":     with(func(b *repo_model.BranchType) { b.Prefix = "a b/" }),
		"merge queue":        with(func(b *repo_model.BranchType) { b.Prefix = "merge-queue/" }),
		"inside the queue":   with(func(b *repo_model.BranchType) { b.Prefix = "merge-queue/x/" }),
		"start of the queue": with(func(b *repo_model.BranchType) { b.Prefix = "merge" }),
		"unknown base":       with(func(b *repo_model.BranchType) { b.Base = "tag" }),
		"empty base":         with(func(b *repo_model.BranchType) { b.Base = "" }),
		"named base empty":   with(func(b *repo_model.BranchType) { b.Base = repo_model.BranchTypeBaseBranch }),
		"named base bad":     with(func(b *repo_model.BranchType) { b.Base, b.BaseBranch = repo_model.BranchTypeBaseBranch, "bad..name" }),
		"named base queue": with(func(b *repo_model.BranchType) {
			b.Base, b.BaseBranch = repo_model.BranchTypeBaseBranch, "merge-queue/1/2"
		}),
		"named base long": with(func(b *repo_model.BranchType) {
			b.Base, b.BaseBranch = repo_model.BranchTypeBaseBranch, strings.Repeat("b", 256)
		}),
		"target queue":                     {DefaultPRTarget: "merge-queue/x"},
		"target bad":                       {DefaultPRTarget: "bad..name"},
		"prefix is the development branch": {DevelopmentBranch: "a/", Types: []repo_model.BranchType{ok}},
		"duplicate":                        {Types: []repo_model.BranchType{ok, ok}},
		"release prefix":                   {ReleasePrefixes: []string{"a/"}, Types: []repo_model.BranchType{ok}},
	} {
		_, err := NormalizeBranchingModel(bad)
		_, isInvalid := IsInvalidBranchingModel(err)
		assert.True(t, isInvalid, name)
	}

	var many []repo_model.BranchType
	for i := range 21 {
		many = append(many, repo_model.BranchType{Name: fmt.Sprintf("T%d", i), Prefix: fmt.Sprintf("t%d/", i), Base: repo_model.BranchTypeBaseDevelopment})
	}
	_, err = NormalizeBranchingModel(&repo_model.BranchingModel{Types: many[:20]})
	require.NoError(t, err)
	_, err = NormalizeBranchingModel(&repo_model.BranchingModel{Types: many})
	require.ErrorIs(t, err, ErrTooManyBranchTypes)
}

func TestMatchType(t *testing.T) {
	m := repo_model.BranchingModel{
		ReleasePrefixes: []string{"release/"},
		Types: []repo_model.BranchType{
			{Name: "Feature", Prefix: "feature/", Base: repo_model.BranchTypeBaseDevelopment},
			{Name: "Big feature", Prefix: "feature/big/", Base: repo_model.BranchTypeBaseBranch, BaseBranch: "big"},
			{Name: "Chore", Prefix: "chore/", Base: repo_model.BranchTypeBaseDevelopment, Off: true},
		},
	}
	for branch, want := range map[string]string{
		"feature/x":     "Feature",
		"feature/big/x": "Big feature", // the longest prefix wins
		"release/1.0":   "Release",
		"chore/x":       "", // turned off
		"feature/":      "", // nothing after the prefix
		"feature":       "",
		"other":         "",
	} {
		got, ok := MatchType(m, branch)
		assert.Equal(t, want != "", ok, branch)
		assert.Equal(t, want, got.Name, branch)
	}
	got, _ := MatchType(m, "release/1.0")
	assert.Equal(t, repo_model.BranchTypeBaseDevelopment, got.Base)
}

func TestResolveTarget(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE branch SET is_deleted = ? WHERE repo_id = 1", false) // the fixture's foo and bar are deleted
	require.NoError(t, err)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}) // branches master (default), foo, bar, branch2
	model := repo_model.BranchingModel{
		DevelopmentBranch: "foo",
		ProductionBranch:  "bar",
		DefaultPRTarget:   "branch2",
		Types: []repo_model.BranchType{
			{Name: "Feature", Prefix: "feature/", Base: repo_model.BranchTypeBaseDevelopment},
			{Name: "Hotfix", Prefix: "hotfix/", Base: repo_model.BranchTypeBaseProduction},
			{Name: "Chore", Prefix: "chore/", Base: repo_model.BranchTypeBaseBranch, BaseBranch: "branch2"},
			{Name: "Gone", Prefix: "gone/", Base: repo_model.BranchTypeBaseBranch, BaseBranch: "does-not-exist"},
		},
	}
	target := func(head string) Target {
		repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		got, err := ResolveTarget(t.Context(), repo, head)
		require.NoError(t, err)
		return got
	}

	// no model: the default branch
	assert.Equal(t, Target{Branch: "master", Rule: TargetRuleDefault}, target("feature/x"))

	require.NoError(t, SetRepoModel(t.Context(), repo, &model))
	assert.Equal(t, Target{Branch: "foo", Rule: TargetRuleType, TypeName: "Feature"}, target("feature/x"))
	assert.Equal(t, Target{Branch: "bar", Rule: TargetRuleType, TypeName: "Hotfix"}, target("hotfix/1"))
	assert.Equal(t, Target{Branch: "branch2", Rule: TargetRuleType, TypeName: "Chore"}, target("chore/x"))
	// untyped: the default target
	assert.Equal(t, Target{Branch: "branch2", Rule: TargetRuleTarget}, target("something"))
	// a named branch that doesn't exist falls back to the development branch
	assert.Equal(t, Target{Branch: "foo", Rule: TargetRuleFallback, TypeName: "Gone", Missing: "does-not-exist"}, target("gone/x"))

	// a missing development branch falls back to the default branch; so does a type whose base is not set
	model.DevelopmentBranch, model.ProductionBranch, model.DefaultPRTarget = "no-dev", "", "no-target"
	require.NoError(t, SetRepoModel(t.Context(), repo, &model))
	assert.Equal(t, Target{Branch: "master", Rule: TargetRuleFallback, TypeName: "Feature", Missing: "no-dev"}, target("feature/x"))
	assert.Equal(t, Target{Branch: "master", Rule: TargetRuleFallback, TypeName: "Hotfix"}, target("hotfix/1"))
	assert.Equal(t, Target{Branch: "master", Rule: TargetRuleFallback, Missing: "no-target"}, target("something"))

	// the target is the default branch itself
	model.DefaultPRTarget = "master"
	require.NoError(t, SetRepoModel(t.Context(), repo, &model))
	assert.Equal(t, Target{Branch: "master", Rule: TargetRuleTarget}, target("something"))

	missing, err := MissingBases(t.Context(), repo, model)
	require.NoError(t, err)
	assert.Equal(t, []string{"does-not-exist"}, missing)
}

func TestCountUntyped(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE branch SET is_deleted = ? WHERE repo_id = 1", false) // the fixture's foo and bar are deleted
	require.NoError(t, err)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}) // branches master, foo, bar, branch2
	m := repo_model.BranchingModel{Types: []repo_model.BranchType{
		{Name: "Foo", Prefix: "fo", Base: repo_model.BranchTypeBaseDevelopment, Off: true},
		{Name: "Bar", Prefix: "bar", Base: repo_model.BranchTypeBaseDevelopment}, // on: not counted
		{Name: "Branch", Prefix: "branch", Base: repo_model.BranchTypeBaseDevelopment, Off: true},
	}}
	counts, err := CountUntyped(t.Context(), repo, m)
	require.NoError(t, err)
	// "foo" starts with the off prefix "fo" and has something after it; "branch2" too; "bar" is not an off type's
	assert.Equal(t, map[string]int{"fo": 1, "branch": 1}, counts)

	counts, err = CountUntyped(t.Context(), repo, repo_model.BranchingModel{})
	require.NoError(t, err)
	assert.Empty(t, counts)
}

func TestKeptReason(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}) // open PR test_branch -> master
	ctx := t.Context()
	reason := func(name string, openPRs bool) string {
		got, err := KeptReason(ctx, repo, name, openPRs)
		require.NoError(t, err)
		return got
	}
	assert.Equal(t, KeptDefault, reason("master", true))
	assert.Empty(t, reason("feature/x", true))

	require.NoError(t, SetRepoModel(ctx, repo, &repo_model.BranchingModel{DevelopmentBranch: "develop", ProductionBranch: "production", ReleasePrefixes: []string{"release/", "rel-"}}))
	repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	assert.Equal(t, KeptDevelopment, reason("develop", true))
	assert.Equal(t, KeptProduction, reason("production", true))
	assert.Equal(t, KeptRelease, reason("release/1.0", true))
	assert.Equal(t, KeptRelease, reason("rel-next", true), "a branch without a version is kept too")
	assert.Equal(t, KeptMergeQueue, reason("merge-queue/master/5", true))
	assert.Empty(t, reason("feature/x", true))

	// the head of an open pull request is kept, unless the caller does its own check
	assert.Equal(t, KeptOpenPR, reason("test_branch", true))
	assert.Empty(t, reason("test_branch", false))

	// a protection rule
	require.NoError(t, db.Insert(ctx, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "keep/*"}))
	assert.Equal(t, KeptProtected, reason("keep/this", true))

	// the model is the one of the repository that owns the branch: another repository without it keeps nothing
	other := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	got, err := KeptReason(ctx, other, "release/1.0", true)
	require.NoError(t, err)
	assert.Empty(t, got)
}
