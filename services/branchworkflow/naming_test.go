// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package branchworkflow

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/translation"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssueSlug(t *testing.T) {
	for _, c := range []struct {
		index int64
		title string
		want  string
	}{
		{43, "Login fails with SSO", "43-login-fails-with-sso"},
		{7, "  Fix: the  /api/v1 route!! ", "7-fix-the-api-v1-route"},
		{5, "", "issue-5"},
		{5, "日本語のタイトル", "issue-5"},
		{5, "Überprüfung der Größe", "5-berpr-fung-der-gr-e"},
		{5, "Kelvin", "5-elvin"}, // the Kelvin sign is not an ASCII k
		{12, "---", "issue-12"},
		{3, strings.Repeat("a", 80), "issue-3"}, // no dash to cut at
		{3, strings.Repeat("word ", 20), "3-word-word-word-word-word-word-word-word-word"},
		{3, strings.Repeat("a", 47) + " b", "3-" + strings.Repeat("a", 47)},
		{3, strings.Repeat("a", 44) + " bcd", "3-" + strings.Repeat("a", 44) + "-bcd"},
		{3, "a ../b", "3-a-b"},
	} {
		got := IssueSlug(c.index, c.title)
		assert.Equal(t, c.want, got, c.title)
		assert.LessOrEqual(t, len(got), maxSlugName)
	}
}

func TestNormalizeNaming(t *testing.T) {
	typed := []repo_model.BranchType{{Name: "Feature", Prefix: "feature/", Base: repo_model.BranchTypeBaseDevelopment}}
	in := func(mod func(*repo_model.BranchingModel)) error {
		m := &repo_model.BranchingModel{Types: typed}
		mod(m)
		_, err := NormalizeBranchingModel(m)
		return err
	}
	reason := func(err error) string {
		e, ok := IsInvalidBranchingModel(err)
		require.True(t, ok, "%v", err)
		return e.Reason
	}

	require.NoError(t, in(func(m *repo_model.BranchingModel) {
		m.RequireBranchType, m.BranchExceptions, m.ExemptUserIDs = true, []string{" renovate/** ", "renovate/**", "", "gh-pages"}, []int64{2, 2, -5, 0}
	}))
	m, err := NormalizeBranchingModel(&repo_model.BranchingModel{Types: typed, RequireBranchType: true, BranchExceptions: []string{" renovate/** ", "renovate/**", "", "gh-pages"}, ExemptUserIDs: []int64{2, 2, -5, 0}, ExemptTeamIDs: []int64{7, 7}})
	require.NoError(t, err)
	assert.Equal(t, []string{"renovate/**", "gh-pages"}, m.BranchExceptions)
	assert.Equal(t, []int64{2}, m.ExemptUserIDs, "a token identity or zero is never listed")
	assert.Equal(t, []int64{7}, m.ExemptTeamIDs)

	assert.Equal(t, ReasonException, reason(in(func(m *repo_model.BranchingModel) { m.BranchExceptions = []string{"[unclosed"} })))
	assert.Equal(t, ReasonException, reason(in(func(m *repo_model.BranchingModel) { m.BranchExceptions = []string{"a\nb"} })))
	assert.Equal(t, ReasonException, reason(in(func(m *repo_model.BranchingModel) { m.BranchExceptions = []string{strings.Repeat("a", 256)} })))
	assert.Equal(t, ReasonTooManyNaming, reason(in(func(m *repo_model.BranchingModel) {
		for i := range 21 {
			m.BranchExceptions = append(m.BranchExceptions, "x"+string(rune('a'+i))+"/*")
		}
	})))
	assert.Equal(t, ReasonTooManyNaming, reason(in(func(m *repo_model.BranchingModel) {
		for i := range 101 {
			m.ExemptUserIDs = append(m.ExemptUserIDs, int64(i+1))
		}
	})))
	assert.Equal(t, ReasonTooManyNaming, reason(in(func(m *repo_model.BranchingModel) {
		for i := range 21 {
			m.ExemptTeamIDs = append(m.ExemptTeamIDs, int64(i+1))
		}
	})))

	// requiring a type with nothing that can match is refused; an exception or a release prefix is enough
	off := []repo_model.BranchType{{Name: "Feature", Prefix: "feature/", Base: repo_model.BranchTypeBaseDevelopment, Off: true}}
	for _, m := range []*repo_model.BranchingModel{{RequireBranchType: true}, {RequireBranchType: true, Types: off}} {
		_, err := NormalizeBranchingModel(m)
		assert.Equal(t, ReasonNoUsableType, reason(err))
	}
	_, err = NormalizeBranchingModel(&repo_model.BranchingModel{RequireBranchType: true, Types: off, BranchExceptions: []string{"x/*"}})
	require.NoError(t, err)
	_, err = NormalizeBranchingModel(&repo_model.BranchingModel{RequireBranchType: true, Types: off, ReleasePrefixes: []string{"release/"}})
	require.NoError(t, err)
	_, err = NormalizeBranchingModel(&repo_model.BranchingModel{Types: off}) // not required: nothing to refuse
	require.NoError(t, err)

	// a model that only requires a type with exceptions is not "empty" (SetOrgModel would drop an empty one)
	assert.False(t, isEmpty(&repo_model.BranchingModel{RequireBranchType: true, BranchExceptions: []string{"x/*"}}))
	assert.True(t, isEmpty(&repo_model.BranchingModel{}))
}

func TestApplyNaming(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	apply := func(owner *user_model.User, n api.BranchNaming) (*repo_model.BranchingModel, error) {
		m := &repo_model.BranchingModel{}
		return m, ApplyNaming(t.Context(), owner, m, n)
	}

	m, err := apply(org, api.BranchNaming{RequireBranchType: true, Exceptions: []string{"x/*"}, ExemptUsers: []string{"user2", " ", "USER4"}, ExemptTeams: []string{"Test_Team"}})
	require.NoError(t, err)
	assert.Equal(t, []int64{2, 4}, m.ExemptUserIDs)
	assert.Equal(t, []int64{7}, m.ExemptTeamIDs)

	for _, c := range []struct {
		owner  *user_model.User
		naming api.BranchNaming
		reason string
	}{
		{org, api.BranchNaming{ExemptUsers: []string{"nobody"}}, ReasonExemptUser},
		{org, api.BranchNaming{ExemptUsers: []string{org.Name}}, ReasonExemptUser}, // an organization is no user
		{org, api.BranchNaming{ExemptTeams: []string{"nope"}}, ReasonExemptTeam},
		{user2, api.BranchNaming{ExemptTeams: []string{"team1"}}, ReasonExemptNeedsTeam},
		{org, api.BranchNaming{ExemptUsers: make([]string, 101)}, ReasonTooManyNaming},
	} {
		_, err := apply(c.owner, c.naming)
		e, ok := IsInvalidBranchingModel(err)
		require.True(t, ok, "%v", err)
		assert.Equal(t, c.reason, e.Reason)
	}

	// and back to names
	got, err := NamingToAPI(t.Context(), m)
	require.NoError(t, err)
	assert.Equal(t, api.BranchNaming{RequireBranchType: true, Exceptions: []string{"x/*"}, ExemptUsers: []string{"user2", "user4"}, ExemptTeams: []string{"test_team"}}, got)
	empty, err := NamingToAPI(t.Context(), nil)
	require.NoError(t, err)
	assert.Equal(t, api.BranchNaming{Exceptions: []string{}, ExemptUsers: []string{}, ExemptTeams: []string{}}, empty)
}

func TestCheckNewBranch(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}) // owned by organization 3
	check := func(userID int64, deployKey bool, name string) (bool, error) {
		return CheckNewBranch(ctx, repo, userID, deployKey, name)
	}

	// without a model, or without the requirement, every name is allowed
	exempt, err := check(2, false, "anything")
	require.NoError(t, err)
	assert.False(t, exempt)

	require.NoError(t, SetRepoModel(ctx, repo, &repo_model.BranchingModel{
		DevelopmentBranch: "develop", ProductionBranch: "main", ReleasePrefixes: []string{"release/"}, DefaultPRTarget: "staging",
		Types: []repo_model.BranchType{
			{Name: "Feature", Prefix: "feature/", Base: repo_model.BranchTypeBaseDevelopment},
			{Name: "Chore", Prefix: "chore/", Base: repo_model.BranchTypeBaseBranch, BaseBranch: "chores", Off: true},
			{Name: "Fix", Prefix: "fix/", Base: repo_model.BranchTypeBaseBranch, BaseBranch: "stable"},
		},
		BranchExceptions: []string{"renovate/**", "gh-pages"},
		ExemptUserIDs:    []int64{4}, ExemptTeamIDs: []int64{7},
	}))
	repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	exempt, err = check(2, false, "anything")
	require.NoError(t, err, "not required yet")
	assert.False(t, exempt)

	m := &repo_model.BranchingModel{
		DevelopmentBranch: "develop", ProductionBranch: "main", ReleasePrefixes: []string{"release/"}, DefaultPRTarget: "staging",
		Types: []repo_model.BranchType{
			{Name: "Feature", Prefix: "feature/", Base: repo_model.BranchTypeBaseDevelopment},
			{Name: "Chore", Prefix: "chore/", Base: repo_model.BranchTypeBaseBranch, BaseBranch: "chores", Off: true},
			{Name: "Fix", Prefix: "fix/", Base: repo_model.BranchTypeBaseBranch, BaseBranch: "stable"},
		},
		RequireBranchType: true, BranchExceptions: []string{"renovate/**", "gh-pages"}, ExemptUserIDs: []int64{4}, ExemptTeamIDs: []int64{7},
	}
	require.NoError(t, SetRepoModel(ctx, repo, m))
	repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})

	for _, name := range []string{
		"feature/x", "feature/a/b", "release/1.0", "release/x", "fix/y", // prefixes
		"develop", "main", "master", "staging", "stable", // the model's branches and the default branch
		"renovate/npm/foo", "renovate/x", "gh-pages", // exceptions
	} {
		exempt, err := check(2, false, name)
		require.NoError(t, err, name)
		assert.False(t, exempt, name)
	}
	for _, name := range []string{
		"spike/x", "feature/", "feature", "release/", "chore/x" /* turned off */, "chores", "Feature/x" /* case */, "renovate", "RENOVATE/x", "gh-pages/x", "x",
	} {
		_, err := check(2, false, name)
		refused, ok := errors.AsType[ErrBranchTypeRequired](err)
		require.True(t, ok, "%s: %v", name, err)
		assert.Equal(t, name, refused.Name)
		assert.Equal(t, []string{"release/", "feature/", "fix/"}, refused.Prefixes, "enabled types only")
		assert.Empty(t, refused.SetBy)
	}

	// an exempt user, and a member of an exempt team, may; the exemption is told to the caller so it is recorded
	for _, uid := range []int64{4, 15} {
		exempt, err := check(uid, false, "spike/x")
		require.NoError(t, err, uid)
		assert.True(t, exempt, uid)
	}
	exempt, err = check(4, false, "feature/x")
	require.NoError(t, err)
	assert.False(t, exempt, "an allowed name needs no exemption, so none is recorded")

	// no implicit exemption: a deploy key (also of an exempt owner), the Actions user, a token identity, an admin, a stranger
	for _, c := range []struct {
		uid       int64
		deployKey bool
	}{{4, true}, {15, true}, {user_model.ActionsUserID, false}, {-(1 << 32) - 1, false}, {1, false}, {5, false}, {0, false}} {
		_, err := check(c.uid, c.deployKey, "spike/x")
		require.Error(t, err, "%+v", c)
	}

	// a member of the team of another organization is no member of this one's
	_, err = db.GetEngine(ctx).Exec("UPDATE team_user SET org_id = 17 WHERE team_id = 7")
	require.NoError(t, err)
	_, err = check(15, false, "spike/x")
	require.Error(t, err)
}

func TestBranchTypeRequiredText(t *testing.T) {
	translation.InitLocales(t.Context())
	l := translation.NewLocale("en-US")
	e := ErrBranchTypeRequired{Name: "spike/x", Prefixes: []string{"feature/", "release/"}}
	assert.Equal(t, "Branch spike/x is refused: new branches in this repository must start with feature/, release/.", e.Text(l))
	e.Exceptions = []string{"a/*", "b/*", "c/*", "d/*", "e/*", "f/*", "g/*"}
	e.SetBy = "acme"
	text := e.Text(l)
	assert.Contains(t, text, "or match a/*, b/*, c/*, d/*, e/* and 2 more")
	assert.NotContains(t, text, "f/*", "at most five exceptions are listed")
	assert.Contains(t, text, "organization acme")
	assert.Contains(t, ErrBranchTypeRequired{Name: "x"}.Text(l), "none is enabled")
}

func TestDialogChoices(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	c, err := DialogChoices(ctx, repo, user4)
	require.NoError(t, err)
	assert.Empty(t, c.Types)
	assert.False(t, c.Required)

	require.NoError(t, SetRepoModel(ctx, repo, &repo_model.BranchingModel{
		DevelopmentBranch: "master", ProductionBranch: "prod", ReleasePrefixes: []string{"release/", "support/"},
		Types: []repo_model.BranchType{
			{Name: "Feature", Prefix: "feature/", Base: repo_model.BranchTypeBaseDevelopment},
			{Name: "Hotfix", Prefix: "hotfix/", Base: repo_model.BranchTypeBaseProduction},
			{Name: "Chore", Prefix: "chore/", Base: repo_model.BranchTypeBaseDevelopment, Off: true},
			{Name: "Doc", Prefix: "doc/", Base: repo_model.BranchTypeBaseBranch, BaseBranch: "branch2"},
		},
		RequireBranchType: true, ExemptUserIDs: []int64{4},
	}))
	repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	c, err = DialogChoices(ctx, repo, user4)
	require.NoError(t, err)
	assert.True(t, c.Exempt)
	assert.False(t, c.Required, "an exempt user may choose Other")
	c, err = DialogChoices(ctx, repo, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5}))
	require.NoError(t, err)
	assert.True(t, c.Required)
	assert.Equal(t, "master", c.Development)
	// Release (first prefix), then the enabled types; a base that doesn't exist (the production branch "prod", not created here) falls back
	want := []TypeChoice{
		{Name: "Release", Prefix: "release/", Base: "master"},
		{Name: "Feature", Prefix: "feature/", Base: "master"},
		{Name: "Hotfix", Prefix: "hotfix/", Base: "master", Missing: "prod"},
		{Name: "Doc", Prefix: "doc/", Base: "master", Missing: "branch2"},
	}
	assert.Equal(t, want, c.Types)
}

func TestSuggestIssueBranch(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	choices := func(m *repo_model.BranchingModel) CreateChoices {
		require.NoError(t, SetRepoModel(ctx, repo, m))
		repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
		c, err := DialogChoices(ctx, repo, doer)
		require.NoError(t, err)
		return c
	}
	suggest := func(c CreateChoices, title string, labels ...string) (IssueSuggestion, bool) {
		s, ok, err := SuggestIssueBranch(ctx, repo, doer, c, 43, title, labels)
		require.NoError(t, err)
		return s, ok
	}
	types := []repo_model.BranchType{
		{Name: "Feature", Prefix: "feature/", Base: repo_model.BranchTypeBaseDevelopment},
		{Name: "Bugfix", Prefix: "bugfix/", Base: repo_model.BranchTypeBaseDevelopment},
	}

	// no model: no type, "<n>-<slug>"
	s, ok := suggest(choices(nil), "Login fails with SSO", "bug")
	assert.True(t, ok)
	assert.Equal(t, IssueSuggestion{Name: "43-login-fails-with-sso"}, s)

	c := choices(&repo_model.BranchingModel{ReleasePrefixes: []string{"release/"}, Types: types})
	s, _ = suggest(c, "Login fails with SSO", "enhancement", "area/bug")
	assert.Equal(t, IssueSuggestion{Type: "Bugfix", Name: "43-login-fails-with-sso"}, s, "a label ending in /bug")
	s, _ = suggest(c, "Login fails with SSO", "Bug")
	assert.Equal(t, "Bugfix", s.Type, "case-insensitive")
	s, _ = suggest(c, "Login fails with SSO", "debug", "bugs")
	assert.Equal(t, "Feature", s.Type, "the first enabled type, never Release")
	s, _ = suggest(c, "日本語", "bug")
	assert.Equal(t, IssueSuggestion{Type: "Bugfix", Name: "issue-43"}, s)

	// Bugfix turned off: a bug gets the first enabled type
	off := slices.Clone(types)
	off[1].Off = true
	s, _ = suggest(choices(&repo_model.BranchingModel{Types: off}), "x", "bug")
	assert.Equal(t, "Feature", s.Type)

	// the suggested name must pass the model: with only Release enabled nothing typed can be suggested, and no type is needed to be refused
	c = choices(&repo_model.BranchingModel{ReleasePrefixes: []string{"release/"}, RequireBranchType: true})
	_, ok = suggest(c, "Anything")
	assert.False(t, ok, "an untyped name is refused by the model")
}

func TestTypeFilter(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	for _, n := range []string{"feature/a", "feature/", "feature/ui/b", "bugfix/c", "release/1", "other", "feature_x", "100%/x", "feature"} {
		require.NoError(t, db.Insert(ctx, &git_model.Branch{RepoID: 3, Name: n, CommitID: "x"}))
	}
	m := repo_model.BranchingModel{
		ReleasePrefixes: []string{"release/"},
		Types: []repo_model.BranchType{
			{Name: "Feature", Prefix: "feature/"},
			{Name: "Ui", Prefix: "feature/ui/"},
			{Name: "Bugfix", Prefix: "bugfix/"},
			{Name: "Off", Prefix: "other", Off: true},
		},
	}
	names := func(typeName string, untyped bool) []string {
		cond := TypeFilter(m, typeName, untyped)
		require.NotNil(t, cond)
		var out []string
		require.NoError(t, db.GetEngine(ctx).Table("branch").Where("repo_id = 3").And(cond).Cols("name").OrderBy("name").Find(&out))
		return out
	}
	assert.Equal(t, []string{"feature/a"}, names("feature", false), "the longer prefix takes feature/ui/b; a bare prefix is untyped")
	assert.Equal(t, []string{"feature/ui/b"}, names("UI", false))
	assert.Equal(t, []string{"release/1"}, names(ReleaseTypeName, false))
	assert.Empty(t, names("Off", false), "a turned-off type matches nothing")
	assert.Empty(t, names("Nope", false))
	assert.Nil(t, TypeFilter(m, "", false))
	assert.Equal(t, []string{"100%/x", "feature", "feature/", "feature_x", "other"}, names("", true))
}
