// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"context"
	"strings"
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionsConfig(t *testing.T) {
	cfg := &ActionsConfig{}
	cfg.DisableWorkflow("test1.yaml")
	assert.Equal(t, []string{"test1.yaml"}, cfg.DisabledWorkflows)

	cfg.DisableWorkflow("test1.yaml")
	assert.Equal(t, []string{"test1.yaml"}, cfg.DisabledWorkflows)

	cfg.EnableWorkflow("test1.yaml")
	assert.Equal(t, []string{}, cfg.DisabledWorkflows)

	cfg.EnableWorkflow("test1.yaml")
	assert.Equal(t, []string{}, cfg.DisabledWorkflows)

	cfg.DisableWorkflow("test1.yaml")
	cfg.DisableWorkflow("test2.yaml")
	cfg.DisableWorkflow("test3.yaml")
	assert.Equal(t, "test1.yaml,test2.yaml,test3.yaml", cfg.ToString())
}

func TestActionsConfigDefaultTokenPermissions(t *testing.T) {
	cfg := &ActionsConfig{}
	require.NoError(t, cfg.FromDB([]byte(`{"DisabledWorkflows":["a.yaml"]}`)))
	assert.Empty(t, cfg.DefaultTokenPermissions)

	cfg.DefaultTokenPermissions = "read"
	bs, err := cfg.ToDB()
	require.NoError(t, err)
	stored := &ActionsConfig{}
	require.NoError(t, stored.FromDB(bs))
	assert.Equal(t, "read", stored.DefaultTokenPermissions)

	for _, tc := range []struct{ repo, instance, want string }{
		{repo: "", instance: "write", want: "write"},
		{repo: "", instance: "read", want: "read"},
		{repo: "read", instance: "write", want: "read"},
		{repo: "write", instance: "read", want: "write"},
		{repo: "banana", instance: "read", want: "read"},
	} {
		defer test.MockVariableValue(&setting.Actions.DefaultTokenPermissions, tc.instance)()
		cfg := &ActionsConfig{DefaultTokenPermissions: tc.repo}
		assert.Equal(t, tc.want, cfg.EffectiveDefaultTokenPermissions(), "repo %q, instance %q", tc.repo, tc.instance)
	}
}

func TestRepoUnitAccessMode(t *testing.T) {
	// assert.Equal(t, perm.AccessModeNone, UnitAccessModeNone.ToAccessMode(perm.AccessModeAdmin))
	// assert.Equal(t, perm.AccessModeRead, UnitAccessModeRead.ToAccessMode(perm.AccessModeAdmin))
	assert.Equal(t, perm.AccessModeWrite, UnitAccessModeWrite.ToAccessMode(perm.AccessModeAdmin))
	assert.Equal(t, perm.AccessModeRead, UnitAccessModeUnset.ToAccessMode(perm.AccessModeRead))
}

func TestRepoPRIsUpdateStyleAllowed(t *testing.T) {
	var cfg PullRequestsConfig
	cfg = PullRequestsConfig{
		AllowRebaseUpdate: true,
	}
	assert.True(t, cfg.IsUpdateStyleAllowed(UpdateStyleMerge))
	assert.True(t, cfg.IsUpdateStyleAllowed(UpdateStyleRebase))

	cfg = PullRequestsConfig{
		AllowRebaseUpdate: false,
	}
	assert.True(t, cfg.IsUpdateStyleAllowed(UpdateStyleMerge))
	assert.False(t, cfg.IsUpdateStyleAllowed(UpdateStyleRebase))
}

func TestRepoPRGetDefaultUpdateStyle(t *testing.T) {
	defer test.MockVariableValue(&setting.Repository.PullRequest.DefaultUpdateStyle, "merge")()

	var cfg PullRequestsConfig
	cfg = PullRequestsConfig{
		DefaultUpdateStyle: "",
	}
	assert.Equal(t, UpdateStyleMerge, cfg.GetDefaultUpdateStyle())
	cfg = PullRequestsConfig{
		DefaultUpdateStyle: "rebase",
	}
	assert.Equal(t, UpdateStyleRebase, cfg.GetDefaultUpdateStyle())
	cfg = PullRequestsConfig{
		DefaultUpdateStyle: "merge",
	}
	assert.Equal(t, UpdateStyleMerge, cfg.GetDefaultUpdateStyle())

	setting.Repository.PullRequest.DefaultUpdateStyle = "rebase"
	cfg = PullRequestsConfig{
		DefaultUpdateStyle: "",
	}
	assert.Equal(t, UpdateStyleRebase, cfg.GetDefaultUpdateStyle())
	cfg = PullRequestsConfig{
		DefaultUpdateStyle: "rebase",
	}
	assert.Equal(t, UpdateStyleRebase, cfg.GetDefaultUpdateStyle())
	cfg = PullRequestsConfig{
		DefaultUpdateStyle: "merge",
	}
	assert.Equal(t, UpdateStyleMerge, cfg.GetDefaultUpdateStyle())
}

func TestWikiConfig(t *testing.T) {
	wikiType := any(int64(unit.TypeWiki))
	for _, bs := range []string{"{}", "null"} {
		r := &RepoUnit{}
		r.BeforeSet("type", &wikiType)
		require.NoError(t, r.Config.FromDB([]byte(bs)))
		assert.Equal(t, &WikiConfig{}, r.WikiConfig(), bs)
		assert.False(t, r.WikiConfig().FromFolder())
	}

	cfg := &WikiConfig{Source: WikiSourceFolder, Folder: "docs", Branch: "release#1"}
	bs, err := cfg.ToDB()
	require.NoError(t, err)
	r := &RepoUnit{}
	r.BeforeSet("type", &wikiType)
	require.NoError(t, r.Config.FromDB(bs))
	assert.Equal(t, cfg, r.WikiConfig())
	assert.True(t, r.WikiConfig().FromFolder())

	// a unit built with another config type reads as the separate wiki
	assert.Equal(t, &WikiConfig{}, (&RepoUnit{Type: unit.TypeWiki, Config: new(UnitConfig)}).WikiConfig())
	assert.Equal(t, &WikiConfig{}, (&RepoUnit{Type: unit.TypeWiki}).WikiConfig())
}

func TestCleanWikiFolder(t *testing.T) {
	for in, want := range map[string]string{
		"docs":                   "docs",
		"docs/":                  "docs",
		"docs//guide":            "docs/guide",
		"./docs":                 "docs",
		"":                       "",
		".":                      "",
		"./":                     "",
		"/":                      "",
		"/docs":                  "",
		"..":                     "",
		"../docs":                "",
		"docs/../x":              "",
		"docs/..":                "",
		"docs\\guide":            "",
		"docs\x00":               "",
		strings.Repeat("a", 255): strings.Repeat("a", 255),
		strings.Repeat("a", 256): "",
	} {
		assert.Equal(t, want, CleanWikiFolder(in), "%q", in)
	}
}

func TestGetRepoUnitForUpdate(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		u, has, err := GetRepoUnitForUpdate(ctx, 1, unit.TypePullRequests)
		require.NoError(t, err)
		assert.True(t, has)
		assert.Equal(t, int64(1), u.RepoID)
		assert.Equal(t, unit.TypePullRequests, u.Type)
		_, has, err = GetRepoUnitForUpdate(ctx, 1, unit.Type(999))
		require.NoError(t, err)
		assert.False(t, has)
		return nil
	}))
}
