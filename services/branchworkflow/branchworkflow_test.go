// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package branchworkflow

import (
	"testing"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	inherit = repo_model.DeleteBranchInherit
	off     = repo_model.DeleteBranchOff
	defOn   = repo_model.DeleteBranchDefaultOn
	always  = repo_model.DeleteBranchAlways
)

func TestResolve(t *testing.T) {
	for _, c := range []struct {
		name            string
		instance, org   repo_model.DeleteBranchMode
		orgLocked       bool
		repo            repo_model.DeleteBranchMode
		mode            repo_model.DeleteBranchMode
		source          string
		locked          bool
		hasOrg, hasRepo bool
	}{
		{"instance only", defOn, inherit, false, inherit, defOn, "instance", false, false, false},
		{"org beats instance", off, always, false, inherit, always, "org", false, true, false},
		{"repo beats org when unlocked", always, defOn, false, off, off, "repo", false, true, true},
		{"repo beats instance", off, inherit, false, defOn, defOn, "repo", false, false, true},
		{"locked org beats repo", off, always, true, off, always, "org", true, true, true},
		{"lock without value is ignored", off, inherit, true, defOn, defOn, "repo", false, true, true},
		{"user-owned repo skips org", always, always, true, inherit, always, "instance", false, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			org := inherit
			if c.hasOrg {
				org = c.org
			}
			got := Resolve(c.instance, org, c.orgLocked, c.repo)
			assert.Equal(t, c.mode, got.Mode)
			assert.Equal(t, c.source, got.Source)
			assert.Equal(t, c.locked, got.Locked)
		})
	}
}

func TestLegacyBoolMapsToDefaultOn(t *testing.T) {
	cfg := &repo_model.PullRequestsConfig{DefaultDeleteBranchAfterMerge: true}
	assert.Equal(t, defOn, cfg.GetDeleteBranchAfterMerge())

	cfg.DeleteBranchAfterMerge = off // an explicit mode wins over the legacy bool
	assert.Equal(t, off, cfg.GetDeleteBranchAfterMerge())

	assert.Equal(t, inherit, (&repo_model.PullRequestsConfig{}).GetDeleteBranchAfterMerge())
}

func TestInstanceDefault(t *testing.T) {
	defer test.MockVariableValue(&setting.Repository.BranchWorkflow.DeleteSourceBranchAfterMerge, "always")()
	assert.Equal(t, always, instanceMode())
	setting.Repository.BranchWorkflow.DeleteSourceBranchAfterMerge = "nonsense"
	assert.Equal(t, off, instanceMode())
	setting.Repository.BranchWorkflow.DeleteSourceBranchAfterMerge = ""
	assert.Equal(t, off, instanceMode())
}

func TestSetOrgAndRepo(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	require.Equal(t, org.ID, repo.OwnerID)

	require.ErrorIs(t, SetOrg(t.Context(), org, inherit, true), ErrLockWithoutValue)

	require.NoError(t, SetOrg(t.Context(), org, defOn, false))
	require.NoError(t, SetRepo(t.Context(), repo, off))
	eff, err := GetEffective(t.Context(), repo)
	require.NoError(t, err)
	assert.Equal(t, off, eff.Mode)
	assert.Equal(t, "repo", eff.Source)

	require.NoError(t, SetOrg(t.Context(), org, always, true))
	eff, err = GetEffective(t.Context(), repo)
	require.NoError(t, err)
	assert.Equal(t, always, eff.Mode)
	assert.True(t, eff.Locked)
	assert.Equal(t, org.Name, eff.SetBy)
	require.ErrorIs(t, SetRepo(t.Context(), repo, off), ErrLocked)

	// unlocking brings the repo's own value back
	require.NoError(t, SetOrg(t.Context(), org, always, false))
	eff, err = GetEffective(t.Context(), repo)
	require.NoError(t, err)
	assert.Equal(t, off, eff.Mode)
}
