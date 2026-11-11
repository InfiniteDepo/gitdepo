// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A user's string in the Pull requests unit that spells the key does not make a repository "have its own setting".
func TestCountCleanupReposIgnoresUserStrings(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	before, err := CountCleanupRepos(t.Context(), org, false)
	require.NoError(t, err)

	repo := &repo_model.Repository{ID: 9150, OwnerID: 3, OwnerName: "org3", Name: "count-own", LowerName: "count-own", Status: repo_model.RepositoryReady, DefaultBranch: "main"}
	require.NoError(t, db.Insert(t.Context(), repo))
	cfg := &repo_model.PullRequestsConfig{BranchingModel: &repo_model.BranchingModel{DevelopmentBranch: "branchcleanup"}}
	require.NoError(t, db.Insert(t.Context(), &repo_model.RepoUnit{RepoID: repo.ID, Type: unit.TypePullRequests, Config: cfg}))

	after, err := CountCleanupRepos(t.Context(), org, false)
	require.NoError(t, err)
	assert.Equal(t, before+1, after, "an inheriting repository is counted")

	// with a setting of its own it is left out
	cfg.BranchCleanup = &repo_model.BranchCleanup{Days: 5}
	_, err = db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", repo.ID, unit.TypePullRequests).Update(&repo_model.RepoUnit{Config: cfg})
	require.NoError(t, err)
	own, err := CountCleanupRepos(t.Context(), org, false)
	require.NoError(t, err)
	assert.Equal(t, before, own)
}
