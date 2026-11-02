// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Trashing takes the repository off its owner's count and forgets what was code-indexed, so that a restore
// indexes the code again.
func TestTrashRepository(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: repo.OwnerID})
	require.NoError(t, db.Insert(t.Context(), &repo_model.RepoIndexerStatus{RepoID: repo.ID, CommitSha: "abc", IndexerType: repo_model.RepoIndexerTypeCode}))
	require.NoError(t, repo_model.SetIndexerBranch(t.Context(), repo.ID, "feature", "def"))

	require.NoError(t, TrashRepository(t.Context(), owner, repo))

	trashed, err := repo_model.GetRepositoryByIDIncludingTrashed(t.Context(), repo.ID)
	require.NoError(t, err)
	assert.True(t, trashed.IsTrashed())
	assert.Equal(t, owner.Name, trashed.TrashedByName)
	assert.Equal(t, owner.NumRepos-1, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: owner.ID}).NumRepos)
	unittest.AssertNotExistsBean(t, &repo_model.RepoIndexerStatus{RepoID: repo.ID})
	branches, err := repo_model.GetIndexerBranches(t.Context(), repo.ID)
	require.NoError(t, err)
	assert.Empty(t, branches)

	_, err = repo_model.GetRepositoryByID(t.Context(), repo.ID)
	assert.True(t, repo_model.IsErrRepoNotExist(err))
	assert.True(t, repo_model.IsErrRepoNotExist(TrashRepository(t.Context(), owner, repo)), "a second trash finds nothing to claim")
}
