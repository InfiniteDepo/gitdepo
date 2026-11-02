// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo_test

import (
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepoIndexerBranch(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()

	require.NoError(t, repo_model.SetIndexerBranch(ctx, 1, "develop", "aaa"))
	require.NoError(t, repo_model.SetIndexerBranch(ctx, 1, "develop", "bbb")) // upsert
	require.NoError(t, repo_model.SetIndexerBranch(ctx, 1, "release/1", "ccc"))
	require.NoError(t, repo_model.SetIndexerBranch(ctx, 2, "develop", "ddd"))

	got, err := repo_model.GetIndexerBranches(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"develop": "bbb", "release/1": "ccc"}, got)

	require.NoError(t, repo_model.DeleteIndexerBranches(ctx, 1, "develop"))
	got, err = repo_model.GetIndexerBranches(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"release/1": "ccc"}, got)

	// no names deletes every row of the repo, other repos stay
	require.NoError(t, repo_model.DeleteIndexerBranches(ctx, 1))
	got, err = repo_model.GetIndexerBranches(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, got)
	got, err = repo_model.GetIndexerBranches(ctx, 2)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

// The code unit config keeps IndexedBranches through the DB round trip, and
// every other unit still loads with its own config type.
func TestCodeConfigRoundTrip(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	ru := &repo_model.RepoUnit{
		RepoID: 1,
		Type:   unit.TypeCode,
		Config: &repo_model.CodeConfig{IndexedBranches: []string{"develop", "release/*"}},
	}
	_, err := db.GetEngine(t.Context()).Where("repo_id = 1 AND type = ?", unit.TypeCode).Delete(new(repo_model.RepoUnit))
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Insert(ru)
	require.NoError(t, err)

	repo, err := repo_model.GetRepositoryByID(t.Context(), 1)
	require.NoError(t, err)
	require.NoError(t, repo.LoadUnits(t.Context()))
	cu, err := repo.GetUnit(t.Context(), unit.TypeCode)
	require.NoError(t, err)
	assert.Equal(t, []string{"develop", "release/*"}, cu.CodeConfig().IndexedBranches)

	// old rows ("{}") decode to an empty list
	_, err = db.GetEngine(t.Context()).Exec("UPDATE repo_unit SET config = '{}' WHERE id = ?", ru.ID)
	require.NoError(t, err)
	repo, err = repo_model.GetRepositoryByID(t.Context(), 1)
	require.NoError(t, err)
	require.NoError(t, repo.LoadUnits(t.Context()))
	cu, err = repo.GetUnit(t.Context(), unit.TypeCode)
	require.NoError(t, err)
	assert.Empty(t, cu.CodeConfig().IndexedBranches)
	for _, u := range repo.Units {
		assert.NotNil(t, u.Config, u.Type.String())
	}
}
