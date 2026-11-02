// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A project variable reaches the repositories of its project only; repository > project > organization > global.
func TestProjectVariables(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	a, err := repo_model.CreateRepoGroup(ctx, org3, "pa", "")
	require.NoError(t, err)
	b, err := repo_model.CreateRepoGroup(ctx, org3, "pb", "")
	require.NoError(t, err)
	add := func(owner, group, repo int64, name, value string) *ActionVariable {
		v, err := InsertVariable(ctx, owner, group, repo, name, value)
		require.NoError(t, err)
		return v
	}
	add(0, 0, 0, "SHARED", "global")
	add(0, 0, 0, "GLOBAL_ONLY", "global")
	add(3, 0, 0, "SHARED", "org")
	add(3, 0, 0, "ORG_ONLY", "org")
	varA := add(3, a.ID, 0, "SHARED", "a")
	add(3, a.ID, 0, "ONLY_A", "a")
	add(3, b.ID, 0, "SHARED", "b")
	add(0, 0, 1, "REPO_WINS", "repo")
	add(3, a.ID, 0, "REPO_WINS", "a")
	repoVar := add(0, a.ID, 1, "SHARED", "repo")
	assert.EqualValues(t, 0, repoVar.GroupID)

	names := func(opts FindVariablesOpts) []string {
		vars, err := FindVariables(ctx, opts)
		require.NoError(t, err)
		ret := []string{}
		for _, v := range vars {
			ret = append(ret, v.Name)
		}
		return ret
	}
	assert.Equal(t, []string{"GLOBAL_ONLY", "SHARED"}, names(FindVariablesOpts{}), "global")
	assert.Equal(t, []string{"ORG_ONLY", "SHARED"}, names(FindVariablesOpts{OwnerID: 3}), "no project variable in the organization list")
	assert.Equal(t, []string{"ONLY_A", "REPO_WINS", "SHARED"}, names(FindVariablesOpts{OwnerID: 3, GroupID: a.ID}))
	assert.Equal(t, []string{"REPO_WINS", "SHARED"}, names(FindVariablesOpts{RepoID: 1, OwnerID: 3, GroupID: a.ID}))

	of := func(group, repo int64) map[string]string {
		vars, err := GetVariablesOfRun(ctx, &ActionRun{RepoID: repo, Repo: &repo_model.Repository{ID: repo, OwnerID: 3, GroupID: group}})
		require.NoError(t, err)
		return vars
	}
	assert.Equal(t, map[string]string{"SHARED": "repo", "GLOBAL_ONLY": "global", "ORG_ONLY": "org", "ONLY_A": "a", "REPO_WINS": "repo"}, of(a.ID, 1))
	assert.Equal(t, map[string]string{"SHARED": "repo", "GLOBAL_ONLY": "global", "ORG_ONLY": "org", "REPO_WINS": "repo"}, of(b.ID, 1), "after a move into B")
	assert.Equal(t, map[string]string{"SHARED": "a", "GLOBAL_ONLY": "global", "ORG_ONLY": "org", "ONLY_A": "a", "REPO_WINS": "a"}, of(a.ID, 99))
	assert.Equal(t, map[string]string{"SHARED": "org", "GLOBAL_ONLY": "global", "ORG_ONLY": "org"}, of(0, 99), "a root repository")

	t.Run("update and delete are bound to the project", func(t *testing.T) {
		ok, err := UpdateVariable(ctx, &ActionVariable{ID: varA.ID, OwnerID: 3, GroupID: b.ID, Name: "SHARED", Data: "x"})
		require.NoError(t, err)
		assert.False(t, ok)
		ok, err = UpdateVariable(ctx, &ActionVariable{ID: varA.ID, OwnerID: 3, Name: "SHARED", Data: "x"})
		require.NoError(t, err)
		assert.False(t, ok, "the organization level")
		ok, err = DeleteVariable(ctx, varA.ID, 3, 0, 0)
		require.NoError(t, err)
		assert.False(t, ok)
		ok, err = DeleteVariable(ctx, varA.ID, 3, b.ID, 0)
		require.NoError(t, err)
		assert.False(t, ok)
		unittest.AssertExistsAndLoadBean(t, &ActionVariable{ID: varA.ID, Data: "a"})
		ok, err = UpdateVariable(ctx, &ActionVariable{ID: varA.ID, OwnerID: 3, GroupID: a.ID, Name: "SHARED", Data: "new"})
		require.NoError(t, err)
		assert.True(t, ok)
		ok, err = DeleteVariable(ctx, varA.ID, 3, a.ID, 0)
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("a row of a project that is gone can't be changed", func(t *testing.T) {
		_, err := db.Exec(ctx, "INSERT INTO `action_variable` (owner_id, group_id, repo_id, name, data, created_unix) VALUES (3, 99999, 0, 'ORPHAN', 'x', 0)")
		require.NoError(t, err)
		orphan := unittest.AssertExistsAndLoadBean(t, &ActionVariable{Name: "ORPHAN"})
		_, err = UpdateVariable(ctx, &ActionVariable{ID: orphan.ID, OwnerID: 3, GroupID: 99999, Name: "ORPHAN", Data: "y"})
		require.ErrorIs(t, err, repo_model.ErrRepoGroupNotExist)
		_, err = DeleteVariable(ctx, orphan.ID, 3, 99999, 0)
		require.ErrorIs(t, err, repo_model.ErrRepoGroupNotExist)
	})

	t.Run("missing project", func(t *testing.T) {
		_, err := InsertVariable(ctx, 3, 99999, 0, "NEW_ONE", "x")
		require.ErrorIs(t, err, repo_model.ErrRepoGroupNotExist)
	})
}
