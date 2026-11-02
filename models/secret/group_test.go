// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secret

import (
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func names(secrets []*Secret) []string {
	ret := []string{}
	for _, s := range secrets {
		ret = append(ret, s.Name)
	}
	return ret
}

// A project secret reaches the repositories of its project only; the closest level wins.
func TestProjectSecrets(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	a, err := repo_model.CreateRepoGroup(ctx, org3, "pa", "")
	require.NoError(t, err)
	b, err := repo_model.CreateRepoGroup(ctx, org3, "pb", "")
	require.NoError(t, err)
	add := func(owner, group, repo int64, name, value string) *Secret {
		s, err := InsertEncryptedSecret(ctx, owner, group, repo, name, value)
		require.NoError(t, err)
		return s
	}
	add(3, 0, 0, "SHARED", "org")
	add(3, 0, 0, "ORG_ONLY", "org")
	secretA := add(3, a.ID, 0, "SHARED", "a")
	add(3, a.ID, 0, "ONLY_A", "a")
	add(3, b.ID, 0, "SHARED", "b")
	add(3, b.ID, 0, "ONLY_B", "b")
	add(0, 0, 1, "REPO_WINS", "repo")
	add(3, a.ID, 0, "REPO_WINS", "a")
	// the repository level wins over the project, whatever the group argument of a repo secret is
	repoSecret, err := InsertEncryptedSecret(ctx, 0, a.ID, 1, "SHARED", "repo")
	require.NoError(t, err)
	assert.EqualValues(t, 0, repoSecret.GroupID, "a repository secret has no project")

	t.Run("lists", func(t *testing.T) {
		orgList, err := db.Find[Secret](ctx, FindSecretsOptions{OwnerID: 3})
		require.NoError(t, err)
		assert.Equal(t, []string{"ORG_ONLY", "SHARED"}, names(orgList), "no project secret in the organization list")
		aList, err := db.Find[Secret](ctx, FindSecretsOptions{OwnerID: 3, GroupID: a.ID})
		require.NoError(t, err)
		assert.Equal(t, []string{"ONLY_A", "REPO_WINS", "SHARED"}, names(aList))
		repoList, err := db.Find[Secret](ctx, FindSecretsOptions{RepoID: 1, GroupID: a.ID, OwnerID: 3})
		require.NoError(t, err)
		assert.Equal(t, []string{"REPO_WINS", "SHARED"}, names(repoList), "group and owner are ignored for a repository")
		for _, s := range repoList {
			assert.EqualValues(t, 0, s.GroupID)
		}
		none, err := db.Find[Secret](ctx, FindSecretsOptions{})
		require.NoError(t, err)
		assert.Empty(t, none, "zero options match no row (global secrets don't exist)")
	})

	t.Run("fetch", func(t *testing.T) {
		got := func(owner, group, repo int64) map[string]string {
			m, err := FetchActionSecrets(ctx, owner, group, repo)
			require.NoError(t, err)
			return m
		}
		assert.Equal(t, map[string]string{"SHARED": "repo", "ORG_ONLY": "org", "ONLY_A": "a", "REPO_WINS": "repo"}, got(3, a.ID, 1))
		// the same repository after it moved: the new project's secrets start, the old stop
		assert.Equal(t, map[string]string{"SHARED": "repo", "ORG_ONLY": "org", "ONLY_B": "b", "REPO_WINS": "repo"}, got(3, b.ID, 1))
		// another repository: project over organization
		assert.Equal(t, map[string]string{"SHARED": "a", "ORG_ONLY": "org", "ONLY_A": "a", "REPO_WINS": "a"}, got(3, a.ID, 99))
		assert.Equal(t, map[string]string{"SHARED": "b", "ORG_ONLY": "org", "ONLY_B": "b"}, got(3, b.ID, 99))
		// a root repository gets the organization's only
		assert.Equal(t, map[string]string{"SHARED": "org", "ORG_ONLY": "org"}, got(3, 0, 99))
		// the owner is bound too: a project ID of another owner's repository matches nothing
		assert.Empty(t, got(36, a.ID, 99))
	})

	t.Run("get and unique", func(t *testing.T) {
		_, err := GetSecretByID(ctx, 3, a.ID, 0, secretA.ID)
		require.NoError(t, err)
		for _, q := range [][3]int64{{3, 0, 0}, {3, b.ID, 0}, {4, a.ID, 0}} {
			_, err = GetSecretByID(ctx, q[0], q[1], q[2], secretA.ID)
			require.ErrorIs(t, err, util.ErrNotExist, "%v", q)
		}
		_, err = InsertEncryptedSecret(ctx, 3, a.ID, 0, "ONLY_A", "again")
		require.Error(t, err, "once per project")
	})

	t.Run("missing project", func(t *testing.T) {
		_, err := InsertEncryptedSecret(ctx, 3, 99999, 0, "NEW_ONE", "x")
		require.ErrorIs(t, err, repo_model.ErrRepoGroupNotExist)
		_, err = InsertEncryptedSecret(ctx, 4, a.ID, 0, "NEW_ONE", "x")
		require.ErrorIs(t, err, repo_model.ErrRepoGroupNotExist, "a project of another owner")
	})
}
