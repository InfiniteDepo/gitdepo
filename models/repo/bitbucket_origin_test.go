// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo_test

import (
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchRepositoryByBitbucketOrigin(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	// org3/repo3 is private; user2 owns org3, user5 can't read it
	require.NoError(t, db.Insert(db.DefaultContext, &repo_model.BitbucketOrigin{RepoID: 3, ProjectKey: "PAY", Slug: "api", Server: "https://bb.example.com"}))
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})

	search := func(t *testing.T, doer *user_model.User, keyword string) []int64 {
		t.Helper()
		repos, _, err := repo_model.SearchRepositoryByName(db.DefaultContext, &repo_model.SearchRepoOptions{
			Keyword: keyword, Actor: doer, Private: doer != nil, Collaborate: optional.None[bool](),
		})
		require.NoError(t, err)
		ids := make([]int64, 0, len(repos))
		for _, r := range repos {
			ids = append(ids, r.ID)
		}
		return ids
	}

	for _, keyword := range []string{
		"PAY/api", "pay/API",
		"https://bb.example.com/scm/pay/api.git",
		"https://bb.example.com/projects/PAY/repos/api/browse",
		"ssh://git@bb.example.com:7999/pay/api.git",
	} {
		assert.Contains(t, search(t, user2, keyword), int64(3), keyword)
		assert.NotContains(t, search(t, user5, keyword), int64(3), keyword)
		assert.NotContains(t, search(t, nil, keyword), int64(3), keyword)
	}
	for _, keyword := range []string{"PAY/web", "OPS/api", "https://other.example.com/scm/pay/api.git", "https://bb.example.com.evil/scm/pay/api.git"} {
		assert.NotContains(t, search(t, user2, keyword), int64(3), keyword)
	}

	t.Run("two-factor requirement", func(t *testing.T) {
		_, err := db.Exec(db.DefaultContext, "UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
		require.NoError(t, err)
		defer func() {
			_, err := db.Exec(db.DefaultContext, "UPDATE `user` SET require_two_factor = ? WHERE id = 3", false)
			require.NoError(t, err)
		}()
		assert.NotContains(t, search(t, user2, "PAY/api"), int64(3), "user2 has no second factor")
	})

	t.Run("trashed", func(t *testing.T) {
		_, err := db.Exec(db.DefaultContext, "UPDATE repository SET trashed_unix = 1 WHERE id = 3")
		require.NoError(t, err)
		defer func() {
			_, err := db.Exec(db.DefaultContext, "UPDATE repository SET trashed_unix = 0 WHERE id = 3")
			require.NoError(t, err)
		}()
		assert.NotContains(t, search(t, user2, "PAY/api"), int64(3))
	})

	t.Run("a project row is no repository", func(t *testing.T) {
		require.NoError(t, db.Insert(db.DefaultContext, &repo_model.BitbucketOrigin{OwnerID: 3, GroupID: 1, ProjectKey: "OPS", Server: "https://bb.example.com"}))
		assert.Empty(t, search(t, user2, "OPS/"))
	})
}

func TestBitbucketOriginLookups(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	group, err := repo_model.CreateRepoGroup(db.DefaultContext, org3, "pay", "")
	require.NoError(t, err)
	require.NoError(t, db.Insert(db.DefaultContext, &repo_model.BitbucketOrigin{OwnerID: 3, GroupID: group.ID, ProjectKey: "PAY", Server: "https://bb.example.com"}))
	require.NoError(t, db.Insert(db.DefaultContext, &repo_model.BitbucketOrigin{RepoID: 3, ProjectKey: "PAY", Slug: "api", Server: "https://bb.example.com"}))

	o, err := repo_model.GetBitbucketOrigin(db.DefaultContext, 3)
	require.NoError(t, err)
	assert.Equal(t, "PAY/api", o.Path())
	o, err = repo_model.GetBitbucketOrigin(db.DefaultContext, 5)
	require.NoError(t, err)
	assert.Nil(t, o)
	o, err = repo_model.GetBitbucketProjectOrigin(db.DefaultContext, 3, group.ID)
	require.NoError(t, err)
	assert.Equal(t, "PAY", o.ProjectKey)
	o, err = repo_model.GetBitbucketProjectOrigin(db.DefaultContext, 17, group.ID)
	require.NoError(t, err)
	assert.Nil(t, o, "another owner's project")

	require.NoError(t, repo_model.DeleteRepoGroup(db.DefaultContext, group))
	unittest.AssertNotExistsBean(t, &repo_model.BitbucketOrigin{GroupID: group.ID})
	unittest.AssertExistsAndLoadBean(t, &repo_model.BitbucketOrigin{RepoID: 3}) // a repository's row stays
}

func TestIsValidBitbucketName(t *testing.T) {
	for name, ok := range map[string]bool{"PAY": true, "~jdoe": true, "a.b": true, "my-repo_1": true, ".": false, "..": false, "": false, "a/b": false, "a b": false} {
		assert.Equal(t, ok, repo_model.IsValidBitbucketName(name), name)
	}
}
