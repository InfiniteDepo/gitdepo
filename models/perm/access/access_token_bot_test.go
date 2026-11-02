// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package access_test

import (
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	perm_model "forgejo.org/models/perm"
	"forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func insertOwnedToken(t *testing.T, ownerType auth_model.AccessTokenOwnerType, ownerID, groupID int64, mode perm_model.AccessMode, allRepos bool, repoIDs ...int64) *user_model.User {
	t.Helper()
	token := &auth_model.AccessToken{
		Name: "bot", OwnerType: ownerType, OwnerID: ownerID, GroupID: groupID, Mode: mode,
		ResourceAllRepos: allRepos, TokenHash: t.Name() + string(rune('a'+ownerType)), Scope: auth_model.AccessTokenScopeWriteRepository,
	}
	require.NoError(t, db.Insert(t.Context(), token))
	for _, repoID := range repoIDs {
		require.NoError(t, db.Insert(t.Context(), &auth_model.AccessTokenResourceRepo{TokenID: token.ID, RepoID: repoID}))
	}
	bot, err := user_model.GetPossibleUserByID(t.Context(), user_model.AccessTokenBotID(token.ID))
	require.NoError(t, err)
	require.True(t, bot.IsAccessTokenBot())
	return bot
}

func botMode(t *testing.T, bot *user_model.User, repoID int64) perm_model.AccessMode {
	t.Helper()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID})
	perm, err := access.GetUserRepoPermission(t.Context(), repo, bot)
	require.NoError(t, err)
	if perm.HasAccess() {
		assert.Equal(t, perm.AccessMode, perm.UnitAccessMode(unit.TypeCode), "every unit has the token's permission")
	}
	level, err := access.AccessLevel(t.Context(), bot, repo)
	require.NoError(t, err)
	assert.Equal(t, perm.UnitAccessMode(unit.TypeCode), level)
	return perm.UnitAccessMode(unit.TypeCode)
}

func TestAccessTokenBotPermission(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	t.Run("repository token", func(t *testing.T) {
		bot := insertOwnedToken(t, auth_model.AccessTokenOwnerRepo, 3, 0, perm_model.AccessModeWrite, true)
		assert.Equal(t, perm_model.AccessModeWrite, botMode(t, bot, 3))
		assert.Equal(t, perm_model.AccessModeNone, botMode(t, bot, 5), "another repository of the organization")
		assert.Equal(t, perm_model.AccessModeNone, botMode(t, bot, 1), "a public repository it doesn't cover")
	})

	t.Run("organization token, all repositories", func(t *testing.T) {
		bot := insertOwnedToken(t, auth_model.AccessTokenOwnerOrg, 3, 0, perm_model.AccessModeRead, true)
		assert.Equal(t, perm_model.AccessModeRead, botMode(t, bot, 3))
		assert.Equal(t, perm_model.AccessModeRead, botMode(t, bot, 5))
		assert.Equal(t, perm_model.AccessModeRead, botMode(t, bot, 32))
		assert.Equal(t, perm_model.AccessModeNone, botMode(t, bot, 2), "another owner's repository")
	})

	t.Run("organization token, selected repositories", func(t *testing.T) {
		bot := insertOwnedToken(t, auth_model.AccessTokenOwnerOrg, 3, 0, perm_model.AccessModeAdmin, false, 5, 2)
		assert.Equal(t, perm_model.AccessModeAdmin, botMode(t, bot, 5))
		assert.Equal(t, perm_model.AccessModeNone, botMode(t, bot, 3), "not selected")
		assert.Equal(t, perm_model.AccessModeNone, botMode(t, bot, 2), "selected, but another owner's repository")
		isAdmin, err := access.IsUserRepoAdmin(t.Context(), unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 5}), bot)
		require.NoError(t, err)
		assert.True(t, isAdmin)
	})

	t.Run("project token follows the repository's project", func(t *testing.T) {
		bot := insertOwnedToken(t, auth_model.AccessTokenOwnerProject, 3, 7, perm_model.AccessModeWrite, true)
		assert.Equal(t, perm_model.AccessModeNone, botMode(t, bot, 3), "at the organization's root")
		_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET group_id = 7 WHERE id = 3")
		require.NoError(t, err)
		assert.Equal(t, perm_model.AccessModeWrite, botMode(t, bot, 3), "moved into the project")
		assert.Equal(t, perm_model.AccessModeNone, botMode(t, bot, 5), "still at the root")
		_, err = db.GetEngine(t.Context()).Exec("UPDATE repository SET group_id = 8 WHERE id = 3")
		require.NoError(t, err)
		assert.Equal(t, perm_model.AccessModeNone, botMode(t, bot, 3), "moved to another project")
		_, err = db.GetEngine(t.Context()).Exec("UPDATE repository SET group_id = 0 WHERE id = 3")
		require.NoError(t, err)
	})

	t.Run("never above admin", func(t *testing.T) {
		bot := insertOwnedToken(t, auth_model.AccessTokenOwnerRepo, 3, 0, perm_model.AccessModeOwner, true)
		assert.Equal(t, perm_model.AccessModeAdmin, botMode(t, bot, 3))
	})

	t.Run("expired token", func(t *testing.T) {
		bot := insertOwnedToken(t, auth_model.AccessTokenOwnerRepo, 3, 0, perm_model.AccessModeWrite, true)
		_, err := db.GetEngine(t.Context()).Exec("UPDATE access_token SET expires_unix = 1 WHERE id = ?", bot.BotToken.ID)
		require.NoError(t, err)
		bot, err = user_model.GetPossibleUserByID(t.Context(), bot.ID)
		require.NoError(t, err)
		assert.False(t, bot.IsActive)
		assert.Equal(t, perm_model.AccessModeNone, botMode(t, bot, 3))
	})

	t.Run("trashed repository", func(t *testing.T) {
		bot := insertOwnedToken(t, auth_model.AccessTokenOwnerRepo, 32, 0, perm_model.AccessModeWrite, true)
		_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 32")
		require.NoError(t, err)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 32})
		perm, err := access.GetUserRepoPermission(t.Context(), repo, bot)
		require.NoError(t, err)
		assert.False(t, perm.HasAccess())
		_, err = db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 0 WHERE id = 32")
		require.NoError(t, err)
	})

	t.Run("deleted token has no identity", func(t *testing.T) {
		bot := insertOwnedToken(t, auth_model.AccessTokenOwnerRepo, 3, 0, perm_model.AccessModeWrite, true)
		require.NoError(t, auth_model.DeleteOwnedAccessTokens(t.Context(), auth_model.AccessTokenOwnerRepo, 3, 0))
		_, err := user_model.GetPossibleUserByID(t.Context(), bot.ID)
		assert.True(t, user_model.IsErrUserNotExist(err))
		users, err := user_model.GetPossibleUserByIDs(t.Context(), []int64{bot.ID, 2})
		require.NoError(t, err)
		assert.Len(t, users, 1)
	})

	t.Run("a personal access token is no identity", func(t *testing.T) {
		_, err := user_model.GetPossibleUserByID(t.Context(), user_model.AccessTokenBotID(1))
		assert.True(t, user_model.IsErrUserNotExist(err), "access_token 1 belongs to user 1")
	})
}
