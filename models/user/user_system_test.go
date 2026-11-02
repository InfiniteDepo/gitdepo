// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package user_test

import (
	"testing"

	"forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessTokenBotNoLink(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	token := &auth.AccessToken{Name: "ci", TokenHash: "bot-link", OwnerType: auth.AccessTokenOwnerOrg, OwnerID: 3, Mode: 1}
	require.NoError(t, db.Insert(t.Context(), token))
	id := user_model.AccessTokenBotID(token.ID)

	// the identity has no profile, and its management page is for the people who manage the token: no link anywhere
	bot, err := user_model.GetAccessTokenBot(t.Context(), id)
	require.NoError(t, err)
	assert.Empty(t, bot.HomeLink())
	assert.Empty(t, bot.HTMLURL())
	bots, err := user_model.GetPossibleUserByIDs(t.Context(), []int64{id, user_model.AccessTokenBotID(token.ID + 1000)})
	require.NoError(t, err)
	require.Len(t, bots, 1)
	assert.Equal(t, "ci [bot]", bots[0].FullName)
	assert.Empty(t, bots[0].HomeLink())

	// the bulk loaders of posters resolve it too, and a deleted token falls back to Ghost
	byID, err := user_model.GetUsersByIDsWithBots(t.Context(), []int64{id, 2})
	require.NoError(t, err)
	_, poster := user_model.GetUserFromMap(id, byID)
	assert.Equal(t, id, poster.ID)
	_, gone := user_model.GetUserFromMap(user_model.AccessTokenBotID(token.ID+1000), byID)
	assert.True(t, gone.IsGhost())

	names, err := user_model.GetAccessTokenBotNames(t.Context(), []int64{id, user_model.AccessTokenBotID(token.ID + 1000)})
	require.NoError(t, err)
	assert.Equal(t, []string{"ci"}, names)
}
