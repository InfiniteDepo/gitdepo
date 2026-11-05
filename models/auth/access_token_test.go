// Copyright 2016 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth_test

import (
	"context"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sysCtx is the server acting by itself, which may create tokens for anyone
func sysCtx() context.Context { return audit_model.WithSystem(db.DefaultContext, "test") }

// A token acts as its owner, so a token (or a new secret) for someone else is only a person's own act; a user's
// request for themselves is unchanged.
func TestNewAccessTokenOwnAct(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	actor := func(uid int64, credential string, sudoBy int64) context.Context {
		a := &audit_model.Actor{Type: audit_model.ActorUser, ID: uid, Name: "u", Credential: audit_model.Credential{Type: credential}}
		if sudoBy != 0 {
			a.SetSudo(sudoBy, "admin")
		}
		return audit_model.WithActor(db.DefaultContext, a)
	}
	adminGrant := actor(1, audit_model.CredentialOAuth2Grant, 0)
	for name, ctx := range map[string]context.Context{
		"grant":       adminGrant,
		"integration": actor(1, audit_model.CredentialAuthorizedIntegration, 0),
		"sudo":        actor(3, audit_model.CredentialAccessToken, 1),
		"no actor":    db.DefaultContext,
	} {
		require.ErrorIs(t, auth_model.NewAccessToken(ctx, &auth_model.AccessToken{UID: 3, Name: "minted " + name}, nil), audit_model.ErrNotOwnAct, name)
		_, err := auth_model.RegenerateAccessTokenByID(ctx, 1, 2) // user 2's token: someone else's for every actor here
		require.ErrorIs(t, err, audit_model.ErrNotOwnAct, name)
		require.ErrorIs(t, auth_model.NewAccessToken(ctx, &auth_model.AccessToken{OwnerType: auth_model.AccessTokenOwnerOrg, OwnerID: 3, Name: "org " + name}, nil), audit_model.ErrNotOwnAct, name)
	}
	unittest.AssertNotExistsBean(t, &auth_model.AccessToken{UID: 3, Name: "minted grant"})

	require.NoError(t, auth_model.NewAccessToken(actor(3, audit_model.CredentialOAuth2Grant, 0), &auth_model.AccessToken{UID: 3, Name: "for themselves"}, nil))
	require.NoError(t, auth_model.NewAccessToken(actor(1, audit_model.CredentialSession, 0), &auth_model.AccessToken{UID: 3, Name: "admin's own act"}, nil))
	require.NoError(t, auth_model.NewAccessToken(audit_model.WithCLI(db.DefaultContext), &auth_model.AccessToken{UID: 3, Name: "cli"}, nil))
}

func TestNewAccessToken(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	token := &auth_model.AccessToken{
		UID:  3,
		Name: "Token C",
	}
	require.NoError(t, auth_model.NewAccessToken(sysCtx(), token, nil))
	unittest.AssertExistsAndLoadBean(t, token)

	invalidToken := &auth_model.AccessToken{
		ID:   token.ID, // duplicate
		UID:  2,
		Name: "Token F",
	}
	require.Error(t, auth_model.NewAccessToken(sysCtx(), invalidToken, nil))
}

func TestAccessTokenByNameExists(t *testing.T) {
	name := "Token Gitea"

	require.NoError(t, unittest.PrepareTestDatabase())
	token := &auth_model.AccessToken{
		UID:  3,
		Name: name,
	}

	// Check to make sure it doesn't exists already
	exist, err := auth_model.AccessTokenByNameExists(db.DefaultContext, token)
	require.NoError(t, err)
	assert.False(t, exist)

	// Save it to the database
	require.NoError(t, auth_model.NewAccessToken(sysCtx(), token, nil))
	unittest.AssertExistsAndLoadBean(t, token)

	// This token must be found by name in the DB now
	exist, err = auth_model.AccessTokenByNameExists(db.DefaultContext, token)
	require.NoError(t, err)
	assert.True(t, exist)

	user4Token := &auth_model.AccessToken{
		UID:  4,
		Name: name,
	}

	// Name matches but different user ID, this shouldn't exists in the
	// database
	exist, err = auth_model.AccessTokenByNameExists(db.DefaultContext, user4Token)
	require.NoError(t, err)
	assert.False(t, exist)
}

func TestGetAccessTokenBySHA(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	token, err := auth_model.GetAccessTokenBySHA(db.DefaultContext, "d2c6c1ba3890b309189a8e618c72a162e4efbf36")
	require.NoError(t, err)
	assert.Equal(t, int64(1), token.UID)
	assert.Equal(t, "Token A", token.Name)
	assert.Equal(t, "2b3668e11cb82d3af8c6e4524fc7841297668f5008d1626f0ad3417e9fa39af84c268248b78c481daa7e5dc437784003494f", token.TokenHash)
	assert.Equal(t, "e4efbf36", token.TokenLastEight)

	_, err = auth_model.GetAccessTokenBySHA(db.DefaultContext, "notahash")
	require.Error(t, err)
	assert.True(t, auth_model.IsErrAccessTokenNotExist(err))

	_, err = auth_model.GetAccessTokenBySHA(db.DefaultContext, "")
	require.Error(t, err)
	assert.True(t, auth_model.IsErrAccessTokenEmpty(err))
}

func TestGetAccessTokenBySHAExpired(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	t.Run("cached", func(t *testing.T) {
		// A first, successful lookup puts the token in the cache.
		token, err := auth_model.GetAccessTokenBySHA(db.DefaultContext, "d2c6c1ba3890b309189a8e618c72a162e4efbf36")
		require.NoError(t, err)

		token.ExpiresUnix = timeutil.TimeStampNow().Add(-1)
		_, err = db.GetEngine(db.DefaultContext).ID(token.ID).Cols("expires_unix").Update(token)
		require.NoError(t, err)

		_, err = auth_model.GetAccessTokenBySHA(db.DefaultContext, "d2c6c1ba3890b309189a8e618c72a162e4efbf36")
		require.ErrorContains(t, err, `access token "Token A" expired on`)
		assert.True(t, auth_model.IsErrAccessTokenExpired(err))
	})

	t.Run("not cached", func(t *testing.T) {
		token := &auth_model.AccessToken{UID: 2, Name: "expired", ExpiresUnix: timeutil.TimeStampNow().Add(-1)}
		require.NoError(t, auth_model.NewAccessToken(sysCtx(), token, nil))

		_, err := auth_model.GetAccessTokenBySHA(db.DefaultContext, token.Token)
		assert.True(t, auth_model.IsErrAccessTokenExpired(err))
	})

	t.Run("not yet expired", func(t *testing.T) {
		token := &auth_model.AccessToken{UID: 2, Name: "valid", ExpiresUnix: timeutil.TimeStampNow().Add(3600)}
		require.NoError(t, auth_model.NewAccessToken(sysCtx(), token, nil))

		_, err := auth_model.GetAccessTokenBySHA(db.DefaultContext, token.Token)
		require.NoError(t, err)
	})
}

func TestListAccessTokens(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	tokens, err := db.Find[auth_model.AccessToken](db.DefaultContext, auth_model.ListAccessTokensOptions{UserID: 1})
	require.NoError(t, err)
	if assert.Len(t, tokens, 2) {
		assert.Equal(t, int64(1), tokens[0].UID)
		assert.Equal(t, int64(1), tokens[1].UID)
		assert.Contains(t, []string{tokens[0].Name, tokens[1].Name}, "Token A")
		assert.Contains(t, []string{tokens[0].Name, tokens[1].Name}, "Token B")
	}

	tokens, err = db.Find[auth_model.AccessToken](db.DefaultContext, auth_model.ListAccessTokensOptions{UserID: 2})
	require.NoError(t, err)
	if assert.Len(t, tokens, 1) {
		assert.Equal(t, int64(2), tokens[0].UID)
		assert.Equal(t, "Token A", tokens[0].Name)
	}

	tokens, err = db.Find[auth_model.AccessToken](db.DefaultContext, auth_model.ListAccessTokensOptions{UserID: 100})
	require.NoError(t, err)
	assert.Empty(t, tokens)
}

func TestUpdateLastUsed(t *testing.T) {
	timeutil.MockSet(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC))
	defer timeutil.MockUnset()

	require.NoError(t, unittest.PrepareTestDatabase())
	token := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: 2})

	require.NoError(t, token.UpdateLastUsed(t.Context(), ""))

	token = unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: 2})
	assert.Equal(t, timeutil.TimeStampNow(), token.UpdatedUnix)
}

func TestDeleteAccessTokenByID(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	token, err := auth_model.GetAccessTokenBySHA(db.DefaultContext, "4c6f36e6cf498e2a448662f915d932c09c5a146c")
	require.NoError(t, err)
	assert.Equal(t, int64(1), token.UID)

	require.NoError(t, auth_model.DeleteAccessTokenByID(db.DefaultContext, token.ID, 1))
	unittest.AssertNotExistsBean(t, token)

	err = auth_model.DeleteAccessTokenByID(db.DefaultContext, 100, 100)
	require.Error(t, err)
	assert.True(t, auth_model.IsErrAccessTokenNotExist(err))
}

func TestRegenerateAccessTokenByID(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	token, err := auth_model.GetAccessTokenBySHA(db.DefaultContext, "4c6f36e6cf498e2a448662f915d932c09c5a146c")
	require.NoError(t, err)

	newToken, err := auth_model.RegenerateAccessTokenByID(sysCtx(), token.ID, 1)
	require.NoError(t, err)
	unittest.AssertNotExistsBean(t, &auth_model.AccessToken{ID: token.ID, UID: token.UID, TokenHash: token.TokenHash})
	newToken = &auth_model.AccessToken{
		ID:        newToken.ID,
		UID:       newToken.UID,
		TokenHash: newToken.TokenHash,
	}
	unittest.AssertExistsAndLoadBean(t, newToken)

	// Token has been recreated, new salt and hash, but should retain the same ID, UID, Name and Scope
	assert.Equal(t, token.ID, newToken.ID)
	assert.NotEqual(t, token.TokenHash, newToken.TokenHash)
	assert.NotEqual(t, token.TokenSalt, newToken.TokenSalt)
	assert.Equal(t, token.UID, newToken.UID)
	assert.Equal(t, token.Name, newToken.Name)
	assert.Equal(t, token.Scope, newToken.Scope)
}

func TestGetAccessTokenBySHACache(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	auth_model.MockSuccessfulAccessTokenCache(t)
	const sha = "d2c6c1ba3890b309189a8e618c72a162e4efbf36"

	token, err := auth_model.GetAccessTokenBySHA(db.DefaultContext, sha)
	require.NoError(t, err)
	cached, err := auth_model.GetAccessTokenBySHA(db.DefaultContext, sha)
	require.NoError(t, err)
	assert.Equal(t, token.ID, cached.ID)
	// the cache holds a hash of the token, not the token itself
	assert.Equal(t, []string{auth_model.TokenCacheKey(sha)}, auth_model.SuccessfulAccessTokenCacheKeys())

	t.Run("hash changed", func(t *testing.T) {
		// a token regenerated in place keeps its row: the cached ID alone must not authenticate it
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE access_token SET token_hash = ? WHERE id = ?", "other", token.ID)
		require.NoError(t, err)
		_, err = auth_model.GetAccessTokenBySHA(db.DefaultContext, sha)
		assert.True(t, auth_model.IsErrAccessTokenNotExist(err))
	})

	t.Run("deleted", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		_, err := auth_model.GetAccessTokenBySHA(db.DefaultContext, sha)
		require.NoError(t, err)
		require.NoError(t, auth_model.DeleteAccessTokenByID(db.DefaultContext, token.ID, token.UID))
		_, err = auth_model.GetAccessTokenBySHA(db.DefaultContext, sha)
		assert.True(t, auth_model.IsErrAccessTokenNotExist(err))
	})
}
