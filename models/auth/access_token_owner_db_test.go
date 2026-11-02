// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth_test

import (
	"fmt"
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteOwnedAccessTokens(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	n := 0
	insert := func(ownerType auth_model.AccessTokenOwnerType, ownerID, groupID int64, repoIDs ...int64) int64 {
		token := &auth_model.AccessToken{OwnerType: ownerType, OwnerID: ownerID, GroupID: groupID, TokenHash: fmt.Sprintf("owned-%d", n)}
		n++
		require.NoError(t, db.Insert(t.Context(), token))
		for _, repoID := range repoIDs {
			require.NoError(t, db.Insert(t.Context(), &auth_model.AccessTokenResourceRepo{TokenID: token.ID, RepoID: repoID}))
		}
		return token.ID
	}
	exists := func(id int64) bool {
		has, err := db.GetEngine(t.Context()).ID(id).Exist(&auth_model.AccessToken{})
		require.NoError(t, err)
		return has
	}

	org := insert(auth_model.AccessTokenOwnerOrg, 3, 0, 3, 5)
	project := insert(auth_model.AccessTokenOwnerProject, 3, 1)
	otherProject := insert(auth_model.AccessTokenOwnerProject, 3, 2)
	repo := insert(auth_model.AccessTokenOwnerRepo, 3, 0)
	otherOrg := insert(auth_model.AccessTokenOwnerOrg, 6, 0)

	require.NoError(t, auth_model.DeleteOwnedAccessTokens(t.Context(), auth_model.AccessTokenOwnerProject, 3, 1))
	assert.False(t, exists(project))
	assert.True(t, exists(otherProject))

	require.NoError(t, auth_model.DeleteOwnedAccessTokens(t.Context(), auth_model.AccessTokenOwnerOrg, 3, 0))
	assert.False(t, exists(org))
	assert.False(t, exists(otherProject))
	unittest.AssertNotExistsBean(t, &auth_model.AccessTokenResourceRepo{TokenID: org})
	assert.True(t, exists(repo), "repository 3's token is not organization 3's")
	assert.True(t, exists(otherOrg))
	assert.True(t, exists(1), "personal access tokens stay")

	require.NoError(t, auth_model.DeleteOwnedAccessTokens(t.Context(), auth_model.AccessTokenOwnerRepo, 3, 0))
	assert.False(t, exists(repo))
	require.Error(t, auth_model.DeleteOwnedAccessTokens(t.Context(), auth_model.AccessTokenOwnerUser, 1, 0))
	assert.True(t, exists(1))
}

func TestRotateAndRevokeOwnedAccessToken(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithSystem(t.Context(), "test")
	opts := auth_model.FindOwnedAccessTokensOptions{OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 1}
	token := &auth_model.AccessToken{Name: "rotate-me", OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 1, Mode: perm.AccessModeWrite, Scope: "read:repository", ResourceAllRepos: true}
	require.NoError(t, auth_model.NewAccessToken(ctx, token, nil))
	first := token.Token

	_, err := auth_model.RotateOwnedAccessToken(ctx, opts, token.ID, "not-the-hash", 0, 2)
	require.ErrorAs(t, err, &auth_model.ErrAccessTokenNotExist{}, "a token rotating itself must still hold the secret it authenticated with")
	_, err = auth_model.RotateOwnedAccessToken(ctx, auth_model.FindOwnedAccessTokensOptions{OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 2}, token.ID, "", 0, 2)
	require.ErrorAs(t, err, &auth_model.ErrAccessTokenNotExist{}, "another repository's token is not found")

	expires := timeutil.TimeStampNow().Add(3600)
	rotated, err := auth_model.RotateOwnedAccessToken(ctx, opts, token.ID, token.TokenHash, expires, 2)
	require.NoError(t, err)
	assert.Equal(t, token.ID, rotated.ID)
	assert.NotEqual(t, first, rotated.Token)
	_, err = auth_model.GetAccessTokenBySHA(ctx, first)
	require.ErrorAs(t, err, &auth_model.ErrAccessTokenNotExist{}, "the old secret stops working")
	got, err := auth_model.GetAccessTokenBySHA(ctx, rotated.Token)
	require.NoError(t, err)
	assert.Equal(t, expires, got.ExpiresUnix)
	assert.EqualValues(t, 2, got.RotatedByID)
	assert.NotZero(t, got.RotatedUnix)
	assert.Equal(t, "rotate-me", got.Name)
	unittest.AssertExistsAndLoadBean(t, &audit_model.Entry{Action: "credential.access_token.rotated", TargetID: token.ID})

	require.NoError(t, auth_model.DeleteOwnedAccessToken(ctx, opts, token.ID, 2))
	_, err = auth_model.GetAccessTokenBySHA(ctx, rotated.Token)
	require.ErrorAs(t, err, &auth_model.ErrAccessTokenNotExist{}, "a revoked token stops working")
	tomb, err := auth_model.GetOwnedAccessTokenByID(ctx, token.ID)
	require.NoError(t, err, "the tombstone keeps the name for history")
	assert.Equal(t, "rotate-me", tomb.Name)
	assert.True(t, tomb.IsRevoked())
	assert.False(t, tomb.IsUsable())
	assert.Empty(t, tomb.TokenLastEight)
	assert.EqualValues(t, 2, tomb.RevokedByID)

	count, err := db.Count[auth_model.AccessToken](ctx, opts)
	require.NoError(t, err)
	assert.Zero(t, count, "a revoked token isn't listed")
	require.ErrorAs(t, auth_model.DeleteOwnedAccessToken(ctx, opts, token.ID, 2), &auth_model.ErrAccessTokenNotExist{})
	_, err = auth_model.RotateOwnedAccessToken(ctx, opts, token.ID, "", 0, 2)
	require.ErrorAs(t, err, &auth_model.ErrAccessTokenNotExist{}, "a revoked token can't be rotated back")

	// its name can be used again
	again := &auth_model.AccessToken{Name: "rotate-me", OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 1, Mode: perm.AccessModeRead, Scope: "read:repository", ResourceAllRepos: true}
	require.NoError(t, auth_model.NewAccessToken(ctx, again, nil))
}
