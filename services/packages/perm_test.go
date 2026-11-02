// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package packages

import (
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeterminePackageAccessModeTwoFactorRequired(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	_, err := db.GetEngine(ctx).In("id", []int64{3, 17, 23}).Cols("require_two_factor").Update(&user_model.User{RequireTwoFactor: true})
	require.NoError(t, err)

	mode := func(ownerID, doerID int64) perm.AccessMode {
		t.Helper()
		owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: ownerID})
		doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: doerID})
		m, err := DeterminePackageAccessMode(ctx, owner, doer)
		require.NoError(t, err)
		return m
	}

	// user 2 owns org3 (public): read only, as any signed-in user
	assert.Equal(t, perm.AccessModeRead, mode(3, 2))
	// user 5 is a member of the private org 23: none
	assert.Equal(t, perm.AccessModeNone, mode(23, 5))
	// user 29 is restricted and a member of org17: none
	assert.Equal(t, perm.AccessModeNone, mode(17, 29))

	require.NoError(t, db.Insert(ctx, &auth_model.TwoFactor{UID: 2}))
	assert.Equal(t, perm.AccessModeOwner, mode(3, 2))
}
