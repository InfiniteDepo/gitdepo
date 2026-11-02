// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"testing"

	"forgejo.org/models/perm"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateOwnedTokenScope(t *testing.T) {
	for _, scope := range []AccessTokenScope{
		"",
		"read:repository",
		"write:repository,write:issue,write:package,read:organization",
		"read:issue,read:package",
	} {
		require.NoError(t, ValidateOwnedTokenScope(scope), scope)
	}
	for _, scope := range []AccessTokenScope{
		"all",
		"public-only",
		"write:organization",
		"read:user",
		"read:repository,write:user",
		"read:notification",
		"read:admin",
		"read:activitypub",
		"read:misc",
	} {
		require.ErrorIs(t, ValidateOwnedTokenScope(scope), ErrOwnedTokenScope, scope)
	}
	require.Error(t, ValidateOwnedTokenScope("read:nonsense"))
}

func TestValidateOwnedTokenMode(t *testing.T) {
	for _, mode := range []perm.AccessMode{perm.AccessModeRead, perm.AccessModeWrite, perm.AccessModeAdmin} {
		require.NoError(t, ValidateOwnedTokenMode(mode))
	}
	for _, mode := range []perm.AccessMode{perm.AccessModeNone, perm.AccessModeOwner} {
		assert.Error(t, ValidateOwnedTokenMode(mode))
	}
}
