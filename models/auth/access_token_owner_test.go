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

func TestAccessTokenRestrictsAccount(t *testing.T) {
	for _, c := range []struct {
		name  string
		token AccessToken
		want  bool
	}{
		{"personal, every repository", AccessToken{OwnerType: AccessTokenOwnerUser, ResourceAllRepos: true, Scope: "write:user"}, false},
		{"personal, public only", AccessToken{OwnerType: AccessTokenOwnerUser, ResourceAllRepos: true, Scope: "public-only,write:user"}, true},
		{"personal, some repositories", AccessToken{OwnerType: AccessTokenOwnerUser, Scope: "write:repository"}, true},
		{"personal, unreadable scope", AccessToken{OwnerType: AccessTokenOwnerUser, ResourceAllRepos: true, Scope: "nonsense"}, true},
		{"organization, some repositories", AccessToken{OwnerType: AccessTokenOwnerOrg, OwnerID: 3, Scope: "write:repository"}, false},
		{"repository", AccessToken{OwnerType: AccessTokenOwnerRepo, OwnerID: 1, Scope: "write:repository"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, c.token.RestrictsAccount())
		})
	}
}
