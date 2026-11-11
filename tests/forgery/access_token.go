// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package forgery

import (
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/require"
)

type CreateAccessTokenOptions struct {
	Name  string // if nil a unique name (derived from the test name) will be generated
	Scope string // scope of which resources the access token may access, if nil all scopes are granted.

	// If specified, this access token becomes repo-specific to specified repositories.
	RepositoryIDs []int64
}

func CreateAccessToken(t testing.TB, user *user_model.User, opts *CreateAccessTokenOptions) *auth_model.AccessToken {
	t.Helper()

	require.NotNil(t, user, "An existing user is required")
	if opts == nil {
		opts = &CreateAccessTokenOptions{}
	}

	if opts.Name == "" {
		opts.Name = "token-" + uniqueSafeName(t.Name())
	}
	if opts.Scope == "" {
		opts.Scope = "all"
	}

	resoureceAllRepos := len(opts.RepositoryIDs) == 0

	scope, err := auth_model.AccessTokenScope(opts.Scope).Normalize()
	require.NoError(t, err)

	accessToken := &auth_model.AccessToken{
		Name:             opts.Name,
		UID:              user.ID,
		Scope:            scope,
		ResourceAllRepos: resoureceAllRepos,
	}
	var resourceRepos []*auth_model.AccessTokenResourceRepo
	for _, repoID := range opts.RepositoryIDs {
		resourceRepos = append(resourceRepos, &auth_model.AccessTokenResourceRepo{RepoID: repoID})
	}
	require.NoError(t, auth_model.NewAccessToken(audit_model.WithSystem(t.Context(), "forgery"), accessToken, resourceRepos))
	for _, accessTokenResourceRepo := range resourceRepos {
		t.Cleanup(func() {
			unittest.AssertSuccessfulDelete(t, &auth_model.AccessTokenResourceRepo{ID: accessTokenResourceRepo.ID})
		})
	}

	t.Cleanup(func() {
		unittest.AssertSuccessfulDelete(t, &auth_model.AccessToken{ID: accessToken.ID})
	})

	return accessToken
}
