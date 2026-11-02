// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"strings"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateScopePolicy(t *testing.T) {
	user := &user_model.User{IsActive: true}
	admin := &user_model.User{IsActive: true, IsAdmin: true}
	inactiveAdmin := &user_model.User{IsAdmin: true}
	prohibitedAdmin := &user_model.User{IsActive: true, IsAdmin: true, ProhibitLogin: true}

	none := setting.AccessTokenScopePolicy{}
	allowed := setting.AccessTokenScopePolicy{Allowed: []string{"write:repository", "read:issue"}}
	allListed := setting.AccessTokenScopePolicy{Allowed: []string{"all"}}
	restrict := setting.AccessTokenScopePolicy{RequireRepoRestriction: []string{"read:repository"}}

	everyScope := "write:activitypub,write:admin,write:misc,write:notification,write:organization,write:package,write:issue,write:repository,write:user"

	for _, tc := range []struct {
		name     string
		policy   setting.AccessTokenScopePolicy
		owner    *user_model.User
		scope    string
		allRepos bool
		err      error
	}{
		{"no policy allows all", none, user, "all", true, nil},
		{"listed scope", allowed, user, "write:repository", true, nil},
		{"write implies read", allowed, user, "read:repository", true, nil},
		{"read does not imply write", allowed, user, "write:issue", true, ErrScopeNotAllowed},
		{"unlisted scope", allowed, user, "read:user", true, ErrScopeNotAllowed},
		{"one unlisted scope among listed ones", allowed, user, "read:issue,read:user", true, ErrScopeNotAllowed},
		{"public-only is always allowed", allowed, user, "public-only,read:issue", true, nil},
		{"all needs all listed", allowed, user, "all", true, ErrScopeNotAllowed},
		{"every scope normalizes to all", allowed, user, everyScope, true, ErrScopeNotAllowed},
		{"all listed", allListed, user, "all", true, nil},
		{"every scope against all", allListed, user, everyScope, true, nil},
		{"every scope against every write scope", setting.AccessTokenScopePolicy{Allowed: strings.Split(everyScope, ",")}, user, everyScope, true, nil},
		{"all against every write scope", setting.AccessTokenScopePolicy{Allowed: strings.Split(everyScope, ",")}, user, "all", true, nil},
		{"admin is exempt", allowed, admin, "all", true, nil},
		{"inactive admin is not exempt", allowed, inactiveAdmin, "all", true, ErrScopeNotAllowed},
		{"prohibited admin is not exempt", allowed, prohibitedAdmin, "all", true, ErrScopeNotAllowed},
		{"restriction: all repos refused", restrict, user, "read:repository", true, ErrScopeNeedsRepoRestriction},
		{"restriction: write implies listed read", restrict, user, "write:repository", true, ErrScopeNeedsRepoRestriction},
		{"restriction: read does not imply listed write", setting.AccessTokenScopePolicy{RequireRepoRestriction: []string{"write:repository"}}, user, "read:repository", true, nil},
		{"restriction: all token refused", restrict, user, "all", true, ErrScopeNeedsRepoRestriction},
		{"restriction: specific repos pass", restrict, user, "read:repository", false, nil},
		{"restriction: other scope passes", restrict, user, "read:issue", true, nil},
		{"restriction: admin is exempt", restrict, admin, "read:repository", true, nil},
		{"invalid config fails closed", setting.AccessTokenScopePolicy{Allowed: []string{"read:nope"}}, user, "read:issue", true, ErrScopePolicyConfig},
		{"sudo-only list fails closed", setting.AccessTokenScopePolicy{Allowed: []string{"sudo"}}, user, "read:issue", true, ErrScopePolicyConfig},
		{"empty items fail closed", setting.AccessTokenScopePolicy{Allowed: []string{"", ""}}, user, "read:issue", true, ErrScopePolicyConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer test.MockVariableValue(&setting.AccessTokenScopes, tc.policy)()
			scope, err := auth_model.AccessTokenScope(tc.scope).Normalize()
			require.NoError(t, err)
			err = ValidateScopePolicy(tc.owner, scope, tc.allRepos)
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}

	t.Run("error lists the allowed scopes", func(t *testing.T) {
		defer test.MockVariableValue(&setting.AccessTokenScopes, allowed)()
		err := ValidateScopePolicy(user, auth_model.AccessTokenScopeReadUser, true)
		require.ErrorIs(t, err, ErrScopeNotAllowed)
		require.ErrorContains(t, err, "read:user")
		require.ErrorContains(t, err, "read:issue, read:repository, write:repository")
	})

	t.Run("combined with ValidateAccessToken", func(t *testing.T) {
		defer test.MockVariableValue(&setting.AccessTokenScopes, restrict)()
		token := &auth_model.AccessToken{Scope: auth_model.AccessTokenScopeReadRepository, ResourceAllRepos: true}
		require.ErrorIs(t, ValidateAccessToken(user, token, nil), ErrScopeNeedsRepoRestriction)
		require.NoError(t, ValidateAccessToken(admin, token, nil))

		token.ResourceAllRepos = false
		require.ErrorIs(t, ValidateAccessToken(user, token, nil), ErrSpecifiedReposNone)
		require.NoError(t, ValidateAccessToken(user, token, []*auth_model.AccessTokenResourceRepo{{RepoID: 1}}))
	})
}

func TestAllowedScopes(t *testing.T) {
	user := &user_model.User{IsActive: true}
	admin := &user_model.User{IsActive: true, IsAdmin: true}

	allowed, err := AllowedScopes(user)
	require.NoError(t, err)
	assert.Nil(t, allowed)

	defer test.MockVariableValue(&setting.AccessTokenScopes, setting.AccessTokenScopePolicy{Allowed: []string{"write:repository", "read:issue"}})()
	allowed, err = AllowedScopes(user)
	require.NoError(t, err)
	assert.Equal(t, []string{"read:issue", "read:repository", "write:repository"}, allowed)

	allowed, err = AllowedScopes(admin)
	require.NoError(t, err)
	assert.Nil(t, allowed)

	defer test.MockVariableValue(&setting.AccessTokenScopes, setting.AccessTokenScopePolicy{Allowed: []string{"public-only"}})()
	_, err = AllowedScopes(user)
	require.ErrorIs(t, err, ErrScopePolicyConfig)
}

func TestCheckScopePolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy setting.AccessTokenScopePolicy
		err    string
	}{
		{"empty", setting.AccessTokenScopePolicy{}, ""},
		{"valid", setting.AccessTokenScopePolicy{Allowed: []string{"all"}, RequireRepoRestriction: []string{"read:repository", "write:issue"}}, ""},
		{"unknown allowed scope", setting.AccessTokenScopePolicy{Allowed: []string{"read:nope"}}, "ACCESS_TOKEN_ALLOWED_SCOPES"},
		{"unknown restricted scope", setting.AccessTokenScopePolicy{RequireRepoRestriction: []string{"read:nope"}}, "ACCESS_TOKEN_SCOPES_REQUIRING_REPO_RESTRICTION"},
		{"restricted scope without repository support", setting.AccessTokenScopePolicy{RequireRepoRestriction: []string{"read:user"}}, "read:user"},
		{"restricted all", setting.AccessTokenScopePolicy{RequireRepoRestriction: []string{"all"}}, "all"},
		{"restricted public-only", setting.AccessTokenScopePolicy{RequireRepoRestriction: []string{"public-only"}}, "public-only"},
		{"allowed sudo", setting.AccessTokenScopePolicy{Allowed: []string{"sudo"}}, "ACCESS_TOKEN_ALLOWED_SCOPES"},
		{"allowed empty items", setting.AccessTokenScopePolicy{Allowed: []string{"", ""}}, "ACCESS_TOKEN_ALLOWED_SCOPES"},
		{"allowed public-only only", setting.AccessTokenScopePolicy{Allowed: []string{"public-only"}}, "names no permission scope"},
		{"restricted sudo", setting.AccessTokenScopePolicy{RequireRepoRestriction: []string{"sudo"}}, "ACCESS_TOKEN_SCOPES_REQUIRING_REPO_RESTRICTION"},
		{"restricted empty items", setting.AccessTokenScopePolicy{RequireRepoRestriction: []string{""}}, "ACCESS_TOKEN_SCOPES_REQUIRING_REPO_RESTRICTION"},
		{"enforce after date", setting.AccessTokenScopePolicy{EnforceAfter: "2030-01-02"}, ""},
		{"enforce after RFC 3339", setting.AccessTokenScopePolicy{EnforceAfter: "2030-01-02T03:04:05Z"}, ""},
		{"enforce after bad value", setting.AccessTokenScopePolicy{EnforceAfter: "2030-01-02 03:04"}, "ACCESS_TOKEN_SCOPE_POLICY_ENFORCE_AFTER"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer test.MockVariableValue(&setting.AccessTokenScopes, tc.policy)()
			err := CheckScopePolicy()
			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.err)
			}
		})
	}
}

func TestCheckScopePolicyInUse(t *testing.T) {
	user := &user_model.User{IsActive: true}
	admin := &user_model.User{IsActive: true, IsAdmin: true}
	inactiveAdmin := &user_model.User{IsAdmin: true}
	prohibitedAdmin := &user_model.User{IsActive: true, IsAdmin: true, ProhibitLogin: true}
	date := time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC)
	before, after := date.Add(-time.Second), date.Add(time.Second)

	for _, tc := range []struct {
		name         string
		enforceAfter string
		now          time.Time
		owner        *user_model.User
		scope        auth_model.AccessTokenScope
		allRepos     bool
		err          error
	}{
		{"unset", "", after, user, "all", true, nil},
		{"before the date", "2030-01-02", before, user, "all", true, nil},
		{"after the date", "2030-01-02", after, user, "all", true, ErrScopePolicyEnforced},
		{"RFC 3339 before", "2030-01-02T01:00:00+01:00", before, user, "all", true, nil},
		{"RFC 3339 after", "2030-01-02T01:00:00+01:00", after, user, "all", true, ErrScopePolicyEnforced},
		{"allowed scope after the date", "2030-01-02", after, user, "read:repository", false, nil},
		{"repo restriction after the date", "2030-01-02", after, user, "write:repository", true, ErrScopePolicyEnforced},
		{"admin is exempt", "2030-01-02", after, admin, "all", true, nil},
		{"inactive admin is not exempt", "2030-01-02", after, inactiveAdmin, "all", true, ErrScopePolicyEnforced},
		{"prohibited admin is not exempt", "2030-01-02", after, prohibitedAdmin, "all", true, ErrScopePolicyEnforced},
		{"bad value fails closed", "tomorrow", after, user, "read:repository", false, ErrScopePolicyConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer test.MockVariableValue(&setting.AccessTokenScopes, setting.AccessTokenScopePolicy{
				Allowed:                []string{"write:repository"},
				RequireRepoRestriction: []string{"write:repository"},
				EnforceAfter:           tc.enforceAfter,
			})()
			timeutil.MockSet(tc.now)
			defer timeutil.MockUnset()
			err := CheckScopePolicyInUse(tc.owner, tc.scope, tc.allRepos)
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}

	t.Run("error lists only the allowed scopes", func(t *testing.T) {
		defer test.MockVariableValue(&setting.AccessTokenScopes, setting.AccessTokenScopePolicy{Allowed: []string{"read:issue"}, EnforceAfter: "2030-01-02"})()
		timeutil.MockSet(after)
		defer timeutil.MockUnset()
		err := CheckScopePolicyInUse(user, auth_model.AccessTokenScopeReadUser, false)
		require.ErrorIs(t, err, ErrScopeNotAllowed)
		assert.EqualError(t, err, "access token breaks the access token scope policy: access token scope not allowed: read:user; allowed scopes: read:issue")
	})
}
