// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"errors"
	"fmt"
	"strings"
	"time"

	auth_model "forgejo.org/models/auth"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
)

var (
	ErrScopeNotAllowed           = errors.New("access token scope not allowed")
	ErrScopeNeedsRepoRestriction = errors.New("access token scope must be limited to specified repositories")
	ErrScopePolicyConfig         = errors.New("invalid access token scope policy")
	ErrScopePolicyEnforced       = errors.New("access token breaks the access token scope policy")
)

// ScopePolicyError is returned by ValidateScopePolicy; it wraps ErrScopeNotAllowed or ErrScopeNeedsRepoRestriction.
type ScopePolicyError struct {
	Err     error
	Scope   string
	Allowed []string // the scopes the owner may choose, with ErrScopeNotAllowed
}

func (e *ScopePolicyError) Error() string {
	if e.Err == ErrScopeNotAllowed {
		return fmt.Sprintf("%v: %s; allowed scopes: %s", e.Err, e.Scope, strings.Join(e.Allowed, ", "))
	}
	return fmt.Sprintf("%v: %s", e.Err, e.Scope)
}

func (e *ScopePolicyError) Unwrap() error {
	return e.Err
}

// policyScope parses a configured list. A set list must name only permission scopes: "" and "sudo", which parsing
// would silently drop, are refused so that a list can't turn into "empty = all".
func policyScope(key string, scopes []string) (auth_model.AccessTokenScope, error) {
	for _, s := range scopes {
		if s == "" || s == "sudo" {
			return "", fmt.Errorf("%w: [security] %s: invalid scope %q", ErrScopePolicyConfig, key, s)
		}
	}
	scope, err := auth_model.AccessTokenScope(strings.Join(scopes, ",")).Normalize()
	if err != nil {
		return "", fmt.Errorf("%w: [security] %s: %w", ErrScopePolicyConfig, key, err)
	}
	if len(scopes) > 0 && !scope.HasPermissionScope() {
		return "", fmt.Errorf("%w: [security] %s: %q names no permission scope", ErrScopePolicyConfig, key, strings.Join(scopes, ","))
	}
	return scope, nil
}

// CheckScopePolicy checks the configured scope policy at startup.
func CheckScopePolicy() error {
	if _, err := policyScope("ACCESS_TOKEN_ALLOWED_SCOPES", setting.AccessTokenScopes.Allowed); err != nil {
		return err
	}
	if _, err := policyScope("ACCESS_TOKEN_SCOPES_REQUIRING_REPO_RESTRICTION", setting.AccessTokenScopes.RequireRepoRestriction); err != nil {
		return err
	}
	if _, err := scopePolicyEnforceAfter(); err != nil {
		return err
	}
	// A scope that a repository-specific token can't have would make every such token impossible to create.
	for _, s := range setting.AccessTokenScopes.RequireRepoRestriction {
		if err := ValidateRepositoryResource(false, auth_model.AccessTokenScope(s), 1); err != nil {
			return fmt.Errorf("%w: [security] ACCESS_TOKEN_SCOPES_REQUIRING_REPO_RESTRICTION: %s can't be limited to specified repositories", ErrScopePolicyConfig, s)
		}
	}
	return nil
}

// scopePolicyExempt: site admins may create any token, but only while they can log in.
func scopePolicyExempt(owner *user_model.User) bool {
	return owner.IsAdmin && owner.IsActive && !owner.ProhibitLogin
}

// AllowedScopes returns the read/write scopes the owner may choose, or nil when any scope is allowed.
func AllowedScopes(owner *user_model.User) ([]string, error) {
	if scopePolicyExempt(owner) || len(setting.AccessTokenScopes.Allowed) == 0 {
		return nil, nil
	}
	allowed, err := policyScope("ACCESS_TOKEN_ALLOWED_SCOPES", setting.AccessTokenScopes.Allowed)
	if err != nil {
		return nil, err
	}
	scopes := []string{}
	for _, category := range auth_model.AllAccessTokenScopeCategories {
		for _, level := range []auth_model.AccessTokenScopeLevel{auth_model.Read, auth_model.Write} {
			for _, s := range auth_model.GetRequiredScopes(level, category) {
				if has, err := allowed.HasScope(s); err != nil {
					return nil, err
				} else if has {
					scopes = append(scopes, string(s))
				}
			}
		}
	}
	return scopes, nil
}

// ValidateScopePolicy checks the scope of a new access token or authorized integration of owner against the policy.
func ValidateScopePolicy(owner *user_model.User, scope auth_model.AccessTokenScope, resourceAllRepos bool) error {
	if scopePolicyExempt(owner) {
		return nil
	}

	if len(setting.AccessTokenScopes.Allowed) > 0 {
		allowed, err := policyScope("ACCESS_TOKEN_ALLOWED_SCOPES", setting.AccessTokenScopes.Allowed)
		if err != nil {
			return err
		}
		for _, s := range scope.StringSlice() {
			// public-only only narrows a token.
			if s == "" || auth_model.AccessTokenScope(s) == auth_model.AccessTokenScopePublicOnly {
				continue
			}
			if has, err := allowed.HasScope(auth_model.AccessTokenScope(s)); err != nil {
				return err
			} else if !has {
				list, err := AllowedScopes(owner)
				if err != nil {
					return err
				}
				return &ScopePolicyError{Err: ErrScopeNotAllowed, Scope: s, Allowed: list}
			}
		}
	}

	if resourceAllRepos {
		if _, err := policyScope("ACCESS_TOKEN_SCOPES_REQUIRING_REPO_RESTRICTION", setting.AccessTokenScopes.RequireRepoRestriction); err != nil {
			return err
		}
		for _, s := range setting.AccessTokenScopes.RequireRepoRestriction {
			if has, err := scope.HasScope(auth_model.AccessTokenScope(s)); err != nil {
				return err
			} else if has {
				return &ScopePolicyError{Err: ErrScopeNeedsRepoRestriction, Scope: s}
			}
		}
	}
	return nil
}

// scopePolicyEnforceAfter returns the time after which existing tokens must follow the policy, or zero for never.
func scopePolicyEnforceAfter() (time.Time, error) {
	value := setting.AccessTokenScopes.EnforceAfter
	if value == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.DateOnly, value); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("%w: [security] ACCESS_TOKEN_SCOPE_POLICY_ENFORCE_AFTER: %q is neither RFC 3339 nor YYYY-MM-DD", ErrScopePolicyConfig, value)
}

// CheckScopePolicyInUse checks a token or authorized integration of owner that is being used, once the policy is
// enforced for existing ones. The caller adds how to fix it.
func CheckScopePolicyInUse(owner *user_model.User, scope auth_model.AccessTokenScope, resourceAllRepos bool) error {
	after, err := scopePolicyEnforceAfter()
	if err != nil {
		return err
	}
	if after.IsZero() || timeutil.TimeStampNow().AsTime().Before(after) {
		return nil
	}
	if err := ValidateScopePolicy(owner, scope, resourceAllRepos); err != nil {
		if _, ok := errors.AsType[*ScopePolicyError](err); ok {
			return fmt.Errorf("%w: %w", ErrScopePolicyEnforced, err)
		}
		return err
	}
	return nil
}
