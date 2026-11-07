// Copyright 2022 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package nuget

import (
	"errors"
	"fmt"
	"net/http"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	"forgejo.org/services/auth"
	"forgejo.org/services/authz"
)

var (
	_ auth.Method               = &Auth{}
	_ auth.AuthenticationResult = &nugetAuthenticationResult{}
)

type nugetAuthenticationResult struct {
	*auth.BaseAuthenticationResult
	user  *user_model.User
	token *auth_model.AccessToken
}

func (r *nugetAuthenticationResult) User() *user_model.User {
	return r.user
}

type Auth struct{}

// https://docs.microsoft.com/en-us/nuget/api/package-publish-resource#request-parameters
func (a *Auth) Verify(req *http.Request, w http.ResponseWriter, sess auth.SessionStore) auth.MethodOutput {
	apiKey := req.Header.Get("X-NuGet-ApiKey")
	if apiKey == "" {
		return &auth.AuthenticationNotAttempted{}
	}
	token, err := auth_model.GetAccessTokenBySHA(req.Context(), apiKey)
	if err != nil {
		if !auth_model.IsErrAccessTokenNotExist(err) && !auth_model.IsErrAccessTokenEmpty(err) && !auth_model.IsErrAccessTokenExpired(err) {
			return &auth.AuthenticationError{Error: fmt.Errorf("nuget auth GetAccessTokenBySHA: %w", err)}
		}
		return &auth.AuthenticationAttemptedIncorrectCredential{Error: err}
	}

	u, err := auth.AccessTokenUser(req.Context(), token)
	if ownerErr := (*auth.CredentialOwnerError)(nil); errors.As(err, &ownerErr) {
		return &auth.AuthenticationAttemptedIncorrectCredential{Error: err}
	} else if err != nil {
		return &auth.AuthenticationError{Error: fmt.Errorf("nuget auth AccessTokenUser: %w", err)}
	}

	if err := authz.CheckScopePolicyInUse(u, token.Scope, token.ReachesAllRepos()); errors.Is(err, authz.ErrScopePolicyEnforced) {
		return &auth.AuthenticationAttemptedIncorrectCredential{Error: fmt.Errorf("%w; replace it with a token that follows the policy", err), UserID: u.ID}
	} else if err != nil {
		return &auth.AuthenticationError{Error: fmt.Errorf("nuget auth CheckScopePolicyInUse: %w", err)}
	}

	if err := token.UpdateLastUsed(req.Context(), auth.TokenUseIP(req)); err != nil {
		log.Error("UpdateLastUsed:  %v", err)
	}

	return &auth.AuthenticationSuccess{Result: &nugetAuthenticationResult{user: u, token: token}}
}

func (r *nugetAuthenticationResult) Credential() audit_model.Credential {
	return audit_model.Credential{Type: audit_model.CredentialAccessToken, ID: r.token.ID, Name: r.token.Name, OwnerID: r.user.ID, Restricted: r.token.RestrictsAccount()}
}
