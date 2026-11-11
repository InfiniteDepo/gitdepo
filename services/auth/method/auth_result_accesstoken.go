// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package method

import (
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/timeutil"
	"forgejo.org/services/auth"
	"forgejo.org/services/authz"
)

var _ auth.AuthenticationResult = &accessTokenAuthenticationResult{}

type accessTokenAuthenticationResult struct {
	*auth.BaseAuthenticationResult
	id      int64
	name    string
	user    *user_model.User
	scope   auth_model.AccessTokenScope
	reducer authz.AuthorizationReducer
	expires timeutil.TimeStamp
	// restricted is AccessToken.RestrictsAccount: a user's own token narrower than the account it acts as
	restricted bool
}

func (r *accessTokenAuthenticationResult) User() *user_model.User {
	return r.user
}

func (r *accessTokenAuthenticationResult) AccessTokenID() int64 {
	return r.id
}

func (r *accessTokenAuthenticationResult) Scope() optional.Option[auth_model.AccessTokenScope] {
	return optional.Some(r.scope)
}

func (r *accessTokenAuthenticationResult) Reducer() authz.AuthorizationReducer {
	return r.reducer
}

func (r *accessTokenAuthenticationResult) ExpiresAt() optional.Option[timeutil.TimeStamp] {
	if r.expires == 0 {
		return optional.None[timeutil.TimeStamp]()
	}
	return optional.Some(r.expires)
}

func (r *accessTokenAuthenticationResult) Credential() audit_model.Credential {
	return audit_model.Credential{Type: audit_model.CredentialAccessToken, ID: r.id, Name: r.name, OwnerID: r.user.ID, Restricted: r.restricted}
}
