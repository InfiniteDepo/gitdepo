// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package method

import (
	"net/http/httptest"
	"testing"

	asymkey_model "forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/lfs"
	"forgejo.org/services/auth"
	"forgejo.org/services/authz"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredential(t *testing.T) {
	u := &user_model.User{ID: 7}
	for _, c := range []struct {
		result auth.AuthenticationResult
		want   audit_model.Credential
	}{
		{&accessTokenAuthenticationResult{id: 3, name: "ci", user: u, reducer: &authz.AllAccessAuthorizationReducer{}}, audit_model.Credential{Type: "access_token", ID: 3, Name: "ci", OwnerID: 7}},
		// a token limited to public data or to some repositories is restricted: never an own act
		{&accessTokenAuthenticationResult{id: 3, name: "ci", user: u, reducer: &authz.PublicReposAuthorizationReducer{}, personal: true}, audit_model.Credential{Type: "access_token", ID: 3, Name: "ci", OwnerID: 7, Restricted: true}},
		{&accessTokenAuthenticationResult{id: 3, name: "ci", user: u, reducer: &authz.SpecificReposAuthorizationReducer{}, personal: true}, audit_model.Credential{Type: "access_token", ID: 3, Name: "ci", OwnerID: 7, Restricted: true}},
		// an organization, project or repository token acts as its own identity: no account to widen
		{&accessTokenAuthenticationResult{id: 3, name: "ci", user: u, reducer: &authz.SpecificReposAuthorizationReducer{}}, audit_model.Credential{Type: "access_token", ID: 3, Name: "ci", OwnerID: 7}},
		{&oAuth2JWTAuthenticationResult{grantID: 4, appID: 5, user: u}, audit_model.Credential{Type: "oauth2_grant", ID: 4, AppID: 5, OwnerID: 7}},
		{&authorizedIntegrationAuthenticationResult{id: 6, name: "deploy", user: u}, audit_model.Credential{Type: "authorized_integration", ID: 6, Name: "deploy", OwnerID: 7}},
		{&httpSignAuthenticationResult{user: u, key: &asymkey_model.PublicKey{ID: 8, Name: "laptop"}}, audit_model.Credential{Type: "ssh_key", ID: 8, Name: "laptop", OwnerID: 7}},
		{&actionsTaskTokenAuthenticationResult{taskID: 9}, audit_model.Credential{Type: "actions_task", ID: 9}},
		{&sessionAuthenticationResult{user: u}, audit_model.Credential{Type: "session", OwnerID: 7}},
		{&basicPaswordAuthenticationResult{user: u}, audit_model.Credential{Type: "password", OwnerID: 7}},
		{&reverseProxyAuthenticationResult{user: u}, audit_model.Credential{Type: "reverse_proxy", OwnerID: 7}},
		{&lfsTokenAuthenticationResult{user: u, claims: &lfs.Claims{}}, audit_model.Credential{Type: "unknown", OwnerID: 7}},
		{&auth.UnauthenticatedResult{}, audit_model.Credential{}},
	} {
		assert.Equal(t, c.want, c.result.Credential(), "%T", c.result)
	}
}

func TestAccessTokenCredential(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.org", nil)
	req.Header.Set("Authorization", "token d2c6c1ba3890b309189a8e618c72a162e4efbf36") // fixture token 1
	output := (&AccessToken{PermitBearer: true, PermitBasic: true}).Verify(req, nil, nil)
	success, ok := output.(*auth.AuthenticationSuccess)
	require.True(t, ok, "%#v", output)
	assert.Equal(t, audit_model.Credential{Type: "access_token", ID: 1, Name: "Token A", OwnerID: 1}, success.Result.Credential())
}
