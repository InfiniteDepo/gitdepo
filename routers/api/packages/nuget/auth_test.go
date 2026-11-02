// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package nuget

import (
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
)

func TestCredential(t *testing.T) {
	u := &user_model.User{ID: 7}
	r := &nugetAuthenticationResult{user: u, token: &auth_model.AccessToken{ID: 3, Name: "nuget-key"}}
	assert.Equal(t, audit_model.Credential{Type: audit_model.CredentialAccessToken, ID: 3, Name: "nuget-key", OwnerID: 7}, r.Credential())
}
