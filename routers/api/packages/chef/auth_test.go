// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package chef

import (
	"testing"

	audit_model "forgejo.org/models/audit"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
)

func TestCredential(t *testing.T) {
	u := &user_model.User{ID: 7}
	r := &chefAuthenticationResult{user: u}
	assert.Equal(t, audit_model.Credential{Type: audit_model.CredentialChefKey, OwnerID: 7}, r.Credential())
}
