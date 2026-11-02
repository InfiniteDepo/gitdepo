// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit_test

import (
	"testing"

	audit_model "forgejo.org/models/audit"

	"github.com/stretchr/testify/assert"
)

func TestSetSudoSelf(t *testing.T) {
	a := &audit_model.Actor{Type: audit_model.ActorUser, ID: 1, Name: "admin"}
	a.SetSudo(1, "admin")
	assert.Zero(t, a.SudoByID)
	a.SetSudo(2, "other")
	assert.EqualValues(t, 1, a.SudoByID)
	assert.EqualValues(t, 2, a.ID)
}

func TestCredentialClaim(t *testing.T) {
	for _, c := range []audit_model.Credential{{}, {Type: audit_model.CredentialUnknown}, {Type: audit_model.CredentialSession}, {Type: audit_model.CredentialSystem}, {Type: audit_model.CredentialCLI}, {Type: audit_model.CredentialReverseProxy, ID: 1}} {
		assert.Empty(t, audit_model.CredentialClaim(c), c.Type)
	}
	assert.Equal(t, "access_token:5", audit_model.CredentialClaim(audit_model.Credential{Type: audit_model.CredentialAccessToken, ID: 5}))
	assert.Equal(t, "password:0", audit_model.CredentialClaim(audit_model.Credential{Type: audit_model.CredentialPassword}))

	for _, typ := range []string{audit_model.CredentialAccessToken, audit_model.CredentialOAuth2Grant, audit_model.CredentialAuthorizedIntegration, audit_model.CredentialSSHKey, audit_model.CredentialDeployKey, audit_model.CredentialOrgDeployKey, audit_model.CredentialProjectDeployKey, audit_model.CredentialActionsTask} {
		assert.Equal(t, audit_model.Credential{Type: typ, ID: 7, OwnerID: 3}, audit_model.CredentialFromClaim(typ+":7", 3), typ)
	}
	assert.Equal(t, audit_model.Credential{Type: audit_model.CredentialPassword, OwnerID: 3}, audit_model.CredentialFromClaim("password:5", 3)) // ID forced to 0
	for _, s := range []string{"", "x", "access_token", "access_token:0", "access_token:-1", "access_token:x", "ssh_key:1:2", "session:1", "system:1", "cli:1", "reverse_proxy:1", "unknown:1", "runner:1", "bogus:1"} {
		assert.Equal(t, audit_model.CredentialUnknown, audit_model.CredentialFromClaim(s, 3).Type, s)
	}
}
