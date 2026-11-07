// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit_test

import (
	"context"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
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

func TestIsOwnAct(t *testing.T) {
	user := func(credential string, sudoBy int64) context.Context {
		return audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, SudoByID: sudoBy, Credential: audit_model.Credential{Type: credential, ID: 1}})
	}
	assert.False(t, audit_model.IsOwnAct(t.Context()), "no actor")
	assert.False(t, audit_model.IsOwnAct(user(audit_model.CredentialAccessToken, 1)), "sudo")
	assert.False(t, audit_model.IsOwnAct(user(audit_model.CredentialOAuth2Grant, 0)))
	assert.False(t, audit_model.IsOwnAct(user(audit_model.CredentialAuthorizedIntegration, 0)))
	assert.True(t, audit_model.IsOwnAct(user(audit_model.CredentialAccessToken, 0)))
	restricted := audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, Credential: audit_model.Credential{Type: audit_model.CredentialAccessToken, ID: 1, Restricted: true}})
	assert.False(t, audit_model.IsOwnAct(restricted), "a token limited to public data or to some repositories")
	assert.True(t, audit_model.IsOwnAct(user(audit_model.CredentialSession, 0)))
	assert.True(t, audit_model.IsOwnAct(audit_model.WithSystem(t.Context(), "test")))
	require.ErrorIs(t, audit_model.CheckOwnAct(t.Context()), audit_model.ErrNotOwnAct)
	require.NoError(t, audit_model.CheckOwnAct(user(audit_model.CredentialAccessToken, 0)))
}

// A refusal is recorded, aggregated and fail open; inside a transaction it is not (it would be rolled back with it).
func TestCheckOwnActRecordsRefusal(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	audit_model.ResetActivity()
	grant := audit_model.WithActor(db.DefaultContext, &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, Credential: audit_model.Credential{Type: audit_model.CredentialOAuth2Grant, ID: 4}})
	refusals := func() int {
		return unittest.GetCount(t, &audit_model.Entry{Action: "auth.refused"}, builder.Like{"data", "not_own_act"})
	}
	before := refusals()
	require.ErrorIs(t, db.WithTx(grant, audit_model.CheckOwnAct), audit_model.ErrNotOwnAct)
	assert.Equal(t, before, refusals(), "not inside a transaction")
	require.ErrorIs(t, audit_model.CheckOwnAct(grant), audit_model.ErrNotOwnAct)
	assert.Equal(t, before+1, refusals())
	require.ErrorIs(t, audit_model.CheckOwnAct(grant), audit_model.ErrNotOwnAct)
	assert.Equal(t, before+1, refusals(), "aggregated")
}
