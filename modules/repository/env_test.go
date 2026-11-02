// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"slices"
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lastEnv is the value a child process sees for key: the last one in env.
func lastEnv(env []string, key string) (string, bool) {
	for _, kv := range slices.Backward(env) {
		if v, ok := strings.CutPrefix(kv, key+"="); ok {
			return v, true
		}
	}
	return "", false
}

func TestPushingEnvironmentAudit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Setenv(EnvAuditIP, "203.0.113.9")
	t.Setenv(EnvAuditCredential, "access_token:1")
	t.Setenv(EnvAuditSudoBy, "1") // inherited: must not survive
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})

	env := PushingEnvironment(t.Context(), doer, repo)
	for _, k := range []string{EnvAuditCredential, EnvAuditIP, EnvAuditRequestID, EnvAuditSudoBy} {
		v, ok := lastEnv(env, k)
		assert.True(t, ok, k)
		assert.Empty(t, v, k) // no actor: set, but empty
	}

	ctx := audit_model.WithActor(t.Context(), &audit_model.Actor{
		Type: audit_model.ActorUser, ID: 2, IP: "192.0.2.1", RequestID: "req",
		Credential: audit_model.Credential{Type: audit_model.CredentialSession, OwnerID: 2},
	})
	env = InternalPushingEnvironment(ctx, doer, repo)
	v, _ := lastEnv(env, EnvAuditCredential)
	assert.Equal(t, "session:0", v)
	v, _ = lastEnv(env, EnvAuditIP)
	assert.Equal(t, "192.0.2.1", v)
	v, _ = lastEnv(env, EnvAuditRequestID)
	assert.Equal(t, "req", v)
	v, _ = lastEnv(env, EnvAuditSudoBy)
	assert.Empty(t, v)

	ctx = audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, SudoByID: 1})
	v, _ = lastEnv(FullPushingEnvironment(ctx, doer, doer, repo, repo.Name, 0), EnvAuditSudoBy)
	assert.Equal(t, "1", v)
}
