// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/json"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func auditCtx() context.Context {
	return audit_model.WithActor(db.DefaultContext, &audit_model.Actor{Type: audit_model.ActorUser, ID: 1, Name: "user1"})
}

func auditMax(t *testing.T) int64 {
	var id int64
	_, err := db.GetEngine(db.DefaultContext).Table("audit_event").Select("COALESCE(MAX(id), 0)").Get(&id)
	require.NoError(t, err)
	return id
}

func auditEntries(t *testing.T, since int64) []*audit_model.Entry {
	var entries []*audit_model.Entry
	require.NoError(t, db.GetEngine(db.DefaultContext).Where("id > ?", since).OrderBy("id").Find(&entries))
	return entries
}

func entryData(t *testing.T, e *audit_model.Entry) map[string]any {
	data := map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(e.Data), &data))
	return data
}

// The offline cleanup deletes only a runner that is still offline when it deletes it (R5).
func TestAuditOfflineRunnerSeenAgain(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	stale := unittest.AssertExistsAndLoadBean(t, &ActionRunner{ID: 10000003})
	olderThan := timeutil.TimeStampNow().AddDuration(-RunnerOfflineTime)
	require.Less(t, int64(stale.LastOnline), int64(olderThan))
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE action_runner SET last_online = ? WHERE id = ?", timeutil.TimeStampNow(), stale.ID)
	require.NoError(t, err)

	since := auditMax(t)
	deleted, err := deleteRunner(auditCtx(), stale, offlineRunnerCond(olderThan), "offline")
	require.NoError(t, err)
	assert.False(t, deleted)
	unittest.AssertExistsAndLoadBean(t, &ActionRunner{ID: stale.ID, UUID: stale.UUID})
	assert.Empty(t, auditEntries(t, since))
}

// A re-register through the CLI records only a new runner, or a change of its scope or secret (R6).
func TestAuditRegisterRunner(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	token := "0123456789012345678901234567890123456789"

	since := auditMax(t)
	runner, err := RegisterRunner(ctx, 2, 0, token, nil, "cli-runner", "v1", false)
	require.NoError(t, err)
	entries := auditEntries(t, since)
	require.Len(t, entries, 1)
	assert.Equal(t, "credential.runner.registered", entries[0].Action)
	assert.Equal(t, runner.ID, entries[0].TargetID)
	assert.EqualValues(t, 2, entries[0].OwnerID)
	assert.Equal(t, "user", entryData(t, entries[0])["level"])

	since = auditMax(t)
	_, err = RegisterRunner(ctx, 2, 0, token, nil, "cli-runner", "v2", false)
	require.NoError(t, err)
	assert.Empty(t, auditEntries(t, since))

	since = auditMax(t)
	_, err = RegisterRunner(ctx, 0, 1, token, nil, "cli-runner", "v2", false)
	require.NoError(t, err)
	entries = auditEntries(t, since)
	require.Len(t, entries, 1)
	assert.Equal(t, "credential.runner.updated", entries[0].Action)
	assert.EqualValues(t, 1, entries[0].RepoID)
	data := entryData(t, entries[0])
	assert.Equal(t, map[string]any{"level": "user"}, data["before"])
	assert.Equal(t, map[string]any{"level": "repo"}, data["after"])

	since = auditMax(t)
	_, err = RegisterRunner(ctx, 0, 1, "0123456789012345deadbeefdeadbeefdeadbeef", nil, "cli-runner", "v2", false)
	require.NoError(t, err)
	entries = auditEntries(t, since)
	require.Len(t, entries, 1)
	assert.Equal(t, true, entryData(t, entries[0])["token_reset"])
	assert.NotContains(t, entries[0].Data, "deadbeef")
}

func TestAuditEditRunner(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	runner := unittest.AssertExistsAndLoadBean(t, &ActionRunner{ID: 10000001})

	since := auditMax(t)
	runner.Description = "only the description"
	require.NoError(t, EditRunner(ctx, runner, false))
	assert.Empty(t, auditEntries(t, since))
	assert.Equal(t, "only the description", unittest.AssertExistsAndLoadBean(t, &ActionRunner{ID: runner.ID}).Description)

	since = auditMax(t)
	runner.Name = "renamed"
	require.NoError(t, EditRunner(ctx, runner, false))
	entries := auditEntries(t, since)
	require.Len(t, entries, 1)
	assert.Equal(t, "credential.runner.updated", entries[0].Action)
	data := entryData(t, entries[0])
	assert.Equal(t, map[string]any{"name": "global-online"}, data["before"])
	assert.Equal(t, map[string]any{"name": "renamed"}, data["after"])

	since = auditMax(t)
	oldHash := runner.TokenHash
	runner.GenerateToken()
	require.NoError(t, EditRunner(ctx, runner, true))
	entries = auditEntries(t, since)
	require.Len(t, entries, 1)
	assert.Equal(t, true, entryData(t, entries[0])["token_reset"])
	assert.NotContains(t, entries[0].Data, runner.Token)
	assert.NotEqual(t, oldHash, unittest.AssertExistsAndLoadBean(t, &ActionRunner{ID: runner.ID}).TokenHash)
}
