// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"cmp"
	"slices"
	"sync"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type capture struct {
	mu      sync.Mutex
	lines   []string
	block   chan struct{}
	started chan struct{}
}

func (c *capture) Write(p []byte) (int, error) {
	if c.block != nil {
		c.started <- struct{}{}
		<-c.block
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, string(p))
	return len(p), nil
}
func (c *capture) Close() error { return nil }

func (c *capture) get() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

// shipTo adds a writer with the JSON format to the audit logger, as the log shipping destinations do.
func shipTo(t *testing.T, c *capture, bufferLen int) {
	t.Helper()
	w := log.NewEventWriterBase("audit-capture", "capture", log.WriterMode{Level: log.TRACE, BufferLen: bufferLen})
	w.FormatEvent = log.EventFormatJSONMessage
	w.OutputWriteCloser = c
	l := log.GetManager().GetLogger("audit")
	l.AddWriters(w)
	t.Cleanup(func() { _ = l.RemoveWriter("audit-capture") })
}

func TestSealShipsEachSealedRowOnce(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	const secret = "audit-ship-secret-0001"
	log.RegisterSecret(secret)
	c := &capture{}
	shipTo(t, c, 1000)

	insertUnsealed(t, 2)
	require.NoError(t, db.Insert(t.Context(), &audit_model.Entry{
		CreatedUnix: timeutil.TimeStamp(2000), Category: "auth", Action: "auth.signin.failed", Result: "failure", ActorType: "user", ActorID: 2,
		IP: "203.0.113.5", UserAgent: "UA/1", Data: `{"token":"` + secret + `"}`,
	}))
	require.NoError(t, SealAll(t.Context()))
	require.Eventually(t, func() bool { return len(c.get()) == 4 }, 5*time.Second, 10*time.Millisecond)

	var events []map[string]any
	for _, l := range c.get() {
		assert.NotContains(t, l, secret) // data goes through the same redaction as every field
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(l), &m))
		events = append(events, m)
	}
	entries := allEntries(t) // by id; audit.chain.started has the highest id but seq 1
	require.Len(t, entries, 4)
	slices.SortFunc(entries, func(a, b *audit_model.Entry) int { return cmp.Compare(*a.Seq, *b.Seq) })
	for i, e := range entries {
		m := events[i]
		assert.Equal(t, e.Action, m["message"], "the message is the action key only")
		assert.Equal(t, e.Action, m["action"])
		assert.EqualValues(t, *e.Seq, m["seq"])
		assert.Equal(t, *e.Hash, m["hash"])
		assert.Equal(t, *e.PrevHash, m["prev_hash"])
		if i > 0 {
			assert.Equal(t, events[i-1]["hash"], m["prev_hash"]) // the receiver's continuity check
		}
		assert.Equal(t, "audit", m["logtype"])
		assert.IsType(t, "", m["data"])
	}
	assert.Equal(t, "audit.chain.started", events[0]["action"])
	failed := events[3]
	assert.Equal(t, "warn", failed["level"]) // result != success
	assert.Equal(t, "info", events[1]["level"])
	assert.Equal(t, "203.0.113.5", failed["ip"])
	assert.Equal(t, "UA/1", failed["user_agent"])
	assert.EqualValues(t, 2, failed["actor_id"])

	// nothing new, nothing shipped
	require.NoError(t, SealAll(t.Context()))
	time.Sleep(50 * time.Millisecond)
	assert.Len(t, c.get(), 4)
}

// A writer that never finishes does not slow or fail sealing.
func TestSealDoesNotWaitForTheWriter(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	c := &capture{block: make(chan struct{}), started: make(chan struct{}, 100)}
	shipTo(t, c, 1)
	t.Cleanup(func() { close(c.block) }) // runs before the writer is removed, which waits for it

	insertUnsealed(t, 20)
	done := make(chan error, 1)
	go func() { done <- SealAll(t.Context()) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Seal waited for the writer")
	}
	assert.EqualValues(t, 21, mustVerify(t).LastSeq)
}

// Every top-level field of the design's list is on a shipped event, with the names resolved and the data fields
// promoted out of `data`.
func TestShippedEventHasEveryTopLevelField(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	c := &capture{}
	shipTo(t, c, 1000)
	group := &repo_model.RepoGroup{OwnerID: 3, Name: "proj", LowerName: "proj"}
	require.NoError(t, db.Insert(t.Context(), group))
	require.NoError(t, db.Insert(t.Context(), &audit_model.Entry{
		CreatedUnix: timeutil.TimeStamp(1700000000), Category: "activity", Action: "activity.api.read", Result: "success",
		ActorType: "user", ActorID: 2, ActorName: "user2", SudoByID: 1,
		CredentialType: "access_token", CredentialID: 5, CredentialName: "tok", CredentialOwnerID: 2,
		IP: "203.0.113.5", UserAgent: "UA/1", RequestID: "req1", OwnerID: 3, GroupID: group.ID, RepoID: 1,
		TargetType: "download", TargetID: 7, TargetName: "obj",
		Data: `{"kind":"archive","bytes":1234,"ip_ambiguous":true,"method":"GET","keep":"me"}`,
	}))
	require.NoError(t, SealAll(t.Context()))
	require.Eventually(t, func() bool { return len(c.get()) == 2 }, 5*time.Second, 10*time.Millisecond)
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(c.get()[1]), &m))
	for _, k := range []string{
		"timestamp", "action", "category", "result", "ip", "ip_ambiguous", "user_agent",
		"actor_type", "actor_id", "actor_name", "sudo_by_id",
		"credential_type", "credential_id", "credential_name", "credential_owner_id",
		"target_type", "target_id", "target_name", "org", "project", "repo",
		"auth_method", "kind", "bytes", "request_id", "seq", "prev_hash", "hash", "data",
	} {
		assert.Contains(t, m, k)
	}
	assert.EqualValues(t, 1700000000000, m["timestamp"]) // the entry's time, not the shipping time
	assert.Equal(t, "org3", m["org"])
	assert.Equal(t, "proj", m["project"])
	assert.Equal(t, "repo1", m["repo"])
	assert.Equal(t, "archive", m["kind"])
	assert.EqualValues(t, 1234, m["bytes"])
	assert.Equal(t, true, m["ip_ambiguous"])
	assert.Empty(t, m["auth_method"]) // "method" of a download is not an auth method
	assert.JSONEq(t, `{"keep":"me","method":"GET"}`, m["data"].(string))
}

func TestSplitDataPromotesAuthMethod(t *testing.T) {
	data, promoted := splitData(&audit_model.Entry{TargetType: "signin", Data: `{"method":"password","reason":"x"}`})
	assert.Equal(t, "password", promoted["auth_method"])
	assert.JSONEq(t, `{"reason":"x"}`, data)
	data, promoted = splitData(&audit_model.Entry{TargetType: "signin", Data: "not json"})
	assert.Equal(t, "not json", data)
	assert.Empty(t, promoted)
}
