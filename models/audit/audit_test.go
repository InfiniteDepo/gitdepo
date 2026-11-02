// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/json"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	unittest.MainTest(m)
}

func recordOne(t *testing.T, ev audit_model.Event) *audit_model.Entry {
	t.Helper()
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, Name: "user2\x1b[31m"})
	require.NoError(t, audit_model.Record(ctx, ev))
	e := &audit_model.Entry{}
	has, err := db.GetEngine(t.Context()).Desc("id").Get(e)
	require.NoError(t, err)
	require.True(t, has)
	return e
}

func decode(t *testing.T, e *audit_model.Entry) map[string]any {
	t.Helper()
	m := map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(e.Data), &m))
	return m
}

func TestRecordWhitelist(t *testing.T) {
	e := recordOne(t, audit_model.Event{
		Action: "credential.access_token.created", Result: audit_model.ResultSuccess,
		TargetType: "access_token", TargetID: 5, TargetName: "ci",
		Data: map[string]any{
			"after":  map[string]any{"name": "ci", "token": "secret", "token_hash": "h", "token_salt": "s", "token_last_eight": "l", "repo_ids": []int64{1, 2}},
			"token":  "secret",
			"other":  1,
			"before": "not a map",
			"reason": "x",
		},
	})
	data := decode(t, e)
	assert.Equal(t, map[string]any{"after": map[string]any{"name": "ci", "repo_ids": []any{1.0, 2.0}}, "reason": "x"}, data)
	assert.NotContains(t, e.Data, "secret")
	assert.Equal(t, "user2?[31m", e.ActorName, "control characters are stripped")
	assert.Nil(t, e.Seq)
	assert.Nil(t, e.Hash)

	for typ, fields := range audit_model.Fields {
		for _, f := range fields {
			assert.NotContains(t, []string{"token", "token_hash", "token_salt", "token_last_eight", "secret", "password"}, f, typ)
		}
	}
}

func TestRecordUnknownTargetKeepsNothing(t *testing.T) {
	e := recordOne(t, audit_model.Event{Action: "audit.exported", TargetType: "nope", Data: map[string]any{"name": "a"}})
	assert.Equal(t, "{}", e.Data)
}

func TestText(t *testing.T) {
	s := strings.Repeat("é", 200) // 400 bytes
	got := audit_model.Text(s, 255)
	assert.LessOrEqual(t, len(got), 255)
	assert.True(t, strings.HasSuffix(got, "…"))
	assert.Equal(t, "a?b", audit_model.Text("a\nb", 255))
	assert.Equal(t, "a\uFFFDb", audit_model.Text("a\xffb", 255), "invalid UTF-8 is replaced")

	e := recordOne(t, audit_model.Event{Action: "audit.exported", TargetType: "access_token", TargetName: s, Data: map[string]any{"name": s}})
	assert.LessOrEqual(t, len(e.TargetName), 255)
	assert.Equal(t, got, decode(t, e)["name"])
}

func TestRecordTruncatesData(t *testing.T) {
	ids := make([]int64, 10000) // ~60 KB of JSON
	for i := range ids {
		ids[i] = 100000 + int64(i)
	}
	e := recordOne(t, audit_model.Event{Action: "audit.exported", TargetType: "access_token", Data: map[string]any{
		"after": map[string]any{"repo_ids": ids, "name": "ci"},
	}})
	assert.LessOrEqual(t, len(e.Data), 32*1024)
	data := decode(t, e)
	assert.Equal(t, true, data["truncated"])
	after := data["after"].(map[string]any)
	assert.Equal(t, "ci", after["name"])
	assert.NotEmpty(t, after["repo_ids"])
}

func TestRecordWithoutActor(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	require.NoError(t, audit_model.Record(t.Context(), audit_model.Event{Action: "audit.exported"}))
	e := &audit_model.Entry{}
	_, err := db.GetEngine(t.Context()).Desc("id").Get(e)
	require.NoError(t, err)
	assert.Equal(t, audit_model.ActorUnknown, e.ActorType)
}

func TestRecordAmbiguousIP(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorUser, IP: "10.0.0.1", IPAmbiguous: true, IPCandidates: []string{"1.2.3.4"}, Task: "cron"})
	require.NoError(t, audit_model.Record(ctx, audit_model.Event{Action: "audit.exported"}))
	e := &audit_model.Entry{}
	_, err := db.GetEngine(t.Context()).Desc("id").Get(e)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1", e.IP)
	assert.JSONEq(t, `{"ip_ambiguous":true,"ip_candidates":["1.2.3.4"],"task":"cron"}`, e.Data)
}

func TestRecordTruncatesNamesBeforeIDs(t *testing.T) {
	audit_model.Fields["test_lists"] = []string{"names", "ids"}
	defer delete(audit_model.Fields, "test_lists")

	names := make([]string, 300) // ~30 KB
	for i := range names {
		names[i] = strings.Repeat("n", 100)
	}
	ids := make([]int64, 1000) // ~7 KB
	for i := range ids {
		ids[i] = 1000000 + int64(i)
	}
	e := recordOne(t, audit_model.Event{Action: "audit.exported", TargetType: "test_lists", Data: map[string]any{"names": names, "ids": ids}})
	assert.LessOrEqual(t, len(e.Data), 32*1024)
	data := decode(t, e)
	assert.Equal(t, true, data["truncated"])
	assert.Len(t, data["ids"], 1000, "IDs are kept")
	assert.Less(t, len(data["names"].([]any)), 300, "names are cut first")
}

func TestRecordCredentialTruncatesSelection(t *testing.T) {
	ids := make([]int64, 10000) // a selection change too large for one entry
	for i := range ids {
		ids[i] = 100000 + int64(i)
	}
	e := recordOne(t, audit_model.Event{Action: "credential.org_deploy_key.updated", TargetType: "org_deploy_key", Data: map[string]any{
		"repos_added": ids, "repos_removed": []int64{1}, "name": "k",
	}})
	data := decode(t, e)
	assert.Equal(t, true, data["truncated"])
	assert.NotEmpty(t, data["repos_added"])
	assert.Less(t, len(data["repos_added"].([]any)), len(ids))
	assert.Equal(t, "k", data["name"])
}

func TestRecordCredentialOnBehalf(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	last := func() map[string]any {
		e := &audit_model.Entry{}
		_, err := db.GetEngine(t.Context()).Desc("id").Get(e)
		require.NoError(t, err)
		return decode(t, e)
	}
	ev := audit_model.Event{Action: "credential.ssh_key.created", TargetType: "ssh_key", SubjectUserID: 2, Data: map[string]any{"name": "k"}}

	admin := audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorUser, ID: 1})
	require.NoError(t, audit_model.RecordCredential(admin, ev))
	assert.Equal(t, true, last()["on_behalf"])

	owner := audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorUser, ID: 2})
	ev.Data = map[string]any{"name": "k"}
	require.NoError(t, audit_model.RecordCredential(owner, ev))
	assert.NotContains(t, last(), "on_behalf")

	ev.Data = map[string]any{"name": "k"}
	require.NoError(t, audit_model.RecordCredential(audit_model.WithSystem(t.Context(), "cron:sync_external_users"), ev))
	assert.NotContains(t, last(), "on_behalf")
}

func TestOrigin(t *testing.T) {
	for raw, want := range map[string]string{
		"https://user:pw@logs.example.com:8443/path/token?q=1#f": "https://logs.example.com:8443",
		"http://example.com":         "http://example.com",
		"mailto:someone@example.com": "",
		"/relative/path":             "",
		"::not a url":                "",
		"":                           "",
	} {
		assert.Equal(t, want, audit_model.Origin(raw), raw)
	}
}

func TestWithLoginSource(t *testing.T) {
	outer := &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, Name: "user2", IP: "192.0.2.1", RequestID: "r1", SudoByID: 1}
	ctx := audit_model.WithLoginSource(audit_model.WithActor(t.Context(), outer), 7, "ldap")
	a := audit_model.ActorFromContext(ctx)
	assert.Equal(t, audit_model.ActorLoginSource, a.Type)
	assert.EqualValues(t, 7, a.ID)
	assert.Equal(t, "ldap", a.Name)
	assert.Equal(t, "192.0.2.1", a.IP)
	assert.Equal(t, "r1", a.RequestID)
	assert.Zero(t, a.SudoByID)
	assert.Equal(t, audit_model.CredentialSystem, a.Credential.Type)
	// the request's actor is left as it was, for what the request records after the sync
	assert.Equal(t, audit_model.ActorUser, outer.Type)
	assert.EqualValues(t, 2, outer.ID)

	assert.Equal(t, ctx, audit_model.WithLoginSource(ctx, 7, "ldap"), "already that source")
	assert.NotEqual(t, ctx, audit_model.WithLoginSource(ctx, 8, "other"))
	assert.Equal(t, audit_model.ActorLoginSource, audit_model.ActorFromContext(audit_model.WithLoginSource(t.Context(), 7, "ldap")).Type)
}

// Written counts committed entries per category; a rolled-back one isn't counted.
func TestRecordCountsWritten(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, Name: "user2"})
	ev := audit_model.Event{Action: "audit.exported", Result: audit_model.ResultSuccess}
	n := audit_model.Written["audit"].Load()

	require.NoError(t, audit_model.Record(ctx, ev))
	assert.Equal(t, n+1, audit_model.Written["audit"].Load(), "outside a transaction")

	require.NoError(t, db.WithTx(ctx, func(ctx context.Context) error {
		require.NoError(t, audit_model.Record(ctx, ev))
		assert.Equal(t, n+1, audit_model.Written["audit"].Load(), "not before the commit")
		return nil
	}))
	assert.Equal(t, n+2, audit_model.Written["audit"].Load(), "after the commit")

	require.Error(t, db.WithTx(ctx, func(ctx context.Context) error {
		require.NoError(t, audit_model.Record(ctx, ev))
		return errors.New("roll back")
	}))
	assert.Equal(t, n+2, audit_model.Written["audit"].Load(), "rolled back")

	for _, c := range audit_model.Categories {
		assert.NotNil(t, audit_model.Written[c], c)
	}
}
