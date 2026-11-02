// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/json"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func exportCtx(t *testing.T) context.Context {
	return audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorUser, ID: 1, Name: "user1"})
}

func insertExportRows(t *testing.T) []*audit_model.Entry {
	t.Helper()
	require.NoError(t, unittest.PrepareTestDatabase())
	rows := []*audit_model.Entry{
		{CreatedUnix: 1000, Category: "credential", Action: "credential.access_token.created", Result: "success", ActorType: "user", ActorID: 2, ActorName: "=1+1", CredentialType: "access_token", CredentialName: "@cmd", UserAgent: "\t=evil", TargetName: "-x", Data: `{"name":"=HYPERLINK(1)"}`},
		{CreatedUnix: 2000, Category: "credential", Action: "credential.access_token.deleted", Result: "success", ActorType: "user", ActorID: 2, Data: `not json`},
		{CreatedUnix: 3000, Category: "credential", Action: "credential.access_token.deleted", Result: "success", ActorType: "user", ActorID: 2},
		{CreatedUnix: 4000, Category: "auth", Action: "auth.signin", Result: "success", ActorType: "user", ActorID: 2},
	}
	for _, e := range rows {
		require.NoError(t, db.Insert(t.Context(), e))
	}
	return rows
}

func lastEntry(t *testing.T) *audit_model.Entry {
	e := &audit_model.Entry{}
	has, err := db.GetEngine(t.Context()).Desc("id").Get(e)
	require.NoError(t, err)
	require.True(t, has)
	return e
}

func TestExportCSV(t *testing.T) {
	rows := insertExportRows(t)
	f, err := parse(t, "")
	require.NoError(t, err)
	var buf bytes.Buffer
	started := false
	m, err := Export(exportCtx(t), &buf, f, "csv", 0, func(m *Manifest) error {
		started = true
		assert.Zero(t, buf.Len(), "start runs before the first byte")
		return nil
	})
	require.NoError(t, err)
	assert.True(t, started)
	assert.Equal(t, 4, m.Rows, "the changes tab and audit.chain.started, without the export's own entry")
	assert.EqualValues(t, 5, m.SealedSeq, "the export sealed the four rows after audit.chain.started")
	assert.Len(t, m.SealedHash, 64)
	assert.False(t, m.Truncated)

	records, err := csv.NewReader(&buf).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 5)
	assert.Equal(t, CSVHeader, records[0])
	first := map[string]string{}
	for i, k := range CSVHeader {
		first[k] = records[1][i]
	}
	assert.Equal(t, "'=1+1", first["actor_name"])
	assert.Equal(t, "'@cmd", first["credential_name"])
	assert.Equal(t, "'\t=evil", first["user_agent"])
	assert.Equal(t, "'-x", first["target_name"])
	assert.JSONEq(t, `{"name":"=HYPERLINK(1)"}`, first["data"])
	assert.Equal(t, "1970-01-01T00:16:40Z", first["time"])
	assert.Equal(t, "2", first["seq"]) // seq 1 is audit.chain.started
	assert.JSONEq(t, `{"_raw":"not json"}`, records[2][23])

	e := lastEntry(t)
	assert.Equal(t, "audit.exported", e.Action)
	assert.Greater(t, e.ID, rows[3].ID)
	assert.JSONEq(t, `{"format":"csv","filter":["category=changes"],"capped":false}`, e.Data)
}

func TestExportJSONCap(t *testing.T) {
	rows := insertExportRows(t)
	f, err := parse(t, "category=all&action=credential.*")
	require.NoError(t, err)
	var buf bytes.Buffer
	m, err := Export(exportCtx(t), &buf, f, "json", 2, func(*Manifest) error { return nil })
	require.NoError(t, err)
	assert.True(t, m.Truncated)
	assert.Equal(t, rows[1].ID, m.ThroughID)
	assert.Equal(t, 2, m.Rows)
	assert.Equal(t, "1970-01-01T00:33:20Z", m.Next(f).Get("since"))
	assert.Equal(t, itoa(rows[1].ID), m.Next(f).Get("after_id"))

	var events []*api.AuditEvent
	require.NoError(t, json.Unmarshal(buf.Bytes(), &events))
	require.Len(t, events, 2)
	assert.Equal(t, map[string]any{"name": "=HYPERLINK(1)"}, events[0].Data)
	assert.Equal(t, map[string]any{"_raw": "not json"}, events[1].Data)

	// the continue link gives the rest
	next, err := ParseFilter(t.Context(), m.Next(f).Get)
	require.NoError(t, err)
	buf.Reset()
	m, err = Export(exportCtx(t), &buf, next, "json", 2, func(*Manifest) error { return nil })
	require.NoError(t, err)
	assert.False(t, m.Truncated)
	require.NoError(t, json.Unmarshal(buf.Bytes(), &events))
	require.Len(t, events, 1)
	assert.Equal(t, rows[2].ID, events[0].ID)
}

func TestExportRecord(t *testing.T) {
	insertExportRows(t)

	t.Run("long values", func(t *testing.T) {
		f, err := parse(t, "category=all&target_type=access_token&request_id=abc")
		require.NoError(t, err)
		f.Values.Set("org", strings.Repeat("o", 300)) // as if a long name had been accepted
		_, err = Export(exportCtx(t), &bytes.Buffer{}, f, "csv", 5, func(*Manifest) error { return nil })
		require.NoError(t, err)
		data := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(lastEntry(t).Data), &data))
		assert.Equal(t, true, data["truncated"])
		filter := data["filter"].([]any)
		require.Len(t, filter, 4)
		assert.Len(t, filter[1], 255)
		assert.Equal(t, "request_id=abc", filter[2])
		assert.Equal(t, "target_type=access_token", filter[3])
	})

	t.Run("a failed record writes nothing", func(t *testing.T) {
		defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error {
			return errors.New("disk full")
		})()
		f, err := parse(t, "")
		require.NoError(t, err)
		var buf bytes.Buffer
		_, err = Export(exportCtx(t), &buf, f, "csv", 0, func(*Manifest) error {
			t.Fatal("start must not run")
			return nil
		})
		require.Error(t, err)
		assert.Zero(t, buf.Len())
	})
}

// A backlog beyond one sealing call is not an error: the export goes on and names the head it reached.
func TestExportSealCap(t *testing.T) {
	insertExportRows(t)
	defer test.MockVariableValue(&SealBatchesPerCall, 1)()
	insertUnsealed(t, 600)
	f, err := parse(t, "category=all&action=credential.*")
	require.NoError(t, err)
	var buf bytes.Buffer
	m, err := Export(exportCtx(t), &buf, f, "json", 0, func(*Manifest) error { return nil })
	require.NoError(t, err)
	assert.EqualValues(t, 500, m.SealedSeq)
}

// A sealing error that is not the backlog cap fails the export before anything is written.
func TestExportSealError(t *testing.T) {
	insertExportRows(t)
	defer test.MockVariableValue(&audit_model.FindUnsealed, func(context.Context, int, int64) ([]*audit_model.Entry, error) {
		return nil, errors.New("database unavailable")
	})()
	f, err := parse(t, "")
	require.NoError(t, err)
	var buf bytes.Buffer
	started := false
	_, err = Export(exportCtx(t), &buf, f, "csv", 0, func(*Manifest) error { started = true; return nil })
	require.ErrorContains(t, err, "database unavailable")
	assert.False(t, started)
	assert.Zero(t, buf.Len())
}
