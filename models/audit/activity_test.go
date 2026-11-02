// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func entriesSince(t *testing.T, since int64) []*audit_model.Entry {
	t.Helper()
	var entries []*audit_model.Entry
	require.NoError(t, db.GetEngine(t.Context()).Where("id > ?", since).OrderBy("id").Find(&entries))
	return entries
}

func maxID(t *testing.T) int64 {
	t.Helper()
	var id int64
	_, err := db.GetEngine(t.Context()).Table("audit_event").Select("COALESCE(MAX(id), 0)").Get(&id)
	require.NoError(t, err)
	return id
}

func failedSignIn(subject int64) audit_model.Event {
	return audit_model.Event{
		Action: "auth.signin.failed", Result: audit_model.ResultFailure, SubjectUserID: subject,
		TargetType: "signin", TargetID: subject, Data: map[string]any{"reason": "bad_password"},
	}
}

func TestRecordUnknownAction(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	require.Error(t, audit_model.Record(t.Context(), audit_model.Event{Action: "nope.not.listed"}))
}

func TestRecordActivityFailsOpen(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error { return errors.New("boom") })()
	before := audit_model.WriteErrors.Load()
	assert.False(t, audit_model.RecordActivity(t.Context(), failedSignIn(2)))
	assert.Equal(t, before+1, audit_model.WriteErrors.Load())
}

func TestAggregation(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	audit_model.ResetActivity()
	defer audit_model.ResetActivity()
	timeutil.MockSet(time.Unix(1_800_000_000, 0))
	defer timeutil.MockUnset()
	ctx := audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorAnonymous, IP: "203.0.113.1", RequestID: "r1"})

	since := maxID(t)
	for range 3 {
		audit_model.RecordAggregated(ctx, failedSignIn(2), "k")
	}
	audit_model.RecordAggregated(ctx, failedSignIn(4), "other")
	entries := entriesSince(t, since)
	require.Len(t, entries, 2, "the first event of each key is written at once")
	assert.Equal(t, "auth.signin.failed", entries[0].Action)
	assert.EqualValues(t, 2, entries[0].SubjectUserID)

	since = maxID(t)
	audit_model.FlushAggregated(t.Context(), false)
	assert.Empty(t, entriesSince(t, since), "the window is still open")

	timeutil.MockSet(time.Unix(1_800_000_061, 0))
	audit_model.FlushAggregated(t.Context(), false)
	entries = entriesSince(t, since)
	require.Len(t, entries, 1, "a bucket without later events writes nothing")
	e := entries[0]
	assert.Equal(t, "auth.signin.failed.aggregated", e.Action)
	assert.Equal(t, "203.0.113.1", e.IP)
	assert.Empty(t, e.RequestID)
	assert.EqualValues(t, 2, e.SubjectUserID)
	assert.JSONEq(t, `{"reason":"bad_password","count":2,"first":1800000000,"last":1800000000}`, e.Data)

	since = maxID(t)
	audit_model.RecordAggregated(ctx, failedSignIn(2), "k")
	assert.Len(t, entriesSince(t, since), 1, "a new window writes its first event again")
}

func TestAggregationOverflow(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	audit_model.ResetActivity()
	defer audit_model.ResetActivity()
	defer test.MockVariableValue(&audit_model.AggregateCap, 2)()
	defer test.MockVariableValue(&audit_model.AggregateOverflowCap, 1)()
	timeutil.MockSet(time.Now()) // first/last are compared with "now" below: a real clock can cross a second
	defer timeutil.MockUnset()
	ctx := audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorAnonymous, IP: "203.0.113.1"})

	since := maxID(t)
	audit_model.RecordAggregated(ctx, failedSignIn(2), "a")
	audit_model.RecordAggregated(ctx, failedSignIn(2), "b")
	// the map is full: new keys of subject 7 share one overflow bucket keyed on the subject
	for i := range 4 {
		audit_model.RecordAggregated(ctx, failedSignIn(7), fmt.Sprint("x", i))
	}
	// the overflow map is full too: subject 8 goes to the bucket of the action
	audit_model.RecordAggregated(ctx, failedSignIn(8), "y")
	audit_model.RecordAggregated(ctx, failedSignIn(9), "z")
	entries := entriesSince(t, since)
	require.Len(t, entries, 4)
	assert.EqualValues(t, 7, entries[2].SubjectUserID)
	assert.EqualValues(t, 8, entries[3].SubjectUserID)

	since = maxID(t)
	audit_model.FlushAggregated(t.Context(), true) // shutdown: every bucket, open windows too
	entries = entriesSince(t, since)
	require.Len(t, entries, 2)
	data := map[int64]string{}
	for _, e := range entries {
		data[e.SubjectUserID] = e.Data
	}
	assert.JSONEq(t, `{"reason":"bad_password","count":3,"first":`+fmt.Sprint(int64(timeutil.TimeStampNow()))+`,"last":`+fmt.Sprint(int64(timeutil.TimeStampNow()))+`,"overflow":true}`, data[7])
	assert.Contains(t, data[8], `"count":1`)
	assert.Contains(t, data[8], `"overflow":true`)

	since = maxID(t)
	audit_model.FlushAggregated(t.Context(), true)
	assert.Empty(t, entriesSince(t, since), "flushed buckets are gone")
}

func TestSeenToday(t *testing.T) {
	audit_model.ResetActivity()
	defer audit_model.ResetActivity()
	defer test.MockVariableValue(&audit_model.SeenCap, 2)()
	audit_model.ResetActivity()
	timeutil.MockSet(time.Date(2026, 10, 15, 23, 59, 0, 0, time.UTC))
	defer timeutil.MockUnset()

	assert.False(t, audit_model.SeenToday("a"))
	audit_model.MarkSeenToday("a")
	assert.True(t, audit_model.SeenToday("a"))

	timeutil.MockSet(time.Date(2026, 10, 16, 0, 0, 1, 0, time.UTC))
	assert.False(t, audit_model.SeenToday("a"), "a new UTC day")
	audit_model.MarkSeenToday("a")
	audit_model.MarkSeenToday("b")
	audit_model.MarkSeenToday("c")
	assert.False(t, audit_model.SeenToday("a"), "capped: the oldest key is evicted")
	assert.True(t, audit_model.SeenToday("c"))
}

func TestIPKey(t *testing.T) {
	a := &audit_model.Actor{IP: "2001:db8:1:2:3:4:5:6"}
	assert.Equal(t, "2001:db8:1:2::/64", audit_model.IPKey(a, 64))
	assert.Equal(t, "2001:db8:1::/48", audit_model.IPKey(a, 48))
	assert.Equal(t, "203.0.113.1", audit_model.IPKey(&audit_model.Actor{IP: "203.0.113.1"}, 48))
	assert.Equal(t, "10.0.0.1|198.51.100.7,2001:db8::/64", audit_model.IPKey(&audit_model.Actor{
		IP: "10.0.0.1", IPAmbiguous: true, IPCandidates: []string{"2001:db8::9", "198.51.100.7"},
	}, 64))
}

func TestRecordCredentialUsed(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	audit_model.ResetActivity()
	defer audit_model.ResetActivity()
	use := func(ip string) int {
		since := maxID(t)
		ctx := audit_model.WithActor(t.Context(), &audit_model.Actor{
			Type: audit_model.ActorUser, ID: 2, Name: "user2", IP: ip,
			Credential: audit_model.Credential{Type: audit_model.CredentialAccessToken, ID: 3, Name: "t", OwnerID: 2},
		})
		audit_model.RecordCredentialUsed(ctx, "api")
		return len(entriesSince(t, since))
	}
	assert.Equal(t, 1, use("2001:db8::1"))
	assert.Equal(t, 0, use("2001:db8::1"))
	assert.Equal(t, 0, use("2001:db8::2"), "the same /64")
	assert.Equal(t, 1, use("2001:db8:0:1::1"))

	defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error { return errors.New("boom") })()
	assert.Equal(t, 0, use("203.0.113.3"))
	audit_model.InsertEntry = func(ctx context.Context, e *audit_model.Entry) error { return db.Insert(ctx, e) }
	assert.Equal(t, 1, use("203.0.113.3"), "a failed write is not remembered")

	since := maxID(t)
	audit_model.RecordCredentialUsed(audit_model.WithActor(t.Context(), &audit_model.Actor{
		Type: audit_model.ActorUser, ID: 2, IP: "203.0.113.4", Credential: audit_model.Credential{Type: audit_model.CredentialSession, OwnerID: 2},
	}), "web")
	assert.Empty(t, entriesSince(t, since), "a session is not a credential use")
}

func TestAggregationFirstWritesCap(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	audit_model.ResetActivity()
	defer audit_model.ResetActivity()
	defer test.MockVariableValue(&audit_model.AggregateFirstWrites, 2)()
	ctx := audit_model.WithActor(t.Context(), &audit_model.Actor{Type: audit_model.ActorAnonymous, IP: "203.0.113.1"})

	since := maxID(t)
	for i := range 4 {
		audit_model.RecordAggregated(ctx, failedSignIn(7), fmt.Sprint("k", i))
	}
	assert.Len(t, entriesSince(t, since), 2, "past the cap a new key is only counted")

	since = maxID(t)
	audit_model.FlushAggregated(t.Context(), true)
	entries := entriesSince(t, since)
	require.Len(t, entries, 1)
	assert.Contains(t, entries[0].Data, `"count":2`)
	assert.Contains(t, entries[0].Data, `"overflow":true`)
}
