// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/json"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chain seals one entry per created time (seq 1..n, in order) and moves the head; unsealed rows follow.
func chain(t *testing.T, created []int64, unsealed int) []*audit_model.Entry {
	t.Helper()
	require.NoError(t, unittest.PrepareTestDatabase())
	require.NoError(t, audit_model.EnsureHead(t.Context()))
	prev := audit_model.ZeroHash
	var rows []*audit_model.Entry
	for i, c := range created {
		e := &audit_model.Entry{CreatedUnix: timeutil.TimeStamp(c), Category: "auth", Action: "auth.signin", Result: "success", ActorType: "user"}
		require.NoError(t, db.Insert(t.Context(), e))
		hash, err := audit_model.HashEntry(prev, e)
		require.NoError(t, err)
		seq := int64(i + 1)
		e.Seq, e.PrevHash, e.Hash = &seq, &prev, &hash
		_, err = db.GetEngine(t.Context()).ID(e.ID).Cols("seq", "prev_hash", "hash").Update(e)
		require.NoError(t, err)
		rows, prev = append(rows, e), hash
	}
	_, err := db.GetEngine(t.Context()).Exec("UPDATE audit_chain_head SET seq = ?, hash = ?", len(created), prev)
	require.NoError(t, err)
	for range unsealed {
		require.NoError(t, db.Insert(t.Context(), &audit_model.Entry{CreatedUnix: 1, Category: "auth", Action: "auth.signin", Result: "success", ActorType: "user"}))
	}
	return rows
}

func purge(t *testing.T, cutoff int64, batch int) (int64, error) {
	t.Helper()
	return audit_model.PurgeBatch(audit_model.WithSystem(t.Context(), "cron"), time.Unix(cutoff, 0), 365, batch)
}

func countRows(t *testing.T) int64 {
	t.Helper()
	n, err := db.GetEngine(t.Context()).Where("seq IS NOT NULL").Count(new(audit_model.Entry))
	require.NoError(t, err)
	return n
}

func purgeEntries(t *testing.T) (es []*audit_model.Entry) {
	t.Helper()
	require.NoError(t, db.GetEngine(t.Context()).Where("action = ?", "audit.purge").OrderBy("id").Find(&es))
	return es
}

// AC8
func TestPurgeBatch(t *testing.T) {
	t.Run("old prefix only, stops at the first newer entry in seq order (M6)", func(t *testing.T) {
		rows := chain(t, []int64{10, 20, 500, 30, 40}, 0) // seq 4 and 5 are old again but follow a newer one
		n, err := purge(t, 100, 10000)
		require.NoError(t, err)
		assert.EqualValues(t, 2, n)
		head, err := audit_model.GetHead(t.Context())
		require.NoError(t, err)
		assert.EqualValues(t, 2, head.AnchorSeq)
		assert.Equal(t, *rows[1].Hash, head.AnchorPrevHash)
		assert.EqualValues(t, 3, countRows(t)) // seq 3..5 stay
	})
	t.Run("entry fields match the anchor", func(t *testing.T) {
		rows := chain(t, []int64{10, 20, 500}, 0)
		_, err := purge(t, 100, 10000)
		require.NoError(t, err)
		es := purgeEntries(t)
		require.Len(t, es, 1)
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(es[0].Data), &d))
		assert.EqualValues(t, 2, d["deleted"])
		assert.EqualValues(t, 2, d["through_seq"])
		assert.Equal(t, *rows[1].Hash, d["through_hash"])
		assert.EqualValues(t, 100, d["cutoff_unix"])
		assert.EqualValues(t, 365, d["retention_days"])
		assert.Equal(t, "audit", es[0].Category)
	})
	t.Run("never the head entry, never unsealed ones", func(t *testing.T) {
		chain(t, []int64{10, 20, 30}, 2)
		n, err := purge(t, 1_000_000, 10000)
		require.NoError(t, err)
		assert.EqualValues(t, 2, n)
		assert.EqualValues(t, 1, countRows(t))
		unsealed, err := db.GetEngine(t.Context()).Where("seq IS NULL AND action = ?", "auth.signin").Count(new(audit_model.Entry))
		require.NoError(t, err)
		assert.EqualValues(t, 2, unsealed)
	})
	t.Run("batch cap, then the rest", func(t *testing.T) {
		chain(t, []int64{1, 2, 3, 4, 5, 6}, 0)
		n, err := purge(t, 1_000_000, 2)
		require.NoError(t, err)
		assert.EqualValues(t, 2, n)
		n, err = purge(t, 1_000_000, 2)
		require.NoError(t, err)
		assert.EqualValues(t, 2, n)
		head, _ := audit_model.GetHead(t.Context())
		assert.EqualValues(t, 4, head.AnchorSeq)
		assert.Len(t, purgeEntries(t), 2)
	})
	t.Run("nothing to delete records nothing", func(t *testing.T) {
		chain(t, []int64{500, 600}, 0)
		n, err := purge(t, 100, 10000)
		require.NoError(t, err)
		assert.Zero(t, n)
		head, _ := audit_model.GetHead(t.Context())
		assert.Zero(t, head.AnchorSeq)
		assert.Empty(t, purgeEntries(t))
		assert.EqualValues(t, 2, countRows(t))
	})
	t.Run("a failing record deletes nothing", func(t *testing.T) {
		chain(t, []int64{10, 20, 500}, 0)
		defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error { return errors.New("boom") })()
		_, err := purge(t, 100, 10000)
		require.Error(t, err)
		head, _ := audit_model.GetHead(t.Context())
		assert.Zero(t, head.AnchorSeq)
		assert.EqualValues(t, 3, countRows(t))
	})
	t.Run("a gap in the range fails and deletes nothing", func(t *testing.T) {
		rows := chain(t, []int64{10, 20, 30, 500}, 0)
		_, err := db.GetEngine(t.Context()).Exec("DELETE FROM audit_event WHERE id = ?", rows[1].ID)
		require.NoError(t, err)
		_, err = purge(t, 100, 10000)
		require.Error(t, err)
		head, _ := audit_model.GetHead(t.Context())
		assert.Zero(t, head.AnchorSeq)
		assert.EqualValues(t, 3, countRows(t))
	})
}
