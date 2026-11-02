// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm/contexts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func insertUnsealed(t *testing.T, n int) {
	t.Helper()
	for i := range n {
		require.NoError(t, db.Insert(t.Context(), &audit_model.Entry{
			CreatedUnix: timeutil.TimeStamp(1000 + i), Category: "auth", Action: "auth.signin", Result: "success", ActorType: "user", ActorID: 2,
			Data: fmt.Sprintf(`{"i":%d}`, i),
		}))
	}
}

func allEntries(t *testing.T) []*audit_model.Entry {
	t.Helper()
	var entries []*audit_model.Entry
	require.NoError(t, db.GetEngine(t.Context()).OrderBy("id").Find(&entries))
	return entries
}

func mustVerify(t *testing.T) *VerifyResult {
	t.Helper()
	res, err := Verify(t.Context(), VerifyOptions{})
	require.NoError(t, err)
	require.Nil(t, res.Failure, "%+v", res.Failure)
	return res
}

type sqlHook struct {
	mu   sync.Mutex
	sqls []string
}

func (h *sqlHook) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	h.mu.Lock()
	h.sqls = append(h.sqls, c.SQL)
	h.mu.Unlock()
	return db.TracingHook{}.BeforeProcess(c)
}

func (h *sqlHook) AfterProcess(c *contexts.ContextHook) error {
	return db.TracingHook{}.AfterProcess(c)
}

func hookSQL(t *testing.T) *sqlHook {
	t.Helper()
	h := &sqlHook{}
	x, err := db.GetMasterEngine(db.GetEngine(db.DefaultContext))
	require.NoError(t, err)
	x.AddHook(h)
	return h
}

func (h *sqlHook) writes() (w []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.sqls {
		if u := strings.ToUpper(strings.TrimSpace(s)); !strings.HasPrefix(u, "SELECT") {
			w = append(w, s)
		}
	}
	return w
}

// AC1: 1200 rows are sealed in id order, 500 at a time, and the head is the last row.
func TestSealOrderAndBatches(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	insertUnsealed(t, 1200)

	n, err := Seal(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 500, n) // the first batch holds audit.chain.started and 499 rows
	require.NoError(t, SealAll(t.Context()))
	assert.Equal(t, 1201, int(mustVerify(t).LastSeq))

	entries := allEntries(t)
	for i := 1; i < len(entries)-1; i++ {
		if entries[i].Action == "audit.chain.started" {
			continue
		}
		require.NotNil(t, entries[i].Seq)
		assert.Greater(t, *entries[i].Seq, *entries[i-1].Seq) // id order is seq order
	}
	head, err := audit_model.GetHead(t.Context())
	require.NoError(t, err)
	assert.EqualValues(t, 1201, head.Seq)
	last, err := audit_model.GetBySeq(t.Context(), head.Seq)
	require.NoError(t, err)
	assert.Equal(t, *last.Hash, head.Hash)
	assert.Len(t, head.Hash, 64)
}

// AC1: a row sealed by someone else rolls the whole batch back.
func TestSealRowAlreadySealed(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	insertUnsealed(t, 3)
	find := audit_model.FindUnsealed
	defer test.MockVariableValue(&audit_model.FindUnsealed, func(ctx context.Context, limit int, skip int64) ([]*audit_model.Entry, error) {
		rows, err := find(ctx, limit, skip)
		if err == nil && len(rows) > 0 { // somebody else seals the first row after we read it
			_, err = db.GetEngine(ctx).Exec("UPDATE audit_event SET seq = 99, prev_hash = 'x', hash = 'x' WHERE id = ?", rows[len(rows)-1].ID)
		}
		return rows, err
	})()

	_, err := Seal(t.Context())
	require.Error(t, err)
	head, err := audit_model.GetHead(t.Context())
	require.NoError(t, err)
	assert.EqualValues(t, 0, head.Seq) // nothing half written
	var sealed int64
	_, err = db.GetEngine(t.Context()).Table("audit_event").Where("seq IS NOT NULL").Select("COUNT(*)").Get(&sealed)
	require.NoError(t, err)
	assert.Zero(t, sealed) // the rows the mock sealed inside the transaction were rolled back with it
}

// AC1: an idle sealer only reads.
func TestSealIdleTakesNoWriteLock(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	h := hookSQL(t)
	n, err := Seal(t.Context())
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Empty(t, h.writes())
	assert.NotEmpty(t, h.sqls)
}

// AC2: audit.chain.started is seq 1, the older rows follow by id, and it is written once.
func TestSealGenesis(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	insertUnsealed(t, 3)
	older := allEntries(t)

	n, err := Seal(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	entries := allEntries(t)
	require.Len(t, entries, 4)
	started := entries[3]
	assert.Equal(t, "audit.chain.started", started.Action)
	assert.EqualValues(t, 1, *started.Seq)
	assert.Equal(t, audit_model.ZeroHash, *started.PrevHash)
	assert.JSONEq(t, fmt.Sprintf(`{"unsealed_before":3,"first_unsealed_id":%d}`, older[0].ID), started.Data)
	for i, e := range entries[:3] {
		assert.EqualValues(t, i+2, *e.Seq)
	}

	insertUnsealed(t, 1)
	_, err = Seal(t.Context())
	require.NoError(t, err)
	var started2 int64
	_, err = db.GetEngine(t.Context()).Table("audit_event").Where("action = ?", "audit.chain.started").Select("COUNT(*)").Get(&started2)
	require.NoError(t, err)
	assert.EqualValues(t, 1, started2)
	mustVerify(t)
}

// AC3: concurrent sealers while rows arrive give seq 1..K, unique and gap free.
func TestSealConcurrent(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	insertUnsealed(t, 20)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 5 {
				_, _ = Seal(t.Context()) // a busy database may refuse one; the next call seals it
			}
		})
	}
	for i := range 20 {
		require.NoError(t, db.Insert(t.Context(), &audit_model.Entry{CreatedUnix: 5000, Category: "auth", Action: "auth.signin", Result: "success", ActorType: "user", Data: fmt.Sprint(i)}))
	}
	wg.Wait()
	require.NoError(t, SealAll(t.Context()))
	res := mustVerify(t)
	assert.EqualValues(t, 41, res.LastSeq)
	assert.EqualValues(t, 41, res.Rows)
	assert.Zero(t, res.Unsealed)
}

// A backlog beyond the per-call cap is not an error.
func TestSealAllCap(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&SealBatchesPerCall, 1)()
	insertUnsealed(t, 600)
	require.NoError(t, SealAll(t.Context()))
	res, err := Verify(t.Context(), VerifyOptions{})
	require.NoError(t, err)
	require.Nil(t, res.Failure)
	assert.EqualValues(t, 500, res.LastSeq)
	assert.EqualValues(t, 101, res.Unsealed)
}

func TestRunSealer(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&SealInterval, 10*time.Millisecond)()
	insertUnsealed(t, 2)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { RunSealer(ctx); close(done) }()
	assert.Eventually(t, func() bool {
		var n int64
		_, err := db.GetEngine(db.DefaultContext).Table("audit_event").Where("seq IS NULL").Select("COUNT(*)").Get(&n)
		return err == nil && n == 0
	}, 5*time.Second, 20*time.Millisecond)
	cancel()
	<-done
}

// The sealer is not a write of a user: it keeps working in maintenance read-only mode.
func TestSealInMaintenanceMode(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Maintenance.Mode, setting.MaintenanceReadOnly)()
	require.True(t, setting.GetMaintenance(t.Context()).ReadOnly())
	insertUnsealed(t, 2)
	n, err := Seal(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	mustVerify(t)
}

// A fresh install has no head row: the first Seal creates it and writes the genesis.
func TestSealCreatesHead(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	_, err := db.GetEngine(t.Context()).Exec("DELETE FROM audit_chain_head")
	require.NoError(t, err)
	insertUnsealed(t, 2)
	res, err := Verify(t.Context(), VerifyOptions{}) // works without a head, and writes nothing
	require.NoError(t, err)
	assert.Nil(t, res.Failure)

	n, err := Seal(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	head, err := audit_model.GetHead(t.Context())
	require.NoError(t, err)
	assert.EqualValues(t, 3, head.Seq)
	entries := allEntries(t)
	assert.Equal(t, "audit.chain.started", entries[2].Action)
	assert.EqualValues(t, 1, *entries[2].Seq)
	mustVerify(t)
}
