// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm/contexts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sealed(t *testing.T, n int) []*audit_model.Entry {
	t.Helper()
	require.NoError(t, unittest.PrepareTestDatabase())
	insertUnsealed(t, n)
	require.NoError(t, SealAll(t.Context()))
	var rows []*audit_model.Entry // rows[i] has seq i+1
	require.NoError(t, db.GetEngine(t.Context()).Where("seq IS NOT NULL").OrderBy("seq").Find(&rows))
	return rows
}

func exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	_, err := db.GetEngine(t.Context()).Exec(append([]any{sql}, args...)...)
	require.NoError(t, err)
}

func verifyFails(t *testing.T, opts VerifyOptions, seq int64, reason string) {
	t.Helper()
	res, err := Verify(t.Context(), opts)
	require.NoError(t, err)
	require.NotNil(t, res.Failure)
	assert.Equal(t, VerifyFailure{Seq: seq, Reason: reason}, *res.Failure)
}

// AC4
func TestVerify(t *testing.T) {
	t.Run("clean", func(t *testing.T) {
		rows := sealed(t, 5)
		insertUnsealed(t, 2)
		h := hookSQL(t)
		res, err := Verify(t.Context(), VerifyOptions{})
		require.NoError(t, err)
		assert.Nil(t, res.Failure)
		assert.EqualValues(t, 6, res.Rows)
		assert.EqualValues(t, 1, res.FirstSeq)
		assert.EqualValues(t, 6, res.LastSeq)
		assert.Equal(t, *rows[len(rows)-1].Hash, res.LastHash)
		assert.EqualValues(t, 2, res.Unsealed)
		assert.NotZero(t, res.OldestUnsealedAge)
		assert.Empty(t, h.writes())
	})
	t.Run("edited", func(t *testing.T) {
		rows := sealed(t, 5)
		exec(t, "UPDATE audit_event SET data = ? WHERE id = ?", `{"i":99}`, rows[2].ID)
		verifyFails(t, VerifyOptions{}, *rows[2].Seq, "hash")
	})
	t.Run("deleted middle", func(t *testing.T) {
		rows := sealed(t, 5)
		exec(t, "DELETE FROM audit_event WHERE id = ?", rows[2].ID)
		verifyFails(t, VerifyOptions{}, *rows[2].Seq, "gap")
	})
	t.Run("deleted tail", func(t *testing.T) {
		rows := sealed(t, 5)
		exec(t, "DELETE FROM audit_event WHERE id = ?", rows[len(rows)-1].ID)
		verifyFails(t, VerifyOptions{}, *rows[len(rows)-1].Seq, "head")
	})
	t.Run("swapped", func(t *testing.T) {
		rows := sealed(t, 5)
		exec(t, "UPDATE audit_event SET seq = 1000 WHERE id = ?", rows[1].ID)
		exec(t, "UPDATE audit_event SET seq = ? WHERE id = ?", *rows[1].Seq, rows[2].ID)
		exec(t, "UPDATE audit_event SET seq = ? WHERE id = ?", *rows[2].Seq, rows[1].ID)
		res, err := Verify(t.Context(), VerifyOptions{})
		require.NoError(t, err)
		require.NotNil(t, res.Failure)
		assert.Contains(t, []string{"link", "hash"}, res.Failure.Reason)
	})
	t.Run("anchor", func(t *testing.T) {
		rows := sealed(t, 5)
		good := fmt.Sprintf("%d:%s", *rows[2].Seq, *rows[2].Hash)
		res, err := Verify(t.Context(), VerifyOptions{Anchor: good})
		require.NoError(t, err)
		assert.Nil(t, res.Failure)

		verifyFails(t, VerifyOptions{Anchor: fmt.Sprintf("%d:%s", *rows[2].Seq, audit_model.ZeroHash)}, *rows[2].Seq, "anchor")
		verifyFails(t, VerifyOptions{Anchor: fmt.Sprintf("99:%s", audit_model.ZeroHash)}, 99, "anchor") // above the last row
		verifyFails(t, VerifyOptions{Anchor: good, From: 4}, *rows[2].Seq, "anchor")                    // below --from
		_, err = Verify(t.Context(), VerifyOptions{Anchor: "nonsense"})
		require.Error(t, err)
	})
	t.Run("from", func(t *testing.T) {
		rows := sealed(t, 5)
		res, err := Verify(t.Context(), VerifyOptions{From: 3})
		require.NoError(t, err)
		assert.Nil(t, res.Failure)
		assert.EqualValues(t, 3, res.FirstSeq)
		assert.EqualValues(t, 4, res.Rows)

		exec(t, "UPDATE audit_event SET prev_hash = ? WHERE id = ?", audit_model.ZeroHash, rows[2].ID) // row 3 of the chain
		verifyFails(t, VerifyOptions{From: 3}, 3, "link")
	})
}

// A head that was set back, even to 0, leaves sealed rows beyond it.
func TestVerifyHeadSetBack(t *testing.T) {
	sealed(t, 5)
	exec(t, "UPDATE audit_chain_head SET seq = 0, hash = ?", audit_model.ZeroHash)
	verifyFails(t, VerifyOptions{}, 0, "head")
}

// sealedOld is sealed with a genesis entry that is two years old, so a purge may take it.
func sealedOld(t *testing.T, n int) []*audit_model.Entry {
	t.Helper()
	timeutil.MockSet(time.Now().AddDate(-2, 0, 0))
	defer timeutil.MockUnset()
	return sealed(t, n)
}

func oldCutoff() time.Time { return time.Now().AddDate(-1, 0, 0) }

// purged seals chain.started and 5 rows, then purges all but the head row, so the anchor is seq 5.
func purged(t *testing.T) []*audit_model.Entry {
	t.Helper()
	rows := sealedOld(t, 5)
	n, err := audit_model.PurgeBatch(audit_model.WithSystem(t.Context(), "cron"), oldCutoff(), 365, 10000)
	require.NoError(t, err)
	require.EqualValues(t, 5, n)
	return rows
}

// AC9
func TestVerifyAfterPurge(t *testing.T) {
	t.Run("passes right after a purge, with the purge entry unsealed (M3), and once it is sealed", func(t *testing.T) {
		purged(t)
		res := mustVerify(t)
		assert.EqualValues(t, 6, res.FirstSeq)
		assert.EqualValues(t, 1, res.Rows)
		assert.EqualValues(t, 5, res.PurgedThrough)
		assert.Contains(t, res.String(), "deleted by retention")
		require.NoError(t, SealAll(t.Context()))
		mustVerify(t)
	})
	t.Run("--from below the anchor starts at the anchor", func(t *testing.T) {
		purged(t)
		res, err := Verify(t.Context(), VerifyOptions{From: 2})
		require.NoError(t, err)
		assert.Nil(t, res.Failure)
		assert.EqualValues(t, 6, res.FirstSeq)
		assert.EqualValues(t, 5, res.PurgedThrough)
	})
	t.Run("--anchor at and below the anchor", func(t *testing.T) {
		rows := purged(t)
		good := fmt.Sprintf("5:%s", *rows[4].Hash)
		res, err := Verify(t.Context(), VerifyOptions{Anchor: good})
		require.NoError(t, err)
		assert.Nil(t, res.Failure)
		verifyFails(t, VerifyOptions{Anchor: fmt.Sprintf("5:%s", audit_model.ZeroHash)}, 5, "anchor")
		verifyFails(t, VerifyOptions{Anchor: fmt.Sprintf("3:%s", *rows[2].Hash)}, 3, "anchor") // entries are gone
		res, err = Verify(t.Context(), VerifyOptions{Anchor: fmt.Sprintf("6:%s", *rows[5].Hash)})
		require.NoError(t, err)
		assert.Nil(t, res.Failure)
	})
	t.Run("edited anchor_prev_hash", func(t *testing.T) {
		purged(t)
		exec(t, "UPDATE audit_chain_head SET anchor_prev_hash = ?", audit_model.ZeroHash)
		res, err := Verify(t.Context(), VerifyOptions{})
		require.NoError(t, err)
		require.NotNil(t, res.Failure)
	})
	t.Run("deleted purge entry", func(t *testing.T) {
		purged(t)
		exec(t, "DELETE FROM audit_event WHERE action = ?", "audit.purge")
		verifyFails(t, VerifyOptions{}, 5, "anchor")
	})
	t.Run("sealed purge entry deleted", func(t *testing.T) {
		purged(t)
		require.NoError(t, SealAll(t.Context()))
		exec(t, "DELETE FROM audit_event WHERE action = ?", "audit.purge")
		res, err := Verify(t.Context(), VerifyOptions{})
		require.NoError(t, err)
		require.NotNil(t, res.Failure)
	})
	for name, data := range map[string]string{
		"through_hash differs": `{"through_seq":5,"through_hash":"%s","cutoff_unix":1000000,"retention_days":365}`,
		"through_seq differs":  `{"through_seq":4,"through_hash":"HASH","cutoff_unix":1000000,"retention_days":365}`,
		"unallowed retention":  `{"through_seq":5,"through_hash":"HASH","cutoff_unix":1000000,"retention_days":31}`,
		"cutoff too recent":    `{"through_seq":5,"through_hash":"HASH","cutoff_unix":4102444800,"retention_days":365}`,
		"not json":             `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			rows := purged(t)
			if strings.Contains(data, "%s") {
				data = fmt.Sprintf(data, audit_model.ZeroHash)
			}
			exec(t, "UPDATE audit_event SET data = ? WHERE action = ?", strings.ReplaceAll(data, "HASH", *rows[4].Hash), "audit.purge")
			verifyFails(t, VerifyOptions{}, 5, "anchor")
		})
	}
	t.Run("entry missing after the anchor", func(t *testing.T) {
		rows := sealedOld(t, 7)
		_, err := audit_model.PurgeBatch(audit_model.WithSystem(t.Context(), "cron"), oldCutoff(), 365, 3)
		require.NoError(t, err)
		exec(t, "DELETE FROM audit_event WHERE id = ?", rows[4].ID) // seq 5, anchor is 3
		verifyFails(t, VerifyOptions{}, 5, "gap")
	})
}

// M4: a purge that moves the anchor while verify runs makes it start over once instead of failing.
func TestVerifyDuringPurge(t *testing.T) {
	sealedOld(t, 5)
	h := &purgeOnRead{t: t}
	x, err := db.GetMasterEngine(db.GetEngine(db.DefaultContext))
	require.NoError(t, err)
	x.AddHook(h)
	res, err := Verify(t.Context(), VerifyOptions{})
	require.NoError(t, err)
	assert.True(t, h.done.Load())
	assert.Nil(t, res.Failure, "%+v", res.Failure)
	assert.EqualValues(t, 5, res.PurgedThrough)
}

// purgeOnRead purges once, right before verify reads its first page of rows.
type purgeOnRead struct {
	t    *testing.T
	done atomic.Bool
}

func (h *purgeOnRead) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if strings.Contains(c.SQL, "ORDER BY seq LIMIT 5000") && h.done.CompareAndSwap(false, true) {
		n, err := audit_model.PurgeBatch(audit_model.WithSystem(db.DefaultContext, "cron"), oldCutoff(), 365, 10000)
		if err != nil || n != 5 {
			h.t.Errorf("purge during verify: %d %v", n, err)
		}
	}
	return db.TracingHook{}.BeforeProcess(c)
}

func (h *purgeOnRead) AfterProcess(c *contexts.ContextHook) error {
	return db.TracingHook{}.AfterProcess(c)
}
