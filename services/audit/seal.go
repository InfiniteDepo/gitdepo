// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"context"
	"fmt"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/modules/log"
)

// SealInterval is how often RunSealer seals; SealBatchesPerCall bounds one SealAll, so a backlog is worked off over
// several ticks. Variables for tests.
var (
	SealInterval       = 2 * time.Second
	SealBatchesPerCall = 20
)

const sealBatch = 500

// Seal chains up to 500 entries that have no seq into the hash chain, oldest id first, and returns how many. The
// first sealed entry of a chain is audit.chain.started. It takes the head lock (a no-op UPDATE of the head row: the
// write lock on SQLite, the row lock elsewhere) before it reads anything, so concurrent sealers on any pod are
// serialized by the database; an idle pod only reads.
func Seal(ctx context.Context) (n int, err error) {
	var sealed []*audit_model.Entry
	if has, err := audit_model.HasUnsealed(ctx); err != nil || !has {
		return 0, err
	}
	err = db.WithTx(ctx, func(ctx context.Context) error {
		n = 0
		if err := audit_model.EnsureHead(ctx); err != nil {
			return err
		}
		if _, err := db.Exec(ctx, "UPDATE audit_chain_head SET seq = seq WHERE id = 1"); err != nil {
			return err
		}
		head, err := audit_model.GetHead(ctx)
		if err != nil {
			return err
		}
		rows, err := audit_model.FindUnsealed(ctx, sealBatch, 0)
		if err != nil || len(rows) == 0 {
			return err // another pod sealed them while we waited for the lock
		}
		if head.Seq == 0 {
			if rows, err = startChain(ctx, rows[0].ID); err != nil {
				return err
			}
		}
		prev, seq := head.Hash, head.Seq
		for _, e := range rows {
			seq++
			hash, err := audit_model.HashEntry(prev, e)
			if err != nil {
				return err
			}
			if updated, err := db.GetEngine(ctx).Table("audit_event").Where("id = ? AND seq IS NULL", e.ID).
				Update(map[string]any{"seq": seq, "prev_hash": prev, "hash": hash}); err != nil {
				return err
			} else if updated != 1 {
				return fmt.Errorf("audit: entry %d was sealed by another sealer", e.ID)
			}
			e.Seq, e.PrevHash, e.Hash = new(seq), new(prev), new(hash)
			prev = hash
		}
		if updated, err := db.GetEngine(ctx).Table("audit_chain_head").Where("id = 1 AND seq = ?", head.Seq).
			Update(map[string]any{"seq": seq, "hash": prev}); err != nil {
			return err
		} else if updated != 1 {
			return fmt.Errorf("audit: the chain head moved from seq %d", head.Seq)
		}
		n, sealed = len(rows), rows
		return nil
	})
	if err == nil {
		shipEntries(ctx, sealed) // only committed rows, once, by the sealer that sealed them
	}
	return n, err
}

// startChain records audit.chain.started and returns the next batch with it in front, so it becomes seq 1 and the
// older entries follow by id.
func startChain(ctx context.Context, firstID int64) ([]*audit_model.Entry, error) {
	count, err := db.GetEngine(ctx).Where("seq IS NULL").Count(new(audit_model.Entry))
	if err != nil {
		return nil, err
	}
	if err := audit_model.Record(audit_model.WithSystem(ctx, "chain"), audit_model.Event{
		Action: "audit.chain.started", Result: audit_model.ResultSuccess, TargetType: "audit_chain",
		Data: map[string]any{"unsealed_before": count, "first_unsealed_id": firstID},
	}); err != nil {
		return nil, err
	}
	started := &audit_model.Entry{}
	if has, err := db.GetEngine(ctx).Where("seq IS NULL AND action = ?", "audit.chain.started").Get(started); err != nil || !has {
		return nil, fmt.Errorf("audit: audit.chain.started not found: %v", err)
	}
	rows, err := audit_model.FindUnsealed(ctx, sealBatch-1, started.ID)
	return append([]*audit_model.Entry{started}, rows...), err
}

// SealAll seals batch after batch until nothing is left or SealBatchesPerCall batches are done; a remaining backlog
// is not an error.
func SealAll(ctx context.Context) error {
	for range SealBatchesPerCall {
		if n, err := Seal(ctx); err != nil || n == 0 {
			return err
		}
	}
	return nil
}

// RunSealer seals every SealInterval until ctx is done. It also runs in maintenance mode, and a sealing error is
// logged, never hidden: the next tick tries again.
func RunSealer(ctx context.Context) {
	t := time.NewTicker(SealInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := SealAll(ctx); err != nil && ctx.Err() == nil {
				log.Error("audit: sealing the chain: %v", err)
			}
		}
	}
}
