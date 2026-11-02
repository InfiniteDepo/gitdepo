// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"context"
	"fmt"
	"time"

	"forgejo.org/models/db"
)

// PurgeBatch deletes up to batch sealed entries that are older than cutoff, in seq order from the anchor on, and
// returns how many. It stops at the first entry (by seq) that is not older, even if later ones are, and never
// deletes the head entry or an unsealed one. In one transaction under the head lock (the sealer's) it moves the
// anchor to the last deleted entry and records audit.purge, so a failed record deletes nothing. ctx carries the actor.
func PurgeBatch(ctx context.Context, cutoff time.Time, retentionDays, batch int) (deleted int64, err error) {
	err = db.WithTx(ctx, func(ctx context.Context) error {
		deleted = 0
		e := db.GetEngine(ctx)
		if _, err := e.Exec("UPDATE audit_chain_head SET seq = seq WHERE id = 1"); err != nil {
			return err
		}
		head, err := GetHead(ctx)
		if err != nil {
			return err
		}
		through := min(head.Seq-1, head.AnchorSeq+int64(batch))
		newer := &Entry{}
		if has, err := e.Where("seq > ? AND created_unix >= ?", head.AnchorSeq, cutoff.Unix()).OrderBy("seq").Get(newer); err != nil {
			return err
		} else if has {
			through = min(through, *newer.Seq-1)
		}
		if through <= head.AnchorSeq {
			return nil
		}
		last, err := GetBySeq(ctx, through)
		if err != nil {
			return err
		}
		if last == nil || last.Hash == nil {
			return fmt.Errorf("audit: sealed entry %d is missing, verify the chain", through)
		}
		n, err := e.Where("seq > ? AND seq <= ?", head.AnchorSeq, through).Delete(new(Entry))
		if err != nil {
			return err
		}
		if n != through-head.AnchorSeq {
			return fmt.Errorf("audit: deleted %d entries for seq %d..%d, verify the chain", n, head.AnchorSeq+1, through)
		}
		if updated, err := e.Table("audit_chain_head").Where("id = 1 AND anchor_seq = ?", head.AnchorSeq).
			Update(map[string]any{"anchor_seq": through, "anchor_prev_hash": *last.Hash}); err != nil {
			return err
		} else if updated != 1 {
			return fmt.Errorf("audit: the anchor moved from seq %d", head.AnchorSeq)
		}
		deleted = n
		return Record(ctx, Event{
			Action: "audit.purge", Result: ResultSuccess, TargetType: "audit_chain",
			Data: map[string]any{
				"deleted": n, "through_seq": through, "through_hash": *last.Hash,
				"cutoff_unix": cutoff.Unix(), "retention_days": retentionDays,
			},
		})
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}
