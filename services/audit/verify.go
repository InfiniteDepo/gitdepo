// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
)

// VerifyOptions: From is the first seq to check (rows before it are not checked, only linked to), Anchor is a
// "SEQ:HASH" the auditor kept outside the database.
type VerifyOptions struct {
	From   int64
	Anchor string
}

// VerifyFailure names the first broken seq and why: hash (edited row), link (prev_hash differs), gap (missing or
// reordered seq), head (the chain ends before or differs from the stored head, e.g. deleted tail) or anchor.
type VerifyFailure struct {
	Seq    int64
	Reason string
}

type VerifyResult struct {
	Rows, FirstSeq, LastSeq int64
	LastHash                string
	Unsealed                int64 // capped at audit_model.UnsealedCountCap
	OldestUnsealedAge       time.Duration
	Failure                 *VerifyFailure
	PurgedThrough           int64 // entries up to this seq were deleted by retention and are not checked
}

var anchorRe = regexp.MustCompile(`^([1-9][0-9]*):([0-9a-f]{64})$`)

const verifyPage = 5000

// Verify checks the chain from the retention anchor (seq 1 if nothing was purged) or o.From up to the head as it was
// when Verify started, and only reads. Rows sealed meanwhile are left for the next run. A purge that moves the
// anchor during the run makes it fail; then it runs once more from the new anchor, and a second failure is real.
func Verify(ctx context.Context, o VerifyOptions) (*VerifyResult, error) {
	for attempt := 0; ; attempt++ {
		res, anchor, err := verifyOnce(ctx, o)
		if err != nil || res.Failure == nil || attempt > 0 {
			return res, err
		}
		if cur, err := audit_model.GetHead(ctx); err != nil || cur.AnchorSeq == anchor {
			return res, err
		}
	}
}

// checkPurgeEntry is AC9: the latest audit.purge (by id, also an unsealed one) names the stored anchor exactly and
// its own numbers are plausible (an allowed retention, a cutoff at least 30 days before the entry).
func checkPurgeEntry(ctx context.Context, head *audit_model.ChainHead) (bool, error) {
	e := &audit_model.Entry{}
	if has, err := db.GetEngine(ctx).Where("action = ?", "audit.purge").OrderBy("id DESC").Get(e); err != nil || !has {
		return false, err
	}
	var d struct {
		ThroughSeq    int64  `json:"through_seq"`
		ThroughHash   string `json:"through_hash"`
		CutoffUnix    int64  `json:"cutoff_unix"`
		RetentionDays int    `json:"retention_days"`
	}
	if json.Unmarshal([]byte(e.Data), &d) != nil {
		return false, nil
	}
	return d.ThroughSeq == head.AnchorSeq && d.ThroughHash == head.AnchorPrevHash &&
		slices.Contains(setting.AuditRetentionAllowed, d.RetentionDays) &&
		d.CutoffUnix <= int64(e.CreatedUnix)-30*24*3600, nil
}

func verifyOnce(ctx context.Context, o VerifyOptions) (*VerifyResult, int64, error) {
	var anchorSeq int64
	var anchorHash string
	if o.Anchor != "" {
		m := anchorRe.FindStringSubmatch(o.Anchor)
		if m == nil {
			return nil, 0, fmt.Errorf("the anchor must be SEQ:HASH (64 lower-case hex digits)")
		}
		anchorSeq, _ = strconv.ParseInt(m[1], 10, 64)
		anchorHash = m[2]
	}
	head, err := audit_model.GetHead(ctx)
	if err != nil {
		return nil, 0, err
	}
	res := &VerifyResult{}
	if res.Unsealed, res.OldestUnsealedAge, err = audit_model.UnsealedStats(ctx); err != nil {
		return nil, 0, err
	}
	fail := func(seq int64, reason string) {
		if res.Failure == nil {
			res.Failure = &VerifyFailure{seq, reason}
		}
	}

	next, prev := max(o.From, 1), audit_model.ZeroHash
	if head.AnchorSeq > 0 {
		res.PurgedThrough = head.AnchorSeq
	}
	if head.AnchorSeq > 0 && next <= head.AnchorSeq+1 {
		next, prev = head.AnchorSeq+1, head.AnchorPrevHash
	} else if next > 1 {
		e, err := audit_model.GetBySeq(ctx, next-1)
		if err != nil {
			return nil, 0, err
		}
		if e == nil || e.Hash == nil {
			fail(next-1, "gap")
			return res, head.AnchorSeq, nil
		}
		prev = *e.Hash
	}
	anchorSeen := false
	if o.Anchor != "" && head.AnchorSeq > 0 && anchorSeq <= head.AnchorSeq {
		// the entries below the retention anchor are gone; only the anchor itself can be compared
		anchorSeen = anchorSeq == head.AnchorSeq && anchorHash == head.AnchorPrevHash
	}
	for after := next - 1; res.Failure == nil && after < head.Seq; {
		rows, err := audit_model.FindSealed(ctx, after, head.Seq, verifyPage)
		if err != nil {
			return nil, 0, err
		}
		if len(rows) == 0 {
			break // the head names rows that are gone
		}
		for _, e := range rows {
			seq := *e.Seq
			if seq != next {
				fail(next, "gap")
				break
			}
			if e.PrevHash == nil || *e.PrevHash != prev {
				fail(seq, "link")
				break
			}
			hash, err := audit_model.HashEntry(prev, e)
			if err != nil {
				return nil, 0, err
			}
			if e.Hash == nil || *e.Hash != hash {
				fail(seq, "hash")
				break
			}
			if seq == anchorSeq {
				anchorSeen = true
				if hash != anchorHash {
					fail(seq, "anchor")
					break
				}
			}
			if res.Rows == 0 {
				res.FirstSeq = seq
			}
			res.Rows, res.LastSeq, res.LastHash = res.Rows+1, seq, hash
			prev, next, after = hash, next+1, seq
		}
	}
	if next-1 != head.Seq || prev != head.Hash {
		fail(head.Seq, "head")
	}
	// a row beyond the head is a head that was set back; read the max first, so rows sealed meanwhile are covered
	maxSeq, err := audit_model.MaxSealedSeq(ctx)
	if err != nil {
		return nil, 0, err
	}
	if cur, err := audit_model.GetHead(ctx); err != nil {
		return nil, 0, err
	} else if maxSeq > cur.Seq {
		fail(cur.Seq, "head")
	}
	if o.Anchor != "" && !anchorSeen {
		fail(anchorSeq, "anchor")
	}
	if head.AnchorSeq > 0 {
		if ok, err := checkPurgeEntry(ctx, head); err != nil {
			return nil, 0, err
		} else if !ok {
			fail(head.AnchorSeq, "anchor")
		}
	}
	return res, head.AnchorSeq, nil
}

// String is the CLI summary line.
func (r *VerifyResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "rows checked: %d (seq %d..%d)\n", r.Rows, r.FirstSeq, r.LastSeq)
	if r.PurgedThrough > 0 {
		fmt.Fprintf(&b, "entries up to seq %d were deleted by retention and are not checked\n", r.PurgedThrough)
	}
	if r.LastSeq > 0 {
		fmt.Fprintf(&b, "latest: %d:%s\n", r.LastSeq, r.LastHash)
	}
	fmt.Fprintf(&b, "unsealed: %d, oldest %s old\n", r.Unsealed, r.OldestUnsealedAge.Round(time.Second))
	if f := r.Failure; f != nil {
		fmt.Fprintf(&b, "FAILED at seq %d: %s\n", f.Seq, f.Reason)
	} else {
		b.WriteString("OK\n")
	}
	return b.String()
}
