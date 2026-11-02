// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json" //nolint:depguard // the canonical form is defined by encoding/json, never by the swappable json module
	"strings"
	"time"

	"forgejo.org/models/db"
	"forgejo.org/modules/setting"
)

// ZeroHash is the hash before the first sealed entry.
var ZeroHash = strings.Repeat("0", 64)

const chainDomain = "gitdepo-audit-v1\n"

// Canonical returns the JSON array that is hashed: every column of e in a fixed order except seq, prev_hash and
// hash, with the id and data as stored. Strings are escaped like encoding/json does.
func Canonical(e *Entry) ([]byte, error) {
	return json.Marshal([]any{
		e.ID, int64(e.CreatedUnix), e.Action, e.Category, e.Result, e.ActorType, e.ActorID, e.ActorName, e.SudoByID,
		e.CredentialType, e.CredentialID, e.CredentialName, e.CredentialOwnerID, e.IP, e.UserAgent, e.RequestID,
		e.OwnerID, e.GroupID, e.RepoID, e.SubjectUserID, e.TargetType, e.TargetID, e.TargetName, e.Data,
	})
}

// HashEntry returns SHA-256(prev ‖ "gitdepo-audit-v1\n" ‖ canonical) in lower-case hex.
func HashEntry(prev string, e *Entry) (string, error) {
	canonical, err := Canonical(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(prev + chainDomain + string(canonical)))
	return hex.EncodeToString(sum[:]), nil
}

// GetHead returns the chain head; without a head row (a fresh install before the first seal) it is the empty chain.
// It only reads: EnsureHead creates the row.
func GetHead(ctx context.Context) (*ChainHead, error) {
	h := &ChainHead{}
	if has, err := db.GetEngine(ctx).ID(1).Get(h); err != nil {
		return nil, err
	} else if !has {
		return &ChainHead{ID: 1, Hash: ZeroHash, AnchorPrevHash: ZeroHash}, nil
	}
	return h, nil
}

// EnsureHead creates the head row if it is missing. Fresh installs record the migration without running it, so the
// row is not in the migration. Concurrent callers insert only if absent: an insert error would also abort a
// PostgreSQL transaction.
func EnsureHead(ctx context.Context) error {
	insert := "INSERT INTO audit_chain_head (id, seq, hash, anchor_seq, anchor_prev_hash) VALUES (1, 0, ?, 0, ?) ON CONFLICT (id) DO NOTHING"
	if setting.Database.Type.IsMySQL() {
		insert = "INSERT IGNORE INTO audit_chain_head (id, seq, hash, anchor_seq, anchor_prev_hash) VALUES (1, 0, ?, 0, ?)"
	}
	_, err := db.Exec(ctx, insert, ZeroHash, ZeroHash)
	return err
}

// FindUnsealed returns up to limit entries without a seq, oldest id first, leaving out skipID. It is a variable so
// that tests can race the sealer.
var FindUnsealed = func(ctx context.Context, limit int, skipID int64) (rows []*Entry, err error) {
	return rows, db.GetEngine(ctx).Where("seq IS NULL AND id <> ?", skipID).OrderBy("id").Limit(limit).Find(&rows)
}

// HasUnsealed reports whether any entry waits for the sealer. It reads only.
func HasUnsealed(ctx context.Context) (bool, error) {
	return db.GetEngine(ctx).Where("seq IS NULL").Exist(new(Entry))
}

// UnsealedCountCap bounds the count of UnsealedStats: n is at most UnsealedCountCap, which the page shows as "10000+".
const UnsealedCountCap = 10_001

// UnsealedStats returns how many entries wait for the sealer (up to UnsealedCountCap) and the age of the oldest.
func UnsealedStats(ctx context.Context) (n int64, oldest time.Duration, err error) {
	var ids []int64
	if err = db.GetEngine(ctx).Table("audit_event").Where("seq IS NULL").OrderBy("id").Cols("id").Limit(UnsealedCountCap).Find(&ids); err != nil || len(ids) == 0 {
		return 0, 0, err
	}
	first := &Entry{}
	if _, err = db.GetEngine(ctx).ID(ids[0]).Cols("created_unix").Get(first); err != nil {
		return 0, 0, err
	}
	return int64(len(ids)), time.Since(first.CreatedUnix.AsTime()), nil
}

// FindSealed returns up to limit entries with afterSeq < seq <= maxSeq, in seq order.
func FindSealed(ctx context.Context, afterSeq, maxSeq int64, limit int) (rows []*Entry, err error) {
	return rows, db.GetEngine(ctx).Where("seq > ? AND seq <= ?", afterSeq, maxSeq).OrderBy("seq").Limit(limit).Find(&rows)
}

// GetBySeq returns the sealed entry at seq, or nil.
func GetBySeq(ctx context.Context, seq int64) (*Entry, error) {
	e := &Entry{}
	if has, err := db.GetEngine(ctx).Where("seq = ?", seq).Get(e); err != nil || !has {
		return nil, err
	}
	return e, nil
}

// MaxSealedSeq returns the highest seq of any entry, 0 if none is sealed.
func MaxSealedSeq(ctx context.Context) (seq int64, err error) {
	_, err = db.GetEngine(ctx).Table("audit_event").Select("COALESCE(MAX(seq), 0)").Get(&seq)
	return seq, err
}
