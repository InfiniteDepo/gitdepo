// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"context"

	"forgejo.org/models/db"
)

// BranchCleanupState records the days of the cleanup of merged branches that apply to one repository, whichever
// level (repository, organization, lock) they came from, and the change that waits: a turn-on or a lowering is
// pending until PendingFrom (unix seconds), and the recorded Days keep applying meanwhile. LastRunUnix claims the
// scheduled run, so only one server runs a repository's cleanup per day.
type BranchCleanupState struct {
	RepoID      int64 `xorm:"pk"`
	Days        int   `xorm:"NOT NULL DEFAULT 0"` // in force; 0 is off
	PendingDays int   `xorm:"NOT NULL DEFAULT 0"`
	PendingFrom int64 `xorm:"NOT NULL DEFAULT 0"` // 0: nothing waits
	LastRunUnix int64 `xorm:"NOT NULL DEFAULT 0"`
}

func init() {
	db.RegisterModel(new(BranchCleanupState))
}

// GetBranchCleanupState returns the repository's record, nil when it has none yet.
func GetBranchCleanupState(ctx context.Context, repoID int64) (*BranchCleanupState, error) {
	s := &BranchCleanupState{}
	has, err := db.GetEngine(ctx).ID(repoID).Get(s)
	if err != nil || !has {
		return nil, err
	}
	return s, nil
}

// SaveBranchCleanupState stores the days in force and the waiting change of s, creating the record if needed; the
// last run is never touched.
func SaveBranchCleanupState(ctx context.Context, s *BranchCleanupState) error {
	update := func() (int64, error) {
		return db.GetEngine(ctx).ID(s.RepoID).Cols("days", "pending_days", "pending_from").Update(s)
	}
	if n, err := update(); err != nil || n > 0 {
		return err
	}
	has, err := db.GetEngine(ctx).ID(s.RepoID).Exist(new(BranchCleanupState))
	if err != nil || has { // unchanged values count as no row on some databases
		return err
	}
	if _, err := db.GetEngine(ctx).Insert(&BranchCleanupState{RepoID: s.RepoID, Days: s.Days, PendingDays: s.PendingDays, PendingFrom: s.PendingFrom}); err != nil {
		// another server created it first
		_, err = update()
		return err
	}
	return nil
}

// ClaimBranchCleanupRun takes the repository's scheduled run: it succeeds for one caller only, until the last
// claim is older than cutoff (unix seconds). The record must exist.
func ClaimBranchCleanupRun(ctx context.Context, repoID, cutoff, now int64) (bool, error) {
	n, err := db.GetEngine(ctx).Where("repo_id = ? AND last_run_unix < ?", repoID, cutoff).Cols("last_run_unix").Update(&BranchCleanupState{LastRunUnix: now})
	return n == 1, err
}
