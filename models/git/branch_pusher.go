// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"context"

	"forgejo.org/models/db"
	"forgejo.org/modules/timeutil"

	"xorm.io/builder"
)

// BranchPusher records that a user pushed to a branch (UserID 0: a deploy key with no recorded owner did). Rows are
// written by the pre-receive hook before the push is accepted, so a push that is refused later only leaves an extra
// pusher, which makes "ignore pusher approvals" stricter and never looser. Rows stay while the repository exists,
// also after the branch is deleted, so restoring a branch brings its pushers back.
type BranchPusher struct {
	ID          int64              `xorm:"pk autoincr"`
	RepoID      int64              `xorm:"UNIQUE(s) INDEX NOT NULL"`
	Branch      string             `xorm:"UNIQUE(s) NOT NULL"`
	UserID      int64              `xorm:"UNIQUE(s) NOT NULL"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
}

func init() {
	db.RegisterModel(new(BranchPusher))
}

// AddBranchPusher records the push, once per user and branch.
func AddBranchPusher(ctx context.Context, repoID int64, branch string, userID int64) error {
	// by condition, not by bean: xorm drops the zero user ID of a bean
	cond := builder.Eq{"repo_id": repoID, "branch": branch, "user_id": userID}
	has, err := db.GetEngine(ctx).Where(cond).Exist(new(BranchPusher))
	if err != nil || has {
		return err
	}
	if err := db.Insert(ctx, &BranchPusher{RepoID: repoID, Branch: branch, UserID: userID}); err != nil {
		// a concurrent push of the same user wrote the row first
		if has, _ := db.GetEngine(ctx).Where(cond).Exist(new(BranchPusher)); has {
			return nil
		}
		return err
	}
	return nil
}

// FindBranchPusherIDs returns the users who pushed to the branch (0 for a deploy key with no recorded owner).
func FindBranchPusherIDs(ctx context.Context, repoID int64, branch string) ([]int64, error) {
	ids := make([]int64, 0, 4)
	return ids, db.GetEngine(ctx).Table("branch_pusher").Cols("user_id").
		Where(builder.Eq{"repo_id": repoID, "branch": branch}).Find(&ids)
}
