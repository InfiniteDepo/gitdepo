// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "record that a branch was deleted by the scheduled cleanup",
		Upgrade:     addBranchDeletedByCleanup,
	})
}

type v18zzzBranch struct {
	ID               int64 `xorm:"pk autoincr"`
	DeletedByCleanup bool  `xorm:"NOT NULL DEFAULT false"`
}

func (v18zzzBranch) TableName() string {
	return "branch"
}

func addBranchDeletedByCleanup(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zzzBranch))
	return err
}
