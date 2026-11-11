// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the state of the cleanup of merged branches of a repository",
		Upgrade:     addBranchCleanupState,
	})
}

type v18zzyBranchCleanupState struct {
	RepoID      int64 `xorm:"pk"`
	Days        int   `xorm:"NOT NULL DEFAULT 0"`
	PendingDays int   `xorm:"NOT NULL DEFAULT 0"`
	PendingFrom int64 `xorm:"NOT NULL DEFAULT 0"`
	LastRunUnix int64 `xorm:"NOT NULL DEFAULT 0"`
}

func (v18zzyBranchCleanupState) TableName() string {
	return "branch_cleanup_state"
}

func addBranchCleanupState(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zzyBranchCleanupState))
	return err
}
