// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import "code.forgejo.org/xorm/xorm"

func init() {
	registerMigration(&Migration{
		Description: "add the allowed and default merge styles to protected branches and the build style to merge queue entries",
		Upgrade:     addMergeStylesToProtectedBranch,
	})
}

type v18zzzaProtectedBranch struct {
	AllowedMergeStyles []string `xorm:"JSON TEXT"`
	DefaultMergeStyle  string   `xorm:"VARCHAR(30) NOT NULL DEFAULT ''"`
}

func (v18zzzaProtectedBranch) TableName() string {
	return "protected_branch"
}

type v18zzzaMergeQueueEntry struct {
	BuildStyle string `xorm:"VARCHAR(30) NOT NULL DEFAULT ''"`
}

func (v18zzzaMergeQueueEntry) TableName() string {
	return "merge_queue_entry"
}

func addMergeStylesToProtectedBranch(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zzzaProtectedBranch), new(v18zzzaMergeQueueEntry))
	return err
}
