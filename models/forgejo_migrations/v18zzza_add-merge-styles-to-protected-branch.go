// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import "code.forgejo.org/xorm/xorm"

func init() {
	registerMigration(&Migration{
		Description: "add the allowed and default merge styles to protected branches",
		Upgrade:     addMergeStylesToProtectedBranch,
	})
}

type v18zzyProtectedBranch struct {
	AllowedMergeStyles []string `xorm:"JSON TEXT"`
	DefaultMergeStyle  string   `xorm:"VARCHAR(30) NOT NULL DEFAULT ''"`
}

func (v18zzyProtectedBranch) TableName() string {
	return "protected_branch"
}

func addMergeStylesToProtectedBranch(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zzyProtectedBranch))
	return err
}
