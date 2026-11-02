// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the pull mirror branch and tag filters",
		Upgrade:     addMirrorFilters,
	})
}

func addMirrorFilters(x *xorm.Engine) error {
	type Mirror struct {
		BranchFilter string `xorm:"VARCHAR(2048) NOT NULL DEFAULT ''"`
		TagFilter    string `xorm:"VARCHAR(2048) NOT NULL DEFAULT ''"`
		FilterError  string `xorm:"TEXT"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(Mirror))
	return err
}
