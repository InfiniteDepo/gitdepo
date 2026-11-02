// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the repository trash columns",
		Upgrade:     addTrash,
	})
}

func addTrash(x *xorm.Engine) error {
	type Repository struct {
		TrashedUnix      int64  `xorm:"NOT NULL DEFAULT 0 INDEX"`
		TrashedByID      int64  `xorm:"NOT NULL DEFAULT 0"`
		TrashedByName    string `xorm:"NOT NULL DEFAULT ''"`
		TrashedOwnerName string `xorm:"NOT NULL DEFAULT ''"`
		TrashedName      string `xorm:"NOT NULL DEFAULT ''"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(Repository))
	return err
}
