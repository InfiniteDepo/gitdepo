// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the organization and user trash columns",
		Upgrade:     addOwnerTrash,
	})
}

func addOwnerTrash(x *xorm.Engine) error {
	type User struct {
		TrashedUnix   int64  `xorm:"NOT NULL DEFAULT 0 INDEX"`
		TrashedByID   int64  `xorm:"NOT NULL DEFAULT 0"`
		TrashedByName string `xorm:"NOT NULL DEFAULT ''"`
		TrashedName   string `xorm:"NOT NULL DEFAULT ''"`
	}
	type Repository struct {
		TrashedWithOwner bool `xorm:"NOT NULL DEFAULT false"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(User), new(Repository))
	return err
}
