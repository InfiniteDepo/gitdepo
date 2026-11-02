// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add login source provenance to UserGroupUser",
		Upgrade:     addLoginSourceToUserGroupUser,
	})
}

func addLoginSourceToUserGroupUser(x *xorm.Engine) error {
	type UserGroupUser struct {
		LoginSourceID int64 `xorm:"NOT NULL DEFAULT 0"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(UserGroupUser))
	return err
}
