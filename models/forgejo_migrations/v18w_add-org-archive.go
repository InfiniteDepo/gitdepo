// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add organization archive columns and repository.archived_by_org",
		Upgrade:     addOrgArchive,
	})
}

func addOrgArchive(x *xorm.Engine) error {
	type User struct {
		IsArchived   bool  `xorm:"NOT NULL DEFAULT false"`
		ArchivedUnix int64 `xorm:"NOT NULL DEFAULT 0"`
		ArchivedByID int64 `xorm:"NOT NULL DEFAULT 0"`
	}
	type Repository struct {
		ArchivedByOrg bool `xorm:"NOT NULL DEFAULT false"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(User), new(Repository))
	return err
}
