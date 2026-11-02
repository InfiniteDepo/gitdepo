// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the wiki size of repositories",
		Upgrade:     addRepoWikiSize,
	})
}

func addRepoWikiSize(x *xorm.Engine) error {
	type Repository struct {
		WikiSize int64 `xorm:"NOT NULL DEFAULT 0"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(Repository))
	return err
}
