// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add org_category and user.category_id, the categories site admins group organizations in",
		Upgrade:     addOrgCategory,
	})
}

func addOrgCategory(x *xorm.Engine) error {
	type OrgCategory struct {
		ID          int64  `xorm:"pk autoincr"`
		Name        string `xorm:"VARCHAR(100) UNIQUE NOT NULL"`
		Description string `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
		Color       string `xorm:"VARCHAR(7) NOT NULL DEFAULT ''"`
		Position    int    `xorm:"NOT NULL DEFAULT 0"`
	}
	if err := x.Sync(new(OrgCategory)); err != nil {
		return err
	}
	type User struct {
		CategoryID int64 `xorm:"NOT NULL DEFAULT 0 INDEX"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(User))
	return err
}
