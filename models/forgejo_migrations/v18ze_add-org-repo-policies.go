// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the organization repository policies",
		Upgrade:     addOrgRepoPolicies,
	})
}

func addOrgRepoPolicies(x *xorm.Engine) error {
	type User struct {
		RestrictRepoVisibilityChange bool `xorm:"NOT NULL DEFAULT false"`
		PrivateForkPolicy            int  `xorm:"NOT NULL DEFAULT 0"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(User))
	return err
}
