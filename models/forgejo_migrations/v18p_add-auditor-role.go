// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the auditor role granted by user groups",
		Upgrade:     addAuditorRole,
	})
}

func addAuditorRole(x *xorm.Engine) error {
	type User struct {
		IsAuditor bool `xorm:"NOT NULL DEFAULT false"`
	}
	type UserGroup struct {
		GrantsAuditor bool `xorm:"NOT NULL DEFAULT false"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(User), new(UserGroup))
	return err
}
