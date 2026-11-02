// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add token_permissions to action_task",
		Upgrade:     addActionTaskTokenPermissions,
	})
}

func addActionTaskTokenPermissions(x *xorm.Engine) error {
	type ActionTask struct {
		TokenPermissions string `xorm:"TEXT"`
	}
	return x.Sync(new(ActionTask))
}
