// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the keep flag of action runs",
		Upgrade:     addActionRunKeep,
	})
}

func addActionRunKeep(x *xorm.Engine) error {
	type ActionRun struct {
		Keep bool `xorm:"NOT NULL DEFAULT false"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(ActionRun))
	return err
}
