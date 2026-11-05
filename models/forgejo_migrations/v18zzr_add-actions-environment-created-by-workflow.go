// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "mark the Actions environments that a workflow created",
		Upgrade:     addActionsEnvironmentCreatedByWorkflow,
	})
}

type v18zzrActionEnvironment struct {
	ID                int64 `xorm:"pk autoincr"`
	CreatedByWorkflow bool  `xorm:"NOT NULL DEFAULT false"`
}

func (v18zzrActionEnvironment) TableName() string {
	return "action_environment"
}

func addActionsEnvironmentCreatedByWorkflow(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zzrActionEnvironment))
	return err
}
