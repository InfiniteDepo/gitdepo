// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "record when the due-deployments task last looked at an Actions deployment",
		Upgrade:     addActionsDeploymentCheckedUnix,
	})
}

type v18zzuActionDeployment struct {
	ID          int64 `xorm:"pk autoincr"`
	CheckedUnix int64 `xorm:"NOT NULL DEFAULT 0"`
}

func (v18zzuActionDeployment) TableName() string {
	return "action_deployment"
}

func addActionsDeploymentCheckedUnix(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zzuActionDeployment))
	return err
}
