// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "record which mail was sent for a deployment",
		Upgrade:     addMailedStatusToActionDeployment,
	})
}

type v18zzwActionDeployment struct {
	ID           int64 `xorm:"pk autoincr"`
	MailedStatus int   `xorm:"NOT NULL DEFAULT 0"`
}

func (v18zzwActionDeployment) TableName() string {
	return "action_deployment"
}

func addMailedStatusToActionDeployment(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zzwActionDeployment))
	return err
}
