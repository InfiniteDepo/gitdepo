// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "mark the Actions environments that a workflow created, and record when the due-deployments task last looked at a deployment",
		Upgrade:     addActionsEnvironmentCreatedByWorkflow,
	})
}

type v18zztActionEnvironment struct {
	ID                int64 `xorm:"pk autoincr"`
	CreatedByWorkflow bool  `xorm:"NOT NULL DEFAULT false"`
}

func (v18zztActionEnvironment) TableName() string {
	return "action_environment"
}

type v18zztActionDeployment struct {
	ID          int64 `xorm:"pk autoincr"`
	CheckedUnix int64 `xorm:"NOT NULL DEFAULT 0"`
}

func (v18zztActionDeployment) TableName() string {
	return "action_deployment"
}

func addActionsEnvironmentCreatedByWorkflow(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zztActionEnvironment), new(v18zztActionDeployment))
	return err
}
