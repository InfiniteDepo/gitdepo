// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add action_scheduled_dispatch, the manual workflow runs that start at a chosen time",
		Upgrade:     addScheduledDispatch,
	})
}

func addScheduledDispatch(x *xorm.Engine) error {
	type ActionScheduledDispatch struct {
		ID           int64
		RepoID       int64  `xorm:"INDEX NOT NULL"`
		WorkflowID   string `xorm:"VARCHAR(255) NOT NULL"`
		Ref          string `xorm:"VARCHAR(255) NOT NULL"`
		CommitID     string `xorm:"VARCHAR(64) NOT NULL DEFAULT ''"`
		Inputs       string `xorm:"TEXT NOT NULL"`
		DoerID       int64  `xorm:"NOT NULL"`
		RunAt        int64  `xorm:"INDEX NOT NULL"`
		Status       int    `xorm:"NOT NULL DEFAULT 0"`
		CancelReason string `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
		Created      int64  `xorm:"created"`
		Updated      int64  `xorm:"updated"`
	}
	return x.Sync(new(ActionScheduledDispatch))
}
