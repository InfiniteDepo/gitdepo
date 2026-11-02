// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add pull_attention, the users a pull request is waiting on",
		Upgrade:     addPullAttention,
	})
}

func addPullAttention(x *xorm.Engine) error {
	type PullAttention struct {
		ID      int64              `xorm:"pk autoincr"`
		IssueID int64              `xorm:"UNIQUE(s) NOT NULL"`
		UserID  int64              `xorm:"UNIQUE(s) INDEX NOT NULL"`
		DoerID  int64              `xorm:"NOT NULL DEFAULT 0"`
		Kind    int                `xorm:"NOT NULL DEFAULT 0"`
		Reason  string             `xorm:"VARCHAR(255)"`
		Updated timeutil.TimeStamp `xorm:"updated"`
	}
	return x.Sync(new(PullAttention))
}
