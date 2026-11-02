// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add give up deadline to pull request auto merges",
		Upgrade:     addPullAutoMergeGiveUpAfter,
	})
}

type v18qAutoMerge struct {
	GiveUpAfterUnix timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
}

func (v18qAutoMerge) TableName() string {
	return "pull_auto_merge"
}

func addPullAutoMergeGiveUpAfter(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18qAutoMerge))
	return err
}
