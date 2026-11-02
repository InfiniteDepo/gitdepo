// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import "code.forgejo.org/xorm/xorm"

func init() {
	registerMigration(&Migration{
		Description: "add skip merge forward to scheduled auto merges",
		Upgrade:     addAutoMergeSkipMergeForward,
	})
}

type v18zzdAutoMerge struct {
	ID               int64 `xorm:"pk autoincr"`
	SkipMergeForward bool  `xorm:"NOT NULL DEFAULT false"`
}

func (v18zzdAutoMerge) TableName() string {
	return "pull_auto_merge"
}

func addAutoMergeSkipMergeForward(x *xorm.Engine) error {
	return x.Sync(new(v18zzdAutoMerge))
}
