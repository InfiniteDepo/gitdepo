// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add push_rule table",
		Upgrade:     addPushRule,
	})
}

func addPushRule(x *xorm.Engine) error {
	type PushRule struct {
		ID                         int64              `xorm:"pk autoincr"`
		RepoID                     int64              `xorm:"UNIQUE NOT NULL"`
		CommitMessageRegex         string             `xorm:"TEXT"`
		CommitMessageBannedRegex   string             `xorm:"TEXT"`
		BranchNameRegex            string             `xorm:"TEXT"`
		RequireVerifiedAuthorEmail bool               `xorm:"NOT NULL DEFAULT false"`
		MaxFileSizeMB              int64              `xorm:"NOT NULL DEFAULT 0"`
		BannedFilePatterns         string             `xorm:"TEXT"`
		CreatedUnix                timeutil.TimeStamp `xorm:"created"`
		UpdatedUnix                timeutil.TimeStamp `xorm:"updated"`
	}
	return x.Sync(new(PushRule))
}
