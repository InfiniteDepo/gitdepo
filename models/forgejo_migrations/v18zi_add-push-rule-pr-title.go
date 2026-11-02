// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add pull request title rule columns to push_rule",
		Upgrade:     addPushRulePRTitle,
	})
}

func addPushRulePRTitle(x *xorm.Engine) error {
	type PushRule struct {
		PRTitleRegex       string `xorm:"TEXT"`
		PRTitleBannedRegex string `xorm:"TEXT"`
		PRTitleMessage     string `xorm:"VARCHAR(255)"`
		PRTitleBranches    string `xorm:"TEXT"`
		PRTitleBlockMerge  bool   `xorm:"NOT NULL DEFAULT false"`
	}
	return x.Sync(new(PushRule))
}
