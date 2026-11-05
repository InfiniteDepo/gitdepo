// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the option to ignore approvals of users who pushed to a pull request to protected branches",
		Upgrade:     addIgnorePusherApprovals,
	})
}

func addIgnorePusherApprovals(x *xorm.Engine) error {
	type ProtectedBranch struct {
		IgnorePusherApprovals bool `xorm:"NOT NULL DEFAULT false"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(ProtectedBranch))
	return err
}
