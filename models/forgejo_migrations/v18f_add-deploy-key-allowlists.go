// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add deploy key allow-lists to branch and tag protection rules",
		Upgrade:     addDeployKeyAllowlists,
	})
}

func addDeployKeyAllowlists(x *xorm.Engine) error {
	type ProtectedBranch struct {
		WhitelistDeployKeyIDs []int64 `xorm:"JSON TEXT"`
	}
	type ProtectedTag struct {
		AllowlistDeployKeyIDs []int64 `xorm:"JSON TEXT"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(ProtectedBranch), new(ProtectedTag))
	return err
}
