// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add delete and force push allow-lists to branch protection rules",
		Upgrade:     addProtectedBranchDeleteForcePushAllowlists,
	})
}

func addProtectedBranchDeleteForcePushAllowlists(x *xorm.Engine) error {
	type ProtectedBranch struct {
		DeleteAllowlistUserIDs         []int64 `xorm:"JSON TEXT"`
		DeleteAllowlistTeamIDs         []int64 `xorm:"JSON TEXT"`
		DeleteAllowlistDeployKeyIDs    []int64 `xorm:"JSON TEXT"`
		ForcePushAllowlistUserIDs      []int64 `xorm:"JSON TEXT"`
		ForcePushAllowlistTeamIDs      []int64 `xorm:"JSON TEXT"`
		ForcePushAllowlistDeployKeyIDs []int64 `xorm:"JSON TEXT"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(ProtectedBranch))
	return err
}
