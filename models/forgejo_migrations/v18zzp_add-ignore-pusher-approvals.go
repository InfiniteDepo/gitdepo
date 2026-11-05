// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the option to ignore approvals of users who pushed to a pull request, the branch pushers and the deploy key creators",
		Upgrade:     addIgnorePusherApprovals,
	})
}

func addIgnorePusherApprovals(x *xorm.Engine) error {
	type ProtectedBranch struct {
		IgnorePusherApprovals bool `xorm:"NOT NULL DEFAULT false"`
	}
	type DeployKey struct {
		CreatorID int64 `xorm:"NOT NULL DEFAULT 0"`
	}
	type OrgDeployKey struct {
		CreatorID int64 `xorm:"NOT NULL DEFAULT 0"`
	}
	type BranchPusher struct {
		ID          int64  `xorm:"pk autoincr"`
		RepoID      int64  `xorm:"UNIQUE(s) INDEX NOT NULL"`
		Branch      string `xorm:"UNIQUE(s) NOT NULL"`
		UserID      int64  `xorm:"UNIQUE(s) NOT NULL"`
		CreatedUnix int64  `xorm:"created"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(ProtectedBranch), new(DeployKey), new(OrgDeployKey), new(BranchPusher))
	return err
}
