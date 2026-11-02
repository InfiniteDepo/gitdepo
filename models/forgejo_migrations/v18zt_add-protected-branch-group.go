// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add project branch protection rules",
		Upgrade:     addProtectedBranchGroup,
	})
}

type v18ztProtectedBranch struct {
	ID       int64  `xorm:"pk autoincr"`
	RepoID   int64  `xorm:"UNIQUE(s)"`
	OrgID    int64  `xorm:"UNIQUE(s) INDEX NOT NULL DEFAULT 0"`
	GroupID  int64  `xorm:"UNIQUE(s) NOT NULL DEFAULT 0"`
	RuleName string `xorm:"'branch_name' UNIQUE(s)"`
}

func (v18ztProtectedBranch) TableName() string {
	return "protected_branch"
}

func addProtectedBranchGroup(x *xorm.Engine) error {
	// the rule name is unique per repository, organization and project: recreate the index with group_id
	if err := dropIndexIfExists(x, "protected_branch", "UQE_protected_branch_s"); err != nil {
		return err
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18ztProtectedBranch))
	return err
}
