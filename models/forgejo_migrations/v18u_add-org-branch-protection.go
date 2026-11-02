// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add organization branch protection rules",
		Upgrade:     addOrgBranchProtection,
	})
}

type v18uProtectedBranch struct {
	ID                   int64  `xorm:"pk autoincr"`
	RepoID               int64  `xorm:"UNIQUE(s)"`
	OrgID                int64  `xorm:"UNIQUE(s) INDEX NOT NULL DEFAULT 0"`
	RuleName             string `xorm:"'branch_name' UNIQUE(s)"`
	ApplyToSelectedRepos bool   `xorm:"NOT NULL DEFAULT false"`
}

func (v18uProtectedBranch) TableName() string {
	return "protected_branch"
}

type v18uProtectedBranchRepo struct {
	ID                int64 `xorm:"pk autoincr"`
	ProtectedBranchID int64 `xorm:"UNIQUE(s) INDEX NOT NULL"`
	RepoID            int64 `xorm:"UNIQUE(s) INDEX NOT NULL"`
}

func (v18uProtectedBranchRepo) TableName() string {
	return "protected_branch_repo"
}

func addOrgBranchProtection(x *xorm.Engine) error {
	// the rule name is unique per repository and organization: recreate the index with org_id
	if err := dropIndexIfExists(x, "protected_branch", "UQE_protected_branch_s"); err != nil {
		return err
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18uProtectedBranch), new(v18uProtectedBranchRepo))
	return err
}
