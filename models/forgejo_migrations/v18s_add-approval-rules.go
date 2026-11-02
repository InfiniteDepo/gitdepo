// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the approval rules of protected branches",
		Upgrade:     addApprovalRules,
	})
}

type v18sProtectedBranchApprovalRule struct {
	ID                int64              `xorm:"pk autoincr"`
	ProtectedBranchID int64              `xorm:"INDEX UNIQUE(s) NOT NULL"`
	Name              string             `xorm:"VARCHAR(255) UNIQUE(s) NOT NULL"`
	RequiredCount     int64              `xorm:"NOT NULL DEFAULT 1"`
	UserIDs           []int64            `xorm:"JSON TEXT"`
	TeamIDs           []int64            `xorm:"JSON TEXT"`
	PathPatterns      string             `xorm:"TEXT"`
	RequireCodeOwners bool               `xorm:"NOT NULL DEFAULT false"`
	CreatedUnix       timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix       timeutil.TimeStamp `xorm:"updated"`
}

func (v18sProtectedBranchApprovalRule) TableName() string {
	return "protected_branch_approval_rule"
}

func addApprovalRules(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18sProtectedBranchApprovalRule))
	return err
}
