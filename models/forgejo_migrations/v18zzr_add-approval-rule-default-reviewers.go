// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add default reviewers (review requests and a source branch pattern) to approval rules",
		Upgrade:     addApprovalRuleDefaultReviewers,
	})
}

// v18zzrApprovalRule is the whole table, so that Sync keeps its unique key; the new columns are the last two.
type v18zzrApprovalRule struct {
	ID                  int64              `xorm:"pk autoincr"`
	ProtectedBranchID   int64              `xorm:"INDEX UNIQUE(s) NOT NULL"`
	Name                string             `xorm:"VARCHAR(255) UNIQUE(s) NOT NULL"`
	RequiredCount       int64              `xorm:"NOT NULL DEFAULT 1"`
	UserIDs             []int64            `xorm:"JSON TEXT"`
	TeamIDs             []int64            `xorm:"JSON TEXT"`
	PathPatterns        string             `xorm:"TEXT"`
	RequireCodeOwners   bool               `xorm:"NOT NULL DEFAULT false"`
	CreatedUnix         timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix         timeutil.TimeStamp `xorm:"updated"`
	RequestReviews      bool               `xorm:"NOT NULL DEFAULT false"`
	SourceBranchPattern string             `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
}

func (v18zzrApprovalRule) TableName() string {
	return "approval_rule" // what xorm names git_model.ApprovalRule
}

func addApprovalRuleDefaultReviewers(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zzrApprovalRule))
	return err
}
