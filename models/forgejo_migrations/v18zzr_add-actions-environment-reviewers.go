// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add required reviewers and allowed workflows of Actions environments, reviews of deployments",
		Upgrade:     addActionsEnvironmentReviewers,
	})
}

type v18zzrActionEnvironmentReviewer struct {
	ID            int64 `xorm:"pk autoincr"`
	EnvironmentID int64 `xorm:"INDEX UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
	UserID        int64 `xorm:"UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
	TeamID        int64 `xorm:"UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
}

func (v18zzrActionEnvironmentReviewer) TableName() string {
	return "action_environment_reviewer"
}

type v18zzrActionEnvironment struct {
	ID               int64  `xorm:"pk autoincr"`
	AllowedWorkflows string `xorm:"JSON TEXT"`
	ReviewsRequired  bool   `xorm:"NOT NULL DEFAULT false"`
}

func (v18zzrActionEnvironment) TableName() string {
	return "action_environment"
}

type v18zzrActionDeployment struct {
	ID            int64  `xorm:"pk autoincr"`
	ReviewedBy    int64  `xorm:"NOT NULL DEFAULT 0"`
	ReviewedUnix  int64  `xorm:"NOT NULL DEFAULT 0"`
	ReviewComment string `xorm:"TEXT"`
}

func (v18zzrActionDeployment) TableName() string {
	return "action_deployment"
}

type v18zzrActionRunJob struct {
	ID                   int64 `xorm:"pk autoincr"`
	AttemptTriggerUserID int64 `xorm:"NOT NULL DEFAULT 0"`
}

func (v18zzrActionRunJob) TableName() string {
	return "action_run_job"
}

func addActionsEnvironmentReviewers(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true},
		new(v18zzrActionEnvironmentReviewer), new(v18zzrActionEnvironment), new(v18zzrActionDeployment), new(v18zzrActionRunJob))
	return err
}
