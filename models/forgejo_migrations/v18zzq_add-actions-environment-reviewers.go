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

type v18zzqActionEnvironmentReviewer struct {
	ID            int64 `xorm:"pk autoincr"`
	EnvironmentID int64 `xorm:"INDEX UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
	UserID        int64 `xorm:"UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
	TeamID        int64 `xorm:"UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
}

func (v18zzqActionEnvironmentReviewer) TableName() string {
	return "action_environment_reviewer"
}

type v18zzqActionEnvironment struct {
	ID               int64  `xorm:"pk autoincr"`
	AllowedWorkflows string `xorm:"JSON TEXT"`
	ReviewsRequired  bool   `xorm:"NOT NULL DEFAULT false"`
}

func (v18zzqActionEnvironment) TableName() string {
	return "action_environment"
}

type v18zzqActionDeployment struct {
	ID            int64  `xorm:"pk autoincr"`
	ReviewedBy    int64  `xorm:"NOT NULL DEFAULT 0"`
	ReviewedUnix  int64  `xorm:"NOT NULL DEFAULT 0"`
	ReviewComment string `xorm:"TEXT"`
}

func (v18zzqActionDeployment) TableName() string {
	return "action_deployment"
}

type v18zzqActionRunJob struct {
	ID                   int64 `xorm:"pk autoincr"`
	AttemptTriggerUserID int64 `xorm:"NOT NULL DEFAULT 0"`
}

func (v18zzqActionRunJob) TableName() string {
	return "action_run_job"
}

func addActionsEnvironmentReviewers(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true},
		new(v18zzqActionEnvironmentReviewer), new(v18zzqActionEnvironment), new(v18zzqActionDeployment), new(v18zzqActionRunJob))
	return err
}
