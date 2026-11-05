// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "index the team of the required reviewers of Actions environments",
		Upgrade:     addTeamIndexToActionEnvironmentReviewer,
	})
}

type v18zzuActionEnvironmentReviewer struct {
	ID            int64 `xorm:"pk autoincr"`
	EnvironmentID int64 `xorm:"INDEX UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
	UserID        int64 `xorm:"UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
	TeamID        int64 `xorm:"INDEX UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
}

func (v18zzuActionEnvironmentReviewer) TableName() string {
	return "action_environment_reviewer"
}

func addTeamIndexToActionEnvironmentReviewer(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zzuActionEnvironmentReviewer))
	return err
}
