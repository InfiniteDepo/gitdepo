// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "link teams to projects",
		Upgrade:     addTeamGroup,
	})
}

func addTeamGroup(x *xorm.Engine) error {
	type TeamGroup struct {
		ID      int64 `xorm:"pk autoincr"`
		OrgID   int64 `xorm:"INDEX NOT NULL"`
		TeamID  int64 `xorm:"UNIQUE(s) NOT NULL"`
		GroupID int64 `xorm:"UNIQUE(s) INDEX NOT NULL"`
	}
	type TeamRepo struct {
		ViaGroup bool `xorm:"NOT NULL DEFAULT false"`
	}
	if err := x.Sync(new(TeamGroup)); err != nil {
		return err
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(TeamRepo))
	return err
}
