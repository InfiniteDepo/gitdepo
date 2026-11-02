// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add instance-wide user groups that can be linked to organization teams",
		Upgrade:     addUserGroups,
	})
}

func addUserGroups(x *xorm.Engine) error {
	type UserGroup struct {
		ID          int64  `xorm:"pk autoincr"`
		LowerName   string `xorm:"UNIQUE NOT NULL"`
		Name        string `xorm:"NOT NULL"`
		Description string
		CreatedUnix timeutil.TimeStamp `xorm:"INDEX created"`
		UpdatedUnix timeutil.TimeStamp `xorm:"INDEX updated"`
	}
	type UserGroupUser struct {
		ID      int64 `xorm:"pk autoincr"`
		GroupID int64 `xorm:"UNIQUE(s) INDEX NOT NULL"`
		UID     int64 `xorm:"UNIQUE(s) INDEX NOT NULL"`
	}
	type UserGroupTeam struct {
		ID      int64 `xorm:"pk autoincr"`
		GroupID int64 `xorm:"UNIQUE(s) INDEX NOT NULL"`
		TeamID  int64 `xorm:"UNIQUE(s) INDEX NOT NULL"`
		OrgID   int64 `xorm:"INDEX NOT NULL"`
	}
	return x.Sync(new(UserGroup), new(UserGroupUser), new(UserGroupTeam))
}
