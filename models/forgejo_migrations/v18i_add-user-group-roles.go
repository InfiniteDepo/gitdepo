// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add instance-level roles granted by user groups",
		Upgrade:     addUserGroupRoles,
	})
}

func addUserGroupRoles(x *xorm.Engine) error {
	type UserGroup struct {
		GrantsSiteAdmin          bool `xorm:"NOT NULL DEFAULT false"`
		GrantsCreateOrganization bool `xorm:"NOT NULL DEFAULT false"`
	}
	type UserGroupRoleGrant struct {
		ID   int64  `xorm:"pk autoincr"`
		UID  int64  `xorm:"UNIQUE(s) NOT NULL"`
		Role string `xorm:"UNIQUE(s) VARCHAR(50) NOT NULL"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(UserGroup), new(UserGroupRoleGrant))
	return err
}
