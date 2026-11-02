// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the organization administrator role granted by user groups",
		Upgrade:     addOrgAdminRole,
	})
}

func addOrgAdminRole(x *xorm.Engine) error {
	type UserGroup struct {
		GrantsOrgAdmin bool `xorm:"NOT NULL DEFAULT false"`
	}
	type UserGroupTeam struct {
		Managed int `xorm:"NOT NULL DEFAULT 0"`
	}
	type OrgAdminExclusion struct {
		ID    int64 `xorm:"pk autoincr"`
		OrgID int64 `xorm:"UNIQUE NOT NULL"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(UserGroup), new(UserGroupTeam), new(OrgAdminExclusion))
	return err
}
