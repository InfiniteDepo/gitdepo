// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add org_unit, the repository units an organization owner turned off",
		Upgrade:     addOrgUnit,
	})
}

func addOrgUnit(x *xorm.Engine) error {
	type OrgUnit struct {
		ID          int64              `xorm:"pk autoincr"`
		OrgID       int64              `xorm:"UNIQUE(s) NOT NULL"`
		Type        int                `xorm:"UNIQUE(s) NOT NULL"`
		Disabled    bool               `xorm:"NOT NULL DEFAULT false"`
		UpdatedBy   int64              `xorm:"NOT NULL DEFAULT 0"`
		UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
	}
	return x.Sync(new(OrgUnit))
}
