// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add org_verified_domain, the email domains an organization verified",
		Upgrade:     addOrgVerifiedDomain,
	})
}

func addOrgVerifiedDomain(x *xorm.Engine) error {
	type OrgVerifiedDomain struct {
		ID                int64              `xorm:"pk autoincr"`
		OrgID             int64              `xorm:"INDEX NOT NULL"`
		Domain            string             `xorm:"VARCHAR(253) UNIQUE NOT NULL"`
		VerifiedUnix      timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
		LastCheckedUnix   timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
		FailingSinceUnix  timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
		VerifiedByAdminID int64              `xorm:"NOT NULL DEFAULT 0"`
	}
	return x.Sync(new(OrgVerifiedDomain))
}
