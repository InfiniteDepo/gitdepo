// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add credential_expiry_notice, the expiry mails sent for keys and tokens",
		Upgrade:     addCredentialExpiryNotice,
	})
}

type v18zzhCredentialExpiryNotice struct {
	ID           int64              `xorm:"pk autoincr"`
	Kind         string             `xorm:"VARCHAR(20) NOT NULL UNIQUE(notice)"`
	CredentialID int64              `xorm:"NOT NULL UNIQUE(notice)"`
	ExpiresUnix  timeutil.TimeStamp `xorm:"NOT NULL UNIQUE(notice) INDEX"`
	Stage        int                `xorm:"NOT NULL UNIQUE(notice)"`
	CreatedUnix  timeutil.TimeStamp `xorm:"created"`
}

func (v18zzhCredentialExpiryNotice) TableName() string {
	return "credential_expiry_notice"
}

func addCredentialExpiryNotice(x *xorm.Engine) error {
	return x.Sync(new(v18zzhCredentialExpiryNotice))
}
