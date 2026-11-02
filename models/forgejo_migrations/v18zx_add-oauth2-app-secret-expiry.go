// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add expiry of OAuth2 application client secrets",
		Upgrade:     addOAuth2AppSecretExpiry,
	})
}

type v18zxOAuth2Application struct {
	ID                      int64              `xorm:"pk autoincr"`
	ClientSecretExpiresUnix timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
}

func (v18zxOAuth2Application) TableName() string {
	return "oauth2_application"
}

func addOAuth2AppSecretExpiry(x *xorm.Engine) error {
	return x.Sync(new(v18zxOAuth2Application))
}
