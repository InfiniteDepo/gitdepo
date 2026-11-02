// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add expiry of authorized integrations",
		Upgrade:     addAuthorizedIntegrationExpiry,
	})
}

type v18zzcAuthorizedIntegration struct {
	ID          int64              `xorm:"pk autoincr"`
	ExpiresUnix timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
}

func (v18zzcAuthorizedIntegration) TableName() string {
	return "authorized_integration"
}

func addAuthorizedIntegrationExpiry(x *xorm.Engine) error {
	return x.Sync(new(v18zzcAuthorizedIntegration))
}
