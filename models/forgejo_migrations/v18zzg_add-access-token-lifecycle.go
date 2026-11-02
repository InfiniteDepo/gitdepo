// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add creator, description, rotation, revocation and last-used address to access tokens",
		Upgrade:     addAccessTokenLifecycle,
	})
}

type v18zzgAccessToken struct {
	ID          int64  `xorm:"pk autoincr"`
	CreatorID   int64  `xorm:"NOT NULL DEFAULT 0"`
	Description string `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
	SelfRotate  bool   `xorm:"NOT NULL DEFAULT false"`
	RotatedUnix int64  `xorm:"NOT NULL DEFAULT 0"`
	RotatedByID int64  `xorm:"NOT NULL DEFAULT 0"`
	RevokedUnix int64  `xorm:"NOT NULL DEFAULT 0 INDEX"`
	RevokedByID int64  `xorm:"NOT NULL DEFAULT 0"`
	LastUsedIP  string `xorm:"VARCHAR(45) NOT NULL DEFAULT ''"`
}

func (v18zzgAccessToken) TableName() string {
	return "access_token"
}

func addAccessTokenLifecycle(x *xorm.Engine) error {
	return x.Sync(new(v18zzgAccessToken))
}
