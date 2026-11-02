// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the custom patterns of secret scanning",
		Upgrade:     addSecretCustomPattern,
	})
}

type v18zznSecretCustomPattern struct {
	ID          int64  `xorm:"pk autoincr"`
	OwnerID     int64  `xorm:"UNIQUE(owner_name_deleted) NOT NULL DEFAULT 0"`
	Name        string `xorm:"VARCHAR(64) UNIQUE(owner_name_deleted) NOT NULL"`
	Pattern     string `xorm:"TEXT NOT NULL"`
	Keywords    string `xorm:"TEXT NOT NULL"`
	Enabled     bool   `xorm:"NOT NULL DEFAULT true"`
	DeletedUnix int64  `xorm:"UNIQUE(owner_name_deleted) NOT NULL DEFAULT 0"`
	CreatedByID int64  `xorm:"NOT NULL DEFAULT 0"`
	CreatedUnix int64  `xorm:"created"`
	UpdatedUnix int64  `xorm:"updated"`
}

func (v18zznSecretCustomPattern) TableName() string {
	return "secret_custom_pattern"
}

func addSecretCustomPattern(x *xorm.Engine) error {
	return x.Sync(new(v18zznSecretCustomPattern))
}
