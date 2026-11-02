// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the per-user size limit of personal repositories",
		Upgrade:     addPersonalRepoSizeLimit,
	})
}

type v18zzUser struct {
	ID                    int64 `xorm:"pk autoincr"`
	PersonalRepoSizeLimit int64 `xorm:"NOT NULL DEFAULT 0"`
}

func (v18zzUser) TableName() string {
	return "user"
}

func addPersonalRepoSizeLimit(x *xorm.Engine) error {
	return x.Sync(new(v18zzUser))
}
