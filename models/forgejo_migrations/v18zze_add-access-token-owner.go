// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the owner and permission of organization, project and repository access tokens",
		Upgrade:     addAccessTokenOwner,
	})
}

type v18zzeAccessToken struct {
	ID        int64 `xorm:"pk autoincr"`
	OwnerType int   `xorm:"NOT NULL DEFAULT 0 INDEX(owner)"`
	OwnerID   int64 `xorm:"NOT NULL DEFAULT 0 INDEX(owner)"`
	GroupID   int64 `xorm:"NOT NULL DEFAULT 0 INDEX(owner)"`
	Mode      int   `xorm:"NOT NULL DEFAULT 0"`
}

func (v18zzeAccessToken) TableName() string {
	return "access_token"
}

func addAccessTokenOwner(x *xorm.Engine) error {
	return x.Sync(new(v18zzeAccessToken))
}
