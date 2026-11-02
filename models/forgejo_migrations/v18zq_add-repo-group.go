// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add repository groups (projects)",
		Upgrade:     addRepoGroup,
	})
}

func addRepoGroup(x *xorm.Engine) error {
	type RepoGroup struct {
		ID          int64              `xorm:"pk autoincr"`
		OwnerID     int64              `xorm:"UNIQUE(s) INDEX NOT NULL"`
		Name        string             `xorm:"NOT NULL"`
		LowerName   string             `xorm:"UNIQUE(s) NOT NULL"`
		Description string             `xorm:"TEXT"`
		Avatar      string             `xorm:"VARCHAR(64)"`
		CreatedUnix timeutil.TimeStamp `xorm:"created"`
		UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
	}
	type RepoGroupNameClaim struct {
		ID        int64  `xorm:"pk autoincr"`
		OwnerID   int64  `xorm:"UNIQUE(s) NOT NULL"`
		LowerName string `xorm:"UNIQUE(s) NOT NULL"`
	}
	// the unique key (owner_id, lower_name) becomes (owner_id, lower_name, group_id); the other indexes stay
	type Repository struct {
		ID        int64  `xorm:"pk autoincr"`
		OwnerID   int64  `xorm:"UNIQUE(s) index"`
		LowerName string `xorm:"UNIQUE(s) INDEX NOT NULL"`
		GroupID   int64  `xorm:"UNIQUE(s) INDEX NOT NULL DEFAULT 0"`
		GroupName string `xorm:"NOT NULL DEFAULT ''"`
	}
	if err := x.Sync(new(RepoGroup), new(RepoGroupNameClaim)); err != nil {
		return err
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(Repository))
	return err
}
