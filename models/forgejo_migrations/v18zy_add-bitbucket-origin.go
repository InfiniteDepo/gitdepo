// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the Bitbucket origin of imported repositories and projects",
		Upgrade:     addBitbucketOrigin,
	})
}

type v18zyBitbucketOrigin struct {
	ID          int64              `xorm:"pk autoincr"`
	ProjectKey  string             `xorm:"UNIQUE(s) NOT NULL"`
	Slug        string             `xorm:"UNIQUE(s) NOT NULL"`
	Server      string             `xorm:"UNIQUE(s) NOT NULL"`
	OwnerID     int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	RepoID      int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	GroupID     int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
}

func (v18zyBitbucketOrigin) TableName() string {
	return "bitbucket_origin"
}

func addBitbucketOrigin(x *xorm.Engine) error {
	return x.Sync(new(v18zyBitbucketOrigin))
}
