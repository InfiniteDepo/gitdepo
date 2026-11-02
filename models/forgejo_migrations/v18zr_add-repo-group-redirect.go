// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add redirects in and of projects",
		Upgrade:     addRepoGroupRedirect,
	})
}

func addRepoGroupRedirect(x *xorm.Engine) error {
	// the unique key (owner_id, lower_name) becomes (owner_id, group_id, lower_name)
	type Redirect struct {
		ID             int64  `xorm:"pk autoincr"`
		OwnerID        int64  `xorm:"UNIQUE(s)"`
		GroupID        int64  `xorm:"UNIQUE(s) NOT NULL DEFAULT 0"`
		LowerName      string `xorm:"UNIQUE(s) INDEX NOT NULL"`
		RedirectRepoID int64
	}
	type RepoGroupRedirect struct {
		ID              int64  `xorm:"pk autoincr"`
		OwnerID         int64  `xorm:"UNIQUE(s) NOT NULL"`
		LowerName       string `xorm:"UNIQUE(s) NOT NULL"`
		RedirectGroupID int64  `xorm:"INDEX NOT NULL"`
	}
	if err := x.Table("repo_redirect").Sync(new(Redirect)); err != nil {
		return err
	}
	return x.Sync(new(RepoGroupRedirect))
}
