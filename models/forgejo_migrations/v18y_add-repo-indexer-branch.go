// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add repo_indexer_branch",
		Upgrade:     addRepoIndexerBranch,
	})
}

func addRepoIndexerBranch(x *xorm.Engine) error {
	type RepoIndexerBranch struct {
		ID        int64  `xorm:"pk autoincr"`
		RepoID    int64  `xorm:"UNIQUE(s) NOT NULL"`
		Branch    string `xorm:"UNIQUE(s) VARCHAR(255) NOT NULL"`
		CommitSha string `xorm:"VARCHAR(64)"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(RepoIndexerBranch))
	return err
}
