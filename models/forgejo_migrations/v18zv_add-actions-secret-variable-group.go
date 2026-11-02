// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add project Actions secrets and variables",
		Upgrade:     addActionsSecretVariableGroup,
	})
}

type v18zvSecret struct {
	ID      int64  `xorm:"pk autoincr"`
	OwnerID int64  `xorm:"INDEX UNIQUE(owner_repo_name) NOT NULL"`
	GroupID int64  `xorm:"UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	RepoID  int64  `xorm:"INDEX UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	Name    string `xorm:"UNIQUE(owner_repo_name) NOT NULL"`
}

func (v18zvSecret) TableName() string {
	return "secret"
}

type v18zvActionVariable struct {
	ID      int64  `xorm:"pk autoincr"`
	OwnerID int64  `xorm:"UNIQUE(owner_repo_name)"`
	GroupID int64  `xorm:"UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	RepoID  int64  `xorm:"INDEX UNIQUE(owner_repo_name)"`
	Name    string `xorm:"UNIQUE(owner_repo_name) NOT NULL"`
}

func (v18zvActionVariable) TableName() string {
	return "action_variable"
}

func addActionsSecretVariableGroup(x *xorm.Engine) error {
	// the name is unique per owner, project and repository: recreate the indexes with group_id
	for _, table := range []string{"secret", "action_variable"} {
		if err := dropIndexIfExists(x, table, "UQE_"+table+"_owner_repo_name"); err != nil {
			return err
		}
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zvSecret), new(v18zvActionVariable))
	return err
}
