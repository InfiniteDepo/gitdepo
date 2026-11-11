// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the repositories an organization's Actions environment applies to",
		Upgrade:     addRepositorySelectionToActionEnvironment,
	})
}

type v18zzxActionEnvironment struct {
	ID       int64 `xorm:"pk autoincr"`
	AllRepos bool  `xorm:"NOT NULL DEFAULT false"`
}

func (v18zzxActionEnvironment) TableName() string {
	return "action_environment"
}

type v18zzxActionEnvironmentRepo struct {
	ID            int64 `xorm:"pk autoincr"`
	EnvironmentID int64 `xorm:"UNIQUE(environment_repo) NOT NULL"`
	RepoID        int64 `xorm:"UNIQUE(environment_repo) INDEX NOT NULL"`
}

func (v18zzxActionEnvironmentRepo) TableName() string {
	return "action_environment_repo"
}

func addRepositorySelectionToActionEnvironment(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zzxActionEnvironment), new(v18zzxActionEnvironmentRepo))
	return err
}
