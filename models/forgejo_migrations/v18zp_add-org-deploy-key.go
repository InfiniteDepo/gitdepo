// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add organization deploy keys",
		Upgrade:     addOrgDeployKey,
	})
}

func addOrgDeployKey(x *xorm.Engine) error {
	type OrgDeployKey struct {
		ID               int64 `xorm:"pk autoincr"`
		KeyID            int64 `xorm:"UNIQUE(s) INDEX"`
		OrgID            int64 `xorm:"UNIQUE(s) INDEX"`
		Name             string
		Fingerprint      string
		Mode             int                `xorm:"NOT NULL DEFAULT 1"`
		IncludesAllRepos bool               `xorm:"NOT NULL DEFAULT false"`
		ExpiresUnix      timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
		CreatedUnix      timeutil.TimeStamp `xorm:"created"`
		UpdatedUnix      timeutil.TimeStamp `xorm:"updated"`
	}
	type OrgDeployKeyRepo struct {
		ID             int64 `xorm:"pk autoincr"`
		OrgDeployKeyID int64 `xorm:"UNIQUE(s) INDEX"`
		RepoID         int64 `xorm:"UNIQUE(s) INDEX"`
	}
	return x.Sync(new(OrgDeployKey), new(OrgDeployKeyRepo))
}
