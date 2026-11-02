// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add project deploy keys",
		Upgrade:     addOrgDeployKeyGroup,
	})
}

type v18zwOrgDeployKey struct {
	ID      int64 `xorm:"pk autoincr"`
	KeyID   int64 `xorm:"UNIQUE(s) INDEX"`
	OrgID   int64 `xorm:"UNIQUE(s) INDEX"`
	GroupID int64 `xorm:"UNIQUE(s) NOT NULL DEFAULT 0"`
}

func (v18zwOrgDeployKey) TableName() string {
	return "org_deploy_key"
}

func addOrgDeployKeyGroup(x *xorm.Engine) error {
	// a key is unique per organization and project: recreate the index with group_id
	if err := dropIndexIfExists(x, "org_deploy_key", "UQE_org_deploy_key_s"); err != nil {
		return err
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zwOrgDeployKey))
	return err
}
