// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18vUserGroupBefore struct {
	ID        int64  `xorm:"pk autoincr"`
	LowerName string `xorm:"UNIQUE NOT NULL"`
}

func (v18vUserGroupBefore) TableName() string { return "user_group" }

type v18vUserGroupTeamBefore struct {
	ID      int64 `xorm:"pk autoincr"`
	GroupID int64 `xorm:"UNIQUE(s) NOT NULL"`
	TeamID  int64 `xorm:"UNIQUE(s) NOT NULL"`
	OrgID   int64 `xorm:"NOT NULL"`
}

func (v18vUserGroupTeamBefore) TableName() string { return "user_group_team" }

// AC9: the role column, the managed flag and the exclusion table are added; existing groups and links keep working.
func Test_addOrgAdminRole(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18vUserGroupBefore), new(v18vUserGroupTeamBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO user_group (lower_name) VALUES ('g')")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO user_group_team (group_id, team_id, org_id) VALUES (1, 2, 3)")
	require.NoError(t, err)

	require.NoError(t, addOrgAdminRole(x))

	count, err := x.Table("user_group").Where("lower_name = 'g' AND grants_org_admin = ?", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
	count, err = x.Table("user_group_team").Where("team_id = 2 AND managed = 0").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)

	_, err = x.Exec("INSERT INTO org_admin_exclusion (org_id) VALUES (3)")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO org_admin_exclusion (org_id) VALUES (3)")
	require.Error(t, err) // one exclusion per org

	require.NoError(t, addOrgAdminRole(x)) // idempotent
}
