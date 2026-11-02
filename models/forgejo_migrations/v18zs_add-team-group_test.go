// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/require"
)

func Test_addTeamGroup(t *testing.T) {
	type TeamRepo struct {
		ID     int64 `xorm:"pk autoincr"`
		OrgID  int64 `xorm:"INDEX"`
		TeamID int64 `xorm:"UNIQUE(s)"`
		RepoID int64 `xorm:"UNIQUE(s)"`
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(TeamRepo))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO team_repo (org_id, team_id, repo_id) VALUES (3, 1, 1)")
	require.NoError(t, err)

	require.NoError(t, addTeamGroup(x))
	require.NoError(t, addTeamGroup(x), "the migration can run again")

	var via []bool
	require.NoError(t, x.Table("team_repo").Cols("via_group").Find(&via))
	require.Equal(t, []bool{false}, via, "existing rows are direct")
	_, err = x.Exec("INSERT INTO team_group (org_id, team_id, group_id) VALUES (3, 1, 2)")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO team_group (org_id, team_id, group_id) VALUES (3, 1, 2)")
	require.Error(t, err, "a team is linked to a project once")
}
