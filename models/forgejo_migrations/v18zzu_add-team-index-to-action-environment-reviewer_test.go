// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addTeamIndexToActionEnvironmentReviewer(t *testing.T) {
	type ActionEnvironmentReviewer struct {
		ID            int64 `xorm:"pk autoincr"`
		EnvironmentID int64 `xorm:"INDEX UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
		UserID        int64 `xorm:"UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
		TeamID        int64 `xorm:"UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(ActionEnvironmentReviewer))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO action_environment_reviewer (environment_id, team_id) VALUES (1, 2)")
	require.NoError(t, err)

	require.NoError(t, addTeamIndexToActionEnvironmentReviewer(x))
	require.NoError(t, addTeamIndexToActionEnvironmentReviewer(x), "the migration can run again")

	tables, err := x.DBMetas()
	require.NoError(t, err)
	var columns [][]string
	for _, table := range tables {
		if table.Name == "action_environment_reviewer" {
			for _, index := range table.Indexes {
				columns = append(columns, index.Cols)
			}
		}
	}
	assert.Contains(t, columns, []string{"team_id"})
	count, err := x.Table("action_environment_reviewer").Where("team_id = 2").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}
