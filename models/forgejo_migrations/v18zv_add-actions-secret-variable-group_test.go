// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addActionsSecretVariableGroup(t *testing.T) {
	type Secret struct {
		ID      int64  `xorm:"pk autoincr"`
		OwnerID int64  `xorm:"INDEX UNIQUE(owner_repo_name) NOT NULL"`
		RepoID  int64  `xorm:"INDEX UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
		Name    string `xorm:"UNIQUE(owner_repo_name) NOT NULL"`
	}
	type ActionVariable struct {
		ID      int64  `xorm:"pk autoincr"`
		OwnerID int64  `xorm:"UNIQUE(owner_repo_name)"`
		RepoID  int64  `xorm:"INDEX UNIQUE(owner_repo_name)"`
		Name    string `xorm:"UNIQUE(owner_repo_name) NOT NULL"`
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(Secret), new(ActionVariable))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO secret (owner_id, repo_id, name) VALUES (3, 0, 'TOKEN')")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO action_variable (owner_id, repo_id, name) VALUES (3, 0, 'TOKEN')")
	require.NoError(t, err)

	require.NoError(t, addActionsSecretVariableGroup(x))
	require.NoError(t, addActionsSecretVariableGroup(x), "the migration can run again")

	for _, table := range []string{"secret", "action_variable"} {
		count, err := x.Table(table).Where("owner_id = 3 AND group_id = 0 AND name = 'TOKEN'").Count()
		require.NoError(t, err)
		assert.EqualValues(t, 1, count, table+": existing rows are organization rows")
		// the same name in the organization and in each project, but once per project
		_, err = x.Exec("INSERT INTO " + table + " (owner_id, group_id, repo_id, name) VALUES (3, 1, 0, 'TOKEN'), (3, 2, 0, 'TOKEN')")
		require.NoError(t, err, table)
		_, err = x.Exec("INSERT INTO " + table + " (owner_id, group_id, repo_id, name) VALUES (3, 1, 0, 'TOKEN')")
		require.Error(t, err, table)
	}
}
