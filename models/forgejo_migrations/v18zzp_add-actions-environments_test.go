// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addActionsEnvironments(t *testing.T) {
	type Secret struct {
		ID      int64  `xorm:"pk autoincr"`
		OwnerID int64  `xorm:"INDEX UNIQUE(owner_repo_name) NOT NULL"`
		GroupID int64  `xorm:"UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
		RepoID  int64  `xorm:"INDEX UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
		Name    string `xorm:"UNIQUE(owner_repo_name) NOT NULL"`
	}
	type ActionVariable struct {
		ID      int64  `xorm:"pk autoincr"`
		OwnerID int64  `xorm:"UNIQUE(owner_repo_name)"`
		GroupID int64  `xorm:"UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
		RepoID  int64  `xorm:"INDEX UNIQUE(owner_repo_name)"`
		Name    string `xorm:"UNIQUE(owner_repo_name) NOT NULL"`
	}
	type ActionRunJob struct {
		ID int64 `xorm:"pk autoincr"`
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(Secret), new(ActionVariable), new(ActionRunJob))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO secret (owner_id, repo_id, name) VALUES (0, 3, 'TOKEN')")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO action_variable (owner_id, repo_id, name) VALUES (0, 3, 'TOKEN')")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO action_run_job (id) VALUES (1)")
	require.NoError(t, err)

	require.NoError(t, addActionsEnvironments(x))
	require.NoError(t, addActionsEnvironments(x), "the migration can run again")

	for _, table := range []string{"secret", "action_variable"} {
		count, err := x.Table(table).Where("repo_id = 3 AND environment_id = 0 AND name = 'TOKEN'").Count()
		require.NoError(t, err)
		assert.EqualValues(t, 1, count, table+": existing rows belong to no environment")
		// the same name in the repository and in each environment, but once per environment
		_, err = x.Exec("INSERT INTO " + table + " (owner_id, group_id, repo_id, environment_id, name) VALUES (0, 0, 3, 1, 'TOKEN'), (0, 0, 3, 2, 'TOKEN')")
		require.NoError(t, err, table)
		_, err = x.Exec("INSERT INTO " + table + " (owner_id, group_id, repo_id, environment_id, name) VALUES (0, 0, 3, 1, 'TOKEN')")
		require.Error(t, err, table)
	}

	count, err := x.Table("action_run_job").Where("environment_name = ''").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)

	env := "INSERT INTO action_environment (owner_id, repo_id, name, lower_name) VALUES (0, ?, ?, ?)"
	_, err = x.Exec(env, 3, "Prod", "prod")
	require.NoError(t, err)
	_, err = x.Exec(env, 3, "PROD", "prod")
	require.Error(t, err, "a name is unique per repository, ignoring case")
	_, err = x.Exec(env, 4, "Prod", "prod")
	require.NoError(t, err)

	dep := "INSERT INTO action_deployment (repo_id, environment_id, job_id, attempt) VALUES (3, 1, 7, ?)"
	_, err = x.Exec(dep, 1)
	require.NoError(t, err)
	_, err = x.Exec(dep, 1)
	require.Error(t, err, "one deployment per job attempt")
	_, err = x.Exec(dep, 2)
	require.NoError(t, err)
}
