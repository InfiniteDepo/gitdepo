// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addRepositorySelectionToActionEnvironment(t *testing.T) {
	type ActionEnvironment struct {
		ID      int64 `xorm:"pk autoincr"`
		OwnerID int64 `xorm:"NOT NULL DEFAULT 0"`
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(ActionEnvironment))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO action_environment (owner_id) VALUES (3)")
	require.NoError(t, err)

	require.NoError(t, addRepositorySelectionToActionEnvironment(x))
	require.NoError(t, addRepositorySelectionToActionEnvironment(x), "the migration can run again")

	// an environment from before applies to no repository until one is selected (fail closed)
	var all []bool
	require.NoError(t, x.Table("action_environment").Cols("all_repos").Find(&all))
	assert.Equal(t, []bool{false}, all)
	_, err = x.Exec("INSERT INTO action_environment_repo (environment_id, repo_id) VALUES (1, 2)")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO action_environment_repo (environment_id, repo_id) VALUES (1, 2)")
	require.Error(t, err, "a repository is selected once")
}
