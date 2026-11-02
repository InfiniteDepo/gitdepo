// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addUserGroups(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addUserGroups(x))

	for _, table := range []string{"user_group", "user_group_user", "user_group_team"} {
		exists, err := x.IsTableExist(table)
		require.NoError(t, err)
		assert.True(t, exists, table)
	}

	exists, err := indexExists(x, "user_group_user", "UQE_user_group_user_s")
	require.NoError(t, err)
	assert.True(t, exists)
	exists, err = indexExists(x, "user_group_team", "UQE_user_group_team_s")
	require.NoError(t, err)
	assert.True(t, exists)

	// running the migration again is a no-op
	require.NoError(t, addUserGroups(x))
}
