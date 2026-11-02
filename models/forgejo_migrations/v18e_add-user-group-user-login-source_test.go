// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addLoginSourceToUserGroupUser(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addUserGroups(x))
	_, err := x.Exec("INSERT INTO user_group_user (group_id, uid) VALUES (1, 2)")
	require.NoError(t, err)

	require.NoError(t, addLoginSourceToUserGroupUser(x))

	var sourceIDs []int64
	require.NoError(t, x.Table("user_group_user").Cols("login_source_id").Find(&sourceIDs))
	assert.Equal(t, []int64{0}, sourceIDs)

	// running the migration again is a no-op
	require.NoError(t, addLoginSourceToUserGroupUser(x))
}
