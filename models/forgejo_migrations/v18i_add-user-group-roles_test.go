// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addUserGroupRoles(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addUserGroups(x))
	_, err := x.Exec("INSERT INTO user_group (lower_name, name) VALUES ('g', 'g')")
	require.NoError(t, err)

	require.NoError(t, addUserGroupRoles(x))

	var grants []bool
	require.NoError(t, x.Table("user_group").Cols("grants_site_admin").Find(&grants))
	assert.Equal(t, []bool{false}, grants)

	_, err = x.Exec("INSERT INTO user_group_role_grant (uid, role) VALUES (1, 'site_admin')")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO user_group_role_grant (uid, role) VALUES (1, 'site_admin')")
	require.Error(t, err, "uid and role are unique")

	// running the migration again is a no-op
	require.NoError(t, addUserGroupRoles(x))
}
