// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/require"
)

func Test_addBranchCleanupState(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addBranchCleanupState(x))
	require.NoError(t, addBranchCleanupState(x), "the migration can run again")
	_, err := x.Exec("INSERT INTO branch_cleanup_state (repo_id, days) VALUES (1, 30)")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO branch_cleanup_state (repo_id, days) VALUES (1, 30)")
	require.Error(t, err, "a repository has one record")
}
