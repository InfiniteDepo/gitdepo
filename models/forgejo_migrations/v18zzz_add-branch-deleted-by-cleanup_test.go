// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addBranchDeletedByCleanup(t *testing.T) {
	type Branch struct {
		ID     int64  `xorm:"pk autoincr"`
		RepoID int64  `xorm:"UNIQUE(s)"`
		Name   string `xorm:"UNIQUE(s) NOT NULL"`
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(Branch))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO branch (repo_id, name) VALUES (1, 'a')")
	require.NoError(t, err)

	require.NoError(t, addBranchDeletedByCleanup(x))
	require.NoError(t, addBranchDeletedByCleanup(x), "the migration can run again")

	var marked []bool
	require.NoError(t, x.Table("branch").Cols("deleted_by_cleanup").Find(&marked))
	assert.Equal(t, []bool{false}, marked)
}
