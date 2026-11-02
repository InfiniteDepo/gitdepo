// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addRepoGroup(t *testing.T) {
	type Repository struct {
		ID        int64  `xorm:"pk autoincr"`
		OwnerID   int64  `xorm:"UNIQUE(s) index"`
		LowerName string `xorm:"UNIQUE(s) INDEX NOT NULL"`
		Name      string `xorm:"INDEX NOT NULL"`
		IsPrivate bool   `xorm:"INDEX"`
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(Repository))
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addRepoGroup(x))
	require.NoError(t, addRepoGroup(x), "the migration can run again")

	indexes, err := x.DBMetas()
	require.NoError(t, err)
	for _, table := range indexes {
		if table.Name == "repository" {
			require.Contains(t, table.Indexes, "s")
			assert.ElementsMatch(t, []string{"owner_id", "lower_name", "group_id"}, table.Indexes["s"].Cols)
			assert.Contains(t, table.Indexes, "is_private", "other indexes stay")
		}
	}

	insert := func(groupID int64) error {
		_, err := x.Exec("INSERT INTO repository (owner_id, lower_name, name, group_id) VALUES (3, 'api', 'api', ?)", groupID)
		return err
	}
	require.NoError(t, insert(0))
	require.NoError(t, insert(1), "the same name in a group")
	require.NoError(t, insert(2), "the same name in another group")
	require.Error(t, insert(1), "the same name twice in a group")
	require.Error(t, insert(0), "the same name twice at the root")

	_, err = x.Exec("INSERT INTO repo_group (owner_id, name, lower_name) VALUES (3, 'Pay', 'pay')")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO repo_group (owner_id, name, lower_name) VALUES (3, 'PAY', 'pay')")
	require.Error(t, err)
	_, err = x.Exec("INSERT INTO repo_group_name_claim (owner_id, lower_name) VALUES (3, 'pay')")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO repo_group_name_claim (owner_id, lower_name) VALUES (3, 'pay')")
	require.Error(t, err)
}
