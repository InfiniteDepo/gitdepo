// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addRepoGroupRedirect(t *testing.T) {
	type Redirect struct {
		ID             int64  `xorm:"pk autoincr"`
		OwnerID        int64  `xorm:"UNIQUE(s)"`
		LowerName      string `xorm:"UNIQUE(s) INDEX NOT NULL"`
		RedirectRepoID int64
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(Redirect))
	defer deferable()
	require.NotNil(t, x)
	require.NoError(t, x.Table("repo_redirect").Sync(new(Redirect)))

	require.NoError(t, addRepoGroupRedirect(x))
	require.NoError(t, addRepoGroupRedirect(x), "the migration can run again")

	tables, err := x.DBMetas()
	require.NoError(t, err)
	for _, table := range tables {
		if table.Name == "repo_redirect" {
			require.Contains(t, table.Indexes, "s")
			assert.ElementsMatch(t, []string{"owner_id", "group_id", "lower_name"}, table.Indexes["s"].Cols)
		}
	}

	insert := func(groupID int64) error {
		_, err := x.Exec("INSERT INTO repo_redirect (owner_id, group_id, lower_name, redirect_repo_id) VALUES (3, ?, 'api', 1)", groupID)
		return err
	}
	require.NoError(t, insert(0))
	require.NoError(t, insert(1), "the same name in a project")
	require.Error(t, insert(1), "the same name twice in a project")
	require.Error(t, insert(0), "the same name twice at the root")

	_, err = x.Exec("INSERT INTO repo_group_redirect (owner_id, lower_name, redirect_group_id) VALUES (3, 'pay', 1)")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO repo_group_redirect (owner_id, lower_name, redirect_group_id) VALUES (3, 'pay', 2)")
	require.Error(t, err)
}
