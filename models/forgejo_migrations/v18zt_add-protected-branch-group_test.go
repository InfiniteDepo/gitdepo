// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addProtectedBranchGroup(t *testing.T) {
	type ProtectedBranch struct {
		ID       int64  `xorm:"pk autoincr"`
		RepoID   int64  `xorm:"UNIQUE(s)"`
		OrgID    int64  `xorm:"UNIQUE(s) INDEX NOT NULL DEFAULT 0"`
		RuleName string `xorm:"'branch_name' UNIQUE(s)"`
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(ProtectedBranch))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO protected_branch (repo_id, org_id, branch_name) VALUES (0, 3, 'main')")
	require.NoError(t, err)

	require.NoError(t, addProtectedBranchGroup(x))
	require.NoError(t, addProtectedBranchGroup(x), "the migration can run again")

	count, err := x.Table("protected_branch").Where("org_id = 3 AND group_id = 0 AND branch_name = 'main'").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing rules are organization rules")
	// the same name in the organization and in each project, but once per project
	_, err = x.Exec("INSERT INTO protected_branch (repo_id, org_id, group_id, branch_name) VALUES (0, 3, 1, 'main'), (0, 3, 2, 'main')")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO protected_branch (repo_id, org_id, group_id, branch_name) VALUES (0, 3, 1, 'main')")
	require.Error(t, err)
}
