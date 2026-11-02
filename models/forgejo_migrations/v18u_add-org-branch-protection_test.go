// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18uProtectedBranchBefore struct {
	ID                int64  `xorm:"pk autoincr"`
	RepoID            int64  `xorm:"UNIQUE(s)"`
	RuleName          string `xorm:"'branch_name' UNIQUE(s)"`
	RequiredApprovals int64  `xorm:"NOT NULL DEFAULT 0"`
}

func (v18uProtectedBranchBefore) TableName() string {
	return "protected_branch"
}

// AC10: the migration adds the organization rule storage and keeps the repository rules.
func Test_addOrgBranchProtection(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18uProtectedBranchBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO protected_branch (repo_id, branch_name, required_approvals) VALUES (1, 'main', 2)")
	require.NoError(t, err)

	require.NoError(t, addOrgBranchProtection(x))

	count, err := x.Table("protected_branch").Where("repo_id = 1 AND org_id = 0 AND branch_name = 'main' AND required_approvals = 2 AND apply_to_selected_repos = ?", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)

	// the same name in two organizations and a repository
	_, err = x.Exec("INSERT INTO protected_branch (repo_id, org_id, branch_name) VALUES (0, 3, 'main'), (0, 7, 'main')")
	require.NoError(t, err)
	// but not twice in one repository or organization
	_, err = x.Exec("INSERT INTO protected_branch (repo_id, org_id, branch_name) VALUES (1, 0, 'main')")
	require.Error(t, err)
	_, err = x.Exec("INSERT INTO protected_branch (repo_id, org_id, branch_name) VALUES (0, 3, 'main')")
	require.Error(t, err)

	_, err = x.Exec("INSERT INTO protected_branch_repo (protected_branch_id, repo_id) VALUES (2, 1)")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO protected_branch_repo (protected_branch_id, repo_id) VALUES (2, 1)")
	require.Error(t, err)

	// running it again changes nothing
	require.NoError(t, addOrgBranchProtection(x))
}
