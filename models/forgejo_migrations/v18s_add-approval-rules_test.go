// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18sProtectedBranchBefore struct {
	ID                int64  `xorm:"pk autoincr"`
	RepoID            int64  `xorm:"UNIQUE(s)"`
	RuleName          string `xorm:"'branch_name' UNIQUE(s)"`
	RequiredApprovals int64  `xorm:"NOT NULL DEFAULT 0"`
}

func (v18sProtectedBranchBefore) TableName() string {
	return "protected_branch"
}

// AC14: the approval rule table is added and existing protected branches are untouched.
func Test_addApprovalRules(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18sProtectedBranchBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO protected_branch (repo_id, branch_name, required_approvals) VALUES (1, 'main', 2)")
	require.NoError(t, err)

	require.NoError(t, addApprovalRules(x))

	count, err := x.Table("protected_branch").Where("branch_name = 'main' AND required_approvals = 2").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)

	_, err = x.Exec("INSERT INTO approval_rule (protected_branch_id, name, required_count, user_i_ds, team_i_ds, path_patterns) VALUES (1, 'Security', 1, '[2]', '[]', '')")
	require.NoError(t, err)
	// names are unique per protected branch
	_, err = x.Exec("INSERT INTO approval_rule (protected_branch_id, name, required_count, user_i_ds, team_i_ds, path_patterns) VALUES (1, 'Security', 1, '[2]', '[]', '')")
	require.Error(t, err)

	// running the migration again is a no-op
	require.NoError(t, addApprovalRules(x))
}
