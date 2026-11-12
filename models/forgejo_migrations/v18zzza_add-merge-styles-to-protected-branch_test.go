// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zzzaOldProtectedBranch struct {
	ID         int64 `xorm:"pk autoincr"`
	RepoID     int64
	BranchName string
}

func (v18zzzaOldProtectedBranch) TableName() string {
	return "protected_branch"
}

func Test_addMergeStylesToProtectedBranch(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zzzaOldProtectedBranch))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO protected_branch (repo_id, branch_name) VALUES (1, 'main')")
	require.NoError(t, err)

	require.NoError(t, addMergeStylesToProtectedBranch(x))
	require.NoError(t, addMergeStylesToProtectedBranch(x), "the migration can run again")

	count, err := x.Table("protected_branch").Where("default_merge_style = '' AND (allowed_merge_styles IS NULL OR allowed_merge_styles = '')").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing rules have no opinion on merge styles")
}
