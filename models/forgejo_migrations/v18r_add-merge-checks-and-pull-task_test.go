// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18rProtectedBranchBefore struct {
	ID       int64  `xorm:"pk autoincr"`
	RepoID   int64  `xorm:"UNIQUE(s)"`
	RuleName string `xorm:"'branch_name' UNIQUE(s)"`
}

func (v18rProtectedBranchBefore) TableName() string {
	return "protected_branch"
}

func Test_addMergeChecksAndPullTask(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18rProtectedBranchBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO protected_branch (repo_id, branch_name) VALUES (1, 'main')")
	require.NoError(t, err)

	require.NoError(t, addMergeChecksAndPullTask(x))

	var rows []map[string]any
	rows, err = x.Table("protected_branch").Cols("block_on_unresolved_conversations", "ignore_outdated_conversations", "block_on_incomplete_tasks").QueryInterface()
	require.NoError(t, err)
	require.Len(t, rows, 1)
	for _, v := range rows[0] {
		assert.EqualValues(t, 0, v)
	}

	_, err = x.Exec("INSERT INTO pull_task (issue_id, content, creator_id) VALUES (2, 'add a test', 1)")
	require.NoError(t, err)
	count, err := x.Table("pull_task").Where("is_done = ? AND comment_id = 0 AND assignee_id = 0", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)

	// running the migration again is a no-op
	require.NoError(t, addMergeChecksAndPullTask(x))
}
