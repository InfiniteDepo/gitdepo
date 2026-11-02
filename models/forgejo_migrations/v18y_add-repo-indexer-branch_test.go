// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18yRepoIndexerStatusBefore struct {
	ID        int64 `xorm:"pk autoincr"`
	RepoID    int64 `xorm:"INDEX(s)"`
	CommitSha string
}

func (v18yRepoIndexerStatusBefore) TableName() string { return "repo_indexer_status" }

// AC12: the table exists, (repo_id, branch) is unique, existing status rows are untouched.
func Test_addRepoIndexerBranch(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18yRepoIndexerStatusBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO repo_indexer_status (repo_id, commit_sha) VALUES (1, 'abc')")
	require.NoError(t, err)

	require.NoError(t, addRepoIndexerBranch(x))

	_, err = x.Exec("INSERT INTO repo_indexer_branch (repo_id, branch, commit_sha) VALUES (1, 'develop', 'def')")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO repo_indexer_branch (repo_id, branch, commit_sha) VALUES (1, 'develop', 'ghi')")
	require.Error(t, err)

	count, err := x.Table("repo_indexer_status").Where("commit_sha = 'abc'").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}
