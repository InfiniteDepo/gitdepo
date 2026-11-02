// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zzjTestRepository struct {
	ID   int64 `xorm:"pk autoincr"`
	Name string
}

func (v18zzjTestRepository) TableName() string {
	return "repository"
}

func Test_addRepoDependency(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)
	// a repository that exists before the migration
	require.NoError(t, x.Sync(new(v18zzjTestRepository)))
	_, err := x.Insert(&v18zzjTestRepository{Name: "before"})
	require.NoError(t, err)

	require.NoError(t, addRepoDependency(x))
	require.NoError(t, addRepoDependency(x), "the migration can run again")

	_, err = x.Exec("INSERT INTO repo_dependency (repo_id, ecosystem, name, version, manifest_path, direct, license) VALUES (1, 'Go', 'a', 'v1', 'go.mod', ?, '')", true)
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO repo_dependency_scan (repo_id, commit_sha, scanned_unix, status, error, manifest_count, dependency_count) VALUES (1, 'abc', 1, 'ok', '', 1, 1)")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO repo_dependency_scan (repo_id) VALUES (1)")
	require.Error(t, err, "one scan row per repository")

	var requirement []string
	require.NoError(t, x.SQL("SELECT requirement FROM repo_dependency WHERE repo_id = 1").Find(&requirement))
	assert.Equal(t, []string{""}, requirement, "requirement defaults to empty (a pinned version)")
	_, err = x.Exec("INSERT INTO repo_dependency (repo_id, ecosystem, name, version, manifest_path, direct, license, requirement) VALUES (1, 'npm', 'b', '', 'package.json', ?, '', '^1')", true)
	require.NoError(t, err)

	var disabled []bool
	require.NoError(t, x.SQL("SELECT dependency_graph_disabled FROM repository WHERE name = 'before'").Find(&disabled))
	assert.Equal(t, []bool{false}, disabled, "the dependency graph is on for a repository by default")
}
