// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18znRepositoryBefore struct {
	ID      int64 `xorm:"pk autoincr"`
	Name    string
	GitSize int64 `xorm:"NOT NULL DEFAULT 0"`
}

func (v18znRepositoryBefore) TableName() string { return "repository" }

// AC1: wiki_size is added with 0 for existing repositories.
func Test_addRepoWikiSize(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18znRepositoryBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO repository (name, git_size) VALUES ('repo', 5)")
	require.NoError(t, err)

	require.NoError(t, addRepoWikiSize(x))

	count, err := x.Table("repository").Where("wiki_size = 0 AND git_size = 5").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}
