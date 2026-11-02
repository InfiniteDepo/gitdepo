// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zbUserBefore struct {
	ID   int64 `xorm:"pk autoincr"`
	Name string
}

func (v18zbUserBefore) TableName() string { return "user" }

type v18zbRepositoryBefore struct {
	ID      int64 `xorm:"pk autoincr"`
	OwnerID int64
}

func (v18zbRepositoryBefore) TableName() string { return "repository" }

// AC21: the owner trash columns are added and existing accounts and repositories stay live.
func Test_addOwnerTrash(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zbUserBefore), new(v18zbRepositoryBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO `user` (name) VALUES ('u')")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO repository (owner_id) VALUES (1)")
	require.NoError(t, err)

	require.NoError(t, addOwnerTrash(x))

	count, err := x.Table("user").Where("trashed_unix = 0 AND trashed_by_id = 0 AND trashed_by_name = '' AND trashed_name = ''").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
	count, err = x.Table("repository").Where("trashed_with_owner = ?", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}
