// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zRepositoryBefore struct {
	ID      int64 `xorm:"pk autoincr"`
	OwnerID int64
}

func (v18zRepositoryBefore) TableName() string { return "repository" }

// AC21: the trash columns are added and existing repositories stay live.
func Test_addTrash(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zRepositoryBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO repository (owner_id) VALUES (1)")
	require.NoError(t, err)

	require.NoError(t, addTrash(x))

	count, err := x.Table("repository").Where("trashed_unix = 0 AND trashed_by_id = 0 AND trashed_by_name = '' AND trashed_owner_name = '' AND trashed_name = ''").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}
