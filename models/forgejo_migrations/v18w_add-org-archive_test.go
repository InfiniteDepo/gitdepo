// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18wUserBefore struct {
	ID        int64  `xorm:"pk autoincr"`
	LowerName string `xorm:"UNIQUE NOT NULL"`
}

func (v18wUserBefore) TableName() string { return "user" }

type v18wRepositoryBefore struct {
	ID      int64 `xorm:"pk autoincr"`
	OwnerID int64
}

func (v18wRepositoryBefore) TableName() string { return "repository" }

// AC11: the columns are added and existing orgs and repos stay active.
func Test_addOrgArchive(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18wUserBefore), new(v18wRepositoryBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO `user` (lower_name) VALUES ('org')")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO repository (owner_id) VALUES (1)")
	require.NoError(t, err)

	require.NoError(t, addOrgArchive(x))

	count, err := x.Table("user").Where("is_archived = ? AND archived_unix = 0 AND archived_by_id = 0", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
	count, err = x.Table("repository").Where("archived_by_org = ?", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}
