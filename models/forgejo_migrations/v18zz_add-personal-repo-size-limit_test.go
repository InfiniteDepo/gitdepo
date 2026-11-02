// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zzOldUser struct {
	ID        int64  `xorm:"pk autoincr"`
	LowerName string `xorm:"UNIQUE NOT NULL"`
}

func (v18zzOldUser) TableName() string {
	return "user"
}

func Test_addPersonalRepoSizeLimit(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zzOldUser))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO `user` (lower_name) VALUES ('old')")
	require.NoError(t, err)

	require.NoError(t, addPersonalRepoSizeLimit(x))
	require.NoError(t, addPersonalRepoSizeLimit(x), "the migration can run again")

	count, err := x.Table("user").Where("lower_name = 'old' AND personal_repo_size_limit = 0").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing users get the site limit")
}
