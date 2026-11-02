// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zfUserBefore struct {
	ID   int64 `xorm:"pk autoincr"`
	Name string
}

func (v18zfUserBefore) TableName() string { return "user" }

func Test_addUserRequireTwoFactor(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zfUserBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO `user` (name) VALUES ('org')")
	require.NoError(t, err)

	require.NoError(t, addUserRequireTwoFactor(x))

	count, err := x.Table("user").Where("require_two_factor = ?", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}
