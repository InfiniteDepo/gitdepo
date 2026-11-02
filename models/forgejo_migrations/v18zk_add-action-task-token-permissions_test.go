// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zkActionTaskBefore struct {
	ID     int64 `xorm:"pk autoincr"`
	RepoID int64 `xorm:"index"`
}

func (v18zkActionTaskBefore) TableName() string { return "action_task" }

func Test_addActionTaskTokenPermissions(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zkActionTaskBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO action_task (repo_id) VALUES (1)")
	require.NoError(t, err)

	require.NoError(t, addActionTaskTokenPermissions(x))

	// an existing task keeps the legacy (empty) token permissions
	count, err := x.Table("action_task").Where("token_permissions IS NULL").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}
