// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zoActionRunBefore struct {
	ID    int64 `xorm:"pk autoincr"`
	Title string
}

func (v18zoActionRunBefore) TableName() string { return "action_run" }

// AC1: keep is added as false for existing runs.
func Test_addActionRunKeep(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zoActionRunBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO action_run (title) VALUES ('run')")
	require.NoError(t, err)

	require.NoError(t, addActionRunKeep(x))

	count, err := x.Table("action_run").Where("keep = ? AND title = 'run'", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}
