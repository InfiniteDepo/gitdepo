// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18ziPushRuleBefore struct {
	ID     int64 `xorm:"pk autoincr"`
	RepoID int64 `xorm:"UNIQUE NOT NULL"`
}

func (v18ziPushRuleBefore) TableName() string { return "push_rule" }

func Test_addPushRulePRTitle(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18ziPushRuleBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO push_rule (repo_id) VALUES (1)")
	require.NoError(t, err)

	require.NoError(t, addPushRulePRTitle(x))

	count, err := x.Table("push_rule").Where("pr_title_block_merge = ? AND pr_title_regex IS NULL", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}
