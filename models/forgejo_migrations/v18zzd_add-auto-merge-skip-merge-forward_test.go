// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zzdOldAutoMerge struct {
	ID     int64 `xorm:"pk autoincr"`
	PullID int64 `xorm:"UNIQUE"`
}

func (v18zzdOldAutoMerge) TableName() string {
	return "pull_auto_merge"
}

func Test_addAutoMergeSkipMergeForward(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zzdOldAutoMerge))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO pull_auto_merge (pull_id) VALUES (7)")
	require.NoError(t, err)

	require.NoError(t, addAutoMergeSkipMergeForward(x))
	require.NoError(t, addAutoMergeSkipMergeForward(x), "the migration can run again")

	count, err := x.Table("pull_auto_merge").Where("pull_id = 7 AND skip_merge_forward = ?", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing auto merges merge forward")
}
