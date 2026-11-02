// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addPullAutoMergeGiveUpAfter(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addPullAutoMergeScheduledAfter(x))
	_, err := x.Exec("INSERT INTO pull_auto_merge (scheduled_after_unix) VALUES (1)")
	require.NoError(t, err)

	require.NoError(t, addPullAutoMergeGiveUpAfter(x))

	var giveUpAfter []int64
	require.NoError(t, x.Table("pull_auto_merge").Cols("give_up_after_unix").Find(&giveUpAfter))
	assert.Equal(t, []int64{0}, giveUpAfter)

	// running the migration again is a no-op
	require.NoError(t, addPullAutoMergeGiveUpAfter(x))
}
