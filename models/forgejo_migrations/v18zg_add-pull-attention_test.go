// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addPullAttention(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addPullAttention(x))
	_, err := x.Exec("INSERT INTO pull_attention (issue_id, user_id, kind, reason) VALUES (2, 1, 4, 'please look')")
	require.NoError(t, err)
	// one row per pull request and user
	_, err = x.Exec("INSERT INTO pull_attention (issue_id, user_id) VALUES (2, 1)")
	require.Error(t, err)
	n, err := x.Table("pull_attention").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
}
