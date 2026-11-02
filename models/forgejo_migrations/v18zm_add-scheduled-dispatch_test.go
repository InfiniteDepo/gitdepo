// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addScheduledDispatch(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addScheduledDispatch(x))

	_, err := x.Exec("INSERT INTO `action_scheduled_dispatch` (repo_id, workflow_id, ref, inputs, doer_id, run_at) VALUES (1, 'a.yml', 'main', '{}', 2, 100)")
	require.NoError(t, err)
	var status int
	var reason string
	has, err := x.Table("action_scheduled_dispatch").Cols("status", "cancel_reason").Get(&status, &reason)
	require.NoError(t, err)
	assert.True(t, has)
	assert.Zero(t, status)
	assert.Empty(t, reason)
}
