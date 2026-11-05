// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addActionsEnvironmentCreatedByWorkflow(t *testing.T) {
	type ActionEnvironment struct {
		ID   int64  `xorm:"pk autoincr"`
		Name string `xorm:"VARCHAR(255) NOT NULL"`
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(ActionEnvironment))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO action_environment (name) VALUES ('production')")
	require.NoError(t, err)

	require.NoError(t, addActionsEnvironmentCreatedByWorkflow(x))
	require.NoError(t, addActionsEnvironmentCreatedByWorkflow(x), "the migration can run again")

	count, err := x.Table("action_environment").Where("created_by_workflow = ?", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "an existing environment is not marked")
}
