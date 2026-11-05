// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addActionsDeploymentCheckedUnix(t *testing.T) {
	type ActionDeployment struct {
		ID    int64 `xorm:"pk autoincr"`
		JobID int64 `xorm:"NOT NULL DEFAULT 0"`
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(ActionDeployment))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO action_deployment (job_id) VALUES (1)")
	require.NoError(t, err)

	require.NoError(t, addActionsDeploymentCheckedUnix(x))
	require.NoError(t, addActionsDeploymentCheckedUnix(x), "the migration can run again")

	count, err := x.Table("action_deployment").Where("checked_unix = 0").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "an existing deployment was never looked at")
}
