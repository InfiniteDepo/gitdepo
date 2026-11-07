// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addMailedStatusToActionDeployment(t *testing.T) {
	type ActionDeployment struct {
		ID     int64 `xorm:"pk autoincr"`
		RunID  int64 `xorm:"NOT NULL DEFAULT 0"`
		Status int   `xorm:"NOT NULL DEFAULT 0"`
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(ActionDeployment))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO action_deployment (run_id, status) VALUES (1, 5)")
	require.NoError(t, err)

	require.NoError(t, addMailedStatusToActionDeployment(x))
	require.NoError(t, addMailedStatusToActionDeployment(x), "the migration can run again")

	// a deployment from before counts as not mailed
	var mailed []int
	require.NoError(t, x.Table("action_deployment").Cols("mailed_status").Find(&mailed))
	assert.Equal(t, []int{0}, mailed)
}
