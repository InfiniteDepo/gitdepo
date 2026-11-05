// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addActionsEnvironmentReviewers(t *testing.T) {
	type ActionEnvironment struct {
		ID   int64  `xorm:"pk autoincr"`
		Name string `xorm:"VARCHAR(255) NOT NULL"`
	}
	type ActionDeployment struct {
		ID     int64 `xorm:"pk autoincr"`
		Status int   `xorm:"NOT NULL DEFAULT 0"`
	}
	type ActionRunJob struct {
		ID int64 `xorm:"pk autoincr"`
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(ActionEnvironment), new(ActionDeployment), new(ActionRunJob))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO action_environment (name) VALUES ('production')")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO action_deployment (status) VALUES (1)")
	require.NoError(t, err)

	_, err = x.Exec("INSERT INTO action_run_job (id) VALUES (1)")
	require.NoError(t, err)

	require.NoError(t, addActionsEnvironmentReviewers(x))
	require.NoError(t, addActionsEnvironmentReviewers(x), "the migration can run again")

	count, err := x.Table("action_deployment").Where("review_comment IS NULL AND reviewed_by = 0 AND reviewed_unix = 0").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing deployments are unreviewed")

	count, err = x.Table("action_environment").Where("reviews_required = ?", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "an environment requires no review until its reviewers are edited")
	count, err = x.Table("action_run_job").Where("attempt_trigger_user_id = 0").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)

	_, err = x.Exec("INSERT INTO action_environment_reviewer (environment_id, user_id, team_id) VALUES (1, 2, 0), (1, 0, 3)")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO action_environment_reviewer (environment_id, user_id, team_id) VALUES (1, 2, 0)")
	require.Error(t, err, "a reviewer is listed once")
}
