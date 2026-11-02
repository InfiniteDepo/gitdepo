// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addOrgDeployKeyGroup(t *testing.T) {
	type OrgDeployKey struct {
		ID    int64 `xorm:"pk autoincr"`
		KeyID int64 `xorm:"UNIQUE(s) INDEX"`
		OrgID int64 `xorm:"UNIQUE(s) INDEX"`
		Name  string
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(OrgDeployKey))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO org_deploy_key (key_id, org_id, name) VALUES (7, 3, 'ci')")
	require.NoError(t, err)

	require.NoError(t, addOrgDeployKeyGroup(x))
	require.NoError(t, addOrgDeployKeyGroup(x), "the migration can run again")

	count, err := x.Table("org_deploy_key").Where("key_id = 7 AND org_id = 3 AND group_id = 0").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing keys are organization keys")
	// the same key on the organization and on each project, but once per project
	_, err = x.Exec("INSERT INTO org_deploy_key (key_id, org_id, group_id, name) VALUES (7, 3, 1, 'ci'), (7, 3, 2, 'ci')")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO org_deploy_key (key_id, org_id, group_id, name) VALUES (7, 3, 1, 'ci')")
	require.Error(t, err)
}
