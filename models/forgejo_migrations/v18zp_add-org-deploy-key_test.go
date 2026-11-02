// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addOrgDeployKey(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addOrgDeployKey(x))

	_, err := x.Exec("INSERT INTO org_deploy_key (key_id, org_id, name, fingerprint) VALUES (1, 3, 'ci', 'fp')")
	require.NoError(t, err)
	count, err := x.Table("org_deploy_key").Where("mode = 1 AND includes_all_repos = ? AND expires_unix = 0", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)

	_, err = x.Exec("INSERT INTO org_deploy_key_repo (org_deploy_key_id, repo_id) VALUES (1, 2)")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO org_deploy_key_repo (org_deploy_key_id, repo_id) VALUES (1, 2)")
	require.Error(t, err, "a repository is selected once per key")
}
