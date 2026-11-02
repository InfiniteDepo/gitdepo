// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/require"
)

func Test_addBitbucketOrigin(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addBitbucketOrigin(x))
	require.NoError(t, addBitbucketOrigin(x), "the migration can run again")

	_, err := x.Exec("INSERT INTO bitbucket_origin (project_key, slug, server, repo_id) VALUES ('PAY', 'api', 'https://bb.example.com', 1)")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO bitbucket_origin (project_key, slug, server, repo_id) VALUES ('PAY', 'api', 'https://bb.example.com', 2)")
	require.Error(t, err, "a Bitbucket repository is imported once")
	_, err = x.Exec("INSERT INTO bitbucket_origin (project_key, slug, server, owner_id, group_id) VALUES ('PAY', '', 'https://bb.example.com', 3, 1)")
	require.NoError(t, err)
}
