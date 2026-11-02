// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addCredentialExpiryNotice(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addCredentialExpiryNotice(x))
	require.NoError(t, addCredentialExpiryNotice(x), "the migration can run again")

	_, err := x.Exec("INSERT INTO credential_expiry_notice (kind, credential_id, expires_unix, stage, created_unix) VALUES ('access_token', 1, 100, 0, 1)")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO credential_expiry_notice (kind, credential_id, expires_unix, stage, created_unix) VALUES ('access_token', 1, 100, 1, 1)")
	require.NoError(t, err, "another stage of the same credential")
	_, err = x.Exec("INSERT INTO credential_expiry_notice (kind, credential_id, expires_unix, stage, created_unix) VALUES ('access_token', 1, 100, 0, 2)")
	require.Error(t, err, "a notice is sent once")

	count, err := x.Table("credential_expiry_notice").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 2, count)
}
