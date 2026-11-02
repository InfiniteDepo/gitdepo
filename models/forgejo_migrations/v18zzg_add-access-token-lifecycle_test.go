// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zzgOldAccessToken struct {
	ID        int64 `xorm:"pk autoincr"`
	UID       int64 `xorm:"INDEX"`
	Name      string
	TokenHash string `xorm:"UNIQUE"`
}

func (v18zzgOldAccessToken) TableName() string {
	return "access_token"
}

func Test_addAccessTokenLifecycle(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zzgOldAccessToken))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO access_token (uid, name, token_hash) VALUES (2, 'old', 'h')")
	require.NoError(t, err)

	require.NoError(t, addAccessTokenLifecycle(x))
	require.NoError(t, addAccessTokenLifecycle(x), "the migration can run again")

	count, err := x.Table("access_token").Where("uid = 2 AND creator_id = 0 AND description = '' AND self_rotate = ? AND rotated_unix = 0 AND rotated_by_id = 0 AND revoked_unix = 0 AND revoked_by_id = 0 AND last_used_ip = ''", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing tokens get the defaults: not revoked, never rotated")
}
