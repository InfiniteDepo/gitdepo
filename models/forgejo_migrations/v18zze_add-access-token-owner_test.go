// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zzeOldAccessToken struct {
	ID        int64 `xorm:"pk autoincr"`
	UID       int64 `xorm:"INDEX"`
	Name      string
	TokenHash string `xorm:"UNIQUE"`
}

func (v18zzeOldAccessToken) TableName() string {
	return "access_token"
}

func Test_addAccessTokenOwner(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zzeOldAccessToken))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO access_token (uid, name, token_hash) VALUES (2, 'old', 'h')")
	require.NoError(t, err)

	require.NoError(t, addAccessTokenOwner(x))
	require.NoError(t, addAccessTokenOwner(x), "the migration can run again")

	count, err := x.Table("access_token").Where("uid = 2 AND owner_type = 0 AND owner_id = 0 AND group_id = 0 AND mode = 0").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing tokens stay personal access tokens")
}
