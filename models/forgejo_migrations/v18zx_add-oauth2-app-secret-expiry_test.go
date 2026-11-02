// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zxOldOAuth2Application struct {
	ID       int64 `xorm:"pk autoincr"`
	Name     string
	ClientID string `xorm:"unique"`
}

func (v18zxOldOAuth2Application) TableName() string {
	return "oauth2_application"
}

func Test_addOAuth2AppSecretExpiry(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zxOldOAuth2Application))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO oauth2_application (name, client_id) VALUES ('old', 'c1')")
	require.NoError(t, err)

	require.NoError(t, addOAuth2AppSecretExpiry(x))
	require.NoError(t, addOAuth2AppSecretExpiry(x), "the migration can run again")

	count, err := x.Table("oauth2_application").Where("client_id = 'c1' AND client_secret_expires_unix = 0").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing secrets never expire")
}
