// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zzcOldAuthorizedIntegration struct {
	ID       int64 `xorm:"pk autoincr"`
	Name     string
	Issuer   string `xorm:"NOT NULL UNIQUE(s)"`
	Audience string `xorm:"NOT NULL UNIQUE(s)"`
}

func (v18zzcOldAuthorizedIntegration) TableName() string {
	return "authorized_integration"
}

func Test_addAuthorizedIntegrationExpiry(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zzcOldAuthorizedIntegration))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO authorized_integration (name, issuer, audience) VALUES ('old', 'i', 'a')")
	require.NoError(t, err)

	require.NoError(t, addAuthorizedIntegrationExpiry(x))
	require.NoError(t, addAuthorizedIntegrationExpiry(x), "the migration can run again")

	count, err := x.Table("authorized_integration").Where("audience = 'a' AND expires_unix = 0").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing integrations never expire")
}
