// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addWebhookGroup(t *testing.T) {
	type Webhook struct {
		ID      int64 `xorm:"pk autoincr"`
		OwnerID int64 `xorm:"INDEX"`
		URL     string
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(Webhook))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO webhook (owner_id, url) VALUES (3, 'http://example.com')")
	require.NoError(t, err)

	require.NoError(t, addWebhookGroup(x))
	require.NoError(t, addWebhookGroup(x), "the migration can run again")

	count, err := x.Table("webhook").Where("owner_id = 3 AND group_id = 0").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing hooks are organization hooks")
}
