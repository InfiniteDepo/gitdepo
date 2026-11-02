// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addAnnouncements(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addAnnouncements(x))

	for _, table := range []string{"announcement", "announcement_dismissal"} {
		exists, err := x.IsTableExist(table)
		require.NoError(t, err)
		assert.True(t, exists, table)
	}

	exists, err := indexExists(x, "announcement_dismissal", "UQE_announcement_dismissal_s")
	require.NoError(t, err)
	assert.True(t, exists)

	// running the migration again is a no-op
	require.NoError(t, addAnnouncements(x))
}
