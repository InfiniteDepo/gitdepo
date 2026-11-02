// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addSecretCustomPattern(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addSecretCustomPattern(x))
	require.NoError(t, addSecretCustomPattern(x), "the migration can run again")

	insert := "INSERT INTO secret_custom_pattern (owner_id, name, pattern, keywords, enabled, deleted_unix) VALUES (?, ?, 'x', '[]', ?, ?)"
	_, err := x.Exec(insert, 0, "one", true, 0)
	require.NoError(t, err)
	_, err = x.Exec(insert, 0, "one", true, 0)
	require.Error(t, err, "a name is unique per owner among the live patterns")
	_, err = x.Exec(insert, 5, "one", true, 0)
	require.NoError(t, err, "the same name of another owner")
	_, err = x.Exec(insert, 0, "one", false, 100)
	require.NoError(t, err, "a deleted pattern keeps its name next to a live one")
	_, err = x.Exec(insert, 0, "one", false, 100)
	require.Error(t, err, "two tombstones of one name need different times")

	assert.ElementsMatch(t, []string{"unique:owner_id,name,deleted_unix"}, indexSets(t, x, "secret_custom_pattern"))
}
