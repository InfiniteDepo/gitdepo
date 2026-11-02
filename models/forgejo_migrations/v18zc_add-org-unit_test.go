// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addOrgUnit(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addOrgUnit(x))
	_, err := x.Exec("INSERT INTO org_unit (org_id, type, disabled) VALUES (3, 2, ?)", true)
	require.NoError(t, err)
	// one row per organization and unit
	_, err = x.Exec("INSERT INTO org_unit (org_id, type, disabled) VALUES (3, 2, ?)", false)
	require.Error(t, err)
	n, err := x.Table("org_unit").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
}
