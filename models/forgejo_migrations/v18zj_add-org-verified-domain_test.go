// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addOrgVerifiedDomain(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0)
	defer deferable()
	require.NotNil(t, x)

	require.NoError(t, addOrgVerifiedDomain(x))
	_, err := x.Exec("INSERT INTO org_verified_domain (org_id, domain) VALUES (3, 'example.com')")
	require.NoError(t, err)
	// one organization per domain
	_, err = x.Exec("INSERT INTO org_verified_domain (org_id, domain) VALUES (6, 'example.com')")
	require.Error(t, err)
	n, err := x.Table("org_verified_domain").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
}
