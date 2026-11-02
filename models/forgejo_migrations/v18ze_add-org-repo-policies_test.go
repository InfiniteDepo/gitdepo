// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zeUserBefore struct {
	ID   int64 `xorm:"pk autoincr"`
	Name string
}

func (v18zeUserBefore) TableName() string { return "user" }

// AC1: the policy columns are added and existing organizations keep today's behaviour.
func Test_addOrgRepoPolicies(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zeUserBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO `user` (name) VALUES ('org')")
	require.NoError(t, err)

	require.NoError(t, addOrgRepoPolicies(x))

	count, err := x.Table("user").Where("restrict_repo_visibility_change = ? AND private_fork_policy = 0", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}
