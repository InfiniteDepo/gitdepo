// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zlUserBefore struct {
	ID   int64 `xorm:"pk autoincr"`
	Name string
}

func (v18zlUserBefore) TableName() string { return "user" }

func Test_addOrgCategory(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zlUserBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO `user` (name) VALUES ('org')")
	require.NoError(t, err)

	require.NoError(t, addOrgCategory(x))

	count, err := x.Table("user").Where("category_id = ?", 0).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)

	_, err = x.Exec("INSERT INTO `org_category` (name, description, color, position) VALUES ('Payments', '', '#112233', 1)")
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO `org_category` (name, description, color, position) VALUES ('Payments', '', '#112233', 2)")
	require.Error(t, err, "category names are unique")
}
