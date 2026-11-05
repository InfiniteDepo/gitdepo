// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zzpProtectedBranchBefore struct {
	ID       int64 `xorm:"pk autoincr"`
	RuleName string
}

func (v18zzpProtectedBranchBefore) TableName() string { return "protected_branch" }

func Test_addIgnorePusherApprovals(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zzpProtectedBranchBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO protected_branch (rule_name) VALUES ('main')")
	require.NoError(t, err)

	require.NoError(t, addIgnorePusherApprovals(x))
	require.NoError(t, addIgnorePusherApprovals(x), "the migration can run again")

	count, err := x.Table("protected_branch").Where("ignore_pusher_approvals = ? AND rule_name = 'main'", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing rules keep counting pushers")
}
