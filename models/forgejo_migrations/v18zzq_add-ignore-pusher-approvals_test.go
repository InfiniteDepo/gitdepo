// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18zzqProtectedBranchBefore struct {
	ID       int64 `xorm:"pk autoincr"`
	RuleName string
}

func (v18zzqProtectedBranchBefore) TableName() string { return "protected_branch" }

type v18zzqDeployKeyBefore struct {
	ID   int64 `xorm:"pk autoincr"`
	Name string
}

func (v18zzqDeployKeyBefore) TableName() string { return "deploy_key" }

type v18zzqOrgDeployKeyBefore struct {
	ID   int64 `xorm:"pk autoincr"`
	Name string
}

func (v18zzqOrgDeployKeyBefore) TableName() string { return "org_deploy_key" }

func Test_addIgnorePusherApprovals(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18zzqProtectedBranchBefore), new(v18zzqDeployKeyBefore), new(v18zzqOrgDeployKeyBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO protected_branch (rule_name) VALUES ('main')")
	require.NoError(t, err)

	_, err = x.Exec("INSERT INTO deploy_key (name) VALUES ('k')")
	require.NoError(t, err)

	require.NoError(t, addIgnorePusherApprovals(x))
	require.NoError(t, addIgnorePusherApprovals(x), "the migration can run again")

	count, err := x.Table("protected_branch").Where("ignore_pusher_approvals = ? AND rule_name = 'main'", false).Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing rules keep counting pushers")

	count, err = x.Table("deploy_key").Where("creator_id = 0 AND name = 'k'").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "existing deploy keys have no recorded owner")
	_, err = x.Table("org_deploy_key").Count()
	require.NoError(t, err)

	const insert = "INSERT INTO branch_pusher (repo_id, branch, user_id, created_unix) VALUES (1, 'b', ?, 1)"
	_, err = x.Exec(insert, 3)
	require.NoError(t, err)
	_, err = x.Exec(insert, 3)
	require.Error(t, err, "a pusher is recorded once per branch")
	_, err = x.Exec(insert, 0)
	require.NoError(t, err, "0 marks a deploy key with no recorded owner")
}
