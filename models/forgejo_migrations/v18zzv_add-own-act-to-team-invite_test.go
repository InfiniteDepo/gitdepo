// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addOwnActToTeamInvite(t *testing.T) {
	type TeamInvite struct {
		ID     int64  `xorm:"pk autoincr"`
		Token  string `xorm:"UNIQUE(token) INDEX NOT NULL DEFAULT ''"`
		TeamID int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
	}
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(TeamInvite))
	defer deferable()
	require.NotNil(t, x)
	_, err := x.Exec("INSERT INTO team_invite (token, team_id) VALUES ('t1', 2)")
	require.NoError(t, err)

	require.NoError(t, addOwnActToTeamInvite(x))
	require.NoError(t, addOwnActToTeamInvite(x), "the migration can run again")

	// an invitation from before is not taken for an own act
	var ownAct []bool
	require.NoError(t, x.Table("team_invite").Cols("own_act").Find(&ownAct))
	assert.Equal(t, []bool{false}, ownAct)
}
