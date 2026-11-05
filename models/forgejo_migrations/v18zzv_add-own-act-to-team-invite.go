// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "record whether a team invitation was its inviter's own act",
		Upgrade:     addOwnActToTeamInvite,
	})
}

type v18zzvTeamInvite struct {
	ID     int64 `xorm:"pk autoincr"`
	OwnAct bool  `xorm:"NOT NULL DEFAULT false"`
}

func (v18zzvTeamInvite) TableName() string {
	return "team_invite"
}

func addOwnActToTeamInvite(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zzvTeamInvite))
	return err
}
