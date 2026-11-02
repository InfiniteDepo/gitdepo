// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add user.require_two_factor, an organization requiring two-factor authentication of its members",
		Upgrade:     addUserRequireTwoFactor,
	})
}

func addUserRequireTwoFactor(x *xorm.Engine) error {
	type User struct {
		RequireTwoFactor bool `xorm:"NOT NULL DEFAULT false INDEX"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(User))
	return err
}
