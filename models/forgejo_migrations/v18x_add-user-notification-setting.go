// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add user_notification_setting",
		Upgrade:     addUserNotificationSetting,
	})
}

func addUserNotificationSetting(x *xorm.Engine) error {
	type UserNotificationSetting struct {
		ID      int64  `xorm:"pk autoincr"`
		UserID  int64  `xorm:"UNIQUE(user_repo_event) NOT NULL"`
		RepoID  int64  `xorm:"UNIQUE(user_repo_event) NOT NULL DEFAULT 0"`
		Event   string `xorm:"UNIQUE(user_repo_event) VARCHAR(40) NOT NULL"`
		Enabled bool   `xorm:"NOT NULL"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(UserNotificationSetting))
	return err
}
