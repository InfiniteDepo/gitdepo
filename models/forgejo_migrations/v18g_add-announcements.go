// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add site-wide announcements and their dismissals",
		Upgrade:     addAnnouncements,
	})
}

func addAnnouncements(x *xorm.Engine) error {
	type Announcement struct {
		ID          int64              `xorm:"pk autoincr"`
		Message     string             `xorm:"TEXT NOT NULL"`
		Type        string             `xorm:"VARCHAR(16) NOT NULL"`
		Audience    string             `xorm:"VARCHAR(16) NOT NULL"`
		Dismissible bool               `xorm:"NOT NULL DEFAULT false"`
		StartUnix   timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
		EndUnix     timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
		CreatedByID int64              `xorm:"NOT NULL DEFAULT 0"`
		CreatedUnix timeutil.TimeStamp `xorm:"created"`
		UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
	}
	type AnnouncementDismissal struct {
		ID             int64  `xorm:"pk autoincr"`
		AnnouncementID int64  `xorm:"UNIQUE(s) INDEX NOT NULL"`
		UserID         int64  `xorm:"UNIQUE(s) INDEX NOT NULL"`
		ContentHash    string `xorm:"VARCHAR(64) NOT NULL"`
	}
	return x.Sync(new(Announcement), new(AnnouncementDismissal))
}
