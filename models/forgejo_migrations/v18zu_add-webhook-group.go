// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add project webhooks",
		Upgrade:     addWebhookGroup,
	})
}

type v18zuWebhook struct {
	ID      int64 `xorm:"pk autoincr"`
	GroupID int64 `xorm:"INDEX NOT NULL DEFAULT 0"`
}

func (v18zuWebhook) TableName() string {
	return "webhook"
}

func addWebhookGroup(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zuWebhook))
	return err
}
