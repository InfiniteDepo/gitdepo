// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"testing"

	migration_tests "forgejo.org/models/gitea_migrations/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type v18xUserBefore struct {
	ID                           int64  `xorm:"pk autoincr"`
	LowerName                    string `xorm:"UNIQUE NOT NULL"`
	EmailNotificationsPreference string `xorm:"VARCHAR(20) NOT NULL DEFAULT 'enabled'"`
}

func (v18xUserBefore) TableName() string { return "user" }

// AC10, AC11: the table exists with a unique (user, repo, event) key and existing presets are untouched.
func Test_addUserNotificationSetting(t *testing.T) {
	x, deferable := migration_tests.PrepareTestEnv(t, 0, new(v18xUserBefore))
	defer deferable()
	require.NotNil(t, x)

	_, err := x.Exec("INSERT INTO `user` (lower_name, email_notifications_preference) VALUES ('a', 'onmention')")
	require.NoError(t, err)

	require.NoError(t, addUserNotificationSetting(x))

	count, err := x.Table("user").Where("email_notifications_preference = 'onmention'").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
	count, err = x.Table("user_notification_setting").Count()
	require.NoError(t, err)
	assert.EqualValues(t, 0, count, "no backfill")

	_, err = x.Exec("INSERT INTO user_notification_setting (user_id, repo_id, event, enabled) VALUES (1, 0, 'mention', ?)", true)
	require.NoError(t, err)
	_, err = x.Exec("INSERT INTO user_notification_setting (user_id, repo_id, event, enabled) VALUES (1, 0, 'mention', ?)", false)
	require.Error(t, err, "unique key")
}
