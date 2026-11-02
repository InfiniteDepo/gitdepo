// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package user_test

import (
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AC12: the fallback chain is repo row -> user row -> instance default list -> built-in default.
func TestNotificationSettingsChain(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	e := user_model.NotifyEventPRComment

	s, err := user_model.LoadNotificationSettings(ctx, []int64{2}, 1)
	require.NoError(t, err)
	assert.True(t, s[2].Enabled(e), "built-in default")
	assert.False(t, s[2].Enabled(user_model.NotifyEventWatchEveryComment), "every comment is off by default")
	assert.False(t, s[2].Enabled(user_model.NotifyEventOwnActions))
	assert.False(t, s[2].HasRepoOverride())

	t.Run("instance list", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Admin.DefaultEmailNotificationEvents, []string{"pr_comment"})()
		assert.True(t, s[2].Enabled(e))
		assert.False(t, s[2].Enabled(user_model.NotifyEventPRMerged))
	})

	require.NoError(t, user_model.SaveNotificationSettings(ctx, 2, 0, map[user_model.NotifyEvent]bool{e: false}))
	s, err = user_model.LoadNotificationSettings(ctx, []int64{2}, 1)
	require.NoError(t, err)
	assert.False(t, s[2].Enabled(e), "user row beats default")
	assert.True(t, s[2].Enabled(user_model.NotifyEventPRMerged), "missing row falls through")

	require.NoError(t, user_model.SaveNotificationSettings(ctx, 2, 1, map[user_model.NotifyEvent]bool{e: true}))
	s, err = user_model.LoadNotificationSettings(ctx, []int64{2}, 1)
	require.NoError(t, err)
	assert.True(t, s[2].Enabled(e), "repo row beats user row")
	assert.True(t, s[2].HasRepoOverride())

	s, err = user_model.LoadNotificationSettings(ctx, []int64{2}, 2)
	require.NoError(t, err)
	assert.False(t, s[2].Enabled(e), "override is per repo")

	require.NoError(t, user_model.DeleteRepoNotificationSettings(ctx, 2, 1))
	unittest.AssertNotExistsBean(t, &user_model.NotificationSetting{UserID: 2, RepoID: 1})
	unittest.AssertExistsAndLoadBean(t, &user_model.NotificationSetting{UserID: 2, RepoID: 0})
}

func TestNotifyEventNames(t *testing.T) {
	for _, e := range user_model.AllNotifyEvents {
		assert.True(t, e.IsValid(), e)
	}
	assert.False(t, user_model.NotifyEvent("nope").IsValid())
	assert.True(t, user_model.IsValidEmailNotificationsPreference(user_model.EmailNotificationsCustom))
	assert.False(t, user_model.IsValidEmailNotificationsPreference("x"))
}
