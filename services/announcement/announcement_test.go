// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package announcement

import (
	"strings"
	"testing"
	"time"

	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/cache"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func messages(banners []*Banner) []string {
	result := make([]string, 0, len(banners))
	for _, b := range banners {
		result = append(result, string(b.RenderedMessage))
	}
	return result
}

func TestActiveForUser(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.CacheService.Cache, setting.Cache{Adapter: "memory", TTL: time.Hour})()
	require.NoError(t, cache.Init())
	cache.Remove(cacheKey)
	ctx := t.Context()

	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

	banners, err := ActiveForUser(ctx, nil, nil)
	require.NoError(t, err)
	assert.Empty(t, banners)

	now := timeutil.TimeStampNow()
	info := &system_model.Announcement{Message: "info *one*", Type: system_model.AnnouncementInfo, Audience: system_model.AnnouncementAudienceEveryone, Dismissible: true}
	critical := &system_model.Announcement{Message: "critical", Type: system_model.AnnouncementCritical, Audience: system_model.AnnouncementAudienceAdmins}
	scheduled := &system_model.Announcement{Message: "later", Type: system_model.AnnouncementWarning, Audience: system_model.AnnouncementAudienceEveryone, StartUnix: now + 3600}
	for _, a := range []*system_model.Announcement{info, critical, scheduled} {
		require.NoError(t, Create(ctx, a))
	}

	// creating invalidates the cache
	banners, err = ActiveForUser(ctx, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"<p>info <em>one</em></p>\n"}, messages(banners))

	banners, err = ActiveForUser(ctx, admin, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"<p>critical</p>\n", "<p>info <em>one</em></p>\n"}, messages(banners))

	// changes made without the service are not seen until the cache is invalidated
	info.Message = "info two"
	require.NoError(t, system_model.UpdateAnnouncement(ctx, info))
	banners, err = ActiveForUser(ctx, user, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"<p>info <em>one</em></p>\n"}, messages(banners))

	require.NoError(t, Update(ctx, info))
	banners, err = ActiveForUser(ctx, user, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"<p>info two</p>\n"}, messages(banners))

	// dismissals are applied on top of the cached list
	require.NoError(t, system_model.DismissAnnouncement(ctx, info, user.ID))
	banners, err = ActiveForUser(ctx, user, nil)
	require.NoError(t, err)
	assert.Empty(t, banners)
	banners, err = ActiveForUser(ctx, nil, nil)
	require.NoError(t, err)
	assert.Len(t, banners, 1)

	require.NoError(t, Delete(ctx, info.ID))
	banners, err = ActiveForUser(ctx, nil, nil)
	require.NoError(t, err)
	assert.Empty(t, banners)
}

func TestActiveForUserAnonymousDismissed(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.CacheService.Cache, setting.Cache{Adapter: "memory", TTL: time.Hour})()
	require.NoError(t, cache.Init())
	cache.Remove(cacheKey)
	ctx := t.Context()

	info := &system_model.Announcement{Message: "info", Type: system_model.AnnouncementInfo, Audience: system_model.AnnouncementAudienceEveryone, Dismissible: true}
	fixed := &system_model.Announcement{Message: "fixed", Type: system_model.AnnouncementInfo, Audience: system_model.AnnouncementAudienceEveryone}
	critical := &system_model.Announcement{Message: "critical", Type: system_model.AnnouncementCritical, Audience: system_model.AnnouncementAudienceEveryone, Dismissible: true}
	for _, a := range []*system_model.Announcement{info, fixed, critical} {
		require.NoError(t, Create(ctx, a))
	}

	dismissed := map[int64]string{info.ID: CookieHash(info), fixed.ID: CookieHash(fixed), critical.ID: CookieHash(critical)}
	banners, err := ActiveForUser(ctx, nil, dismissed)
	require.NoError(t, err)
	// only the dismissible, non-critical one is hidden
	assert.Equal(t, []string{"<p>critical</p>\n", "<p>fixed</p>\n"}, messages(banners))

	// the banner is back once the message changes
	info.Message = "info changed"
	require.NoError(t, Update(ctx, info))
	banners, err = ActiveForUser(ctx, nil, dismissed)
	require.NoError(t, err)
	assert.Equal(t, []string{"<p>critical</p>\n", "<p>fixed</p>\n", "<p>info changed</p>\n"}, messages(banners))

	// signed-in users ignore the cookie
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	banners, err = ActiveForUser(ctx, user, map[int64]string{info.ID: CookieHash(info)})
	require.NoError(t, err)
	assert.Len(t, banners, 3)
}

func TestDismissCookie(t *testing.T) {
	assert.Empty(t, ParseDismissCookie(""))
	assert.Equal(t, map[int64]string{1: "aaaaaaaa", 22: "bbbbbbbb"}, ParseDismissCookie("1:aaaaaaaa,22:bbbbbbbb"))
	// malformed items are skipped
	assert.Equal(t, map[int64]string{3: "cccccccc"}, ParseDismissCookie("x:aaaaaaaa,5,:,7:,3:cccccccc,,"))
	// oversized values are ignored
	assert.Empty(t, ParseDismissCookie(strings.Repeat("1:aaaaaaaa,", 60)))

	v := AddToDismissCookie("", 1, "aaaaaaaa")
	assert.Equal(t, "1:aaaaaaaa", v)
	v = AddToDismissCookie(v, 2, "bbbbbbbb")
	assert.Equal(t, "1:aaaaaaaa,2:bbbbbbbb", v)
	// replacing moves the entry to the end
	assert.Equal(t, "2:bbbbbbbb,1:cccccccc", AddToDismissCookie(v, 1, "cccccccc"))

	// at most 20 entries are kept, the oldest go first
	v = ""
	for i := int64(1); i <= 30; i++ {
		v = AddToDismissCookie(v, i, "aaaaaaaa")
	}
	parsed := ParseDismissCookie(v)
	assert.Len(t, parsed, 20)
	assert.NotContains(t, parsed, int64(10))
	assert.Contains(t, parsed, int64(11))
	assert.Contains(t, parsed, int64(30))
	assert.LessOrEqual(t, len(v), 512)
}
