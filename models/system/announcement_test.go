// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package system_test

import (
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/system"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnnouncementIsVisibleTo(t *testing.T) {
	cases := []struct {
		audience                 system.AnnouncementAudience
		anonymous, signed, admin bool
	}{
		{system.AnnouncementAudienceEveryone, true, true, true},
		{system.AnnouncementAudienceSignedIn, false, true, true},
		{system.AnnouncementAudienceAdmins, false, false, true},
		{"unknown", false, false, false},
	}
	for _, c := range cases {
		t.Run(string(c.audience), func(t *testing.T) {
			a := &system.Announcement{Audience: c.audience}
			assert.Equal(t, c.anonymous, a.IsVisibleTo(false, false))
			assert.Equal(t, c.signed, a.IsVisibleTo(true, false))
			assert.Equal(t, c.admin, a.IsVisibleTo(true, true))
		})
	}
}

func TestAnnouncementIsActiveAt(t *testing.T) {
	const now timeutil.TimeStamp = 1000
	cases := []struct {
		name       string
		start, end timeutil.TimeStamp
		active     bool
	}{
		{"unbounded", 0, 0, true},
		{"started", 900, 0, true},
		{"starts now", 1000, 0, true},
		{"not started", 1001, 0, false},
		{"ends later", 0, 1001, true},
		{"ends now", 0, 1000, false},
		{"ended", 0, 999, false},
		{"inside window", 900, 1100, true},
		{"before window", 1100, 1200, false},
		{"after window", 800, 900, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := &system.Announcement{StartUnix: c.start, EndUnix: c.end}
			assert.Equal(t, c.active, a.IsActiveAt(now))
		})
	}
}

func TestAnnouncementCanBeDismissed(t *testing.T) {
	assert.True(t, (&system.Announcement{Type: system.AnnouncementInfo, Dismissible: true}).CanBeDismissed())
	assert.True(t, (&system.Announcement{Type: system.AnnouncementWarning, Dismissible: true}).CanBeDismissed())
	assert.False(t, (&system.Announcement{Type: system.AnnouncementInfo}).CanBeDismissed())
	assert.False(t, (&system.Announcement{Type: system.AnnouncementCritical, Dismissible: true}).CanBeDismissed())
}

func TestSortAnnouncements(t *testing.T) {
	list := []*system.Announcement{
		{ID: 1, Type: system.AnnouncementInfo},
		{ID: 2, Type: system.AnnouncementCritical},
		{ID: 3, Type: system.AnnouncementWarning},
		{ID: 4, Type: system.AnnouncementCritical},
	}
	system.SortAnnouncements(list)
	ids := make([]int64, 0, len(list))
	for _, a := range list {
		ids = append(ids, a.ID)
	}
	assert.Equal(t, []int64{4, 2, 3, 1}, ids)
}

func TestAnnouncementDismissal(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	dismissible := &system.Announcement{Message: "hello", Type: system.AnnouncementInfo, Audience: system.AnnouncementAudienceEveryone, Dismissible: true}
	fixed := &system.Announcement{Message: "fixed", Type: system.AnnouncementWarning, Audience: system.AnnouncementAudienceEveryone}
	require.NoError(t, system.InsertAnnouncement(ctx, dismissible))
	require.NoError(t, system.InsertAnnouncement(ctx, fixed))
	all := []*system.Announcement{dismissible, fixed}

	filtered, err := system.FilterDismissedAnnouncements(ctx, all, 2)
	require.NoError(t, err)
	assert.Len(t, filtered, 2)

	require.NoError(t, system.DismissAnnouncement(ctx, dismissible, 2))
	// dismissing twice keeps a single row
	require.NoError(t, system.DismissAnnouncement(ctx, dismissible, 2))
	unittest.AssertCount(t, &system.AnnouncementDismissal{AnnouncementID: dismissible.ID}, 1)

	filtered, err = system.FilterDismissedAnnouncements(ctx, all, 2)
	require.NoError(t, err)
	assert.Equal(t, []*system.Announcement{fixed}, filtered)

	// other users still see it
	filtered, err = system.FilterDismissedAnnouncements(ctx, all, 4)
	require.NoError(t, err)
	assert.Len(t, filtered, 2)

	// changing the message brings it back
	dismissible.Message = "hello again"
	require.NoError(t, system.UpdateAnnouncement(ctx, dismissible))
	filtered, err = system.FilterDismissedAnnouncements(ctx, all, 2)
	require.NoError(t, err)
	assert.Len(t, filtered, 2)

	// deleting removes the dismissals
	require.NoError(t, system.DismissAnnouncement(ctx, dismissible, 2))
	require.NoError(t, system.DeleteAnnouncement(ctx, dismissible.ID))
	unittest.AssertNotExistsBean(t, &system.Announcement{ID: dismissible.ID})
	unittest.AssertCount(t, &system.AnnouncementDismissal{AnnouncementID: dismissible.ID}, 0)
}
