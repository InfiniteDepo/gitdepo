// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package convert

import (
	"time"

	system_model "forgejo.org/models/system"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
)

// OptionalTime converts a timestamp to a time, nil when it is 0.
func OptionalTime(ts timeutil.TimeStamp) *time.Time {
	if ts == 0 {
		return nil
	}
	t := ts.AsTime()
	return &t
}

// ToAnnouncement converts an announcement to its API representation
func ToAnnouncement(a *system_model.Announcement) *api.Announcement {
	return &api.Announcement{
		ID:          a.ID,
		Message:     a.Message,
		Type:        string(a.Type),
		Audience:    string(a.Audience),
		Dismissible: a.Dismissible,
		StartAt:     OptionalTime(a.StartUnix),
		EndAt:       OptionalTime(a.EndUnix),
		Created:     a.CreatedUnix.AsTime(),
		Updated:     a.UpdatedUnix.AsTime(),
	}
}

// ToAnnouncements converts a list of announcements to their API representation
func ToAnnouncements(list []*system_model.Announcement) []*api.Announcement {
	result := make([]*api.Announcement, 0, len(list))
	for _, a := range list {
		result = append(result, ToAnnouncement(a))
	}
	return result
}
