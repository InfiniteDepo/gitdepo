// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

import "time"

// Announcement is a message site administrators show as a banner on every page
type Announcement struct {
	ID int64 `json:"id"`
	// Markdown message
	Message string `json:"message"`
	// enum: info,warning,critical
	Type string `json:"type"`
	// Who sees the announcement
	// enum: everyone,signed_in,admins
	Audience string `json:"audience"`
	// Whether signed-in users can close the announcement. Critical announcements are never dismissible.
	Dismissible bool `json:"dismissible"`
	// When the announcement starts being shown, null if right away
	// swagger:strfmt date-time
	StartAt *time.Time `json:"start_at"`
	// When the announcement stops being shown, null if never
	// swagger:strfmt date-time
	EndAt *time.Time `json:"end_at"`
	// swagger:strfmt date-time
	Created time.Time `json:"created_at"`
	// swagger:strfmt date-time
	Updated time.Time `json:"updated_at"`
}

// CreateAnnouncementOption options for creating an announcement
type CreateAnnouncementOption struct {
	// Markdown message
	// required: true
	Message string `json:"message" binding:"Required;MaxSize(65535)"`
	// required: true
	// enum: info,warning,critical
	Type string `json:"type" binding:"Required;In(info,warning,critical)"`
	// required: true
	// enum: everyone,signed_in,admins
	Audience    string `json:"audience" binding:"Required;In(everyone,signed_in,admins)"`
	Dismissible bool   `json:"dismissible"`
	// swagger:strfmt date-time
	StartAt *time.Time `json:"start_at"`
	// swagger:strfmt date-time
	EndAt *time.Time `json:"end_at"`
}

// EditAnnouncementOption options for editing an announcement. Fields left out are not changed.
type EditAnnouncementOption struct {
	Message *string `json:"message" binding:"OmitEmpty;MaxSize(65535)"`
	// enum: info,warning,critical
	Type *string `json:"type" binding:"OmitEmpty;In(info,warning,critical)"`
	// enum: everyone,signed_in,admins
	Audience    *string `json:"audience" binding:"OmitEmpty;In(everyone,signed_in,admins)"`
	Dismissible *bool   `json:"dismissible"`
	// Set to 0001-01-01T00:00:00Z to remove the start time
	// swagger:strfmt date-time
	StartAt *time.Time `json:"start_at"`
	// Set to 0001-01-01T00:00:00Z to remove the end time
	// swagger:strfmt date-time
	EndAt *time.Time `json:"end_at"`
}
