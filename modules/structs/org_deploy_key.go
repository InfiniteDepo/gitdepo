// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

import "time"

// OrgDeployKey is a deploy key of an organization, for all its repositories or the selected ones
type OrgDeployKey struct {
	ID          int64  `json:"id"`
	KeyID       int64  `json:"key_id"`
	Key         string `json:"key"`
	URL         string `json:"url"`
	Title       string `json:"title"`
	Fingerprint string `json:"fingerprint"`
	// swagger:strfmt date-time
	Created  time.Time `json:"created_at"`
	ReadOnly bool      `json:"read_only"`
	// whether the key covers all repositories of the organization, including later ones, or only the selected ones
	AllRepositories bool `json:"all_repositories"`
	// ID of the project whose repositories the key covers, omitted for a key of the organization
	ProjectID int64 `json:"project_id,omitempty"`
	// When the key expires, omitted if never
	// swagger:strfmt date-time
	Expires *time.Time `json:"expires_at,omitempty"`
	// When the key was last used, omitted if never
	// swagger:strfmt date-time
	LastUsed *time.Time `json:"last_used_at,omitempty"`
}

// CreateOrgDeployKeyOption options for adding a deploy key to an organization
type CreateOrgDeployKeyOption struct {
	// Title of the key, unique in the organization
	//
	// required: true
	Title string `json:"title" binding:"Required;MaxSize(50)"`
	// An armored SSH key to add
	//
	// required: true
	Key string `json:"key" binding:"Required"`
	// Describe if the key has only read access or read/write
	ReadOnly bool `json:"read_only"`
	// Cover all repositories of the organization, including later ones
	AllRepositories bool `json:"all_repositories"`
	// Names of the repositories of the organization to cover, at least one unless all_repositories is set; at
	// most 1000
	Repositories []string `json:"repositories"`
	// When it expires. Required by default, at most 365 days from today ([security] *_EXPIRY_REQUIRED and *_MAX_LIFETIME_DAYS); omit for never only when the instance allows it
	// swagger:strfmt date-time
	ExpiresAt *time.Time `json:"expires_at"`
}

// EditOrgDeployKeyOption options for changing which repositories a deploy key of an organization covers. The title,
// the key, its access mode and its expiry can't be changed. At least one field is required.
type EditOrgDeployKeyOption struct {
	// true: all repositories of the organization; false: the selection, which must not be empty (repositories, or
	// the existing selection when repositories is omitted). Can't be true together with repositories. Setting it
	// to true keeps the stored selection, so setting it back to false alone covers those repositories again (the
	// web form deletes the selection instead).
	AllRepositories *bool `json:"all_repositories"`
	// Names of the repositories of the organization to cover, at most 1000; replaces the selection
	Repositories *[]string `json:"repositories"`
}
