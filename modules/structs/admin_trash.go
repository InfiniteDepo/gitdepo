// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

import "time"

// TrashItem is a deleted repository or organization in the trash, restorable by site admins until it is purged
type TrashItem struct {
	// the kind of item, "repo" or "org"
	Type string `json:"type"`
	ID   int64  `json:"id"`
	// the owner and name the repository, or the name the organization, had when it was deleted
	FullName  string `json:"full_name"`
	DeletedBy string `json:"deleted_by"`
	// when it was moved to the trash
	Deleted time.Time `json:"deleted"`
	// days left before it is deleted permanently
	DaysRemaining int `json:"days_remaining"`
	// size of the repository, or of the repositories of the organization, in bytes
	Size int64 `json:"size"`
	// true while a permanent deletion is in progress
	Purging bool `json:"purging"`
	// of an organization: the number of its repositories in the trash, which are deleted with it
	RepoCount int64 `json:"repo_count,omitempty"`
}

// RestoreTrashOption says where a restored item goes
type RestoreTrashOption struct {
	// a repository only: restore it under this user or organization; needed while its owner is in the trash
	NewOwner string `json:"new_owner"`
	// restore it under this name
	NewName string `json:"new_name"`
}
