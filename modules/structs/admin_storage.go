// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

// StorageSummary is the storage used by all repositories of the instance, in bytes
type StorageSummary struct {
	RepoCount int64 `json:"repo_count"`
	GitSize   int64 `json:"git_size"`
	LFSSize   int64 `json:"lfs_size"`
	StorageSizes
	// every type of storage except the trash
	TotalSize int64 `json:"total_size"`
	// mean git and LFS size per repository (not total_size divided by repo_count)
	AverageSize int64 `json:"average_size"`
}

// StorageSizes are the types of storage besides git and LFS, in bytes
type StorageSizes struct {
	WikiSize int64 `json:"wiki_size"`
	// issue and release attachments
	AttachmentsSize int64 `json:"attachments_size"`
	// each package blob counts once per owner, and once in the instance's total
	PackagesSize int64 `json:"packages_size"`
	// Actions artifacts that are not expired or deleted
	ArtifactsSize int64 `json:"artifacts_size"`
	// Actions logs that are not expired
	LogsSize int64 `json:"logs_size"`
	// git, LFS and wiki of repositories in the trash, which the other sizes leave out
	TrashSize int64 `json:"trash_size"`
}

// OwnerStorage is the storage used by the repositories of one owner, in bytes
type OwnerStorage struct {
	OwnerID   int64  `json:"owner_id"`
	OwnerName string `json:"owner_name"`
	// "user" or "org"
	OwnerType string `json:"owner_type"`
	RepoCount int64  `json:"repo_count"`
	GitSize   int64  `json:"git_size"`
	LFSSize   int64  `json:"lfs_size"`
	StorageSizes
	// every type of storage except the trash
	TotalSize int64 `json:"total_size"`
	// share of the instance's total size, in percent
	Percent float64 `json:"percent"`
}
