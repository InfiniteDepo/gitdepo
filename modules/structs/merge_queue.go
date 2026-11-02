// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

import "time"

// MergeQueueEntry is a pull request in the merge queue of a branch
type MergeQueueEntry struct {
	// position in the queue, from 1
	Position int `json:"position"`
	// index of the pull request
	Number int64  `json:"number"`
	Title  string `json:"title"`
	// waiting: to be tested; testing: the required checks run on test_sha; passed: the checks passed, it merges
	// once the pull requests ahead of it did; grouping: the checks passed, it waits for the minimum group size or
	// the wait time; merging: test_sha is being pushed to the branch
	// enum: ["waiting", "testing", "passed", "grouping", "merging"]
	State                  string `json:"state"`
	MergeStyle             string `json:"merge_style"`
	DeleteBranchAfterMerge bool   `json:"delete_branch_after_merge"`
	// the head of the pull request when it was added
	HeadSHA string `json:"head_sha"`
	// the commit the queue tests: the branch, the pull requests ahead and this one
	TestSHA    string `json:"test_sha,omitempty"`
	EnqueuedBy *User  `json:"enqueued_by"`
	// swagger:strfmt date-time
	EnqueuedAt time.Time `json:"enqueued_at"`
	// swagger:strfmt date-time
	StartedAt *time.Time `json:"started_at,omitempty"`
}
