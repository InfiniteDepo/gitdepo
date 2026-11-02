// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

import "time"

// PullTask is a to-do item on a pull request
type PullTask struct {
	ID      int64  `json:"id"`
	Content string `json:"content"`
	// ID of the comment the task was created from, 0 for a standalone task
	CommentID int64 `json:"comment_id"`
	Creator   *User `json:"creator"`
	Assignee  *User `json:"assignee"`
	// enum: open,done
	Status string `json:"status"`
	// swagger:strfmt date-time
	Created time.Time `json:"created_at"`
	// swagger:strfmt date-time
	Updated time.Time `json:"updated_at"`
}

// CreatePullTaskOption options for creating a pull request task
type CreatePullTaskOption struct {
	// required: true
	Content string `json:"content" binding:"Required;MaxSize(255)"`
	// ID of a comment of the pull request to create the task from
	CommentID int64 `json:"comment_id"`
}

// EditPullTaskOption options for changing the status of a pull request task
type EditPullTaskOption struct {
	// required: true
	// enum: open,done
	Status string `json:"status" binding:"Required;In(open,done)"`
}
