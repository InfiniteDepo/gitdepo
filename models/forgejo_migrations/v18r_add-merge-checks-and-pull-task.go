// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add conversation and task merge checks to protected branches, and the pull_task table",
		Upgrade:     addMergeChecksAndPullTask,
	})
}

type v18rProtectedBranch struct {
	BlockOnUnresolvedConversations bool `xorm:"NOT NULL DEFAULT false"`
	IgnoreOutdatedConversations    bool `xorm:"NOT NULL DEFAULT false"`
	BlockOnIncompleteTasks         bool `xorm:"NOT NULL DEFAULT false"`
}

func (v18rProtectedBranch) TableName() string {
	return "protected_branch"
}

type v18rPullTask struct {
	ID          int64              `xorm:"pk autoincr"`
	IssueID     int64              `xorm:"INDEX NOT NULL"`
	CommentID   int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	Content     string             `xorm:"VARCHAR(255) NOT NULL"`
	CreatorID   int64              `xorm:"NOT NULL"`
	AssigneeID  int64              `xorm:"NOT NULL DEFAULT 0"`
	IsDone      bool               `xorm:"INDEX NOT NULL DEFAULT false"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

func (v18rPullTask) TableName() string {
	return "pull_task"
}

func addMergeChecksAndPullTask(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18rProtectedBranch), new(v18rPullTask))
	return err
}
