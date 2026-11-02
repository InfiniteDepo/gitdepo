// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"forgejo.org/modules/timeutil"

	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the merge queue and its settings on protected branches",
		Upgrade:     addMergeQueue,
	})
}

type v18zzfProtectedBranch struct {
	RequireMergeQueue             bool   `xorm:"NOT NULL DEFAULT false"`
	MergeQueueBuildConcurrency    int    `xorm:"NOT NULL DEFAULT 0"`
	MergeQueueMinGroupSize        int    `xorm:"NOT NULL DEFAULT 0"`
	MergeQueueMaxGroupSize        int    `xorm:"NOT NULL DEFAULT 0"`
	MergeQueueWaitMinutes         int    `xorm:"NOT NULL DEFAULT 0"`
	MergeQueueCheckTimeoutMinutes int    `xorm:"NOT NULL DEFAULT 0"`
	MergeQueueMergeStyle          string `xorm:"VARCHAR(30) NOT NULL DEFAULT ''"`
}

func (v18zzfProtectedBranch) TableName() string {
	return "protected_branch"
}

type v18zzfMergeQueueEntry struct {
	ID            int64              `xorm:"pk autoincr"`
	RepoID        int64              `xorm:"INDEX(queue) NOT NULL"`
	BaseBranch    string             `xorm:"INDEX(queue) VARCHAR(255) NOT NULL"`
	PullID        int64              `xorm:"UNIQUE NOT NULL"`
	Position      int64              `xorm:"NOT NULL"`
	Status        int                `xorm:"NOT NULL DEFAULT 0"`
	MergeStyle    string             `xorm:"VARCHAR(30) NOT NULL"`
	DeleteBranch  bool               `xorm:"NOT NULL DEFAULT false"`
	SkipForward   bool               `xorm:"NOT NULL DEFAULT false"`
	Forced        bool               `xorm:"NOT NULL DEFAULT false"`
	BuildFailures int                `xorm:"NOT NULL DEFAULT 0"`
	MergingUnix   timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
	HeadCommitID  string             `xorm:"VARCHAR(64) NOT NULL"`
	BaseCommitID  string             `xorm:"VARCHAR(64)"`
	TempCommitID  string             `xorm:"INDEX VARCHAR(64)"`
	EnqueuedByID  int64              `xorm:"NOT NULL"`
	EnqueuedUnix  timeutil.TimeStamp `xorm:"created"`
	StartedUnix   timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
}

func (v18zzfMergeQueueEntry) TableName() string {
	return "merge_queue_entry"
}

func addMergeQueue(x *xorm.Engine) error {
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(v18zzfProtectedBranch), new(v18zzfMergeQueueEntry))
	return err
}
