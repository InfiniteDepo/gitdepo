// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add merged_base_commit_id to pull_request",
		Upgrade:     addPullRequestMergedBaseCommitID,
	})
}

func addPullRequestMergedBaseCommitID(x *xorm.Engine) error {
	type PullRequest struct {
		MergedBaseCommitID string `xorm:"VARCHAR(64)"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(PullRequest))
	return err
}
