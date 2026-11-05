// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package issues

import (
	"context"
	"strings"

	"forgejo.org/models/db"
	"forgejo.org/modules/git"

	"xorm.io/builder"
)

// PullPushers returns the IDs of the users who pushed to the pull request: the posters of its push comments (web
// update, web edits, conflict resolution and every push to the head branch make one) and the users whose activated
// email is the author or committer email of a commit of the pull request. A rule that ignores pusher approvals
// removes them from the approvers, so a mistake here can only remove an approver, never admit one.
func PullPushers(ctx context.Context, pr *PullRequest) (map[int64]bool, error) {
	if err := pr.LoadBaseRepo(ctx); err != nil {
		return nil, err
	}
	ids := make([]int64, 0, 4)
	if err := db.GetEngine(ctx).Table("comment").Distinct("poster_id").
		Where("issue_id = ? AND type = ?", pr.IssueID, CommentTypePullRequestPush).Find(&ids); err != nil {
		return nil, err
	}

	// the head is read from the pull ref of the base repository, which holds it for every kind of pull request
	stdout, _, err := git.NewCommand(ctx, "log", "--format=%ae%n%ce").
		AddDynamicArguments(git.BranchPrefix + pr.BaseBranch + ".." + pr.GetGitRefName()).
		RunStdString(&git.RunOpts{Dir: pr.BaseRepo.RepoPath()})
	if err != nil {
		return nil, err
	}
	emails := map[string]struct{}{}
	for e := range strings.FieldsSeq(stdout) {
		emails[strings.ToLower(e)] = struct{}{}
	}
	if len(emails) > 0 {
		lower := make([]string, 0, len(emails))
		for e := range emails {
			lower = append(lower, e)
		}
		var uids []int64
		if err := db.GetEngine(ctx).Table("email_address").Cols("uid").
			Where(builder.In("lower_email", lower)).And("is_activated = ?", true).Find(&uids); err != nil {
			return nil, err
		}
		ids = append(ids, uids...)
	}

	pushers := make(map[int64]bool, len(ids))
	for _, id := range ids {
		pushers[id] = true
	}
	return pushers, nil
}
