// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package mergequeue

import (
	"context"

	issues_model "forgejo.org/models/issues"
	pull_model "forgejo.org/models/pull"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/log"
	"forgejo.org/modules/repository"
	notify_service "forgejo.org/services/notify"
	shared "forgejo.org/services/shared/mergequeue"
)

// notifier starts a pass of a merge queue when one of its pull requests or its branch changes
type notifier struct {
	notify_service.NullNotifier
}

var _ notify_service.Notifier = &notifier{}

// triggerPull starts a pass of the queue pr is in, if any
func triggerPull(ctx context.Context, pullID int64) {
	e, err := pull_model.GetMergeQueueEntryByPullID(ctx, pullID)
	if err != nil {
		log.Error("GetMergeQueueEntryByPullID[%d]: %v", pullID, err)
		return
	}
	if e != nil {
		shared.Trigger(e.RepoID, e.BaseBranch)
	}
}

func triggerIssue(ctx context.Context, issue *issues_model.Issue) {
	if !issue.IsPull {
		return
	}
	pr, err := issues_model.GetPullRequestByIssueIDWithNoAttributes(ctx, issue.ID)
	if err != nil {
		log.Error("GetPullRequestByIssueID[%d]: %v", issue.ID, err)
		return
	}
	triggerPull(ctx, pr.ID)
}

// triggerBranch starts a pass of the queue of the branch, if it has one
func triggerBranch(ctx context.Context, repo *repo_model.Repository, ref git.RefName) {
	if !ref.IsBranch() || pull_model.IsMergeQueueBranch(ref.BranchName()) {
		return
	}
	keys, err := pull_model.FindMergeQueueKeysOfRepo(ctx, repo.ID)
	if err != nil {
		log.Error("FindMergeQueueKeysOfRepo[%d]: %v", repo.ID, err)
		return
	}
	for _, k := range keys {
		if k.BaseBranch == ref.BranchName() {
			shared.Trigger(k.RepoID, k.BaseBranch)
		}
	}
}

func (n *notifier) PullRequestSynchronized(ctx context.Context, _ *user_model.User, pr *issues_model.PullRequest) {
	triggerPull(ctx, pr.ID)
}

func (n *notifier) PullRequestChangeTargetBranch(ctx context.Context, _ *user_model.User, pr *issues_model.PullRequest, _ string) {
	triggerPull(ctx, pr.ID)
}

func (n *notifier) PullRequestReview(ctx context.Context, pr *issues_model.PullRequest, _ *issues_model.Review, _ *issues_model.Comment, _ []*user_model.User) {
	triggerPull(ctx, pr.ID)
}

func (n *notifier) PullReviewDismiss(ctx context.Context, _ *user_model.User, review *issues_model.Review, _ *issues_model.Comment) {
	if err := review.LoadIssue(ctx); err != nil {
		log.Error("LoadIssue: %v", err)
		return
	}
	triggerIssue(ctx, review.Issue)
}

func (n *notifier) IssueChangeStatus(ctx context.Context, _ *user_model.User, _ *issues_model.PRNotificationInfo, issue *issues_model.Issue, _ *issues_model.Comment, _ bool) {
	triggerIssue(ctx, issue)
}

func (n *notifier) IssueChangeTitle(ctx context.Context, _ *user_model.User, issue *issues_model.Issue, _ string) {
	triggerIssue(ctx, issue)
}

func (n *notifier) PushCommits(ctx context.Context, _ *user_model.User, repo *repo_model.Repository, opts *repository.PushUpdateOptions, _ *repository.PushCommits) {
	triggerBranch(ctx, repo, opts.RefFullName)
}

func (n *notifier) SyncPushCommits(ctx context.Context, _ *user_model.User, repo *repo_model.Repository, opts *repository.PushUpdateOptions, _ *repository.PushCommits) {
	triggerBranch(ctx, repo, opts.RefFullName)
}

func (n *notifier) DeleteRef(ctx context.Context, _ *user_model.User, repo *repo_model.Repository, ref git.RefName) {
	triggerBranch(ctx, repo, ref)
}
