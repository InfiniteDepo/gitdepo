// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package issues

import (
	"context"
	"math"
	"strconv"
	"strings"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/modules/cache"
	"forgejo.org/modules/git"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"

	"xorm.io/builder"
)

// MaxPusherCommits is how many commits of a pull request are read to find the emails of its authors. A pull request
// with more fails closed for a rule that ignores pusher approvals (PusherTooMany).
const MaxPusherCommits = 5000

const (
	// PusherUnknownDeployKey is in Pushers when a deploy key with no recorded owner pushed to the branch.
	PusherUnknownDeployKey int64 = 0
	// PusherTooMany is in Pushers when the pull request has more than MaxPusherCommits commits or they can't be read.
	PusherTooMany int64 = math.MinInt64
)

// Pushers are the IDs of the users who pushed to a pull request. It is shared through the request cache: don't change it.
type Pushers map[int64]bool

// Blocked reports that the pushers can't be told, so no approval can be counted for a rule that ignores them.
func (p Pushers) Blocked() bool { return p[PusherUnknownDeployKey] || p[PusherTooMany] }

// PullPushers returns the users who pushed to the pull request: the users recorded by the pre-receive hook for the
// head branch (branch_pusher: every push, the web editor, update branch, Actions, tokens and deploy keys, credited to
// the user behind them), the posters of its push comments and the users whose activated email, or no-reply address,
// is the author or committer email of a commit of the pull request. A rule that ignores pusher approvals removes them
// from the approvers, so a mistake here can only remove an approver, never admit one. The result is computed once per
// request.
func PullPushers(ctx context.Context, pr *PullRequest) (Pushers, error) {
	return cache.GetWithContextCache(ctx, "pull_pushers", strconv.FormatInt(pr.ID, 10), func() (Pushers, error) {
		return pullPushers(ctx, pr)
	})
}

// PullHeadCommitID returns the head of pr as its pull ref in the base repository names it (the ref holds it for every
// kind of pull request), read once per request. Every merge check that needs the head reads it here, and Merge is
// pinned to it, so what is merged is always what was checked.
func PullHeadCommitID(ctx context.Context, pr *PullRequest) (string, error) {
	return cache.GetWithContextCache(ctx, "pull_head", strconv.FormatInt(pr.ID, 10), func() (string, error) {
		if err := pr.LoadBaseRepo(ctx); err != nil {
			return "", err
		}
		return git.GetFullCommitID(ctx, pr.BaseRepo.RepoPath(), pr.GetGitRefName())
	})
}

func pullPushers(ctx context.Context, pr *PullRequest) (Pushers, error) {
	if err := pr.LoadBaseRepo(ctx); err != nil {
		return nil, err
	}
	ids := make([]int64, 0, 4)
	if err := db.GetEngine(ctx).Table("comment").Distinct("poster_id").
		Where("issue_id = ? AND type = ?", pr.IssueID, CommentTypePullRequestPush).Find(&ids); err != nil {
		return nil, err
	}
	// an AGit pull request has no head branch: its head is the poster's, read through the comments and the emails
	if pr.Flow != PullRequestFlowAGit {
		pushed, err := git_model.FindBranchPusherIDs(ctx, pr.HeadRepoID, pr.HeadBranch)
		if err != nil {
			return nil, err
		}
		ids = append(ids, pushed...)
	}

	pushers := make(Pushers, len(ids))
	for _, id := range ids {
		pushers[id] = true
	}

	// the commits are read at the head the merge is pinned to
	head, err := PullHeadCommitID(ctx, pr)
	if err != nil {
		log.Error("Unable to read the head of %-v to find its pushers: %v", pr, err)
		pushers[PusherTooMany] = true
		return pushers, nil
	}
	stdout, _, err := git.NewCommand(ctx, "log", "--format=%ae%x00%ce").AddOptionFormat("--max-count=%d", MaxPusherCommits+1).
		AddDynamicArguments(git.BranchPrefix + pr.BaseBranch + ".." + head).
		RunStdString(&git.RunOpts{Dir: pr.BaseRepo.RepoPath()})
	if err != nil {
		// e.g. the base branch of a closed pull request was deleted: nothing is counted, and the page and API still answer
		log.Error("Unable to read the commits of %-v to find its pushers: %v", pr, err)
		pushers[PusherTooMany] = true
		return pushers, nil
	}
	emails := map[string]struct{}{}
	commits := 0
	for line := range strings.Lines(stdout) {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		commits++
		for e := range strings.SplitSeq(line, "\x00") {
			if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
				emails[e] = struct{}{}
			}
		}
	}
	if commits > MaxPusherCommits {
		pushers[PusherTooMany] = true
		return pushers, nil
	}

	var lower, names []string
	for e := range emails {
		lower = append(lower, e)
		// the protected no-reply address of a user, matched like GetUserByEmail does
		if name, ok := strings.CutSuffix(e, "@"+strings.ToLower(setting.Service.NoReplyAddress)); ok {
			names = append(names, name)
		}
	}
	if len(lower) > 0 {
		var uids []int64
		if err := db.GetEngine(ctx).Table("email_address").Cols("uid").
			Where(builder.In("lower_email", lower)).And("is_activated = ?", true).Find(&uids); err != nil {
			return nil, err
		}
		for _, id := range uids {
			pushers[id] = true
		}
	}
	if len(names) > 0 {
		var uids []int64
		if err := db.GetEngine(ctx).Table("user").Cols("id").
			Where(builder.In("lower_name", names)).And("trashed_unix = 0").Find(&uids); err != nil {
			return nil, err
		}
		for _, id := range uids {
			pushers[id] = true
		}
	}
	return pushers, nil
}
