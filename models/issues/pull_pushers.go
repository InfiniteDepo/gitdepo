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
	r, err := pullPushersAtHead(ctx, pr)
	return r.pushers, err
}

// PullPushersHead returns the head commit the pushers of PullPushers were read at (the pull ref, read once and kept
// with them), "" when it can't be read. A merge pins itself to it, so it refuses a head that moved after the check.
func PullPushersHead(ctx context.Context, pr *PullRequest) (string, error) {
	r, err := pullPushersAtHead(ctx, pr)
	return r.head, err
}

type pushersAtHead struct {
	pushers Pushers
	head    string
}

func pullPushersAtHead(ctx context.Context, pr *PullRequest) (pushersAtHead, error) {
	return cache.GetWithContextCache(ctx, "pull_pushers", strconv.FormatInt(pr.ID, 10), func() (pushersAtHead, error) {
		return pullPushers(ctx, pr)
	})
}

func pullPushers(ctx context.Context, pr *PullRequest) (pushersAtHead, error) {
	if err := pr.LoadBaseRepo(ctx); err != nil {
		return pushersAtHead{}, err
	}
	ids := make([]int64, 0, 4)
	if err := db.GetEngine(ctx).Table("comment").Distinct("poster_id").
		Where("issue_id = ? AND type = ?", pr.IssueID, CommentTypePullRequestPush).Find(&ids); err != nil {
		return pushersAtHead{}, err
	}
	// an AGit pull request has no head branch: its head is the poster's, read through the comments and the emails
	if pr.Flow != PullRequestFlowAGit {
		pushed, err := git_model.FindBranchPusherIDs(ctx, pr.HeadRepoID, pr.HeadBranch)
		if err != nil {
			return pushersAtHead{}, err
		}
		ids = append(ids, pushed...)
	}

	pushers := make(Pushers, len(ids))
	for _, id := range ids {
		pushers[id] = true
	}

	// the head is read once from the pull ref of the base repository, which holds it for every kind of pull request;
	// the commits are read at that commit, and the merge is pinned to it
	head, err := git.GetFullCommitID(ctx, pr.BaseRepo.RepoPath(), pr.GetGitRefName())
	if err != nil {
		log.Error("Unable to read the head of %-v to find its pushers: %v", pr, err)
		pushers[PusherTooMany] = true
		return pushersAtHead{pushers: pushers}, nil
	}
	stdout, _, err := git.NewCommand(ctx, "log", "--format=%ae%x00%ce").AddOptionFormat("--max-count=%d", MaxPusherCommits+1).
		AddDynamicArguments(git.BranchPrefix + pr.BaseBranch + ".." + head).
		RunStdString(&git.RunOpts{Dir: pr.BaseRepo.RepoPath()})
	if err != nil {
		// e.g. the base branch of a closed pull request was deleted: nothing is counted, and the page and API still answer
		log.Error("Unable to read the commits of %-v to find its pushers: %v", pr, err)
		pushers[PusherTooMany] = true
		return pushersAtHead{pushers, head}, nil
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
		return pushersAtHead{pushers, head}, nil
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
			return pushersAtHead{}, err
		}
		for _, id := range uids {
			pushers[id] = true
		}
	}
	if len(names) > 0 {
		var uids []int64
		if err := db.GetEngine(ctx).Table("user").Cols("id").
			Where(builder.In("lower_name", names)).And("trashed_unix = 0").Find(&uids); err != nil {
			return pushersAtHead{}, err
		}
		for _, id := range uids {
			pushers[id] = true
		}
	}
	return pushersAtHead{pushers, head}, nil
}
