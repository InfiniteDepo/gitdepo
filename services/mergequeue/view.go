// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package mergequeue

import (
	"context"

	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	pull_model "forgejo.org/models/pull"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/timeutil"
)

// States of an entry as shown to users
const (
	StateWaiting  = "waiting"  // to be tested
	StateTesting  = "testing"  // the checks run on its test commit
	StatePassed   = "passed"   // the checks passed, it merges once the entries ahead of it did
	StateGrouping = "grouping" // the checks passed, it waits for the minimum group size or the wait time
	StateMerging  = "merging"  // its build is being pushed to the branch
)

// ViewEntry is an entry of the queue of a branch as shown to users
type ViewEntry struct {
	*pull_model.MergeQueueEntry
	Position   int // from 1
	Pull       *issues_model.PullRequest
	EnqueuedBy *user_model.User
	State      string
	// of a grouping entry: passed entries so far, the minimum group size, and when it merges at the latest
	GroupPassed, GroupMin int
	GroupUntil            timeutil.TimeStamp
}

// View returns the queue of the branch of repo in order, nil if the branch has no merge queue rule. It reads the
// stored state: a pass may change it at any time.
func View(ctx context.Context, repo *repo_model.Repository, branch string) ([]*ViewEntry, *git_model.ProtectedBranch, error) {
	rules, err := git_model.GetMatchedProtectedBranchRules(ctx, repo.ID, branch)
	if err != nil {
		return nil, nil, err
	}
	rule := git_model.MergeQueueRule(rules)
	if rule == nil {
		return nil, nil, nil //nolint:nilnil // nil rule: the branch has no merge queue
	}
	entries, err := pull_model.FindMergeQueue(ctx, repo.ID, branch)
	if err != nil {
		return nil, nil, err
	}
	p := &pass{ctx: ctx, repo: repo, rules: rules}
	view := make([]*ViewEntry, 0, len(entries))
	for _, e := range entries {
		pr, err := issues_model.GetPullRequestByID(ctx, e.PullID)
		if issues_model.IsErrPullRequestNotExist(err) {
			continue
		} else if err != nil {
			return nil, nil, err
		}
		pr.BaseRepo = repo
		if err := pr.LoadIssue(ctx); err != nil {
			return nil, nil, err
		}
		v := &ViewEntry{MergeQueueEntry: e, Position: len(view) + 1, Pull: pr, EnqueuedBy: p.poster(e), State: StateWaiting}
		if e.Status == pull_model.MergeQueueBuilding {
			v.State = StateTesting
			state, err := p.checksState(e.TempCommitID, e.StartedUnix)
			if err != nil {
				return nil, nil, err
			}
			if state.IsSuccess() {
				v.State = StatePassed
			}
		}
		if e.MergingUnix != 0 {
			v.State = StateMerging
		}
		view = append(view, v)
	}
	markGrouping(view, rule.MergeQueueConfig())
	return view, rule, nil
}

// markGrouping marks the passed entries that wait for their group, as merge decides it
func markGrouping(view []*ViewEntry, cfg git_model.MergeQueueConfig) {
	last := -1
	for i := 0; i < len(view) && i < cfg.MaxGroupSize && (view[i].State == StateTesting || view[i].State == StatePassed); i++ {
		if view[i].State == StatePassed {
			last = i
		}
	}
	if last < 0 || last+1 >= cfg.MinGroupSize || since(view[0].EnqueuedUnix) >= cfg.WaitTime {
		return
	}
	for _, v := range view[:last+1] {
		if v.State == StatePassed {
			v.State, v.GroupPassed, v.GroupMin = StateGrouping, last+1, cfg.MinGroupSize
			v.GroupUntil = view[0].EnqueuedUnix.AddDuration(cfg.WaitTime)
		}
	}
}
