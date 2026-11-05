// Copyright 2019 The Gitea Authors.
// All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"errors"
	"fmt"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/log"
	"forgejo.org/modules/structs"

	"github.com/gobwas/glob"
)

// MergeRequiredContextsCommitStatus returns a commit status state for given required contexts
func MergeRequiredContextsCommitStatus(commitStatuses []*git_model.CommitStatus, requiredContexts []string) structs.CommitStatusState {
	// matchedCount is the number of `CommitStatus.Context` that match any context of `requiredContexts`
	matchedCount := 0
	returnedStatus := structs.CommitStatusSuccess

	if len(requiredContexts) > 0 {
		requiredContextsGlob := make(map[string]glob.Glob, len(requiredContexts))
		for _, ctx := range requiredContexts {
			if gp, err := glob.Compile(ctx); err != nil {
				log.Error("glob.Compile %s failed. Error: %v", ctx, err)
			} else {
				requiredContextsGlob[ctx] = gp
			}
		}

		for _, gp := range requiredContextsGlob {
			var targetStatus structs.CommitStatusState
			for _, commitStatus := range commitStatuses {
				if gp.Match(commitStatus.Context) {
					if targetStatus == "" {
						targetStatus = commitStatus.State
					} else if commitStatus.State.NoBetterThan(targetStatus) {
						targetStatus = commitStatus.State
					}
					matchedCount++
				}
			}

			// If required rule not match any action, then it is pending
			if targetStatus == "" {
				if structs.CommitStatusPending.NoBetterThan(returnedStatus) {
					returnedStatus = structs.CommitStatusPending
				}
				break
			}

			if targetStatus.NoBetterThan(returnedStatus) {
				returnedStatus = targetStatus
			}
		}
	}

	if matchedCount == 0 && returnedStatus == structs.CommitStatusSuccess {
		status := git_model.CalcCommitStatus(commitStatuses)
		if status != nil {
			return status.State
		}
		return ""
	}

	return returnedStatus
}

// IsPullCommitStatusPass returns if all required status checks of every matching rule PASS
func IsPullCommitStatusPass(ctx context.Context, pr *issues_model.PullRequest) (bool, error) {
	rules, err := git_model.GetMatchedProtectedBranchRules(ctx, pr.BaseRepoID, pr.BaseBranch)
	if err != nil {
		return false, fmt.Errorf("GetMatchedProtectedBranchRules: %w", err)
	}
	for _, pb := range rules {
		if pass, err := isPullCommitStatusPass(ctx, pr, pb); err != nil || !pass {
			return false, err
		}
	}
	return true, nil
}

// IsPullCommitStatusFailed reports whether a required status check of pr has failed (not merely pending)
func IsPullCommitStatusFailed(ctx context.Context, pr *issues_model.PullRequest) (bool, error) {
	rules, err := git_model.GetMatchedProtectedBranchRules(ctx, pr.BaseRepoID, pr.BaseBranch)
	if err != nil {
		return false, fmt.Errorf("GetMatchedProtectedBranchRules: %w", err)
	}
	for _, pb := range rules {
		if !pb.EnableStatusCheck {
			continue
		}
		commitStatuses, err := getPullRequestCommitStatuses(ctx, pr)
		if err != nil {
			return false, err
		}
		if state := MergeRequiredContextsCommitStatus(commitStatuses, pb.StatusCheckContexts); state.IsFailure() || state.IsError() {
			return true, nil
		}
	}
	return false, nil
}

func isPullCommitStatusPass(ctx context.Context, pr *issues_model.PullRequest, pb *git_model.ProtectedBranch) (bool, error) {
	if !pb.EnableStatusCheck {
		return true, nil
	}
	commitStatuses, err := getPullRequestCommitStatuses(ctx, pr)
	if err != nil {
		return false, err
	}
	return MergeRequiredContextsCommitStatus(commitStatuses, pb.StatusCheckContexts).IsSuccess(), nil
}

// getPullRequestCommitStatuses returns the latest commit statuses of the head of the pull request
func getPullRequestCommitStatuses(ctx context.Context, pr *issues_model.PullRequest) ([]*git_model.CommitStatus, error) {
	// Ensure HeadRepo is loaded
	if err := pr.LoadHeadRepo(ctx); err != nil {
		return nil, fmt.Errorf("LoadHeadRepo: %w", err)
	}

	// check if all required status checks are successful
	headGitRepo, closer, err := gitrepo.RepositoryFromContextOrOpen(ctx, pr.HeadRepo)
	if err != nil {
		return nil, fmt.Errorf("RepositoryFromContextOrOpen: %w", err)
	}
	defer closer.Close()

	if pr.Flow == issues_model.PullRequestFlowGithub && !headGitRepo.IsBranchExist(pr.HeadBranch) {
		return nil, errors.New("head branch does not exist, can not merge")
	}
	if pr.Flow == issues_model.PullRequestFlowAGit && !headGitRepo.IsReferenceExist(pr.GetGitRefName()) {
		return nil, errors.New("head branch does not exist, can not merge")
	}

	// the head the merge is pinned to, so the statuses checked are those of the commit that is merged
	sha, err := issues_model.PullHeadCommitID(ctx, pr)
	if err != nil {
		return nil, err
	}

	commitStatuses, _, err := git_model.GetLatestCommitStatus(ctx, pr.BaseRepo.ID, sha, db.ListOptionsAll)
	if err != nil {
		return nil, fmt.Errorf("GetLatestCommitStatus: %w", err)
	}
	return commitStatuses, nil
}
