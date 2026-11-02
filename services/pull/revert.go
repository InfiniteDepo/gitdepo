// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"fmt"
	"regexp"

	issues_model "forgejo.org/models/issues"
	"forgejo.org/modules/git"
)

var revertBranchSuffixPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// GetRevertBase returns the commit the base branch pointed to before pr was merged, so that
// reverting pr means bringing back the changes between MergedCommitID and it.
// It returns "" when that commit can't be determined safely; the PR is then not revertable.
// It only looks at the PR row and commit parents, so it is cheap enough for page views.
func GetRevertBase(gitRepo *git.Repository, pr *issues_model.PullRequest) (string, error) {
	if !pr.HasMerged || pr.MergedCommitID == "" {
		return "", nil
	}
	// Set when Forgejo merged the PR: the old tip of the base branch.
	if pr.MergedBaseCommitID != "" {
		return pr.MergedBaseCommitID, nil
	}

	// Older, migrated and manually merged PRs: only trust what the commit graph proves.
	merged, err := gitRepo.GetCommit(pr.MergedCommitID)
	if err != nil {
		if git.IsErrNotExist(err) {
			return "", nil
		}
		return "", err
	}
	head, err := gitRepo.GetRefCommitID(pr.GetGitRefName())
	if err != nil {
		if git.IsErrNotExist(err) {
			return "", nil
		}
		return "", err
	}
	mergedID := merged.ID.String()

	// Fast-forwarded: the PR's commits are MergeBase..head.
	if mergedID == head {
		return pr.MergeBase, nil
	}
	// A merge commit of the PR head: revert against the first parent.
	if merged.ParentCount() >= 2 {
		if second, _ := merged.ParentID(1); second != nil && second.String() == head {
			first, _ := merged.ParentID(0)
			return first.String(), nil
		}
		return "", nil
	}
	// A single-commit PR squashed or rebased onto the base branch.
	if merged.ParentCount() == 1 && pr.MergeBase != "" {
		count, err := gitRepo.CommitsCountBetween(pr.MergeBase, head)
		if err != nil {
			return "", err
		}
		if count == 1 {
			first, _ := merged.ParentID(0)
			return first.String(), nil
		}
	}
	return "", nil
}

// RevertBranchName is the branch a revert of pr is pushed to.
func RevertBranchName(pr *issues_model.PullRequest) string {
	name := fmt.Sprintf("revert-%d", pr.Index)
	if suffixed := name + "-" + pr.HeadBranch; revertBranchSuffixPattern.MatchString(pr.HeadBranch) && git.IsValidRefPattern(suffixed) {
		return suffixed
	}
	return name
}

// RevertInstructions returns the git commands that revert pr locally, for when the revert conflicts.
func RevertInstructions(gitRepo *git.Repository, pr *issues_model.PullRequest, base string) string {
	cmd := fmt.Sprintf("git revert --no-commit %s..%s && git commit", base, pr.MergedCommitID)
	if merged, err := gitRepo.GetCommit(pr.MergedCommitID); err == nil {
		if first, err := merged.ParentID(0); err == nil && first.String() == base {
			if merged.ParentCount() >= 2 {
				cmd = "git revert -m 1 " + pr.MergedCommitID
			} else {
				cmd = "git revert " + pr.MergedCommitID
			}
		}
	}
	return fmt.Sprintf("git fetch origin\ngit switch -c %s origin/%s\n%s", RevertBranchName(pr), pr.BaseBranch, cmd)
}
