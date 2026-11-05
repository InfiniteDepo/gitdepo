// Copyright 2024 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package issue

import (
	"context"
	"fmt"

	issues_model "forgejo.org/models/issues"
	org_model "forgejo.org/models/organization"
	access_model "forgejo.org/models/perm/access"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
)

type ReviewRequestNotifier struct {
	Comment    *issues_model.Comment
	IsAdd      bool
	Reviewer   *user_model.User
	ReviewTeam *org_model.Team
}

// LoadCodeOwnerRules reads the CODEOWNERS file of the commit. truncated is true when the file is too big and was only read in part.
func LoadCodeOwnerRules(ctx context.Context, commit *git.Commit) (owners *issues_model.CodeOwners, truncated bool, err error) {
	for _, file := range []string{"CODEOWNERS", "docs/CODEOWNERS", ".gitea/CODEOWNERS", ".forgejo/CODEOWNERS"} {
		blob, err := commit.GetBlobByPath(file)
		if git.IsErrNotExist(err) {
			continue
		} else if err != nil {
			return nil, false, err
		}
		rc, size, err := blob.NewTruncatedReader(setting.UI.MaxDisplayFileSize)
		if err != nil {
			return nil, false, err
		}
		truncated = size > setting.UI.MaxDisplayFileSize
		owners = issues_model.ParseCodeOwners(ctx, rc, truncated)
		owners.File = file
		return owners, truncated, nil
	}
	return &issues_model.CodeOwners{}, false, nil
}

// CodeOwnerRulesOfFile returns the CODEOWNERS lines that apply to the file, the way PullRequestCodeOwnersReview matches them.
func CodeOwnerRulesOfFile(rules []*issues_model.CodeOwnerRule, file string) (matching []*issues_model.CodeOwnerRule) {
	for _, rule := range rules {
		if rule.Rule.MatchString(file) != rule.Negative {
			matching = append(matching, rule)
		}
	}
	return matching
}

func PullRequestCodeOwnersReview(ctx context.Context, issue *issues_model.Issue, pr *issues_model.PullRequest) ([]*ReviewRequestNotifier, error) {
	if pr.IsWorkInProgress(ctx) {
		return nil, nil
	}

	if err := pr.LoadHeadRepo(ctx); err != nil {
		return nil, err
	}

	if err := pr.LoadBaseRepo(ctx); err != nil {
		return nil, err
	}

	if pr.BaseRepo.IsFork {
		return nil, nil
	}

	repo, err := gitrepo.OpenRepository(ctx, pr.BaseRepo)
	if err != nil {
		return nil, err
	}
	defer repo.Close()

	commit, err := repo.GetBranchCommit(pr.BaseRepo.DefaultBranch)
	if err != nil {
		return nil, err
	}

	owners, _, _ := LoadCodeOwnerRules(ctx, commit)
	var rules []*issues_model.CodeOwnerRule
	if owners != nil {
		rules = owners.Rules
	}

	mergeBase, err := repo.GetMergeBaseSimple(git.BranchPrefix+pr.BaseBranch, pr.GetGitRefName())
	if err != nil {
		return nil, err
	}

	// https://github.com/go-gitea/gitea/issues/29763, we need to get the files changed
	// between the merge base and the head commit but not the base branch and the head commit
	changedFiles, err := repo.GetFilesChangedBetween(mergeBase, pr.GetGitRefName())
	if err != nil {
		return nil, err
	}

	uniqUsers := make(map[int64]*user_model.User)
	uniqTeams := make(map[string]*org_model.Team)
	for _, rule := range rules {
		for _, f := range changedFiles {
			if (rule.Rule.MatchString(f) && !rule.Negative) || (!rule.Rule.MatchString(f) && rule.Negative) {
				for _, u := range rule.Users {
					uniqUsers[u.ID] = u
				}
				for _, t := range rule.Teams {
					uniqTeams[fmt.Sprintf("%d/%d", t.OrgID, t.ID)] = t
				}
			}
		}
	}

	notifiers := make([]*ReviewRequestNotifier, 0, len(uniqUsers)+len(uniqTeams))

	if err := issue.LoadPoster(ctx); err != nil {
		return nil, err
	}

	for _, u := range uniqUsers {
		permission, err := access_model.GetUserRepoPermission(ctx, issue.Repo, u)
		if err != nil {
			return nil, fmt.Errorf("GetUserRepoPermission: %w", err)
		}
		if u.ID != issue.Poster.ID && permission.CanRead(unit.TypePullRequests) {
			comment, err := issues_model.AddReviewRequest(ctx, issue, u, issue.Poster)
			if err != nil {
				log.Warn("Failed add assignee user: %s to PR review: %s#%d, error: %s", u.Name, pr.BaseRepo.Name, pr.ID, err)
				return nil, err
			}
			notifiers = append(notifiers, &ReviewRequestNotifier{
				Comment:  comment,
				IsAdd:    true,
				Reviewer: u,
			})
		}
	}
	for _, t := range uniqTeams {
		comment, err := issues_model.AddTeamReviewRequest(ctx, issue, t, issue.Poster)
		if err != nil {
			log.Warn("Failed add assignee team: %s to PR review: %s#%d, error: %s", t.Name, pr.BaseRepo.Name, pr.ID, err)
			return nil, err
		}
		notifiers = append(notifiers, &ReviewRequestNotifier{
			Comment:    comment,
			IsAdd:      true,
			ReviewTeam: t,
		})
	}

	return notifiers, nil
}
