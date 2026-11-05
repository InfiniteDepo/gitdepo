// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package issue

import (
	"context"
	"fmt"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	org_model "forgejo.org/models/organization"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/log"
)

// DefaultReviewerRequests asks the users and teams of the approval rules that request reviews for a review of the pull
// request, and returns what to notify once the caller's transaction is committed. It looks at the rules of every
// protected branch rule matching the base branch, whose source branch pattern matches the head branch and that apply to
// the changed files. With oldHead (the head commit before a push) only a rule with path patterns that did not apply to
// the files at oldHead is used. The requests are advisory: nobody who is the author, can't sign in, is blocked by the
// organization's two-factor requirement, can't read pull requests or already has a review or request is asked, and a
// failure for one reviewer is logged and doesn't stop the others. A user or team whose request on this pull request
// someone removed is never asked again.
func DefaultReviewerRequests(ctx context.Context, issue *issues_model.Issue, pr *issues_model.PullRequest, oldHead string) ([]*ReviewRequestNotifier, error) {
	if issue.IsClosed || pr.HasMerged || pr.IsWorkInProgress(ctx) {
		return nil, nil
	}
	if err := pr.LoadBaseRepo(ctx); err != nil {
		return nil, err
	}
	matched, err := git_model.GetMatchedProtectedBranchRules(ctx, pr.BaseRepoID, pr.BaseBranch)
	if err != nil {
		return nil, err
	}
	var rules []*git_model.ApprovalRule
	for _, pb := range matched {
		approvalRules, err := git_model.GetApprovalRules(ctx, pb.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range approvalRules {
			// the source branch is chosen by the author: it only limits requests, never what a rule requires
			if r.RequestReviews && r.MatchesSourceBranch(pr.HeadBranch) {
				rules = append(rules, r)
			}
		}
	}
	if len(rules) == 0 {
		return nil, nil
	}

	var files, oldFiles []string
	if files, oldFiles, err = changedFiles(ctx, pr, oldHead); err != nil {
		return nil, err
	}
	// the value says whether a rule with a count asks: only then the request is official and can block
	userIDs, teamIDs := map[int64]bool{}, map[int64]bool{}
	for _, r := range rules {
		if !newlyApplies(r, files, oldFiles, oldHead != "") {
			continue
		}
		for _, id := range r.UserIDs {
			userIDs[id] = userIDs[id] || r.RequiredCount > 0
		}
		for _, id := range r.TeamIDs {
			teamIDs[id] = teamIDs[id] || r.RequiredCount > 0
		}
	}
	// a person removed these requests: they are never made again on this pull request
	var removed []*issues_model.Comment
	if err := db.GetEngine(ctx).Cols("assignee_id", "assignee_team_id").Where("issue_id = ? AND type = ? AND removed_assignee = ?",
		issue.ID, issues_model.CommentTypeReviewRequest, true).Find(&removed); err != nil {
		return nil, err
	}
	for _, c := range removed {
		delete(userIDs, c.AssigneeID)
		delete(teamIDs, c.AssigneeTeamID)
	}
	if len(userIDs)+len(teamIDs) == 0 {
		return nil, nil
	}

	if err := issue.LoadPoster(ctx); err != nil {
		return nil, err
	}
	if err := issue.LoadRepo(ctx); err != nil {
		return nil, err
	}
	if err := pr.BaseRepo.LoadOwner(ctx); err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(userIDs))
	for id := range userIDs {
		ids = append(ids, id)
	}
	users, err := user_model.GetUserByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}

	var notifiers []*ReviewRequestNotifier
	for _, u := range users {
		// a check that fails is no permission
		if ok, err := mayRequestReview(ctx, issue, pr, u); err != nil {
			log.Error("%-v default reviewer %d: %v", pr, u.ID, err)
			continue
		} else if !ok {
			continue
		}
		comment, err := requestUnofficially(ctx, userIDs[u.ID], func(ctx context.Context) (*issues_model.Comment, error) {
			return issues_model.AddReviewRequest(ctx, issue, u, issue.Poster)
		})
		if err != nil {
			log.Error("%-v AddReviewRequest of %d: %v", pr, u.ID, err)
		} else if comment != nil {
			notifiers = append(notifiers, &ReviewRequestNotifier{Comment: comment, IsAdd: true, Reviewer: u})
		}
	}
	for id, official := range teamIDs {
		team, err := org_model.GetTeamByID(ctx, id)
		if err != nil {
			log.Error("%-v default reviewer team %d: %v", pr, id, err)
			continue
		}
		// teams only exist in organizations; a team must have the repository and its pull requests, or its members would learn of a pull request they can't see
		if team.OrgID != pr.BaseRepo.OwnerID || !org_model.HasTeamRepo(ctx, team.OrgID, team.ID, pr.BaseRepoID) ||
			team.UnitAccessMode(ctx, unit.TypePullRequests) < perm.AccessModeRead {
			continue
		}
		comment, err := requestUnofficially(ctx, official, func(ctx context.Context) (*issues_model.Comment, error) {
			return issues_model.AddTeamReviewRequest(ctx, issue, team, issue.Poster)
		})
		if err != nil {
			log.Error("%-v AddTeamReviewRequest of %d: %v", pr, id, err)
		} else if comment != nil {
			notifiers = append(notifiers, &ReviewRequestNotifier{Comment: comment, IsAdd: true, ReviewTeam: team})
		}
	}
	return notifiers, nil
}

// newlyApplies returns whether the rule asks now: when the pull request opens or is retargeted (push false) if its
// paths match the files, and after a push only if they start to match. Paths that can't be matched
// (git_model.ApprovalRule.MatchesPaths) ask nobody: requests are advisory.
//
//	rule with paths:    matches files && !matches oldFiles
//	rule without paths: files changed now && no files changed at the old head (a pull request that opened empty)
func newlyApplies(r *git_model.ApprovalRule, files, oldFiles []string, push bool) bool {
	if push && r.PathPatterns == "" {
		return len(files) > 0 && len(oldFiles) == 0
	}
	matches, decided := r.MatchesPaths(files)
	if !matches || !decided || !push {
		return matches && decided
	}
	oldMatches, oldDecided := r.MatchesPaths(oldFiles)
	return oldDecided && !oldMatches
}

// requestUnofficially adds a review request with add and, unless official, makes it advisory, in one transaction.
// The comment is nil if nothing was requested or the transaction failed.
func requestUnofficially(ctx context.Context, official bool, add func(context.Context) (*issues_model.Comment, error)) (comment *issues_model.Comment, err error) {
	err = db.WithTx(ctx, func(ctx context.Context) (err error) {
		if comment, err = add(ctx); err != nil || comment == nil || official {
			return err
		}
		return issues_model.MarkReviewRequestAdvisory(ctx, comment.ReviewID)
	})
	if err != nil {
		return nil, err
	}
	return comment, nil
}

// mayRequestReview returns true if u can be asked for a review of the pull request.
func mayRequestReview(ctx context.Context, issue *issues_model.Issue, pr *issues_model.PullRequest, u *user_model.User) (bool, error) {
	// token identities have negative IDs
	if u.ID <= 0 || u.IsAccessTokenBot() || u.ID == issue.PosterID || !u.IsActive || u.ProhibitLogin {
		return false, nil
	}
	if blocked, err := u.TwoFactorBlocked(ctx, pr.BaseRepo.Owner); blocked || err != nil {
		return false, err
	}
	perm, err := access_model.GetUserRepoPermission(ctx, issue.Repo, u)
	if err != nil || !perm.CanRead(unit.TypePullRequests) {
		return false, err
	}
	_, err = issues_model.GetReviewByIssueIDUserIDAndTypes(ctx, issue.ID, u.ID, []issues_model.ReviewType{
		issues_model.ReviewTypeApprove, issues_model.ReviewTypeReject, issues_model.ReviewTypeComment, issues_model.ReviewTypeRequest,
	})
	if issues_model.IsErrReviewNotExist(err) {
		return true, nil
	}
	return false, err
}

// changedFiles returns the files the pull request changes since the merge base and, if oldHead is set, the files it changed at oldHead.
func changedFiles(ctx context.Context, pr *issues_model.PullRequest, oldHead string) (files, oldFiles []string, err error) {
	repo, err := gitrepo.OpenRepository(ctx, pr.BaseRepo)
	if err != nil {
		return nil, nil, err
	}
	defer repo.Close()
	mergeBase, err := repo.GetMergeBaseSimple(git.BranchPrefix+pr.BaseBranch, pr.GetGitRefName())
	if err != nil {
		return nil, nil, err
	}
	if files, err = repo.GetFilesChangedBetween(mergeBase, pr.GetGitRefName()); err != nil || oldHead == "" {
		return files, nil, err
	}
	if oldFiles, err = repo.GetFilesChangedBetween(mergeBase, oldHead); err != nil {
		return nil, nil, fmt.Errorf("files at %s: %w", oldHead, err)
	}
	return files, oldFiles, nil
}
