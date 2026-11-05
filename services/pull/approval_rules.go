// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"context"
	"fmt"
	"slices"

	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	issue_service "forgejo.org/services/issue"
)

// ApprovalRuleStatus is the state of one approval rule of a pull request.
type ApprovalRuleStatus struct {
	Rule      *git_model.ApprovalRule // nil for the RequiredApprovals of the protected branch rule
	Name      string
	Required  int64
	Granted   int64
	Approvers []*user_model.User
	// UncoveredFiles counts changed files with code owners that none of their owners approved (RequireCodeOwners)
	UncoveredFiles int
	Satisfied      bool
}

// Reason says why the rule is not satisfied.
func (s *ApprovalRuleStatus) Reason() string {
	if s.Granted < s.Required {
		return fmt.Sprintf("Approval rule %q needs %d approval(s), has %d", s.Name, s.Required, s.Granted)
	}
	return fmt.Sprintf("Approval rule %q: %d changed file(s) are not approved by a code owner", s.Name, s.UncoveredFiles)
}

// ApprovalRuleStatuses returns the status of the RequiredApprovals of the protected branch rule, if set,
// followed by the status of its applicable approval rules.
func ApprovalRuleStatuses(ctx context.Context, pb *git_model.ProtectedBranch, pr *issues_model.PullRequest) ([]*ApprovalRuleStatus, error) {
	statuses, err := EvaluateApprovalRules(ctx, pb, pr)
	if err != nil || pb.RequiredApprovals == 0 {
		return statuses, err
	}
	granted := issues_model.GetGrantedApprovalsCount(ctx, pb, pr)
	name := "Default"
	if pb.OrgID != 0 {
		name = "Default (organization)"
	}
	def := &ApprovalRuleStatus{Name: name, Required: pb.RequiredApprovals, Granted: granted, Satisfied: granted >= pb.RequiredApprovals}
	return append([]*ApprovalRuleStatus{def}, statuses...), nil
}

// EvaluateApprovalRules returns the status of every approval rule of the protected branch rule that applies to the pull request.
// The RequiredApprovals of the protected branch rule are not part of it, HasEnoughApprovals checks them.
func EvaluateApprovalRules(ctx context.Context, pb *git_model.ProtectedBranch, pr *issues_model.PullRequest) ([]*ApprovalRuleStatus, error) {
	rules, err := git_model.GetApprovalRules(ctx, pb.ID)
	// a rule that only requests reviews (count 0) requires nothing and is never applicable
	rules = slices.DeleteFunc(rules, func(r *git_model.ApprovalRule) bool { return r.RequiredCount == 0 })
	if err != nil || len(rules) == 0 {
		return nil, err
	}
	if err := pr.LoadIssue(ctx); err != nil {
		return nil, err
	}
	if err := pr.LoadBaseRepo(ctx); err != nil {
		return nil, err
	}
	approvers, err := issues_model.ValidReviewers(ctx, pb, pr, issues_model.ReviewTypeApprove)
	if err != nil {
		return nil, err
	}

	var files []string
	var codeOwners []*issues_model.CodeOwnerRule
	needFiles := slices.ContainsFunc(rules, func(r *git_model.ApprovalRule) bool { return r.PathPatterns != "" || r.RequireCodeOwners })
	if needFiles {
		needOwners := slices.ContainsFunc(rules, func(r *git_model.ApprovalRule) bool { return r.RequireCodeOwners })
		if files, codeOwners, err = loadPullGitInfo(ctx, pr, needOwners); err != nil {
			return nil, err
		}
	}

	statuses := make([]*ApprovalRuleStatus, 0, len(rules))
	for _, rule := range rules {
		if !rule.AppliesTo(files) {
			continue
		}
		s := &ApprovalRuleStatus{Rule: rule, Name: rule.Name, Required: rule.RequiredCount}
		for _, u := range approvers {
			// without listed approvers (code owner rules only) any valid approver is eligible
			eligible := !rule.HasApprovers()
			if !eligible {
				if eligible, err = rule.IsApprover(ctx, u.ID); err != nil {
					return nil, err
				}
			}
			if eligible {
				s.Approvers = append(s.Approvers, u)
			}
		}
		s.Granted = int64(len(s.Approvers))
		s.Satisfied = s.Granted >= s.Required
		if rule.RequireCodeOwners {
			if s.UncoveredFiles, err = countUncoveredFiles(ctx, rule, files, codeOwners, s.Approvers); err != nil {
				return nil, err
			}
			s.Satisfied = s.Satisfied && s.UncoveredFiles == 0
		}
		statuses = append(statuses, s)
	}
	return statuses, nil
}

// loadPullGitInfo returns the files the pull request changes since the merge base and, if wanted, the CODEOWNERS
// rules of the target branch. The head of the pull request must never decide who the owners are, and a CODEOWNERS
// file that can't be read in full fails the check.
func loadPullGitInfo(ctx context.Context, pr *issues_model.PullRequest, withOwners bool) (files []string, owners []*issues_model.CodeOwnerRule, err error) {
	gitRepo, err := gitrepo.OpenRepository(ctx, pr.BaseRepo)
	if err != nil {
		return nil, nil, err
	}
	defer gitRepo.Close()

	mergeBase, err := gitRepo.GetMergeBaseSimple(git.BranchPrefix+pr.BaseBranch, pr.GetGitRefName())
	if err != nil {
		return nil, nil, err
	}
	if files, err = gitRepo.GetFilesChangedBetween(mergeBase, pr.GetGitRefName()); err != nil || !withOwners {
		return files, nil, err
	}

	commit, err := gitRepo.GetBranchCommit(pr.BaseBranch)
	if err != nil {
		return nil, nil, err
	}
	owners, truncated, err := issue_service.LoadCodeOwnerRules(ctx, commit)
	if err == nil && truncated {
		err = fmt.Errorf("CODEOWNERS of %s is too big", pr.BaseBranch)
	}
	return files, owners, err
}

// countUncoveredFiles counts the changed files in the scope of the rule where a matching CODEOWNERS line has no approving owner.
// Every matching line is required, so a catch-all line can't cover a file that a more specific line gives to other owners.
func countUncoveredFiles(ctx context.Context, rule *git_model.ApprovalRule, files []string, codeOwners []*issues_model.CodeOwnerRule, approvers []*user_model.User) (int, error) {
	uncovered := 0
	covered := map[*issues_model.CodeOwnerRule]bool{} // lines are shared by many files
	for _, f := range files {
		if !rule.AppliesTo([]string{f}) {
			continue
		}
		for _, line := range issue_service.CodeOwnerRulesOfFile(codeOwners, f) {
			ok, seen := covered[line]
			if !seen {
				var err error
				if ok, err = lineApproved(ctx, line, approvers); err != nil {
					return 0, err
				}
				covered[line] = ok
			}
			if !ok {
				uncovered++
				break
			}
		}
	}
	return uncovered, nil
}

// lineApproved returns true if one of the approvers is an owner named on the line, directly or through a team.
func lineApproved(ctx context.Context, line *issues_model.CodeOwnerRule, approvers []*user_model.User) (bool, error) {
	teamIDs := make([]int64, len(line.Teams))
	for i, t := range line.Teams {
		teamIDs[i] = t.ID
	}
	for _, a := range approvers {
		if slices.ContainsFunc(line.Users, func(u *user_model.User) bool { return u.ID == a.ID }) {
			return true, nil
		}
		if len(teamIDs) > 0 {
			if ok, err := organization.IsUserInTeams(ctx, a.ID, teamIDs); err != nil || ok {
				return ok, err
			}
		}
	}
	return false, nil
}

// ApprovalRulesFromAPI resolves the user and team names of the rules. Unknown names return
// user_model.ErrUserNotExist or organization.ErrTeamNotExist.
func ApprovalRulesFromAPI(ctx context.Context, owner *user_model.User, apiRules []*api.ApprovalRule) ([]*git_model.ApprovalRule, error) {
	rules := make([]*git_model.ApprovalRule, 0, len(apiRules))
	for _, r := range apiRules {
		if r == nil {
			return nil, util.NewInvalidArgumentErrorf("approval rule is null")
		}
		userIDs, err := user_model.GetUserIDsByNames(ctx, r.Usernames, false)
		if err != nil {
			return nil, err
		}
		var teamIDs []int64
		if len(r.Teams) > 0 {
			if !owner.IsOrganization() {
				return nil, util.NewInvalidArgumentErrorf("teams only exist in repositories of organizations")
			}
			if teamIDs, err = organization.GetTeamIDsByNames(ctx, owner.ID, r.Teams, false); err != nil {
				return nil, err
			}
		}
		rules = append(rules, &git_model.ApprovalRule{
			Name: r.Name, RequiredCount: r.RequiredCount, UserIDs: userIDs, TeamIDs: teamIDs,
			PathPatterns: r.PathPatterns, RequireCodeOwners: r.RequireCodeOwners,
			RequestReviews: r.RequestReviews, SourceBranchPattern: r.SourceBranchPattern,
		})
	}
	return rules, nil
}
