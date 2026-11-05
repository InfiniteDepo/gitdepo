// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"context"
	"fmt"
	"maps"
	"slices"

	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	"forgejo.org/models/unit"
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
	// Shortfalls are the CODEOWNERS sections that need more approving owners than they have (RequireCodeOwners)
	Shortfalls []*SectionShortfall
	// CodeOwnersErrorLine is the line of a malformed CODEOWNERS section header, which fails every code owner rule
	CodeOwnersErrorLine int
	Satisfied           bool
}

// SectionShortfall is a CODEOWNERS section with fewer approving owners than it needs.
type SectionShortfall struct {
	Name     string
	Required int
	Granted  int
	Eligible int // people who can approve; below Required, the section can't be satisfied
}

// Reason says why the rule is not satisfied.
func (s *ApprovalRuleStatus) Reason() string {
	if s.CodeOwnersErrorLine != 0 {
		return fmt.Sprintf("Approval rule %q: CODEOWNERS has an error on line %d", s.Name, s.CodeOwnersErrorLine)
	}
	if s.Granted < s.Required {
		return fmt.Sprintf("Approval rule %q needs %d approval(s), has %d", s.Name, s.Required, s.Granted)
	}
	if len(s.Shortfalls) > 0 {
		return fmt.Sprintf("Approval rule %q: %s", s.Name, s.Shortfalls[0].String())
	}
	return fmt.Sprintf("Approval rule %q: %d changed file(s) are not approved by a code owner", s.Name, s.UncoveredFiles)
}

func (f *SectionShortfall) String() string {
	if f.Eligible < f.Required {
		return fmt.Sprintf("CODEOWNERS section %q needs %d approvals, only %d people can approve", f.Name, f.Required, f.Eligible)
	}
	return fmt.Sprintf("CODEOWNERS section %q needs %d approvals, has %d", f.Name, f.Required, f.Granted)
}

// PusherApprovers returns the users whose approval does not count under pb because they pushed to the pull
// request. It is empty unless pb ignores pusher approvals.
func PusherApprovers(ctx context.Context, pb *git_model.ProtectedBranch, pr *issues_model.PullRequest) ([]*user_model.User, error) {
	if !pb.IgnorePusherApprovals {
		return nil, nil
	}
	if err := pr.LoadIssue(ctx); err != nil {
		return nil, err
	}
	pushers, err := issues_model.PullPushers(ctx, pr)
	if err != nil {
		return nil, err
	}
	// every valid approver, as if the rule counted pushers
	approvers, err := issues_model.ValidReviewers(ctx, &git_model.ProtectedBranch{}, pr, issues_model.ReviewTypeApprove)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(approvers, func(u *user_model.User) bool { return !pushers[u.ID] }), nil
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
	var codeOwners *issues_model.CodeOwners
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
			if codeOwners.ErrorLine != 0 {
				// the file can't be trusted: no owner requirement is met
				s.CodeOwnersErrorLine = codeOwners.ErrorLine
				s.Satisfied = false
			} else {
				if s.UncoveredFiles, s.Shortfalls, err = countUncoveredFiles(ctx, pb, pr, rule, files, codeOwners.Rules, s.Approvers); err != nil {
					return nil, err
				}
				s.Satisfied = s.Satisfied && s.UncoveredFiles == 0
			}
		}
		statuses = append(statuses, s)
	}
	return statuses, nil
}

// loadPullGitInfo returns the files the pull request changes since the merge base and, if wanted, the CODEOWNERS
// rules of the target branch. The head of the pull request must never decide who the owners are, and a CODEOWNERS
// file that can't be read in full fails the check.
func loadPullGitInfo(ctx context.Context, pr *issues_model.PullRequest, withOwners bool) (files []string, owners *issues_model.CodeOwners, err error) {
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

// countUncoveredFiles counts the changed files in the scope of the rule where a section of CODEOWNERS is not met:
// every matching line of a section needs an approving owner, so a catch-all line can't cover a file that a more
// specific line gives to other owners, and the distinct approving owners over the matching lines of the section must
// reach its number of approvals. Optional sections never block.
func countUncoveredFiles(ctx context.Context, pb *git_model.ProtectedBranch, pr *issues_model.PullRequest, rule *git_model.ApprovalRule, files []string, codeOwners []*issues_model.CodeOwnerRule, approvers []*user_model.User) (int, []*SectionShortfall, error) {
	uncovered := 0
	var shortfalls []*SectionShortfall
	reported := map[*issues_model.CodeOwnerSection]bool{}
	byLine := map[*issues_model.CodeOwnerRule]map[int64]bool{} // lines are shared by many files
	for _, f := range files {
		if !rule.AppliesTo([]string{f}) {
			continue
		}
		var sections []*issues_model.CodeOwnerSection // in the order of the file
		lines := map[*issues_model.CodeOwnerSection][]*issues_model.CodeOwnerRule{}
		for _, line := range issue_service.CodeOwnerRulesOfFile(codeOwners, f) {
			if lines[line.Section] == nil {
				sections = append(sections, line.Section)
			}
			lines[line.Section] = append(lines[line.Section], line)
		}
		covered := true
		for _, section := range sections {
			required := 1
			if section != nil {
				if section.Optional {
					continue
				}
				required = section.Required
			}
			owners := map[int64]bool{}
			for _, line := range lines[section] {
				ids, seen := byLine[line]
				if !seen {
					var err error
					if ids, err = lineApprovers(ctx, line, approvers); err != nil {
						return 0, nil, err
					}
					byLine[line] = ids
				}
				if len(ids) == 0 {
					covered = false
				}
				maps.Copy(owners, ids)
			}
			if len(owners) >= required {
				continue
			}
			covered = false
			if section != nil && section.Name != "" && !reported[section] {
				reported[section] = true
				eligible, err := eligibleOwners(ctx, pb, pr, rule, lines[section])
				if err != nil {
					return 0, nil, err
				}
				shortfalls = append(shortfalls, &SectionShortfall{Name: section.Name, Required: required, Granted: len(owners), Eligible: eligible})
			}
		}
		if !covered {
			uncovered++
		}
	}
	return uncovered, shortfalls, nil
}

// lineApprovers returns the IDs of the approvers who are owners named on the line, directly or through a team.
func lineApprovers(ctx context.Context, line *issues_model.CodeOwnerRule, approvers []*user_model.User) (map[int64]bool, error) {
	teamIDs := make([]int64, len(line.Teams))
	for i, t := range line.Teams {
		teamIDs[i] = t.ID
	}
	ids := map[int64]bool{}
	for _, a := range approvers {
		if slices.ContainsFunc(line.Users, func(u *user_model.User) bool { return u.ID == a.ID }) {
			ids[a.ID] = true
		} else if len(teamIDs) > 0 {
			if ok, err := organization.IsUserInTeams(ctx, a.ID, teamIDs); err != nil {
				return nil, err
			} else if ok {
				ids[a.ID] = true
			}
		}
	}
	return ids, nil
}

// eligibleOwners counts the people named on the lines who could approve under the rule: they can write the code, are
// no author of the pull request and, where the protected branch ignores them, no pusher. It only explains a section
// that is short of approvals, so a number above it can never be met.
func eligibleOwners(ctx context.Context, pb *git_model.ProtectedBranch, pr *issues_model.PullRequest, rule *git_model.ApprovalRule, lines []*issues_model.CodeOwnerRule) (int, error) {
	var pushers map[int64]bool
	if pb.IgnorePusherApprovals {
		var err error
		if pushers, err = issues_model.PullPushers(ctx, pr); err != nil {
			return 0, err
		}
	}
	candidates := map[int64]*user_model.User{}
	for _, line := range lines {
		for _, u := range line.Users {
			candidates[u.ID] = u
		}
		for _, t := range line.Teams {
			members, err := organization.GetTeamMembers(ctx, &organization.SearchMembersOptions{TeamID: t.ID})
			if err != nil {
				return 0, err
			}
			for _, u := range members {
				candidates[u.ID] = u
			}
		}
	}
	eligible := 0
	for _, u := range candidates {
		if u.ID == pr.Issue.PosterID || pushers[u.ID] || !u.IsActive || u.ProhibitLogin {
			continue
		}
		if ok, err := access_model.HasAccessUnit(ctx, u, pr.BaseRepo, unit.TypeCode, perm.AccessModeWrite); err != nil {
			return 0, err
		} else if !ok {
			continue
		}
		if rule.HasApprovers() {
			if ok, err := rule.IsApprover(ctx, u.ID); err != nil {
				return 0, err
			} else if !ok {
				continue
			}
		}
		eligible++
	}
	return eligible, nil
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
		})
	}
	return rules, nil
}
