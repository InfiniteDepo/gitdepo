// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"context"

	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/gitrepo"
	issue_service "forgejo.org/services/issue"
)

// Kinds of RuleWarning.
const (
	WarnApproversShort = "approvers_short" // an approval rule has fewer people who can approve than it needs
	WarnOwnerLine      = "owner_line"      // a CODEOWNERS line has no owner who can approve
	WarnOwnerSection   = "owner_section"   // a CODEOWNERS section has fewer owners who can approve than it needs
)

// maxRuleWarnings bounds the warnings of a rule page.
const maxRuleWarnings = 20

// RuleWarning is a problem of a protected branch rule that would block merges.
type RuleWarning struct {
	Kind     string
	Name     string // the approval rule or the CODEOWNERS section
	Line     int
	Required int
	Eligible int
}

// BranchRuleWarnings checks the approval rules of a repository's protected branch rule: each needs as many people
// who are active, can sign in and can write the code as its count, and, if one asks for code owners, the CODEOWNERS
// file of the branch must have owners who can approve. A rule can't be met by the code owners of a line a rule's
// path patterns don't reach, but the patterns (globs) and the lines (regular expressions) can't be intersected, so
// every line counts. CODEOWNERS is read only when the rule names one branch: a glob has no single branch to read.
// Organization and project rules have no repository here and are not checked.
func BranchRuleWarnings(ctx context.Context, repo *repo_model.Repository, pb *git_model.ProtectedBranch) ([]RuleWarning, error) {
	rules, err := git_model.GetApprovalRules(ctx, pb.ID)
	if err != nil || len(rules) == 0 {
		return nil, err
	}
	var warnings []RuleWarning
	var withApprovers []*git_model.ApprovalRule
	var sets []OwnerSet
	needOwners := false
	for _, r := range rules {
		needOwners = needOwners || r.RequireCodeOwners
		if r.HasApprovers() {
			withApprovers, sets = append(withApprovers, r), append(sets, OwnerSet{UserIDs: r.UserIDs, TeamIDs: r.TeamIDs})
		}
	}
	if len(sets) > 0 {
		checks, err := IneligibleOwners(ctx, repo, sets)
		if err != nil {
			return nil, err
		}
		for i, r := range withApprovers {
			if int64(len(checks[i].Eligible)) < r.RequiredCount {
				warnings = append(warnings, RuleWarning{Kind: WarnApproversShort, Name: r.Name, Required: int(r.RequiredCount), Eligible: len(checks[i].Eligible)})
			}
		}
	}
	if needOwners && !git_model.IsRuleNameSpecial(pb.RuleName) {
		more, err := codeOwnerWarnings(ctx, repo, pb.RuleName)
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, more...)
	}
	return warnings[:min(len(warnings), maxRuleWarnings)], nil
}

func codeOwnerWarnings(ctx context.Context, repo *repo_model.Repository, branch string) ([]RuleWarning, error) {
	gitRepo, err := gitrepo.OpenRepository(ctx, repo)
	if err != nil {
		return nil, err
	}
	defer gitRepo.Close()
	if !gitRepo.IsBranchExist(branch) {
		return nil, nil
	}
	commit, err := gitRepo.GetBranchCommit(branch)
	if err != nil {
		return nil, err
	}
	owners, _, err := issue_service.LoadCodeOwnerRules(ctx, commit)
	if err != nil || owners.File == "" || owners.ErrorLine != 0 { // no file: no warning; a malformed one is reported elsewhere
		return nil, err
	}
	sets := make([]OwnerSet, len(owners.Rules))
	for i, l := range owners.Rules {
		sets[i] = CodeOwnerSet(l)
	}
	checks, err := IneligibleOwners(ctx, repo, sets)
	if err != nil {
		return nil, err
	}
	var warnings []RuleWarning
	var order []*issues_model.CodeOwnerSection
	eligible := map[*issues_model.CodeOwnerSection]map[int64]bool{}
	for i, l := range owners.Rules {
		if l.Section.Optional {
			continue
		}
		if eligible[l.Section] == nil {
			eligible[l.Section] = map[int64]bool{}
			order = append(order, l.Section)
		}
		for _, id := range checks[i].Eligible {
			eligible[l.Section][id] = true
		}
		if len(checks[i].Eligible) == 0 {
			warnings = append(warnings, RuleWarning{Kind: WarnOwnerLine, Line: l.Line})
		}
	}
	for _, s := range order {
		if s.Name != "" && len(eligible[s]) < s.Required {
			warnings = append(warnings, RuleWarning{Kind: WarnOwnerSection, Name: s.Name, Required: s.Required, Eligible: len(eligible[s])})
		}
	}
	return warnings, nil
}
