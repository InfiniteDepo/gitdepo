// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"context"
	"strconv"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/util"
	"forgejo.org/services/approvers"
	issue_service "forgejo.org/services/issue"
)

// Kinds of RuleWarning.
const (
	WarnApproversShort = "approvers_short" // an approval rule has fewer people who can approve than it needs
	WarnOwnerLine      = "owner_line"      // a CODEOWNERS line has no owner who can approve
	WarnOwnerSection   = "owner_section"   // a line of a CODEOWNERS section has fewer owners who can approve than it needs
)

// Bounds of a rule page: warnings, and the owners named in one.
const (
	maxRuleWarnings = 20
	maxWarnedOwners = 3
)

// RuleWarning is a problem of a protected branch rule that would block merges.
type RuleWarning struct {
	Kind     string
	Name     string // the approval rule or the CODEOWNERS section
	Line     int
	Link     string // the CODEOWNERS line, on the branch
	Required int
	Eligible int
	// WriteUnchecked: the rule covers too many repositories to check write access, so its count may be too high
	WriteUnchecked bool
	Owners         []OwnerMark // up to maxWarnedOwners, with the reasons the viewer may see
}

// RuleReport is what a rule page shows.
type RuleReport struct {
	Warnings []RuleWarning
	More     bool
	// CodeOwnersSkipped: the rule needs code owners, but names a pattern, so no branch's CODEOWNERS was read
	CodeOwnersSkipped bool
}

// BranchRuleWarnings checks the approval rules of a protected branch rule: each needs as many people who are
// active, can sign in and can write the code as its count, and, if one asks for code owners, the CODEOWNERS file of
// the branch must have owners who can approve on every line, and for a section as many as it asks. Lines of a
// section are checked one by one, which can warn where the lines of one file add up (a lower bound that errs on the
// side of warning). A rule's path patterns (globs) and the lines (regular expressions) can't be intersected, so
// every line counts. CODEOWNERS is read only when the rule names one branch: a pattern has no single branch to read,
// which the report says. With a nil repository (an organization or project rule) only the approval rules are checked,
// and a user counts who can write at least one repository the rule covers.
func BranchRuleWarnings(ctx context.Context, repo *repo_model.Repository, pb *git_model.ProtectedBranch, v OwnerViewer) (*RuleReport, error) {
	report := &RuleReport{}
	rules, err := git_model.GetApprovalRules(ctx, pb.ID)
	if err != nil || len(rules) == 0 {
		return report, err
	}
	writers := approvers.NewWriters() // one access computation for the whole page
	checked, err := approvers.Check(ctx, rules, nil, writers)
	if err != nil {
		return nil, err
	}
	var short []*git_model.ApprovalRule
	needOwners := false
	for _, r := range rules {
		needOwners = needOwners || r.RequireCodeOwners
		if res := checked.Results[r.ID]; r.HasApprovers() && res != nil && res.Remaining < r.RequiredCount {
			short = append(short, r)
			report.Warnings = append(report.Warnings, RuleWarning{Kind: WarnApproversShort, Name: r.Name, Required: int(r.RequiredCount), Eligible: int(res.Remaining), WriteUnchecked: !res.WriteChecked})
		}
	}
	if repo != nil && len(short) > 0 { // name who can't approve
		sets := make([]OwnerSet, len(short))
		var teamIDs []int64
		for _, r := range short {
			teamIDs = append(teamIDs, r.TeamIDs...)
		}
		teams, err := db.GetByIDs(ctx, "id", uniqIDs(teamIDs), &organization.Team{})
		if err != nil {
			return nil, err
		}
		for i, r := range short {
			sets[i].UserIDs = r.UserIDs
			for _, id := range r.TeamIDs {
				if t := teams[id]; t != nil {
					sets[i].Teams = append(sets[i].Teams, t)
				}
			}
		}
		owners, _, err := IneligibleOwners(ctx, repo, writers, v, sets, 1<<30)
		if err != nil {
			return nil, err
		}
		for i := range short {
			report.Warnings[i].Owners = owners[i].Marks[:min(len(owners[i].Marks), maxWarnedOwners)]
		}
	}
	if repo != nil && needOwners {
		if git_model.IsRuleNameSpecial(pb.RuleName) {
			report.CodeOwnersSkipped = true
		} else {
			more, err := codeOwnerWarnings(ctx, repo, writers, v, pb.RuleName)
			if err != nil {
				return nil, err
			}
			report.Warnings = append(report.Warnings, more...)
		}
	}
	if len(report.Warnings) > maxRuleWarnings {
		report.Warnings, report.More = report.Warnings[:maxRuleWarnings], true
	}
	return report, nil
}

func codeOwnerWarnings(ctx context.Context, repo *repo_model.Repository, writers *approvers.Writers, v OwnerViewer, branch string) ([]RuleWarning, error) {
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
	checks, more, err := IneligibleOwners(ctx, repo, writers, v, sets, 1<<30)
	if err != nil || more { // too many people to check them all: say nothing rather than something wrong
		return nil, err
	}
	link := func(line int) string {
		return repo.Link() + "/src/branch/" + util.PathEscapeSegments(branch) + "/" + util.PathEscapeSegments(owners.File) + "#L" + strconv.Itoa(line)
	}
	var warnings []RuleWarning
	reported := map[*issues_model.CodeOwnerSection]bool{}
	for i, l := range owners.Rules {
		if l.Section.Optional {
			continue
		}
		c := checks[i]
		switch {
		case c.Eligible == 0:
			warnings = append(warnings, RuleWarning{Kind: WarnOwnerLine, Line: l.Line, Link: link(l.Line), Owners: c.Marks[:min(len(c.Marks), maxWarnedOwners)]})
		case l.Section.Name != "" && c.Eligible < l.Section.Required && !reported[l.Section]:
			reported[l.Section] = true
			warnings = append(warnings, RuleWarning{Kind: WarnOwnerSection, Name: l.Section.Name, Line: l.Line, Link: link(l.Line), Required: l.Section.Required, Eligible: c.Eligible, Owners: c.Marks[:min(len(c.Marks), maxWarnedOwners)]})
		}
		if len(warnings) > maxRuleWarnings {
			break
		}
	}
	return warnings, nil
}
