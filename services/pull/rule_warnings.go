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
	user_model "forgejo.org/models/user"
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
	// CodeOwnersCapped: the rule needs code owners, but the file names more people or teams than are checked
	CodeOwnersCapped bool
}

// BranchRuleWarnings checks the approval rules of a protected branch rule: each needs as many people who are
// active, can sign in and can write the code as its count, and, if one asks for code owners, the CODEOWNERS file of
// the branch must have owners who can approve on every line, and for a section as many as it asks. Lines of a
// section are checked one by one, which can warn where the lines of one file add up (a lower bound that errs on the
// side of warning). A rule's path patterns (globs) and the lines (regular expressions) can't be intersected, so
// every line counts. CODEOWNERS is read only when the rule names one branch: a pattern has no single branch to read,
// and a file that names more people than one check looks at is not checked either; the report says both. With a nil
// repository (an organization or project rule) only the approval rules are checked, and a user counts who can write
// at least one repository the rule covers; the users it lists who can't approve are named, a team is not.
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
	owners, err := shortRuleOwners(ctx, repo, writers, v, rules, checked)
	if err != nil {
		return nil, err
	}
	needOwners := false
	for _, r := range rules {
		needOwners = needOwners || r.RequireCodeOwners
		if res := checked.Results[r.ID]; r.HasApprovers() && res != nil && res.Remaining < r.RequiredCount {
			report.Warnings = append(report.Warnings, RuleWarning{Kind: WarnApproversShort, Name: r.Name, Required: int(r.RequiredCount), Eligible: int(res.Remaining), WriteUnchecked: !res.WriteChecked, Owners: owners[r.ID]})
		}
	}
	if repo != nil && needOwners {
		if git_model.IsRuleNameSpecial(pb.RuleName) {
			report.CodeOwnersSkipped = true
		} else {
			more, capped, err := codeOwnerWarnings(ctx, repo, writers, v, pb.RuleName)
			if err != nil {
				return nil, err
			}
			report.Warnings, report.CodeOwnersCapped = append(report.Warnings, more...), capped
		}
	}
	if len(report.Warnings) > maxRuleWarnings {
		report.Warnings, report.More = report.Warnings[:maxRuleWarnings], true
	}
	return report, nil
}

// shortRuleOwners names, for the rules that lack approvers, up to maxWarnedOwners of the listed people and teams who
// can't approve, by rule ID.
func shortRuleOwners(ctx context.Context, repo *repo_model.Repository, writers *approvers.Writers, v OwnerViewer, rules []*git_model.ApprovalRule, checked *approvers.Checked) (map[int64][]OwnerMark, error) {
	var short []*git_model.ApprovalRule
	for _, r := range rules {
		if res := checked.Results[r.ID]; r.HasApprovers() && res != nil && res.Remaining < r.RequiredCount {
			short = append(short, r)
		}
	}
	out := map[int64][]OwnerMark{}
	if len(short) == 0 {
		return out, nil
	}
	if repo == nil { // the users who can't approve, from the check itself
		var ids []int64
		for _, r := range short {
			for _, u := range checked.Results[r.ID].Unusable {
				ids = append(ids, u.ID)
			}
		}
		list, err := user_model.GetUserByIDs(ctx, approvers.Uniq(ids))
		if err != nil {
			return nil, err
		}
		names := make(map[int64]string, len(list))
		for _, user := range list {
			names[user.ID] = user.Name
		}
		for _, r := range short {
			for _, u := range checked.Results[r.ID].Unusable {
				if name, ok := names[u.ID]; ok && len(out[r.ID]) < maxWarnedOwners {
					out[r.ID] = append(out[r.ID], OwnerMark{Name: name, Reason: v.reason(OwnerReason(u.Reason))})
				}
			}
		}
		return out, nil
	}
	sets := make([]OwnerSet, len(short))
	var teamIDs []int64
	for _, r := range short {
		teamIDs = append(teamIDs, r.TeamIDs...)
	}
	teams, err := db.GetByIDs(ctx, "id", approvers.Uniq(teamIDs), &organization.Team{})
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
	checks, _, err := IneligibleOwners(ctx, repo, writers, v, sets, 1<<30)
	if err != nil {
		return nil, err
	}
	for i, r := range short {
		out[r.ID] = checks[i].Marks[:min(len(checks[i].Marks), maxWarnedOwners)]
	}
	return out, nil
}

// codeOwnerWarnings reports capped=true, with no warning, when the file names more people than one check looks at.
func codeOwnerWarnings(ctx context.Context, repo *repo_model.Repository, writers *approvers.Writers, v OwnerViewer, branch string) (warnings []RuleWarning, capped bool, err error) {
	gitRepo, err := gitrepo.OpenRepository(ctx, repo)
	if err != nil {
		return nil, false, err
	}
	defer gitRepo.Close()
	if !gitRepo.IsBranchExist(branch) {
		return nil, false, nil
	}
	commit, err := gitRepo.GetBranchCommit(branch)
	if err != nil {
		return nil, false, err
	}
	owners, _, err := issue_service.LoadCodeOwnerRules(ctx, repo.OwnerID, commit)
	if err != nil || owners.File == "" || owners.ErrorLine != 0 { // no file: no warning; a malformed one is reported elsewhere
		return nil, false, err
	}
	sets := make([]OwnerSet, len(owners.Rules))
	for i, l := range owners.Rules {
		sets[i] = CodeOwnerSet(l)
	}
	checks, more, err := IneligibleOwners(ctx, repo, writers, v, sets, 1<<30)
	if err != nil || more { // too many people to check them all: say so rather than something wrong
		return nil, more, err
	}
	link := func(line int) string {
		return repo.Link() + "/src/branch/" + util.PathEscapeSegments(branch) + "/" + util.PathEscapeSegments(owners.File) + "#L" + strconv.Itoa(line)
	}
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
	return warnings, false, nil
}
