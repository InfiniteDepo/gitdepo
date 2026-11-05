// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package user

import (
	"context"
	"net/url"
	"slices"
	"strconv"
	"sync"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/translation"
	"forgejo.org/services/approvers"
)

// LastApproverWarning says that deactivating a user, or prohibiting their login, would leave something that
// needs approvals without enough people. Kind is a readable label of what it is (a locale key, which the admin page
// translates, or plain text), Link a relative URL to it and Name its display text, which the check builds.
type LastApproverWarning struct {
	UserID           int64
	Kind, Link, Name string
}

var (
	lastApproverMu     sync.Mutex
	lastApproverChecks []func(ctx context.Context, userIDs []int64) ([]LastApproverWarning, error)
)

// RegisterLastApproverCheck adds a check that LastApproverWarnings runs. It reports what the users leaving would
// leave without enough approvers; Kind is a readable label, Link a relative URL beginning with "/".
func RegisterLastApproverCheck(check func(ctx context.Context, userIDs []int64) ([]LastApproverWarning, error)) {
	lastApproverMu.Lock()
	defer lastApproverMu.Unlock()
	lastApproverChecks = append(lastApproverChecks, check)
}

// LastApproverWarnings returns the warnings of every registered check for the users. A failing check fails the call.
func LastApproverWarnings(ctx context.Context, userIDs []int64) ([]LastApproverWarning, error) {
	lastApproverMu.Lock()
	checks := slices.Clone(lastApproverChecks)
	lastApproverMu.Unlock()
	var all []LastApproverWarning
	for _, check := range checks {
		w, err := check(ctx, userIDs)
		if err != nil {
			return nil, err
		}
		all = append(all, w...)
	}
	return all, nil
}

// Kinds of the warnings of the approval rule check. A Kind is a short label a person reads as it is, so that the
// admin page needs no table of the kinds of every check.
const (
	LastApproverRepoRule    = "admin.users.last_approver.kind.repo_rule"
	LastApproverProjectRule = "admin.users.last_approver.kind.project_rule"
	LastApproverOrgRule     = "admin.users.last_approver.kind.org_rule"
)

func init() { RegisterLastApproverCheck(approvalRuleWarnings) }

// approvalRuleWarnings finds the approval rules, of repositories, projects and organizations, that list one of the
// users or a team of theirs and would have fewer eligible approvers than their count without them. Eligible means
// active, able to sign in and with write access to the code (approvers.Check: a project or organization rule counts
// a user who can write at least one repository it covers). The queries don't depend on the number of rules.
// CODEOWNERS is not checked: it needs a git read per repository.
func approvalRuleWarnings(ctx context.Context, userIDs []int64) ([]LastApproverWarning, error) {
	teamIDs, err := organization.GetTeamIDsOfUsers(ctx, userIDs)
	if err != nil {
		return nil, err
	}
	rules, err := git_model.FindApprovalRulesListing(ctx, userIDs, teamIDs)
	if err != nil || len(rules) == 0 {
		return nil, err
	}
	checked, err := approvers.Check(ctx, rules, userIDs, approvers.NewWriters())
	if err != nil {
		return nil, err
	}
	var repoIDs, ownerIDs, groupIDs []int64
	for _, pb := range checked.Branches {
		switch {
		case pb.RepoID != 0:
			repoIDs = append(repoIDs, pb.RepoID)
		case pb.GroupID != 0:
			ownerIDs, groupIDs = append(ownerIDs, pb.OrgID), append(groupIDs, pb.GroupID)
		default:
			ownerIDs = append(ownerIDs, pb.OrgID)
		}
	}
	repos, err := repo_model.GetRepositoriesMapByIDs(ctx, repoIDs)
	if err != nil {
		return nil, err
	}
	owners, err := db.GetByIDs(ctx, "id", ownerIDs, &user_model.User{})
	if err != nil {
		return nil, err
	}
	groups, err := db.GetByIDs(ctx, "id", groupIDs, &repo_model.RepoGroup{})
	if err != nil {
		return nil, err
	}

	var warnings []LastApproverWarning
	for _, r := range rules {
		pb, res := checked.Branches[r.ProtectedBranchID], checked.Results[r.ID]
		// nothing changes for a rule none of the users counts in now
		if pb == nil || res == nil || res.Leaving == 0 || res.Remaining >= r.RequiredCount {
			continue
		}
		w := LastApproverWarning{UserID: res.Leaving}
		name := func(where string) string {
			return translation.NewLocale("").TrString("admin.users.last_approver_item", r.Name, pb.RuleName, where)
		}
		edit := "/settings/branches/edit?rule_name=" + url.QueryEscape(pb.RuleName)
		switch {
		case pb.RepoID != 0:
			repo := repos[pb.RepoID]
			if repo == nil {
				continue
			}
			w.Kind, w.Link, w.Name = LastApproverRepoRule, repo.Link()+edit, name(repo.FullName())
		case pb.GroupID != 0:
			owner, group := owners[pb.OrgID], groups[pb.GroupID]
			if owner == nil || group == nil {
				continue
			}
			w.Kind, w.Link, w.Name = LastApproverProjectRule, setting.AppSubURL+"/org/"+url.PathEscape(owner.Name)+"/groups/"+strconv.FormatInt(pb.GroupID, 10)+edit, name(owner.Name+"/"+group.Name)
		default:
			owner := owners[pb.OrgID]
			if owner == nil {
				continue
			}
			w.Kind, w.Link, w.Name = LastApproverOrgRule, setting.AppSubURL+"/org/"+url.PathEscape(owner.Name)+edit, name(owner.Name)
		}
		warnings = append(warnings, w)
	}
	return warnings, nil
}
