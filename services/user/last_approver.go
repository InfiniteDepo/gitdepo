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
)

// LastApproverWarning says that deactivating a user, or prohibiting their login, would leave something that
// needs approvals without enough people. Kind names what it is, Link is a relative URL to it and Name is its name.
type LastApproverWarning struct {
	UserID           int64
	Kind, Link, Name string
}

var (
	lastApproverMu     sync.Mutex
	lastApproverChecks []func(ctx context.Context, userIDs []int64) ([]LastApproverWarning, error)
)

// RegisterLastApproverCheck adds a check that LastApproverWarnings runs.
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

// Kinds of the warnings of the approval rule check.
const (
	LastApproverRepoRule    = "repository_approval_rule"
	LastApproverProjectRule = "project_approval_rule"
	LastApproverOrgRule     = "organization_approval_rule"
)

func init() { RegisterLastApproverCheck(approvalRuleWarnings) }

// approvalRuleWarnings finds the approval rules, of repositories, projects and organizations, that list one of the
// users or a team of theirs and would have fewer eligible approvers than their count without them. Eligible here is
// active and able to sign in: write access is not checked (that needs the repositories' access, one load per
// repository, and the rule pages warn about it), so a listed user who can't write still counts. The queries don't
// depend on the number of rules. CODEOWNERS is not checked: it needs a git read per repository.
func approvalRuleWarnings(ctx context.Context, userIDs []int64) ([]LastApproverWarning, error) {
	teamIDs, err := organization.GetTeamIDsOfUsers(ctx, userIDs)
	if err != nil {
		return nil, err
	}
	rules, err := git_model.FindApprovalRulesListing(ctx, userIDs, teamIDs)
	if err != nil || len(rules) == 0 {
		return nil, err
	}
	var pbIDs, ruleTeams, ids []int64
	for _, r := range rules {
		pbIDs, ruleTeams, ids = append(pbIDs, r.ProtectedBranchID), append(ruleTeams, r.TeamIDs...), append(ids, r.UserIDs...)
	}
	members, err := organization.GetTeamsMemberIDs(ctx, ruleTeams)
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		ids = append(ids, m...)
	}
	users, err := user_model.GetUserByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]*user_model.User, len(users))
	for _, u := range users {
		byID[u.ID] = u
	}
	pbs, err := db.GetByIDs(ctx, "id", pbIDs, &git_model.ProtectedBranch{})
	if err != nil {
		return nil, err
	}
	var repoIDs, ownerIDs []int64
	for _, pb := range pbs {
		if pb.RepoID != 0 {
			repoIDs = append(repoIDs, pb.RepoID)
		} else {
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

	var warnings []LastApproverWarning
	for _, r := range rules {
		pb := pbs[r.ProtectedBranchID]
		if pb == nil {
			continue
		}
		candidates := slices.Clone(r.UserIDs)
		for _, t := range r.TeamIDs {
			candidates = append(candidates, members[t]...)
		}
		slices.Sort(candidates)
		remaining, affected := int64(0), int64(0)
		for _, id := range slices.Compact(candidates) {
			u := byID[id]
			if u == nil || !u.IsActive || u.ProhibitLogin {
				continue
			}
			if slices.Contains(userIDs, id) {
				affected = id
			} else {
				remaining++
			}
		}
		// nothing changes for a rule whose listed users are all unusable already
		if affected == 0 || remaining >= r.RequiredCount {
			continue
		}
		w := LastApproverWarning{UserID: affected, Name: pb.RuleName + ": " + r.Name}
		edit := "/settings/branches/edit?rule_name=" + url.QueryEscape(pb.RuleName)
		switch {
		case pb.RepoID != 0:
			repo := repos[pb.RepoID]
			if repo == nil {
				continue
			}
			w.Kind, w.Link, w.Name = LastApproverRepoRule, repo.Link()+edit, repo.FullName()+" "+w.Name
		case pb.GroupID != 0:
			owner := owners[pb.OrgID]
			if owner == nil {
				continue
			}
			w.Kind, w.Link, w.Name = LastApproverProjectRule, setting.AppSubURL+"/org/"+url.PathEscape(owner.Name)+"/groups/"+strconv.FormatInt(pb.GroupID, 10)+edit, owner.Name+" "+w.Name
		default:
			owner := owners[pb.OrgID]
			if owner == nil {
				continue
			}
			w.Kind, w.Link, w.Name = LastApproverOrgRule, setting.AppSubURL+"/org/"+url.PathEscape(owner.Name)+edit, owner.Name+" "+w.Name
		}
		warnings = append(warnings, w)
	}
	return warnings, nil
}
