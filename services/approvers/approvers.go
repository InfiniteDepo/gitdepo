// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package approvers counts the people who can satisfy the approval rules of protected branch rules.
package approvers

import (
	"context"
	"slices"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/services/accessreport"
)

// MaxCheckedRepos is how many repositories one Check loads the access of. A rule whose repositories don't fit
// is counted without the write check: the people it lists count when they are active and can sign in.
const MaxCheckedRepos = 50

// Writers holds who can write which repositories, loaded once and shared by every computation of a request.
type Writers struct{ by map[int64]map[int64]bool }

// NewWriters returns an empty set; Load fills it.
func NewWriters() *Writers { return &Writers{by: map[int64]map[int64]bool{}} }

// Load computes the access of the repositories that are not loaded yet, in a fixed number of queries.
func (w *Writers) Load(ctx context.Context, repoIDs ...int64) error {
	var missing []int64
	for _, id := range repoIDs {
		if _, ok := w.by[id]; !ok {
			missing = append(missing, id)
			w.by[id] = map[int64]bool{}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	rows, err := accessreport.Compute(ctx, accessreport.Options{RepoIDs: missing})
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.User != nil && row.Perm.CanWrite(unit.TypeCode) {
			w.by[row.Repo.ID][row.User.ID] = true
		}
	}
	return nil
}

// Can reports whether the user can write the loaded repository.
func (w *Writers) Can(repoID, uid int64) bool { return w.by[repoID][uid] }

// Result is the eligible approvers of one approval rule.
type Result struct {
	// WriteChecked is false when the rule covers too many repositories for the write check: its people count when
	// they are active and can sign in.
	WriteChecked bool
	// Remaining counts the eligible listed approvers (directly or through a team) who are not leaving.
	Remaining int64
	// Leaving is one of the leaving users who is eligible now, 0 if none is.
	Leaving int64
}

// Checked holds the results by approval rule ID and the protected branch rules they belong to, by ID.
type Checked struct {
	Results  map[int64]*Result
	Branches map[int64]*git_model.ProtectedBranch
}

// Check counts, for every rule, the listed users and members of listed teams who can approve: active, able to sign
// in and with write access to the code. A repository rule is checked on its repository, a project or organization
// rule on the repositories it covers: a user counts if they can write at least one of them (exact counting per
// repository would multiply the work). The queries don't grow with the number of rules; the access of at most
// MaxCheckedRepos repositories is loaded, repository rules first. leaving users are left out of Remaining.
func Check(ctx context.Context, rules []*git_model.ApprovalRule, leaving []int64, writers *Writers) (*Checked, error) {
	out := &Checked{Results: map[int64]*Result{}}
	if len(rules) == 0 {
		return out, nil
	}
	var pbIDs, teamIDs, ids []int64
	for _, r := range rules {
		pbIDs, teamIDs, ids = append(pbIDs, r.ProtectedBranchID), append(teamIDs, r.TeamIDs...), append(ids, r.UserIDs...)
	}
	members, err := organization.GetTeamsMemberIDs(ctx, uniq(teamIDs))
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		ids = append(ids, m...)
	}
	users, err := user_model.GetUserByIDs(ctx, uniq(ids))
	if err != nil {
		return nil, err
	}
	usable := map[int64]bool{}
	for _, u := range users {
		usable[u.ID] = u.IsActive && !u.ProhibitLogin
	}
	if out.Branches, err = db.GetByIDs(ctx, "id", uniq(pbIDs), &git_model.ProtectedBranch{}); err != nil {
		return nil, err
	}
	covered, err := coveredRepos(ctx, out.Branches, writers)
	if err != nil {
		return nil, err
	}

	for _, r := range rules {
		pb := out.Branches[r.ProtectedBranchID]
		if pb == nil {
			continue
		}
		candidates := slices.Clone(r.UserIDs)
		for _, t := range r.TeamIDs {
			candidates = append(candidates, members[t]...)
		}
		slices.Sort(candidates)
		repoIDs, checked := covered[pb.ID]
		res := &Result{WriteChecked: checked}
		for _, id := range slices.Compact(candidates) {
			if !usable[id] || !canWrite(repoIDs, writers, id) {
				continue
			}
			if slices.Contains(leaving, id) {
				res.Leaving = id
			} else {
				res.Remaining++
			}
		}
		out.Results[r.ID] = res
	}
	return out, nil
}

// canWrite is true for a rule without a checked repository (too many, or none covered).
func canWrite(repoIDs []int64, writers *Writers, uid int64) bool {
	if len(repoIDs) == 0 {
		return true
	}
	return slices.ContainsFunc(repoIDs, func(id int64) bool { return writers.Can(id, uid) })
}

func uniq(ids []int64) []int64 {
	ids = slices.Clone(ids)
	slices.Sort(ids)
	return slices.Compact(ids)
}

// coveredRepos returns the repositories each rule covers, left out when they were not checked, and loads who can
// write the checked ones into writers.
func coveredRepos(ctx context.Context, pbs map[int64]*git_model.ProtectedBranch, writers *Writers) (map[int64][]int64, error) {
	var groupIDs, orgIDs, selectedIDs []int64
	for _, pb := range pbs {
		switch {
		case pb.RepoID != 0:
		case pb.GroupID != 0:
			groupIDs = append(groupIDs, pb.GroupID)
		case pb.ApplyToSelectedRepos:
			selectedIDs = append(selectedIDs, pb.ID)
		default:
			orgIDs = append(orgIDs, pb.OrgID)
		}
	}
	byGroup, byOrg, bySelected := map[int64][]int64{}, map[int64][]int64{}, map[int64][]int64{}
	var repos []*repo_model.Repository
	if len(groupIDs) > 0 {
		if err := db.GetEngine(ctx).Cols("id", "group_id").In("group_id", groupIDs).And(repo_model.NotTrashedCond("id")).Find(&repos); err != nil {
			return nil, err
		}
		for _, r := range repos {
			byGroup[r.GroupID] = append(byGroup[r.GroupID], r.ID)
		}
	}
	if len(orgIDs) > 0 {
		repos = nil
		if err := db.GetEngine(ctx).Cols("id", "owner_id").In("owner_id", orgIDs).And(repo_model.NotTrashedCond("id")).Find(&repos); err != nil {
			return nil, err
		}
		for _, r := range repos {
			byOrg[r.OwnerID] = append(byOrg[r.OwnerID], r.ID)
		}
	}
	if len(selectedIDs) > 0 {
		var rows []*git_model.ProtectedBranchRepo
		if err := db.GetEngine(ctx).In("protected_branch_id", selectedIDs).Find(&rows); err != nil {
			return nil, err
		}
		for _, r := range rows {
			bySelected[r.ProtectedBranchID] = append(bySelected[r.ProtectedBranchID], r.RepoID)
		}
	}

	// repository rules first, then projects, then organizations; a rule that doesn't fit is not checked
	ordered := make([]*git_model.ProtectedBranch, 0, len(pbs))
	for _, pb := range pbs {
		ordered = append(ordered, pb)
	}
	rank := func(pb *git_model.ProtectedBranch) int {
		switch {
		case pb.RepoID != 0:
			return 0
		case pb.GroupID != 0:
			return 1
		}
		return 2
	}
	slices.SortFunc(ordered, func(a, b *git_model.ProtectedBranch) int {
		if rank(a) != rank(b) {
			return rank(a) - rank(b)
		}
		return int(a.ID - b.ID)
	})
	covered := map[int64][]int64{}
	checked := map[int64]bool{}
	for _, pb := range ordered {
		var ids []int64
		switch {
		case pb.RepoID != 0:
			ids = []int64{pb.RepoID}
		case pb.GroupID != 0:
			ids = byGroup[pb.GroupID]
		case pb.ApplyToSelectedRepos:
			ids = bySelected[pb.ID]
		default:
			ids = byOrg[pb.OrgID]
		}
		extra := 0
		for _, id := range ids {
			if !checked[id] {
				extra++
			}
		}
		if len(checked)+extra > MaxCheckedRepos {
			continue
		}
		for _, id := range ids {
			checked[id] = true
		}
		covered[pb.ID] = ids
	}
	repoIDs := make([]int64, 0, len(checked))
	for id := range checked {
		repoIDs = append(repoIDs, id)
	}
	return covered, writers.Load(ctx, repoIDs...)
}
