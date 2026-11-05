// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"context"
	"slices"
	"strings"

	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/translation"
	"forgejo.org/services/accessreport"
)

// OwnerReason is why an owner or listed approver can't approve in a repository.
type OwnerReason string

const (
	OwnerInactive   OwnerReason = "inactive"
	OwnerProhibited OwnerReason = "prohibited"
	OwnerNoWrite    OwnerReason = "no_write"
	OwnerTwoFactor  OwnerReason = "two_factor"
)

// Text returns the reason in the language of the viewer.
func (r OwnerReason) Text(l translation.Locale) string {
	switch r {
	case OwnerInactive:
		return l.TrString("repo.codeowners.reason_inactive")
	case OwnerProhibited:
		return l.TrString("repo.codeowners.reason_prohibited")
	case OwnerTwoFactor:
		return l.TrString("repo.codeowners.reason_two_factor")
	}
	return l.TrString("repo.codeowners.reason_no_write")
}

// OwnerMark is an owner who can't approve.
type OwnerMark struct {
	Name   string
	Reason OwnerReason
}

// OwnerSet is the users and teams named on a CODEOWNERS line or an approval rule.
type OwnerSet struct{ UserIDs, TeamIDs []int64 }

// CodeOwnerSet returns the owners named on the line.
func CodeOwnerSet(line *issues_model.CodeOwnerRule) OwnerSet {
	var s OwnerSet
	for _, u := range line.Users {
		s.UserIDs = append(s.UserIDs, u.ID)
	}
	for _, t := range line.Teams {
		s.TeamIDs = append(s.TeamIDs, t.ID)
	}
	return s
}

// OwnerCheck is the result for one OwnerSet: the users who can approve and those who can't.
type OwnerCheck struct {
	Eligible []int64
	Marks    []OwnerMark // by name
}

// IneligibleOwners checks, for each set, the users named in it (directly or as members of its teams) who can't
// approve in the repository: inactive, login prohibited, without write access to the code, or kept out of the
// owner organization by its two-factor requirement. It loads teams, members and users once for all sets, and the
// repository's access once, so the queries don't grow with the number of sets.
func IneligibleOwners(ctx context.Context, repo *repo_model.Repository, sets []OwnerSet) ([]OwnerCheck, error) {
	var teamIDs []int64
	for _, s := range sets {
		teamIDs = append(teamIDs, s.TeamIDs...)
	}
	members, err := organization.GetTeamsMemberIDs(ctx, teamIDs)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for _, s := range sets {
		ids = append(ids, s.UserIDs...)
		for _, t := range s.TeamIDs {
			ids = append(ids, members[t]...)
		}
	}
	users, err := user_model.GetUserByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]*user_model.User, len(users))
	for _, u := range users {
		byID[u.ID] = u
	}

	// access is loaded when the first active owner needs it
	var writers map[int64]bool
	reasons := map[int64]OwnerReason{}
	reason := func(u *user_model.User) (OwnerReason, error) {
		if r, ok := reasons[u.ID]; ok {
			return r, nil
		}
		r := OwnerReason("")
		switch {
		case !u.IsActive:
			r = OwnerInactive
		case u.ProhibitLogin:
			r = OwnerProhibited
		default:
			if writers == nil {
				rows, err := accessreport.Compute(ctx, accessreport.Options{RepoIDs: []int64{repo.ID}})
				if err != nil {
					return "", err
				}
				writers = map[int64]bool{}
				for _, row := range rows {
					if row.User != nil && row.Perm.CanWrite(unit.TypeCode) {
						writers[row.User.ID] = true
					}
				}
			}
			if !writers[u.ID] {
				r = OwnerNoWrite
				if err := repo.LoadOwner(ctx); err != nil {
					return "", err
				}
				if blocked, err := u.TwoFactorBlocked(ctx, repo.Owner); err != nil {
					return "", err
				} else if blocked {
					r = OwnerTwoFactor
				}
			}
		}
		reasons[u.ID] = r
		return r, nil
	}

	out := make([]OwnerCheck, len(sets))
	for i, s := range sets {
		owners := slices.Clone(s.UserIDs)
		for _, t := range s.TeamIDs {
			owners = append(owners, members[t]...)
		}
		slices.Sort(owners)
		for _, id := range slices.Compact(owners) {
			u := byID[id]
			if u == nil {
				continue
			}
			r, err := reason(u)
			if err != nil {
				return nil, err
			}
			if r != "" {
				out[i].Marks = append(out[i].Marks, OwnerMark{Name: u.Name, Reason: r})
			} else {
				out[i].Eligible = append(out[i].Eligible, id)
			}
		}
		slices.SortFunc(out[i].Marks, func(a, b OwnerMark) int { return strings.Compare(a.Name, b.Name) })
	}
	return out, nil
}

// maxOwnerMarks is how many owners a CODEOWNERS view lists; the rest are cut off.
const maxOwnerMarks = 200

// LineOwnerMarks are the owners of one CODEOWNERS line who can't approve.
type LineOwnerMarks struct {
	Line  int
	Marks []OwnerMark
}

// CodeOwnerLineMarks returns the lines of a CODEOWNERS file that name an owner who can't approve, in file order.
func CodeOwnerLineMarks(ctx context.Context, repo *repo_model.Repository, lines []*issues_model.CodeOwnerRule) ([]LineOwnerMarks, error) {
	sets := make([]OwnerSet, len(lines))
	for i, l := range lines {
		sets[i] = CodeOwnerSet(l)
	}
	marks, err := IneligibleOwners(ctx, repo, sets)
	if err != nil {
		return nil, err
	}
	var out []LineOwnerMarks
	total := 0
	for i, c := range marks {
		m := c.Marks
		if len(m) == 0 || total >= maxOwnerMarks {
			continue
		}
		m = m[:min(len(m), maxOwnerMarks-total)]
		total += len(m)
		out = append(out, LineOwnerMarks{Line: lines[i].Line, Marks: m})
	}
	return out, nil
}
