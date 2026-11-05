// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"context"
	"html/template"
	"slices"
	"strconv"
	"strings"

	auth_model "forgejo.org/models/auth"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/translation"
	"forgejo.org/services/approvers"
)

// OwnerReason is why a named owner can't approve in a repository. The empty reason is the neutral "can't approve",
// all that a viewer without the right to know more is told.
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

// OwnerViewer says how much of the reasons a viewer sees: the specific reasons are for repository and site admins,
// and the two-factor reason for site admins and the acting owners of the organization that requires it (as the
// members page of #147 does). Everyone else sees the neutral mark.
type OwnerViewer struct{ Details, TwoFactor bool }

// NewOwnerViewer returns what doer may see in repo. repoAdmin is whether they administer it (site admins do).
func NewOwnerViewer(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, repoAdmin bool) OwnerViewer {
	v := OwnerViewer{Details: repoAdmin}
	if doer == nil {
		return OwnerViewer{}
	}
	if doer.IsAdmin {
		v.Details, v.TwoFactor = true, true
	} else if repo.Owner != nil && repo.Owner.IsOrganization() {
		owner, err := organization.GetOrgByID(ctx, repo.OwnerID)
		if err == nil {
			v.TwoFactor, _ = owner.IsActingOwner(ctx, doer)
		}
	}
	return v
}

func (v OwnerViewer) reason(r OwnerReason) OwnerReason {
	if !v.Details || r == OwnerTwoFactor && !v.TwoFactor {
		return ""
	}
	return r
}

// OwnerMark is a named owner, or a team, who can't approve. A user has a Reason (maybe neutral); a team is one
// mark with the number of its members who can, and is never expanded.
type OwnerMark struct {
	Name     string
	Reason   OwnerReason
	Team     bool
	Foreign  bool // a team of another organization, which can never grant write
	Eligible int  // the members of a team who can approve
}

// Text renders the mark.
func (m OwnerMark) Text(l translation.Locale) template.HTML {
	switch {
	case m.Foreign:
		return l.Tr("repo.codeowners.team_foreign", m.Name)
	case m.Team && m.Eligible == 0:
		return l.Tr("repo.codeowners.team_none", m.Name)
	case m.Team:
		return l.TrPluralString(m.Eligible, "repo.codeowners.team_only", m.Name, m.Eligible)
	case m.Reason == "":
		return l.Tr("repo.codeowners.owner_neutral", m.Name)
	}
	return l.Tr("repo.codeowners.owner_reason", m.Name, m.Reason.Text(l))
}

// OwnerSet is the users and teams named on a CODEOWNERS line or an approval rule.
type OwnerSet struct {
	UserIDs []int64
	Teams   []*organization.Team
}

// CodeOwnerSet returns the owners named on the line.
func CodeOwnerSet(line *issues_model.CodeOwnerRule) OwnerSet {
	s := OwnerSet{Teams: line.Teams}
	for _, u := range line.Users {
		s.UserIDs = append(s.UserIDs, u.ID)
	}
	return s
}

// OwnerCheck is the result for one set: how many distinct people can approve and who can't.
type OwnerCheck struct {
	Eligible int
	Marks    []OwnerMark
}

// The work of one call is bounded by what it shows: at most this many teams are expanded and this many people
// looked at, and it stops once limit marks are found.
const (
	maxOwnerTeams      = 100
	maxOwnerCandidates = 2000
)

// IneligibleOwners checks every set against the repository, with the access, users, teams and two-factor
// enrolment loaded once for all sets (IDs deduplicated first), so the work depends on the people named, not on the
// number of lines naming them. Teams of the repository owner's organization are counted but never listed; any
// other team can't grant write and is a mark of its own. It stops after limit marks and reports more=true if it
// left sets or people out (their check is then empty). The reasons shown follow v.
func IneligibleOwners(ctx context.Context, repo *repo_model.Repository, writers *approvers.Writers, v OwnerViewer, sets []OwnerSet, limit int) (checks []OwnerCheck, more bool, err error) {
	if err := repo.LoadOwner(ctx); err != nil {
		return nil, false, err
	}
	var teamIDs, userIDs []int64
	for _, s := range sets {
		userIDs = append(userIDs, s.UserIDs...)
		for _, t := range s.Teams {
			if t.OrgID == repo.OwnerID {
				teamIDs = append(teamIDs, t.ID)
			}
		}
	}
	teamIDs = uniqIDs(teamIDs)
	if len(teamIDs) > maxOwnerTeams {
		teamIDs, more = teamIDs[:maxOwnerTeams], true
	}
	members, err := organization.GetTeamsMemberIDs(ctx, teamIDs)
	if err != nil {
		return nil, false, err
	}
	candidates := uniqIDs(userIDs)
	known := map[int64]bool{}
	for _, id := range candidates {
		known[id] = true
	}
	for _, id := range teamIDs { // a team that doesn't fit is left out whole
		fresh := 0
		for _, m := range members[id] {
			if !known[m] {
				fresh++
			}
		}
		if len(candidates)+fresh > maxOwnerCandidates {
			delete(members, id)
			more = true
			continue
		}
		for _, m := range members[id] {
			if !known[m] {
				known[m] = true
				candidates = append(candidates, m)
			}
		}
	}
	if len(candidates) > maxOwnerCandidates {
		candidates, more = candidates[:maxOwnerCandidates], true
	}
	users, err := user_model.GetUserByIDs(ctx, candidates)
	if err != nil {
		return nil, false, err
	}
	var enrolled map[int64]bool // only where the owner requires two-factor
	if repo.Owner.IsOrganization() && repo.Owner.RequireTwoFactor {
		set, err := auth_model.UserIDsWithTwoFactor(ctx, candidates)
		if err != nil {
			return nil, false, err
		}
		enrolled = map[int64]bool{}
		for id := range set {
			enrolled[id] = true
		}
	}
	if err := writers.Load(ctx, repo.ID); err != nil {
		return nil, false, err
	}
	reasons := make(map[int64]OwnerReason, len(users)) // the real reason, "-" for a person who can approve
	for _, u := range users {
		switch {
		case !u.IsActive:
			reasons[u.ID] = OwnerInactive
		case u.ProhibitLogin:
			reasons[u.ID] = OwnerProhibited
		case writers.Can(repo.ID, u.ID):
			reasons[u.ID] = "-"
		case enrolled != nil && !u.IsAdmin && !enrolled[u.ID]:
			reasons[u.ID] = OwnerTwoFactor
		default:
			reasons[u.ID] = OwnerNoWrite
		}
	}
	names := make(map[int64]string, len(users))
	for _, u := range users {
		names[u.ID] = u.Name
	}

	checks = make([]OwnerCheck, len(sets))
	cache := map[string]OwnerCheck{} // lines of one section share their owners
	total := 0
	for i, s := range sets {
		if total >= limit {
			more = true
			break
		}
		key := setKey(s)
		if c, ok := cache[key]; ok {
			checks[i] = c
			total += len(c.Marks)
			continue
		}
		c := OwnerCheck{}
		eligible := map[int64]bool{}
		ids := uniqIDs(s.UserIDs)
		slices.SortFunc(ids, func(a, b int64) int { return strings.Compare(names[a], names[b]) })
		for _, id := range ids {
			switch r, ok := reasons[id]; {
			case !ok: // unknown or left out
			case r == "-":
				eligible[id] = true
			default:
				c.Marks = append(c.Marks, OwnerMark{Name: names[id], Reason: v.reason(r)})
			}
		}
		for _, t := range s.Teams {
			if t.OrgID != repo.OwnerID {
				c.Marks = append(c.Marks, OwnerMark{Name: "@" + t.Name, Team: true, Foreign: true})
				continue
			}
			ms, ok := members[t.ID]
			if !ok {
				continue
			}
			n := 0
			for _, m := range ms {
				if reasons[m] == "-" {
					eligible[m] = true
					n++
				}
			}
			if n < len(ms) || len(ms) == 0 {
				c.Marks = append(c.Marks, OwnerMark{Name: "@" + t.Name, Team: true, Eligible: n})
			}
		}
		c.Eligible = len(eligible)
		cache[key] = c
		checks[i] = c
		total += len(c.Marks)
	}
	return checks, more, nil
}

func uniqIDs(ids []int64) []int64 {
	ids = slices.Clone(ids)
	slices.Sort(ids)
	return slices.Compact(ids)
}

func setKey(s OwnerSet) string {
	var b strings.Builder
	for _, id := range uniqIDs(s.UserIDs) {
		b.WriteString(strconv.FormatInt(id, 10) + ",")
	}
	b.WriteString("|")
	for _, t := range s.Teams {
		b.WriteString(strconv.FormatInt(t.ID, 10) + ",")
	}
	return b.String()
}

// maxOwnerMarks is how many owners a CODEOWNERS view lists.
const maxOwnerMarks = 200

// LineOwnerMarks are the owners of one CODEOWNERS line who can't approve.
type LineOwnerMarks struct {
	Line  int
	Marks []OwnerMark
}

// CodeOwnerLineMarks returns the lines of a CODEOWNERS file that name an owner who can't approve, in file order,
// and whether more were left out.
func CodeOwnerLineMarks(ctx context.Context, repo *repo_model.Repository, v OwnerViewer, lines []*issues_model.CodeOwnerRule) ([]LineOwnerMarks, bool, error) {
	sets := make([]OwnerSet, len(lines))
	for i, l := range lines {
		sets[i] = CodeOwnerSet(l)
	}
	checks, more, err := IneligibleOwners(ctx, repo, approvers.NewWriters(), v, sets, maxOwnerMarks)
	if err != nil {
		return nil, false, err
	}
	var out []LineOwnerMarks
	for i, c := range checks {
		if len(c.Marks) > 0 {
			out = append(out, LineOwnerMarks{Line: lines[i].Line, Marks: c.Marks})
		}
	}
	return out, more, nil
}
