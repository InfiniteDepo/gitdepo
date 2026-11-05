// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"github.com/gobwas/glob"
	"xorm.io/builder"
)

// MaxApprovalRules is the number of approval rules a protected branch rule can have.
const MaxApprovalRules = 20

// ApprovalRule is a named approval requirement of a protected branch rule. Every applicable rule must be
// satisfied before a pull request can be merged, on top of the RequiredApprovals of the protected branch rule.
type ApprovalRule struct {
	ID                int64   `xorm:"pk autoincr"`
	ProtectedBranchID int64   `xorm:"INDEX UNIQUE(s) NOT NULL"`
	Name              string  `xorm:"VARCHAR(255) UNIQUE(s) NOT NULL"`
	RequiredCount     int64   `xorm:"NOT NULL DEFAULT 1"`
	UserIDs           []int64 `xorm:"JSON TEXT"`
	TeamIDs           []int64 `xorm:"JSON TEXT"`
	// PathPatterns is a semicolon separated list of globs like ProtectedBranch.ProtectedFilePatterns.
	// The rule only applies when the pull request changes a matching file.
	PathPatterns      string             `xorm:"TEXT"`
	RequireCodeOwners bool               `xorm:"NOT NULL DEFAULT false"`
	CreatedUnix       timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix       timeutil.TimeStamp `xorm:"updated"`
}

func init() {
	db.RegisterModel(new(ApprovalRule))
}

// GetApprovalRules returns the approval rules of a protected branch rule, oldest first.
func GetApprovalRules(ctx context.Context, protectedBranchID int64) ([]*ApprovalRule, error) {
	rules := make([]*ApprovalRule, 0, 2)
	return rules, db.GetEngine(ctx).Where("protected_branch_id = ?", protectedBranchID).OrderBy("id").Find(&rules)
}

// SetApprovalRules replaces the approval rules of a protected branch rule. Users without write access to
// the repository and teams without access to it are dropped, an invalid rule returns util.ErrInvalidArgument.
func SetApprovalRules(ctx context.Context, repo *repo_model.Repository, protectedBranchID int64, rules []*ApprovalRule) error {
	return setApprovalRules(ctx, protectedBranchID, rules, func(r *ApprovalRule) (err error) {
		if r.UserIDs, err = updateUserWhitelist(ctx, repo, nil, r.UserIDs); err != nil {
			return err
		}
		r.TeamIDs, err = updateTeamWhitelist(ctx, repo, nil, r.TeamIDs)
		return err
	})
}

// setApprovalRules validates the rules, checks their approvers with checkApprovers and replaces the rules of the protected branch rule.
func setApprovalRules(ctx context.Context, protectedBranchID int64, rules []*ApprovalRule, checkApprovers func(*ApprovalRule) error) error {
	if len(rules) > MaxApprovalRules {
		return util.NewInvalidArgumentErrorf("at most %d approval rules are allowed", MaxApprovalRules)
	}
	names := make(map[string]bool, len(rules))
	for _, r := range rules {
		r.ID, r.ProtectedBranchID, r.Name = 0, protectedBranchID, strings.TrimSpace(r.Name)
		switch {
		case r.Name == "" || len(r.Name) > 255:
			return util.NewInvalidArgumentErrorf("an approval rule needs a name of at most 255 characters")
		case names[r.Name]:
			return util.NewInvalidArgumentErrorf("approval rule %q exists twice", r.Name)
		case r.RequiredCount < 1:
			return util.NewInvalidArgumentErrorf("approval rule %q needs at least 1 approval", r.Name)
		}
		names[r.Name] = true
		for expr := range strings.SplitSeq(r.PathPatterns, ";") {
			if _, err := glob.Compile(strings.TrimSpace(expr), '.', '/'); err != nil {
				return util.NewInvalidArgumentErrorf("approval rule %q: invalid path pattern %q", r.Name, expr)
			}
		}
		if err := checkApprovers(r); err != nil {
			return err
		}
		if len(r.UserIDs) == 0 && len(r.TeamIDs) == 0 && !r.RequireCodeOwners {
			return util.NewInvalidArgumentErrorf("approval rule %q needs approvers or the code owner option", r.Name)
		}
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		if _, err := db.GetEngine(ctx).Where("protected_branch_id = ?", protectedBranchID).Delete(new(ApprovalRule)); err != nil {
			return err
		}
		for _, r := range rules {
			if _, err := db.GetEngine(ctx).Insert(r); err != nil {
				return err
			}
		}
		return nil
	})
}

// HasApprovers returns true if the rule names users or teams. Without them any user able to approve is eligible,
// which only happens with RequireCodeOwners.
func (r *ApprovalRule) HasApprovers() bool {
	return len(r.UserIDs) > 0 || len(r.TeamIDs) > 0
}

// IsApprover returns true if the user is listed or a member of a listed team. Write access is checked by the caller.
func (r *ApprovalRule) IsApprover(ctx context.Context, userID int64) (bool, error) {
	if slices.Contains(r.UserIDs, userID) {
		return true, nil
	}
	return organization.IsUserInTeams(ctx, userID, r.TeamIDs)
}

// AppliesTo returns true if the rule has no path patterns or one of the changed files matches.
func (r *ApprovalRule) AppliesTo(changedFiles []string) bool {
	patterns := getFilePatterns(r.PathPatterns)
	// patterns that don't compile to any glob must not switch the rule off
	if len(patterns) == 0 {
		return true
	}
	return slices.ContainsFunc(changedFiles, func(f string) bool { return MatchesAnyGlob(patterns, f) })
}

// MatchesAnyGlob returns true if the lowercased path matches one of the patterns.
func MatchesAnyGlob(patterns []glob.Glob, path string) bool {
	lpath := strings.ToLower(strings.TrimSpace(path))
	return slices.ContainsFunc(patterns, func(g glob.Glob) bool { return g.Match(lpath) })
}

// listingChunk is how many IDs one query of FindApprovalRulesListing matches: every ID is four LIKE terms, and the
// query builder refuses a condition that is too deep.
const listingChunk = 50

// FindApprovalRulesListing returns the approval rules, of every level, that list one of the users or one of the
// teams. The JSON lists are matched as text first (they are stored as `[1,2,3]`), in queries of listingChunk IDs
// each, and checked exactly after, so a rule can't be matched by an ID that is only part of another one.
func FindApprovalRulesListing(ctx context.Context, userIDs, teamIDs []int64) ([]*ApprovalRule, error) {
	type term struct {
		col string
		id  int64
	}
	var terms []term
	for _, id := range userIDs {
		terms = append(terms, term{"user_i_ds", id})
	}
	for _, id := range teamIDs {
		terms = append(terms, term{"team_i_ds", id})
	}
	byID := map[int64]*ApprovalRule{}
	for chunk := range slices.Chunk(terms, listingChunk) {
		cond := builder.NewCond()
		for _, t := range chunk {
			s := strconv.FormatInt(t.id, 10)
			cond = cond.Or(builder.Like{t.col, "[" + s + ","}).Or(builder.Like{t.col, "," + s + ","}).
				Or(builder.Like{t.col, "," + s + "]"}).Or(builder.Eq{t.col: "[" + s + "]"})
		}
		var found []*ApprovalRule
		if err := db.GetEngine(ctx).Where(cond).Find(&found); err != nil {
			return nil, err
		}
		for _, r := range found {
			byID[r.ID] = r
		}
	}
	rules := make([]*ApprovalRule, 0, len(byID))
	for _, r := range byID {
		if slices.ContainsFunc(userIDs, func(id int64) bool { return slices.Contains(r.UserIDs, id) }) ||
			slices.ContainsFunc(teamIDs, func(id int64) bool { return slices.Contains(r.TeamIDs, id) }) {
			rules = append(rules, r)
		}
	}
	slices.SortFunc(rules, func(a, b *ApprovalRule) int { return int(a.ID - b.ID) })
	return rules, nil
}
