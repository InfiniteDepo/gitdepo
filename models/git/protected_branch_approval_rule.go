// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/glob"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
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
	PathPatterns      string `xorm:"TEXT"`
	RequireCodeOwners bool   `xorm:"NOT NULL DEFAULT false"`
	// RequestReviews asks the users and teams of the rule for a review when a pull request opens, is retargeted
	// or starts to change a file of PathPatterns. RequiredCount may then be 0 (a rule that only requests).
	RequestReviews bool `xorm:"NOT NULL DEFAULT false"`
	// SourceBranchPattern is one glob for the head branch of a pull request, empty for any. It only limits who is
	// asked for a review, never RequiredCount: the author chooses the head branch name.
	SourceBranchPattern string             `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
	CreatedUnix         timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix         timeutil.TimeStamp `xorm:"updated"`

	paths *pathMatcher `xorm:"-"` // PathPatterns compiled once, by pathMatcher
}

// pathMatcher holds the compiled path patterns of a rule; invalid if a stored pattern is beyond the limits.
type pathMatcher struct {
	patterns []*regexp.Regexp
	invalid  bool
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
		case r.RequiredCount < 0 || (r.RequiredCount == 0 && !r.RequestReviews):
			return util.NewInvalidArgumentErrorf("approval rule %q needs at least 1 approval, or 0 with review requests", r.Name)
		case r.RequiredCount == 0 && r.RequireCodeOwners:
			// a rule without a count is never applicable, so it could not enforce the code owners
			return util.NewInvalidArgumentErrorf("approval rule %q: a rule that only requests reviews can't require code owners", r.Name)
		}
		r.SourceBranchPattern = strings.TrimSpace(r.SourceBranchPattern)
		if !r.RequestReviews {
			r.SourceBranchPattern = "" // it only limits requests
		}
		if err := ValidateGlobPattern(r.SourceBranchPattern, '/'); err != nil {
			return util.NewInvalidArgumentErrorf("approval rule %q: source branch pattern: %v", r.Name, err)
		}
		names[r.Name] = true
		if len(r.PathPatterns) > maxPathPatternBytes || strings.Count(r.PathPatterns, ";") >= maxPathPatterns {
			return util.NewInvalidArgumentErrorf("approval rule %q: at most %d path patterns and %d bytes are allowed", r.Name, maxPathPatterns, maxPathPatternBytes)
		}
		for expr := range strings.SplitSeq(r.PathPatterns, ";") {
			if err := ValidateGlobPattern(strings.TrimSpace(expr), '.', '/'); err != nil {
				return util.NewInvalidArgumentErrorf("approval rule %q: invalid path pattern %q: %v", r.Name, expr, err)
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

// Bounds of approval-rule path matching. A rule holds at most maxPathPatterns patterns of maxPathPatternBytes in
// total, and matching a rule against the changed files of a pull request may take at most maxPathMatchWork path
// bytes times patterns (10,000 files of 100 bytes against 8 patterns, under 0.4 s for the slowest patterns); beyond
// it the files are not matched.
const (
	maxPathPatterns     = 100
	maxPathPatternBytes = 8 << 10
	maxPathMatchWork    = 8 << 20
)

// AppliesTo returns true if the rule has no path patterns or one of the changed files matches. If the paths can't be
// matched (MatchesPaths), the rule applies: it fails closed.
func (r *ApprovalRule) AppliesTo(changedFiles []string) bool {
	matches, decided := r.MatchesPaths(changedFiles)
	return matches || !decided
}

// MatchesPaths returns whether the rule has no path patterns or one of the changed files matches, and whether that
// could be decided: not when a stored pattern is beyond the limits, or when matching the files would take more than
// the bound of approval-rule path matching.
func (r *ApprovalRule) MatchesPaths(changedFiles []string) (matches, decided bool) {
	m := r.pathMatcher()
	if m.invalid {
		return false, false
	}
	// patterns that don't compile to any glob must not switch the rule off
	if len(m.patterns) == 0 {
		return true, true
	}
	work := 0
	for _, f := range changedFiles {
		if work += len(f) * len(m.patterns); work > maxPathMatchWork {
			return false, false
		}
	}
	return slices.ContainsFunc(changedFiles, func(f string) bool {
		f = strings.ToLower(strings.TrimSpace(f))
		return slices.ContainsFunc(m.patterns, func(g *regexp.Regexp) bool { return g.MatchString(f) })
	}), true
}

// pathMatcher compiles the path patterns of the rule once.
func (r *ApprovalRule) pathMatcher() *pathMatcher {
	if r.paths != nil {
		return r.paths
	}
	r.paths = &pathMatcher{}
	// a stored rule beyond the limits is never matched
	if len(r.PathPatterns) > maxPathPatternBytes || strings.Count(r.PathPatterns, ";") >= maxPathPatterns {
		r.paths.invalid = true
		return r.paths
	}
	for expr := range strings.SplitSeq(strings.ToLower(r.PathPatterns), ";") {
		if expr = strings.TrimSpace(expr); expr == "" {
			continue
		}
		g, err := compileGlobPattern(expr, '.', '/')
		if err != nil {
			r.paths.invalid = true
			return r.paths
		}
		r.paths.patterns = append(r.paths.patterns, g)
	}
	return r.paths
}

// MatchesSourceBranch returns true if the rule has no source branch pattern or the branch matches it. It only decides
// who is asked for a review. A pattern beyond the limits of ValidateGlobPattern matches nothing: nobody is asked.
// For an AGit pull request the branch is "<pusher>/<topic>", as stored.
func (r *ApprovalRule) MatchesSourceBranch(branch string) bool {
	if r.SourceBranchPattern == "" {
		return true
	}
	g, err := compileGlobPattern(r.SourceBranchPattern, '/')
	return err == nil && g.MatchString(branch)
}

// Limits of a glob pattern of an approval rule, an input check. Approval-rule patterns use linear-time matching
// (modules/glob): the time grows linearly with the name.
const (
	maxGlobLength    = 255
	maxGlobWildcards = 6 // `*` and `?` characters, `**` counts 2
	maxGlobBraces    = 3 // `{a,b}` groups, which can't be nested
)

// ValidateGlobPattern checks that expr compiles with the separators and stays within the limits: its length, its
// wildcards and its `{...}` alternations. It refuses control and bidirectional control characters.
func ValidateGlobPattern(expr string, separators ...rune) error {
	_, err := compileGlobPattern(expr, separators...)
	return err
}

// compileGlobPattern checks the limits of ValidateGlobPattern once and compiles the pattern.
func compileGlobPattern(expr string, separators ...rune) (*regexp.Regexp, error) {
	if len(expr) > maxGlobLength {
		return nil, util.NewInvalidArgumentErrorf("pattern is longer than %d bytes", maxGlobLength)
	}
	wildcards, braces, depth := 0, 0, 0
	for _, c := range expr {
		switch {
		case unicode.IsControl(c) || strings.ContainsRune("\u061C\u200E\u200F\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069", c):
			return nil, util.NewInvalidArgumentErrorf("pattern holds a control character")
		case c == '*' || c == '?':
			wildcards++
		case c == '{':
			braces++
			if depth++; depth > 1 {
				return nil, util.NewInvalidArgumentErrorf("alternations can't be nested")
			}
		case c == '}':
			if depth--; depth < 0 {
				return nil, util.NewInvalidArgumentErrorf("unmatched }")
			}
		}
	}
	if wildcards > maxGlobWildcards || braces > maxGlobBraces {
		return nil, util.NewInvalidArgumentErrorf("pattern has more than %d wildcards or %d alternations", maxGlobWildcards, maxGlobBraces)
	}
	g, err := glob.Compile(expr, separators...)
	if err != nil {
		return nil, util.NewInvalidArgumentErrorf("%v", err)
	}
	return g, nil
}
