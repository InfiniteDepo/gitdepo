// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/modules/timeutil"

	"github.com/gobwas/glob"
)

// PushRuleMaxPatternLength caps each regex and the banned file pattern list.
// Go's regexp is linear time, so a length cap is enough against ReDoS.
const PushRuleMaxPatternLength = 1024

// PushRuleMaxPRTitleMessageLength caps the custom message of the pull request title rule.
const PushRuleMaxPRTitleMessageLength = 255

// ErrPRTitleRule is returned when a pull request title violates the title rule.
// An empty Message means the default text; Invalid means the stored rule does not compile.
type ErrPRTitleRule struct {
	Message string
	Invalid bool
}

func (err *ErrPRTitleRule) Error() string {
	if err.Invalid {
		return "pull request title rule is invalid"
	}
	if err.Message == "" {
		return "pull request title does not follow the title rule"
	}
	return "pull request title rule: " + err.Message
}

// IsErrPRTitleRule checks if an error is an ErrPRTitleRule.
func IsErrPRTitleRule(err error) bool {
	_, ok := err.(*ErrPRTitleRule)
	return ok
}

// PushRule holds the push rules of a repository. The pre-receive hook checks them on new commits.
type PushRule struct {
	ID                         int64  `xorm:"pk autoincr"`
	RepoID                     int64  `xorm:"UNIQUE NOT NULL"`
	CommitMessageRegex         string `xorm:"TEXT"`
	CommitMessageBannedRegex   string `xorm:"TEXT"`
	BranchNameRegex            string `xorm:"TEXT"`
	RequireVerifiedAuthorEmail bool   `xorm:"NOT NULL DEFAULT false"`
	MaxFileSizeMB              int64  `xorm:"NOT NULL DEFAULT 0"`
	// semicolon separated globs, matched against the lower-case path and its basename
	BannedFilePatterns string `xorm:"TEXT"`

	PRTitleRegex       string `xorm:"TEXT"`
	PRTitleBannedRegex string `xorm:"TEXT"`
	PRTitleMessage     string `xorm:"VARCHAR(255)"`
	// semicolon separated globs of base branches (case sensitive), empty = all
	PRTitleBranches   string `xorm:"TEXT"`
	PRTitleBlockMerge bool   `xorm:"NOT NULL DEFAULT false"`

	CommitMessageRe       *regexp.Regexp `xorm:"-"`
	CommitMessageBannedRe *regexp.Regexp `xorm:"-"`
	BranchNameRe          *regexp.Regexp `xorm:"-"`
	BannedFileGlobs       []glob.Glob    `xorm:"-"`
	PRTitleRe             *regexp.Regexp `xorm:"-"`
	PRTitleBannedRe       *regexp.Regexp `xorm:"-"`
	PRTitleBranchGlobs    []glob.Glob    `xorm:"-"`

	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

func init() {
	db.RegisterModel(new(PushRule))
}

func compilePushRuleRegex(re **regexp.Regexp, s string) (err error) {
	*re = nil
	if s == "" {
		return nil
	}
	if len(s) > PushRuleMaxPatternLength {
		return fmt.Errorf("regular expression is longer than %d characters", PushRuleMaxPatternLength)
	}
	*re, err = regexp.Compile(s)
	return err
}

// Compile validates the rule and compiles its patterns. Unlike protected file patterns, an invalid glob is an error.
func (r *PushRule) Compile() (err error) {
	if r.MaxFileSizeMB < 0 {
		return fmt.Errorf("maximum file size must not be negative")
	}
	if err = compilePushRuleRegex(&r.CommitMessageRe, r.CommitMessageRegex); err != nil {
		return err
	}
	if err = compilePushRuleRegex(&r.CommitMessageBannedRe, r.CommitMessageBannedRegex); err != nil {
		return err
	}
	if err = compilePushRuleRegex(&r.BranchNameRe, r.BranchNameRegex); err != nil {
		return err
	}
	if len(r.BannedFilePatterns) > PushRuleMaxPatternLength {
		return fmt.Errorf("banned file patterns are longer than %d characters", PushRuleMaxPatternLength)
	}
	r.BannedFileGlobs = nil
	for expr := range strings.SplitSeq(strings.ToLower(r.BannedFilePatterns), ";") {
		if expr = strings.TrimSpace(expr); expr == "" {
			continue
		}
		g, err := glob.Compile(expr, '/')
		if err != nil {
			return fmt.Errorf("invalid glob %q: %w", expr, err)
		}
		r.BannedFileGlobs = append(r.BannedFileGlobs, g)
	}
	return r.CompilePRTitle()
}

// CompilePRTitle validates and compiles only the pull request title fields.
func (r *PushRule) CompilePRTitle() (err error) {
	if err = compilePushRuleRegex(&r.PRTitleRe, r.PRTitleRegex); err != nil {
		return err
	}
	if err = compilePushRuleRegex(&r.PRTitleBannedRe, r.PRTitleBannedRegex); err != nil {
		return err
	}
	if len(r.PRTitleMessage) > PushRuleMaxPRTitleMessageLength {
		return fmt.Errorf("pull request title message is longer than %d characters", PushRuleMaxPRTitleMessageLength)
	}
	if len(r.PRTitleBranches) > PushRuleMaxPatternLength {
		return fmt.Errorf("pull request title branches are longer than %d characters", PushRuleMaxPatternLength)
	}
	r.PRTitleBranchGlobs = nil
	for expr := range strings.SplitSeq(r.PRTitleBranches, ";") {
		if expr = strings.TrimSpace(expr); expr == "" {
			continue
		}
		g, err := glob.Compile(expr, '/')
		if err != nil {
			return fmt.Errorf("invalid glob %q: %w", expr, err)
		}
		r.PRTitleBranchGlobs = append(r.PRTitleBranchGlobs, g)
	}
	return nil
}

// CheckPRTitle returns an *ErrPRTitleRule if the title violates the rule for a pull request into baseBranch.
// A draft title skips the must-match regex, never the must-not-match one. Call Compile first.
func (r *PushRule) CheckPRTitle(baseBranch, title string, isDraft bool) error {
	if len(r.PRTitleBranchGlobs) > 0 && !slices.ContainsFunc(r.PRTitleBranchGlobs, func(g glob.Glob) bool { return g.Match(baseBranch) }) {
		return nil
	}
	title = strings.TrimSpace(title)
	if (r.PRTitleRe != nil && !isDraft && !r.PRTitleRe.MatchString(title)) ||
		(r.PRTitleBannedRe != nil && r.PRTitleBannedRe.MatchString(title)) {
		return &ErrPRTitleRule{Message: r.PRTitleMessage}
	}
	return nil
}

// IsBannedFile reports whether the path or its basename matches a banned glob. Call Compile first.
func (r *PushRule) IsBannedFile(filePath string) bool {
	lpath := strings.ToLower(filePath)
	for _, g := range r.BannedFileGlobs {
		if g.Match(lpath) || g.Match(path.Base(lpath)) {
			return true
		}
	}
	return false
}

// GetPushRule returns the push rule of the repository, or nil if it has none.
func GetPushRule(ctx context.Context, repoID int64) (*PushRule, error) {
	rule := &PushRule{RepoID: repoID}
	if has, err := db.GetEngine(ctx).Get(rule); err != nil || !has {
		return nil, err
	}
	return rule, nil
}

// UpsertPushRule creates or replaces the push rule of rule.RepoID, and records repo.push_rule.created or the
// settings that differ (repo.push_rule.updated).
func UpsertPushRule(ctx context.Context, rule *PushRule) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		existing, err := GetPushRule(ctx, rule.RepoID)
		if err != nil {
			return err
		}
		ev := audit_model.Event{TargetType: "push_rule", Data: rule.AuditFields()}
		if existing == nil {
			if _, err = db.GetEngine(ctx).Insert(rule); err != nil {
				return err
			}
			ev.TargetID = rule.ID
			return recordRepoRule(ctx, "repo.push_rule.created", rule.RepoID, ev)
		}
		rule.ID, ev.TargetID = existing.ID, existing.ID
		if ev.Data = audit_model.Changes(existing.AuditFields(), rule.AuditFields()); ev.Data != nil {
			if err := recordRepoRule(ctx, "repo.push_rule.updated", rule.RepoID, ev); err != nil {
				return err
			}
		}
		_, err = db.GetEngine(ctx).ID(rule.ID).AllCols().Update(rule)
		return err
	})
}
