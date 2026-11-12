// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"context"
	"fmt"
	"slices"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/util"

	"xorm.io/builder"
)

// RuleMergeStyles are the merge styles a rule can allow, in the fixed order used for choosing a default.
var RuleMergeStyles = []repo_model.MergeStyle{
	repo_model.MergeStyleMerge, repo_model.MergeStyleRebase, repo_model.MergeStyleRebaseMerge,
	repo_model.MergeStyleSquash, repo_model.MergeStyleFastForwardOnly, repo_model.MergeStyleManuallyMerged,
}

// ErrInvalidRuleMergeStyles is returned for allowed merge styles that are unknown or a default outside them
var ErrInvalidRuleMergeStyles = util.NewInvalidArgumentErrorf("unknown merge style, or the default merge style is not one of the allowed styles")

// NormalizeMergeStyles checks the allowed merge styles and default of a rule and returns the list without
// duplicates in the fixed order (nil for none). A default needs a list that holds it.
func NormalizeMergeStyles(allowed []string, def string) ([]string, error) {
	var out []string
	for _, s := range RuleMergeStyles {
		if slices.Contains(allowed, string(s)) {
			out = append(out, string(s))
		}
	}
	for _, s := range allowed {
		if !slices.Contains(out, s) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidRuleMergeStyles, s)
		}
	}
	if def != "" && !slices.Contains(out, def) {
		return nil, fmt.Errorf("%w: default %q", ErrInvalidRuleMergeStyles, def)
	}
	return out, nil
}

// ValidateMergeStyles normalizes the rule's allowed merge styles and checks its default.
func (protectBranch *ProtectedBranch) ValidateMergeStyles() error {
	styles, err := NormalizeMergeStyles(protectBranch.AllowedMergeStyles, protectBranch.DefaultMergeStyle)
	protectBranch.AllowedMergeStyles = styles
	return err
}

// Level names the level of the rule: repository, project or organization.
func (protectBranch *ProtectedBranch) Level() string {
	return []string{"repository", "project", "organization"}[protectBranch.level()]
}

// MergeStyleConflicts returns the rules of others that set merge styles, belong to another level than rule and may
// match the same branches (equal patterns, or one pattern matches the other's name), whose styles share none with
// rule's: the pull requests into such branches can't be merged. Nothing is returned for a rule without styles.
func MergeStyleConflicts(rule *ProtectedBranch, others []*ProtectedBranch) []*ProtectedBranch {
	var out []*ProtectedBranch
	if len(rule.AllowedMergeStyles) == 0 {
		return out
	}
	for _, o := range others {
		if o.Level() == rule.Level() || len(o.AllowedMergeStyles) == 0 {
			continue
		}
		if !slices.ContainsFunc(o.AllowedMergeStyles, func(s string) bool { return slices.Contains(rule.AllowedMergeStyles, s) }) &&
			(o.RuleName == rule.RuleName || rule.Match(o.RuleName) || o.Match(rule.RuleName)) {
			out = append(out, o)
		}
	}
	return out
}

// MergeStyleShadowing returns the pairs (first, second) of rules of rule's level in all, one of them rule, that may
// match the same branches (equal patterns, or one pattern matches the other's name) and where second sets styles that
// differ from first's: only the first matching rule of a level counts, so for those branches second's styles are
// ignored (and first's, or the repository's setting, apply).
func MergeStyleShadowing(rule *ProtectedBranch, all []*ProtectedBranch) [][2]*ProtectedBranch {
	var same ProtectedBranchRules
	for _, o := range all {
		if o.level() == rule.level() {
			same = append(same, o)
		}
	}
	same.sort()
	var out [][2]*ProtectedBranch
	for i, first := range same {
		for _, second := range same[i+1:] {
			if (first.ID == rule.ID || second.ID == rule.ID) && len(second.AllowedMergeStyles) > 0 &&
				!slices.Equal(first.AllowedMergeStyles, second.AllowedMergeStyles) &&
				(first.Match(second.RuleName) || second.Match(first.RuleName)) {
				out = append(out, [2]*ProtectedBranch{first, second})
			}
		}
	}
	return out
}

// FindOtherLevelRules returns the rules of the organization at the levels other than groupID's (an organization
// rule with groupID 0: its projects' rules; a project rule: the organization's), for MergeStyleConflicts.
func FindOtherLevelRules(ctx context.Context, orgID, groupID int64) (ProtectedBranchRules, error) {
	var rules ProtectedBranchRules
	var cond builder.Cond = builder.Eq{"repo_id": 0, "org_id": orgID}
	if groupID == 0 {
		cond = builder.And(cond, builder.Neq{"group_id": 0})
	} else {
		cond = builder.And(cond, builder.Eq{"group_id": 0})
	}
	return rules, db.GetEngine(ctx).Where(cond).Find(&rules)
}
