// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"forgejo.org/models"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
)

// MergeStylePolicy is the merge styles a pull request into a branch may use.
type MergeStylePolicy struct {
	Allowed []repo_model.MergeStyle // in the fixed order of git_model.RuleMergeStyles; empty refuses every merge
	Default repo_model.MergeStyle   // "" when nothing is allowed
	// Rules are the matching rules that set styles, most specific first (repository, project, organization); none
	// means the repository's Pull requests setting decided
	Rules []*git_model.ProtectedBranch
}

// Allows returns if style is allowed.
func (p *MergeStylePolicy) Allows(style repo_model.MergeStyle) bool {
	return slices.Contains(p.Allowed, style)
}

// RulesText names the rules that set styles with their styles, like `repository rule "main" (squash)`.
func (p *MergeStylePolicy) RulesText() string {
	parts := make([]string, 0, len(p.Rules))
	for _, r := range p.Rules {
		parts = append(parts, fmt.Sprintf("%s rule %q (%s)", r.Level(), r.RuleName, strings.Join(r.AllowedMergeStyles, ", ")))
	}
	return strings.Join(parts, ", ")
}

// ResolveMergeStyles is the one decision on merge styles. rules are the matching rules as
// git_model.GetMatchedProtectedBranchRules returns them. The allowed styles are the intersection of the lists of the
// rules that set one; without such a rule they are the repository's own (cfg). The default is the first non-empty
// default of the rules, most specific first, if it is allowed (the repository's default without rules), otherwise the
// first allowed style in the fixed order.
func ResolveMergeStyles(rules []*git_model.ProtectedBranch, cfg *repo_model.PullRequestsConfig) *MergeStylePolicy {
	p := &MergeStylePolicy{}
	def := repo_model.MergeStyle("")
	for _, r := range rules {
		if len(r.AllowedMergeStyles) == 0 {
			continue
		}
		p.Rules = append(p.Rules, r)
		if def == "" {
			def = repo_model.MergeStyle(r.DefaultMergeStyle)
		}
	}
	if len(p.Rules) == 0 {
		def = cfg.GetDefaultMergeStyle()
	}
	for _, s := range git_model.RuleMergeStyles {
		if len(p.Rules) == 0 && cfg.IsMergeStyleAllowed(s) ||
			len(p.Rules) > 0 && !slices.ContainsFunc(p.Rules, func(r *git_model.ProtectedBranch) bool { return !slices.Contains(r.AllowedMergeStyles, string(s)) }) {
			p.Allowed = append(p.Allowed, s)
		}
	}
	switch {
	case p.Allows(def):
		p.Default = def
	case len(p.Allowed) > 0:
		p.Default = p.Allowed[0]
	}
	return p
}

// MergeStylesOf returns the policy for pull requests into branch of repo.
func MergeStylesOf(ctx context.Context, repo *repo_model.Repository, branch string) (*MergeStylePolicy, error) {
	rules, err := git_model.GetMatchedProtectedBranchRules(ctx, repo.ID, branch)
	if err != nil {
		return nil, err
	}
	return mergeStylesWith(ctx, repo, rules)
}

func mergeStylesWith(ctx context.Context, repo *repo_model.Repository, rules []*git_model.ProtectedBranch) (*MergeStylePolicy, error) {
	prUnit, err := repo.GetUnit(ctx, unit.TypePullRequests)
	if err != nil {
		return nil, err
	}
	return ResolveMergeStyles(rules, prUnit.PullRequestsConfig()), nil
}

// CheckMergeStyleWithRules returns models.ErrInvalidMergeStyle if style is not allowed for the base branch of pr, whose
// matching rules are rules. Every merge path goes through it (CheckPullMergeable, Merge, MergedManually, the merge
// queue passes); an admin's force merge does not skip it.
func CheckMergeStyleWithRules(ctx context.Context, pr *issues_model.PullRequest, rules []*git_model.ProtectedBranch, style repo_model.MergeStyle) error {
	if err := pr.LoadBaseRepo(ctx); err != nil {
		return err
	}
	p, err := mergeStylesWith(ctx, pr.BaseRepo, rules)
	if err != nil {
		return err
	}
	if !p.Allows(style) {
		return models.ErrInvalidMergeStyle{ID: pr.BaseRepoID, Style: style, Rules: p.RulesText()}
	}
	return nil
}

// CheckMergeStyle is CheckMergeStyleWithRules with the rules read now.
func CheckMergeStyle(ctx context.Context, pr *issues_model.PullRequest, style repo_model.MergeStyle) error {
	rules, err := git_model.GetMatchedProtectedBranchRules(ctx, pr.BaseRepoID, pr.BaseBranch)
	if err != nil {
		return err
	}
	return CheckMergeStyleWithRules(ctx, pr, rules, style)
}
