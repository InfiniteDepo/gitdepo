// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package pull

import (
	"testing"

	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"

	"github.com/stretchr/testify/assert"
)

func styleRule(repoID, groupID, orgID int64, name, def string, styles ...string) *git_model.ProtectedBranch {
	return &git_model.ProtectedBranch{RepoID: repoID, GroupID: groupID, OrgID: orgID, RuleName: name, AllowedMergeStyles: styles, DefaultMergeStyle: def}
}

func TestResolveMergeStyles(t *testing.T) {
	cfg := &repo_model.PullRequestsConfig{AllowMerge: true, AllowSquash: true, DefaultMergeStyle: repo_model.MergeStyleSquash}
	ms := func(s ...string) []repo_model.MergeStyle {
		out := []repo_model.MergeStyle{}
		for _, v := range s {
			out = append(out, repo_model.MergeStyle(v))
		}
		return out
	}
	for _, c := range []struct {
		name    string
		rules   []*git_model.ProtectedBranch
		allowed []repo_model.MergeStyle
		def     repo_model.MergeStyle
		nRules  int
	}{
		{"no rules: the repository setting and its default", nil, ms("merge", "squash"), "squash", 0},
		{"rules without styles: the repository setting", []*git_model.ProtectedBranch{styleRule(1, 0, 0, "main", "")}, ms("merge", "squash"), "squash", 0},
		{"a rule replaces the repository setting, even to turn a style on", []*git_model.ProtectedBranch{styleRule(1, 0, 0, "main", "", "rebase", "fast-forward-only")}, ms("rebase", "fast-forward-only"), "rebase", 1},
		{"the rule's default", []*git_model.ProtectedBranch{styleRule(1, 0, 0, "main", "squash", "merge", "squash")}, ms("merge", "squash"), "squash", 1},
		{
			"intersection across levels, default of the most specific rule",
			[]*git_model.ProtectedBranch{styleRule(1, 0, 0, "main", "squash", "merge", "squash", "rebase"), styleRule(0, 0, 5, "main", "merge", "squash", "rebase", "fast-forward-only")},
			ms("rebase", "squash"), "squash", 2,
		},
		{
			"the most specific default is outside the intersection: first allowed in the fixed order, not a less specific default",
			[]*git_model.ProtectedBranch{styleRule(1, 0, 0, "main", "merge", "merge", "squash"), styleRule(0, 0, 5, "main", "squash", "squash", "rebase")},
			ms("squash"), "squash", 2,
		},
		{
			"a more specific rule without a default leaves it to the next level",
			[]*git_model.ProtectedBranch{styleRule(1, 0, 0, "main", "", "merge", "squash"), styleRule(0, 7, 5, "main", "squash", "squash", "merge")},
			ms("merge", "squash"), "squash", 2,
		},
		{
			"empty intersection: nothing allowed, no default",
			[]*git_model.ProtectedBranch{styleRule(1, 0, 0, "main", "", "merge"), styleRule(0, 0, 5, "ma*", "", "squash")},
			ms(), "", 2,
		},
		{"a rule without styles is skipped among rules that set them", []*git_model.ProtectedBranch{styleRule(1, 0, 0, "main", ""), styleRule(0, 0, 5, "main", "", "squash")}, ms("squash"), "squash", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := ResolveMergeStyles(c.rules, cfg)
			assert.Equal(t, c.allowed, append([]repo_model.MergeStyle{}, p.Allowed...))
			assert.Equal(t, c.def, p.Default)
			assert.Len(t, p.Rules, c.nRules)
		})
	}

	t.Run("nothing allowed by the repository and no rule", func(t *testing.T) {
		p := ResolveMergeStyles(nil, &repo_model.PullRequestsConfig{})
		assert.Empty(t, p.Allowed)
		assert.Empty(t, p.Default)
	})
	t.Run("refusal names the levels and patterns", func(t *testing.T) {
		p := ResolveMergeStyles([]*git_model.ProtectedBranch{styleRule(1, 0, 0, "main", "", "merge"), styleRule(0, 0, 5, "ma*", "", "squash")}, cfg)
		assert.Equal(t, `repository rule "main" (merge), organization rule "ma*" (squash)`, p.RulesText())
	})
}
