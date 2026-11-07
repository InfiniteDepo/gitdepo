// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package branchworkflow

import (
	"context"
	"slices"
	"strings"
	"unicode/utf8"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"

	"xorm.io/builder"
)

// What decided the target branch of a new pull request.
const (
	TargetRuleType     = "type"     // the base of the head branch's type
	TargetRuleTarget   = "target"   // the default pull request target of the branching model
	TargetRuleFallback = "fallback" // the branch the rule named doesn't exist (or is not set): the development branch or the default branch
	TargetRuleDefault  = "default"  // the default branch
)

// ReleaseTypeName is the name of the type whose prefixes are the release prefixes.
const ReleaseTypeName = "Release"

// MatchType returns the type of a branch: the enabled type or release prefix with the longest prefix, which must be
// followed by at least one character. Release branches are created from the development branch.
func MatchType(m repo_model.BranchingModel, branch string) (repo_model.BranchType, bool) {
	var best repo_model.BranchType
	found := false
	consider := func(t repo_model.BranchType) {
		if strings.HasPrefix(branch, t.Prefix) && len(branch) > len(t.Prefix) && (!found || len(t.Prefix) > len(best.Prefix)) {
			best, found = t, true
		}
	}
	for _, p := range m.ReleasePrefixes {
		consider(repo_model.BranchType{Name: ReleaseTypeName, Prefix: p, Base: repo_model.BranchTypeBaseDevelopment})
	}
	for _, t := range m.Types {
		if !t.Off {
			consider(t)
		}
	}
	return best, found
}

// Target is the branch a new pull request targets when none was asked for, and why.
type Target struct {
	Branch   string
	Rule     string // one of the TargetRule constants
	TypeName string // the type of the head branch for TargetRuleType, and for TargetRuleFallback when it came from one
	Missing  string // the branch the rule named, for TargetRuleFallback
}

// ResolveTarget chooses the base branch for a pull request from head into baseRepo, using the branching model of
// baseRepo: the base of head's type, else the default pull request target, else the default branch. A named branch
// that doesn't exist falls back to the development branch, then the default branch. It only suggests: an explicit
// base always wins, so callers use it only when none was given. It reads the branching model and one branch row at most.
func ResolveTarget(ctx context.Context, baseRepo *repo_model.Repository, head string) (Target, error) {
	e, err := GetEffectiveModel(ctx, baseRepo)
	if err != nil {
		return Target{}, err
	}
	return ResolveTargetWith(ctx, baseRepo, e, head)
}

// ResolveTargetWith is ResolveTarget with the model of baseRepo already read, for callers that resolve several heads.
func ResolveTargetWith(ctx context.Context, baseRepo *repo_model.Repository, e EffectiveModel, head string) (Target, error) {
	dev := e.DevelopmentBranch(baseRepo)
	t := Target{Rule: TargetRuleDefault}
	if bt, ok := MatchType(e.Model, head); ok {
		t.Rule, t.TypeName = TargetRuleType, bt.Name
		switch bt.Base {
		case repo_model.BranchTypeBaseDevelopment:
			t.Branch = dev
		case repo_model.BranchTypeBaseProduction:
			t.Branch = e.Model.ProductionBranch
		default:
			t.Branch = bt.BaseBranch
		}
	} else if e.Model.DefaultPRTarget != "" {
		t.Rule, t.Branch = TargetRuleTarget, e.Model.DefaultPRTarget
	}
	exists := func(name string) (bool, error) {
		if name == baseRepo.DefaultBranch {
			return true, nil
		}
		b, err := git_model.GetBranch(ctx, baseRepo.ID, name)
		if git_model.IsErrBranchNotExist(err) {
			return false, nil
		}
		return err == nil && !b.IsDeleted, err
	}
	if t.Rule == TargetRuleDefault {
		t.Branch = baseRepo.DefaultBranch
		return t, nil
	}
	if ok, err := exists(t.Branch); ok || err != nil {
		return t, err
	}
	t.Missing, t.Rule, t.Branch = t.Branch, TargetRuleFallback, dev
	if ok, err := exists(dev); err != nil || !ok {
		t.Branch = baseRepo.DefaultBranch
		return t, err
	}
	return t, nil
}

// MissingBases returns the branches the model names as a base or default pull request target that don't exist in
// repo, in one query. Until they exist, pull requests fall back to the development branch.
func MissingBases(ctx context.Context, repo *repo_model.Repository, m repo_model.BranchingModel) ([]string, error) {
	var names []string
	add := func(n string) {
		if n != "" && n != repo.DefaultBranch && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	add(m.ProductionBranch)
	add(m.DefaultPRTarget)
	for _, t := range m.Types {
		add(t.BaseBranch)
	}
	if len(names) == 0 {
		return nil, nil
	}
	var found []string
	if err := db.GetEngine(ctx).Table("branch").Where("repo_id = ? AND is_deleted = ?", repo.ID, false).In("name", names).Cols("name").Find(&found); err != nil {
		return nil, err
	}
	return slices.DeleteFunc(names, func(n string) bool { return slices.Contains(found, n) }), nil
}

// CountUntyped counts, for every type that is turned off, the existing branches that would have no type: those
// whose name starts with its prefix and that no enabled type or release prefix matches. One query reads their names.
func CountUntyped(ctx context.Context, repo *repo_model.Repository, m repo_model.BranchingModel) (map[string]int, error) {
	cond := builder.NewCond()
	for _, t := range m.Types {
		if t.Off {
			cond = cond.Or(builder.Expr("SUBSTR(name, 1, ?) = ?", utf8.RuneCountInString(t.Prefix), t.Prefix))
		}
	}
	if !cond.IsValid() {
		return map[string]int{}, nil
	}
	var names []string
	if err := db.GetEngine(ctx).Table("branch").Where("repo_id = ? AND is_deleted = ?", repo.ID, false).And(cond).Cols("name").Limit(10000).Find(&names); err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, n := range names {
		if _, typed := MatchType(m, n); typed {
			continue
		}
		var best *repo_model.BranchType
		for i, t := range m.Types {
			if t.Off && strings.HasPrefix(n, t.Prefix) && len(n) > len(t.Prefix) && (best == nil || len(t.Prefix) > len(best.Prefix)) {
				best = &m.Types[i]
			}
		}
		if best != nil {
			counts[best.Prefix]++
		}
	}
	return counts, nil
}
