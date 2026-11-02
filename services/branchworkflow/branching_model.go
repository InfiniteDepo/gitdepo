// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package branchworkflow

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/json"
	"forgejo.org/modules/optional"
)

const (
	keyBranchingModel       = "branch_workflow.branching_model"
	keyBranchingModelLocked = "branch_workflow.branching_model_locked"

	maxReleasePrefixes   = 10
	maxReleasePrefixLen  = 100
	maxDevelopmentBranch = 255
	maxVersionPartDigits = 9
)

// ErrInvalidBranchingModel is returned for a development branch or release prefix that can't be part of a branch name.
type ErrInvalidBranchingModel struct {
	Value string
}

func (e ErrInvalidBranchingModel) Error() string {
	return fmt.Sprintf("invalid branch name or prefix %q", e.Value)
}

// ErrTooManyReleasePrefixes is returned for more than maxReleasePrefixes prefixes.
var ErrTooManyReleasePrefixes = fmt.Errorf("at most %d release prefixes", maxReleasePrefixes)

// NormalizeBranchingModel trims the values, drops empty and repeated prefixes and checks the rest.
func NormalizeBranchingModel(m *repo_model.BranchingModel) (*repo_model.BranchingModel, error) {
	out := &repo_model.BranchingModel{DevelopmentBranch: strings.TrimSpace(m.DevelopmentBranch), ProductionBranch: strings.TrimSpace(m.ProductionBranch), MergeForward: m.MergeForward, MergeForwardNeverBypass: m.MergeForwardNeverBypass, MergeForwardAnyoneMaySkip: m.MergeForwardAnyoneMaySkip}
	for _, b := range []string{out.DevelopmentBranch, out.ProductionBranch} {
		if b != "" && (len(b) > maxDevelopmentBranch || !git.IsValidRefPattern(b)) {
			return nil, ErrInvalidBranchingModel{b}
		}
	}
	if out.ProductionBranch != "" && out.ProductionBranch == out.DevelopmentBranch {
		return nil, ErrInvalidBranchingModel{out.ProductionBranch}
	}
	for _, p := range m.ReleasePrefixes {
		p = strings.TrimSpace(p)
		if p == "" || slices.Contains(out.ReleasePrefixes, p) {
			continue
		}
		// the prefix must be the start of a valid branch name; a comma would break the web form's list
		if len(p) > maxReleasePrefixLen || strings.Contains(p, ",") || !git.IsValidRefPattern(p+"1") {
			return nil, ErrInvalidBranchingModel{p}
		}
		out.ReleasePrefixes = append(out.ReleasePrefixes, p)
	}
	if len(out.ReleasePrefixes) > maxReleasePrefixes {
		return nil, ErrTooManyReleasePrefixes
	}
	return out, nil
}

// parseVersion reads the part of a release branch name after its prefix: numbers separated by dots, optionally after a "v".
func parseVersion(s string) ([]uint64, bool) {
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	v := make([]uint64, len(parts))
	for i, p := range parts {
		if p == "" || len(p) > maxVersionPartDigits || strings.Trim(p, "0123456789") != "" {
			return nil, false
		}
		v[i], _ = strconv.ParseUint(p, 10, 64)
	}
	return v, true
}

// Chain is what the branching model makes of a repository's branches.
type Chain struct {
	Development string   // the branch every cascade ends in
	Releases    []string // the release branches, in version order
	Ignored     []string // branches with a release prefix whose rest is not a version
	Production  string   // the production branch, "" when there is none

	DevelopmentMissing bool // the development branch is not among the branches
	ProductionMissing  bool // the production branch is not among the branches
}

// BuildChain orders the release branches by version. All prefixes share one order; equal versions follow the order
// of the prefixes. A branch belongs to its longest matching prefix. The development branch is never a release branch.
func BuildChain(m repo_model.BranchingModel, development string, branches []string) Chain {
	type release struct {
		name    string
		prefix  int
		version []uint64
	}
	c := Chain{Development: development, DevelopmentMissing: true}
	if m.ProductionBranch != "" && m.ProductionBranch != development {
		c.Production, c.ProductionMissing = m.ProductionBranch, true
	}
	var releases []release
	for _, b := range branches {
		if b == development {
			c.DevelopmentMissing = false
			continue
		}
		if b == c.Production {
			c.ProductionMissing = false
			continue
		}
		prefix := -1
		for i, p := range m.ReleasePrefixes {
			if strings.HasPrefix(b, p) && (prefix < 0 || len(p) > len(m.ReleasePrefixes[prefix])) {
				prefix = i
			}
		}
		if prefix < 0 {
			continue
		}
		if v, ok := parseVersion(b[len(m.ReleasePrefixes[prefix]):]); ok {
			releases = append(releases, release{b, prefix, v})
		} else {
			c.Ignored = append(c.Ignored, b)
		}
	}
	slices.SortFunc(releases, func(a, b release) int {
		return cmp.Or(slices.Compare(a.version, b.version), cmp.Compare(a.prefix, b.prefix), strings.Compare(a.name, b.name))
	})
	for _, r := range releases {
		c.Releases = append(c.Releases, r.name)
	}
	slices.Sort(c.Ignored)
	return c
}

// Forward returns the branches a merge into branch is carried to: every later release branch, then the development
// branch; from the production branch only the development branch. It is empty for any other branch.
func (c Chain) Forward(branch string) []string {
	if c.Production != "" && branch == c.Production && !c.ProductionMissing {
		return []string{c.Development}
	}
	i := slices.Index(c.Releases, branch)
	if i < 0 {
		return nil
	}
	return append(slices.Clone(c.Releases[i+1:]), c.Development)
}

// EffectiveModel is the branching model that applies to a repository and where it comes from.
type EffectiveModel struct {
	Model      repo_model.BranchingModel
	Source     string // SourceNone when neither the repository nor its organization has one
	Locked     bool
	SetBy      string                     // name of the organization when Source is SourceOrg
	Configured *repo_model.BranchingModel // the repository's own value, nil when it inherits
	Org        *repo_model.BranchingModel // the organization's value, nil when it has none
}

// ResolveModel combines the levels as Resolve does. There is no instance default: without one, no branch is a
// release branch.
func ResolveModel(org *repo_model.BranchingModel, orgLocked bool, repo *repo_model.BranchingModel) EffectiveModel {
	e := EffectiveModel{Source: SourceNone, Configured: repo, Org: org}
	switch {
	case org != nil && orgLocked:
		e.Model, e.Source, e.Locked = *org, SourceOrg, true
	case repo != nil:
		e.Model, e.Source = *repo, SourceRepo
	case org != nil:
		e.Model, e.Source = *org, SourceOrg
	}
	return e
}

// GetOrgModel returns the organization's branching model, nil when it has none, and its lock.
func GetOrgModel(ctx context.Context, org *user_model.User) (*repo_model.BranchingModel, bool, error) {
	stored, err := user_model.GetSettings(ctx, org.ID, []string{keyBranchingModel, keyBranchingModelLocked})
	if err != nil {
		return nil, false, err
	}
	var m *repo_model.BranchingModel
	if s := stored[keyBranchingModel]; s != nil {
		m = &repo_model.BranchingModel{}
		if err := json.Unmarshal([]byte(s.SettingValue), m); err != nil {
			return nil, false, err
		}
	}
	return m, m != nil && stored[keyBranchingModelLocked] != nil && stored[keyBranchingModelLocked].SettingValue == "true", nil
}

// GetEffectiveModel is the only way to read the branching model that applies to a repository.
func GetEffectiveModel(ctx context.Context, repo *repo_model.Repository) (EffectiveModel, error) {
	if err := repo.LoadOwner(ctx); err != nil {
		return EffectiveModel{}, err
	}
	var org *repo_model.BranchingModel
	orgLocked := false
	if repo.Owner.IsOrganization() {
		var err error
		if org, orgLocked, err = GetOrgModel(ctx, repo.Owner); err != nil {
			return EffectiveModel{}, err
		}
	}
	var own *repo_model.BranchingModel
	if u, err := repo.GetUnit(ctx, unit.TypePullRequests); err == nil {
		own = u.PullRequestsConfig().BranchingModel
	}
	e := ResolveModel(org, orgLocked, own)
	if e.Source == SourceOrg {
		e.SetBy = repo.Owner.Name
	}
	return e, nil
}

// DevelopmentBranch is the branch the model names, else the repository's default branch.
func (e EffectiveModel) DevelopmentBranch(repo *repo_model.Repository) string {
	return cmp.Or(e.Model.DevelopmentBranch, repo.DefaultBranch)
}

// GetChain applies the model to the repository's branches.
func GetChain(ctx context.Context, repo *repo_model.Repository, e EffectiveModel) (Chain, error) {
	if len(e.Model.ReleasePrefixes) == 0 && e.Model.ProductionBranch == "" {
		return Chain{Development: e.DevelopmentBranch(repo)}, nil
	}
	names, err := git_model.FindBranchNames(ctx, git_model.FindBranchOptions{
		RepoID:          repo.ID,
		IsDeletedBranch: optional.Some(false),
		ListOptions:     db.ListOptionsAll,
	})
	if err != nil {
		return Chain{}, err
	}
	return BuildChain(e.Model, e.DevelopmentBranch(repo), names), nil
}

func auditModel(m *repo_model.BranchingModel, locked bool) map[string]any {
	if m == nil {
		m = &repo_model.BranchingModel{}
	}
	return map[string]any{
		"development_branch":            m.DevelopmentBranch,
		"production_branch":             m.ProductionBranch,
		"release_prefixes":              append([]string{}, m.ReleasePrefixes...),
		"merge_forward":                 m.MergeForward,
		"merge_forward_never_bypass":    m.MergeForwardNeverBypass,
		"merge_forward_anyone_may_skip": m.MergeForwardAnyoneMaySkip,
		"model_locked":                  locked,
	}
}

// SetOrgModel stores the organization's branching model; nil or one without prefixes and production branch removes
// it. Enforcing needs one of them.
func SetOrgModel(ctx context.Context, org *user_model.User, m *repo_model.BranchingModel, locked bool) error {
	if m != nil {
		var err error
		if m, err = NormalizeBranchingModel(m); err != nil {
			return err
		}
	}
	if m != nil && len(m.ReleasePrefixes) == 0 && m.ProductionBranch == "" {
		m = nil
	}
	if locked && m == nil {
		return ErrLockWithoutValue
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		before, beforeLocked, err := GetOrgModel(ctx, org)
		if err != nil {
			return err
		}
		if m == nil {
			if err := user_model.DeleteUserSetting(ctx, org.ID, keyBranchingModel); err != nil {
				return err
			}
		} else {
			bs, err := json.Marshal(m)
			if err != nil {
				return err
			}
			if err := user_model.SetUserSetting(ctx, org.ID, keyBranchingModel, string(bs)); err != nil {
				return err
			}
		}
		if locked {
			err = user_model.SetUserSetting(ctx, org.ID, keyBranchingModelLocked, "true")
		} else {
			err = user_model.DeleteUserSetting(ctx, org.ID, keyBranchingModelLocked)
		}
		if err != nil {
			return err
		}
		if changes := audit_model.Changes(auditModel(before, beforeLocked), auditModel(m, locked)); changes != nil {
			return user_model.RecordOrg(ctx, "org.branch_workflow.changed", org, changes)
		}
		return nil
	})
}

// SetRepoModel stores the repository's own branching model, nil to inherit, unless the organization enforces one.
func SetRepoModel(ctx context.Context, repo *repo_model.Repository, m *repo_model.BranchingModel) error {
	if m != nil {
		var err error
		if m, err = NormalizeBranchingModel(m); err != nil {
			return err
		}
	}
	e, err := GetEffectiveModel(ctx, repo)
	if err != nil {
		return err
	}
	if e.Locked {
		return ErrLocked
	}
	u, err := repo.GetUnit(ctx, unit.TypePullRequests)
	if err != nil {
		return ErrNoPullRequests
	}
	before := repoAuditModel(e.Configured)
	u.PullRequestsConfig().BranchingModel = m
	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := repo_model.UpdateRepoUnit(ctx, u); err != nil {
			return err
		}
		if changes := audit_model.Changes(before, repoAuditModel(m)); changes != nil {
			return repo_model.RecordRepo(ctx, "repo.branch_workflow.changed", repo, changes)
		}
		return nil
	})
}

func repoAuditModel(m *repo_model.BranchingModel) map[string]any {
	data := auditModel(m, false)
	delete(data, "model_locked")
	data["inherit"] = m == nil
	return data
}

// IsInvalidBranchingModel tells if err is an ErrInvalidBranchingModel and returns its value.
func IsInvalidBranchingModel(err error) (string, bool) {
	if e, ok := errors.AsType[ErrInvalidBranchingModel](err); ok {
		return e.Value, true
	}
	return "", false
}
