// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package branchworkflow

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	pull_model "forgejo.org/models/pull"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/json"
	"forgejo.org/modules/optional"
	api "forgejo.org/modules/structs"

	"code.forgejo.org/xorm/xorm/convert"
)

const (
	keyBranchingModel       = "branch_workflow.branching_model"
	keyBranchingModelLocked = "branch_workflow.branching_model_locked"

	maxReleasePrefixes   = 10
	maxReleasePrefixLen  = 100
	maxDevelopmentBranch = 255
	maxVersionPartDigits = 9
	maxBranchTypes       = 20
	maxTypeNameLen       = 50
	maxTypePrefixLen     = 100
)

// The reasons a value of the branching model is refused; a closed set, shown through literal locale keys.
const (
	ReasonName               = "name"                // not a usable type name
	ReasonNameRequired       = "name_required"       // a type without a name
	ReasonNameDuplicate      = "name_duplicate"      // two types with one name
	ReasonNameReserved       = "name_reserved"       // the name of the built-in Release type
	ReasonDuplicatePrefix    = "duplicate_prefix"    // a prefix twice
	ReasonReleasePrefix      = "release_prefix"      // a type prefix that is or starts with a release prefix
	ReasonPrefixIsBranch     = "prefix_is_branch"    // a type prefix that is the development or production branch
	ReasonMergeQueue         = "merge_queue"         // a name or prefix of the merge queue's branches
	ReasonBranchRequired     = "branch_required"     // base "branch" without a branch
	ReasonUnknownBase        = "unknown_base"        // a base that is none of the three
	ReasonProductionRequired = "production_required" // base "production" without a production branch
)

// ErrInvalidBranchingModel is returned for a value of the model that can't be used; Reason is "" for a name or prefix
// that git refuses, else one of the Reason constants.
type ErrInvalidBranchingModel struct {
	Value  string
	Reason string
}

// Error is the human message, without the reason code (that is the Reason field).
func (e ErrInvalidBranchingModel) Error() string {
	switch e.Reason {
	case ReasonName:
		return fmt.Sprintf("%q is not a usable branch type name", e.Value)
	case ReasonNameRequired:
		return "a branch type needs a name"
	case ReasonNameDuplicate:
		return fmt.Sprintf("two branch types are named %q", e.Value)
	case ReasonNameReserved:
		return fmt.Sprintf("%q is the name of the built-in Release type", e.Value)
	case ReasonDuplicatePrefix:
		return fmt.Sprintf("the prefix %q is used by two branch types", e.Value)
	case ReasonReleasePrefix:
		return fmt.Sprintf("the prefix %q is or starts with a release branch prefix", e.Value)
	case ReasonPrefixIsBranch:
		return fmt.Sprintf("the prefix %q is the development or production branch", e.Value)
	case ReasonMergeQueue:
		return fmt.Sprintf("%q is reserved for the branches of the merge queue", e.Value)
	case ReasonBranchRequired:
		return fmt.Sprintf("the branch type %q is created from a branch, but no branch is named", e.Value)
	case ReasonUnknownBase:
		return fmt.Sprintf("%q is not a base: use development, production or branch", e.Value)
	case ReasonProductionRequired:
		return fmt.Sprintf("the branch type %q is created from the production branch, but none is set", e.Value)
	}
	return fmt.Sprintf("invalid branch name or prefix %q", e.Value)
}

// ErrTooManyReleasePrefixes is returned for more than maxReleasePrefixes prefixes.
var ErrTooManyReleasePrefixes = fmt.Errorf("at most %d release prefixes", maxReleasePrefixes)

// ErrTooManyBranchTypes is returned for more than maxBranchTypes branch types.
var ErrTooManyBranchTypes = fmt.Errorf("at most %d branch types", maxBranchTypes)

// hasHiddenChar tells if s holds a control (Cc), format (Cf: bidi marks, zero-width characters) or line/paragraph
// separator (Zl, Zp) character: nothing a name, prefix or branch of the model may hold.
func hasHiddenChar(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
	})
}

// hasVisibleChar tells if s has a character one can see (not a space, not a blank filler such as U+3164 or U+2800).
func hasVisibleChar(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsGraphic(r) && !unicode.IsSpace(r) && r != 0x3164 && r != 0x2800 && r != 0x115F && r != 0x1160 && r != 0xFFA0
	})
}

// checkBranchName is the one check of every branch the model names (development, production, type bases, default
// pull request target): a name git accepts that can't be read as another ref (HEAD, refs/...), starts with no dash
// and is not a merge queue branch.
func checkBranchName(b string) error {
	switch {
	case b == "" || len(b) > maxDevelopmentBranch || hasHiddenChar(b) || !git.IsValidRefPattern(b) || git.IsReservedRefName(b) || strings.HasPrefix(b, "-"):
		return ErrInvalidBranchingModel{Value: b}
	case pull_model.IsMergeQueueBranch(b):
		return ErrInvalidBranchingModel{Value: b, Reason: ReasonMergeQueue}
	}
	return nil
}

// checkPrefix is the one check of every prefix (release and type): the start of a valid branch name under the same
// rules as checkBranchName, of at most maxLen bytes, without a comma (the web form separates release prefixes with
// commas), and neither a merge queue branch nor the start of one ("m" and "merge-" would match them).
func checkPrefix(p string, maxLen int) error {
	if p == "" || len(p) > maxLen || strings.Contains(p, ",") || hasHiddenChar(p) {
		return ErrInvalidBranchingModel{Value: p}
	}
	mq := pull_model.MergeQueueBranchPrefix
	if mq != "" && (strings.HasPrefix(mq, p) || strings.HasPrefix(p, mq)) {
		return ErrInvalidBranchingModel{Value: p, Reason: ReasonMergeQueue}
	}
	if err := checkBranchName(p + "x"); err != nil || git.IsReservedRefName(p) || strings.HasPrefix(p, "refs/") || p == "HEAD" {
		return ErrInvalidBranchingModel{Value: p}
	}
	return nil
}

// checkTypeName refuses empty names, names over maxTypeNameLen characters and control, format (bidi, zero-width)
// and invalid characters, so a name always shows as what it is.
func checkTypeName(n string) error {
	if n == "" {
		return ErrInvalidBranchingModel{Value: n, Reason: ReasonNameRequired}
	}
	if utf8.RuneCountInString(n) > maxTypeNameLen || !utf8.ValidString(n) || hasHiddenChar(n) || !hasVisibleChar(n) {
		return ErrInvalidBranchingModel{Value: n, Reason: ReasonName}
	}
	if strings.EqualFold(n, "Release") {
		return ErrInvalidBranchingModel{Value: n, Reason: ReasonNameReserved}
	}
	return nil
}

// normalizeTypes checks the branch types; names and prefixes must differ, the prefixes also from the release ones.
func normalizeTypes(in []repo_model.BranchType, release []string, production string) ([]repo_model.BranchType, error) {
	if len(in) > maxBranchTypes {
		return nil, ErrTooManyBranchTypes
	}
	var out []repo_model.BranchType
	var prefixes, names []string
	for _, t := range in {
		t.Name, t.Prefix, t.BaseBranch = strings.TrimSpace(t.Name), strings.TrimSpace(t.Prefix), strings.TrimSpace(t.BaseBranch)
		if err := checkTypeName(t.Name); err != nil {
			return nil, err
		}
		lower := strings.ToLower(t.Name)
		if slices.Contains(names, lower) {
			return nil, ErrInvalidBranchingModel{Value: t.Name, Reason: ReasonNameDuplicate}
		}
		names = append(names, lower)
		if err := checkPrefix(t.Prefix, maxTypePrefixLen); err != nil {
			return nil, err
		}
		if slices.ContainsFunc(release, func(r string) bool { return strings.HasPrefix(t.Prefix, r) }) {
			return nil, ErrInvalidBranchingModel{Value: t.Prefix, Reason: ReasonReleasePrefix}
		}
		if slices.Contains(prefixes, t.Prefix) {
			return nil, ErrInvalidBranchingModel{Value: t.Prefix, Reason: ReasonDuplicatePrefix}
		}
		prefixes = append(prefixes, t.Prefix)
		switch t.Base {
		case repo_model.BranchTypeBaseDevelopment:
			t.BaseBranch = ""
		case repo_model.BranchTypeBaseProduction:
			if production == "" {
				return nil, ErrInvalidBranchingModel{Value: t.Name, Reason: ReasonProductionRequired}
			}
			t.BaseBranch = ""
		case repo_model.BranchTypeBaseBranch:
			if t.BaseBranch == "" {
				return nil, ErrInvalidBranchingModel{Value: t.Name, Reason: ReasonBranchRequired}
			}
			if err := checkBranchName(t.BaseBranch); err != nil {
				return nil, err
			}
		default:
			return nil, ErrInvalidBranchingModel{Value: t.Base, Reason: ReasonUnknownBase}
		}
		out = append(out, t)
	}
	return out, nil
}

// NormalizeBranchingModel trims the values, drops empty and repeated prefixes and checks the rest.
func NormalizeBranchingModel(m *repo_model.BranchingModel) (*repo_model.BranchingModel, error) {
	out := &repo_model.BranchingModel{DevelopmentBranch: strings.TrimSpace(m.DevelopmentBranch), ProductionBranch: strings.TrimSpace(m.ProductionBranch), DefaultPRTarget: strings.TrimSpace(m.DefaultPRTarget), MergeForward: m.MergeForward, MergeForwardNeverBypass: m.MergeForwardNeverBypass, MergeForwardAnyoneMaySkip: m.MergeForwardAnyoneMaySkip}
	for _, b := range []string{out.DevelopmentBranch, out.ProductionBranch, out.DefaultPRTarget} {
		if b == "" {
			continue
		}
		if err := checkBranchName(b); err != nil {
			return nil, err
		}
	}
	if out.ProductionBranch != "" && out.ProductionBranch == out.DevelopmentBranch {
		return nil, ErrInvalidBranchingModel{Value: out.ProductionBranch}
	}
	for _, p := range m.ReleasePrefixes {
		p = strings.TrimSpace(p)
		if p == "" || slices.Contains(out.ReleasePrefixes, p) {
			continue
		}
		if err := checkPrefix(p, maxReleasePrefixLen); err != nil {
			return nil, err
		}
		out.ReleasePrefixes = append(out.ReleasePrefixes, p)
	}
	if len(out.ReleasePrefixes) > maxReleasePrefixes {
		return nil, ErrTooManyReleasePrefixes
	}
	var err error
	if out.Types, err = normalizeTypes(m.Types, out.ReleasePrefixes, out.ProductionBranch); err != nil {
		return nil, err
	}
	for _, t := range out.Types {
		if t.Prefix == out.DevelopmentBranch || t.Prefix == out.ProductionBranch {
			return nil, ErrInvalidBranchingModel{Value: t.Prefix, Reason: ReasonPrefixIsBranch}
		}
	}
	if err := normalizeNaming(m, out); err != nil {
		return nil, err
	}
	return out, nil
}

// isEmpty tells if the model sets nothing that a repository could inherit.
func isEmpty(m *repo_model.BranchingModel) bool {
	return len(m.ReleasePrefixes) == 0 && m.ProductionBranch == "" && len(m.Types) == 0 && m.DefaultPRTarget == "" &&
		!m.RequireBranchType && len(m.BranchExceptions) == 0 && len(m.ExemptUserIDs) == 0 && len(m.ExemptTeamIDs) == 0
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

// auditModel is the audited form of a model without its types, which modelChanges adds as the types that changed.
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
		"default_pr_target":             m.DefaultPRTarget,
		"require_branch_type":           m.RequireBranchType,
		"branch_exceptions":             append([]string{}, m.BranchExceptions...),
		"exempt_user_ids":               append([]int64{}, m.ExemptUserIDs...),
		"exempt_team_ids":               append([]int64{}, m.ExemptTeamIDs...),
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
	if m != nil && isEmpty(m) {
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
		if changes := modelChanges(auditModel(before, beforeLocked), auditModel(m, locked), before, m); changes != nil {
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
	var newConfig convert.Conversion
	if err := db.WithTx(ctx, func(ctx context.Context) error {
		// the stored row, not the copy cached on the repository, is what changes and what the entry compares
		stored, has, err := repo_model.GetRepoUnitForUpdate(ctx, repo.ID, unit.TypePullRequests)
		if err != nil {
			return err
		} else if !has {
			return ErrNoPullRequests
		}
		cfg := stored.PullRequestsConfig()
		cfg0 := cfg.BranchingModel
		before := repoAuditModel(cfg0)
		cfg.BranchingModel = m
		if err := repo_model.UpdateRepoUnit(ctx, stored); err != nil {
			return err
		}
		newConfig = stored.Config
		if changes := modelChanges(before, repoAuditModel(m), cfg0, m); changes != nil {
			return repo_model.RecordRepo(ctx, "repo.branch_workflow.changed", repo, changes)
		}
		return nil
	}); err != nil {
		return err
	}
	u.Config = newConfig // the copy cached on the repository follows only a stored change
	return nil
}

// modelChanges is audit_model.Changes with only the added, changed or removed types, plus the sha256 of each whole
// model, so the entry keeps the difference under the size cap and the hashes prove the full models.
func modelChanges(before, after map[string]any, bm, am *repo_model.BranchingModel) map[string]any {
	var bt, at []repo_model.BranchType
	if bm != nil {
		bt = bm.Types
	}
	if am != nil {
		at = am.Types
	}
	before["types"] = typeAudit(slices.DeleteFunc(slices.Clone(bt), func(t repo_model.BranchType) bool { return slices.Contains(at, t) }))
	after["types"] = typeAudit(slices.DeleteFunc(slices.Clone(at), func(t repo_model.BranchType) bool { return slices.Contains(bt, t) }))
	changes := audit_model.Changes(before, after)
	if changes != nil {
		changes["before"].(map[string]any)["model_sha256"], changes["after"].(map[string]any)["model_sha256"] = modelHash(bm), modelHash(am)
	}
	return changes
}

func modelHash(m *repo_model.BranchingModel) string {
	bs, _ := json.Marshal(m) // strings and bools always marshal; nil is "null"
	return fmt.Sprintf("%x", sha256.Sum256(bs))
}

// typeAudit lists the branch types as objects, so that no value can pass for another field.
func typeAudit(types []repo_model.BranchType) []map[string]any {
	out := []map[string]any{}
	for _, t := range types {
		out = append(out, map[string]any{
			"name": audit_model.Text(t.Name, maxTypeNameLen*4), "prefix": audit_model.Text(t.Prefix, maxTypePrefixLen),
			"base": t.Base, "base_branch": audit_model.Text(t.BaseBranch, maxDevelopmentBranch), "on": !t.Off,
		})
	}
	return out
}

func repoAuditModel(m *repo_model.BranchingModel) map[string]any {
	data := auditModel(m, false)
	delete(data, "model_locked")
	data["inherit"] = m == nil
	return data
}

// IsInvalidBranchingModel tells if err is an ErrInvalidBranchingModel and returns its value.
func IsInvalidBranchingModel(err error) (ErrInvalidBranchingModel, bool) {
	e, ok := errors.AsType[ErrInvalidBranchingModel](err)
	return e, ok
}

// TypesToAPI converts the branch types for the API.
func TypesToAPI(types []repo_model.BranchType) []api.BranchType {
	out := make([]api.BranchType, 0, len(types))
	for _, t := range types {
		out = append(out, api.BranchType{Name: t.Name, Prefix: t.Prefix, Base: t.Base, BaseBranch: t.BaseBranch, Off: t.Off})
	}
	return out
}

// TypesFromAPI converts branch types of an API request; NormalizeBranchingModel checks them.
func TypesFromAPI(types []api.BranchType) []repo_model.BranchType {
	var out []repo_model.BranchType
	for _, t := range types {
		out = append(out, repo_model.BranchType{Name: t.Name, Prefix: t.Prefix, Base: t.Base, BaseBranch: t.BaseBranch, Off: t.Off})
	}
	return out
}
