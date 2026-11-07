// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package branchworkflow

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/translation"

	"github.com/gobwas/glob"
	"xorm.io/builder"
)

const (
	maxExceptions     = 20
	maxExceptionLen   = 255
	maxExemptUsers    = 100
	maxExemptTeams    = 20
	maxRefusedListed  = 5 // exceptions named in a refusal; the rest is "and N more"
	refusedPrefixList = 20
)

// More reasons a value of the branching model is refused.
const (
	ReasonException       = "exception"         // an exception pattern that is no glob, too long or holds control characters
	ReasonTooManyNaming   = "too_many_naming"   // too many exceptions, exempt users or exempt teams
	ReasonExemptUser      = "exempt_user"       // an exempt user that doesn't exist or is not an individual
	ReasonExemptTeam      = "exempt_team"       // an exempt team that doesn't exist in the organization
	ReasonNoUsableType    = "no_usable_type"    // require a type with no enabled type, release prefix or exception
	ReasonExemptNeedsTeam = "exempt_needs_team" // exempt teams of a repository that has no organization as owner
)

// compileException compiles one exception pattern the way branch protection rules do (a "/" is a separator).
func compileException(p string) (glob.Glob, error) {
	if p == "" || len(p) > maxExceptionLen || !utf8.ValidString(p) || strings.ContainsFunc(p, unicode.IsControl) {
		return nil, ErrInvalidBranchingModel{Value: p, Reason: ReasonException}
	}
	g, err := glob.Compile(p, '/')
	if err != nil {
		return nil, ErrInvalidBranchingModel{Value: p, Reason: ReasonException}
	}
	return g, nil
}

// normalizeNaming checks the exceptions and the exempt lists of m, which is already trimmed, and sets them on out.
func normalizeNaming(m, out *repo_model.BranchingModel) error {
	if len(m.BranchExceptions) > 4*maxExceptions || len(m.ExemptUserIDs) > maxExemptUsers || len(m.ExemptTeamIDs) > maxExemptTeams {
		return ErrInvalidBranchingModel{Reason: ReasonTooManyNaming}
	}
	for _, p := range m.BranchExceptions {
		if p = strings.TrimSpace(p); p == "" || slices.Contains(out.BranchExceptions, p) {
			continue
		}
		if _, err := compileException(p); err != nil {
			return err
		}
		out.BranchExceptions = append(out.BranchExceptions, p)
	}
	if len(out.BranchExceptions) > maxExceptions {
		return ErrInvalidBranchingModel{Reason: ReasonTooManyNaming}
	}
	for _, id := range m.ExemptUserIDs {
		if id > 0 && !slices.Contains(out.ExemptUserIDs, id) {
			out.ExemptUserIDs = append(out.ExemptUserIDs, id)
		}
	}
	for _, id := range m.ExemptTeamIDs {
		if id > 0 && !slices.Contains(out.ExemptTeamIDs, id) {
			out.ExemptTeamIDs = append(out.ExemptTeamIDs, id)
		}
	}
	out.RequireBranchType = m.RequireBranchType
	if out.RequireBranchType && len(out.BranchExceptions) == 0 && len(out.ReleasePrefixes) == 0 && !slices.ContainsFunc(out.Types, func(t repo_model.BranchType) bool { return !t.Off }) {
		return ErrInvalidBranchingModel{Reason: ReasonNoUsableType}
	}
	return nil
}

// ApplyNaming sets the naming fields of m from their request form. Exempt users are looked up by name; exempt teams
// by name in owner, which must then be an organization. NormalizeBranchingModel checks the rest.
func ApplyNaming(ctx context.Context, owner *user_model.User, m *repo_model.BranchingModel, n api.BranchNaming) error {
	if len(n.ExemptUsers) > maxExemptUsers || len(n.ExemptTeams) > maxExemptTeams || len(n.Exceptions) > 4*maxExceptions {
		return ErrInvalidBranchingModel{Reason: ReasonTooManyNaming}
	}
	m.RequireBranchType, m.BranchExceptions, m.ExemptUserIDs, m.ExemptTeamIDs = n.RequireBranchType, n.Exceptions, nil, nil
	for _, name := range n.ExemptUsers {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		u, err := user_model.GetUserByName(ctx, name)
		if err != nil && !user_model.IsErrUserNotExist(err) {
			return err
		}
		if err != nil || !u.IsIndividual() {
			return ErrInvalidBranchingModel{Value: name, Reason: ReasonExemptUser}
		}
		m.ExemptUserIDs = append(m.ExemptUserIDs, u.ID)
	}
	for _, name := range n.ExemptTeams {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		if owner == nil || !owner.IsOrganization() {
			return ErrInvalidBranchingModel{Value: name, Reason: ReasonExemptNeedsTeam}
		}
		t, err := organization.GetTeam(ctx, owner.ID, name)
		if err != nil && !organization.IsErrTeamNotExist(err) {
			return err
		}
		if err != nil {
			return ErrInvalidBranchingModel{Value: name, Reason: ReasonExemptTeam}
		}
		m.ExemptTeamIDs = append(m.ExemptTeamIDs, t.ID)
	}
	return nil
}

// NamingToAPI returns the naming fields of m with the names of the exempt users and teams.
func NamingToAPI(ctx context.Context, m *repo_model.BranchingModel) (api.BranchNaming, error) {
	n := api.BranchNaming{Exceptions: []string{}, ExemptUsers: []string{}, ExemptTeams: []string{}}
	if m == nil {
		return n, nil
	}
	n.RequireBranchType = m.RequireBranchType
	n.Exceptions = append(n.Exceptions, m.BranchExceptions...)
	if len(m.ExemptUserIDs) > 0 {
		users, err := user_model.GetUsersByIDs(ctx, m.ExemptUserIDs)
		if err != nil {
			return n, err
		}
		for _, u := range users {
			n.ExemptUsers = append(n.ExemptUsers, u.Name)
		}
		slices.Sort(n.ExemptUsers)
	}
	if len(m.ExemptTeamIDs) > 0 {
		var teams []*organization.Team
		if err := db.GetEngine(ctx).In("id", m.ExemptTeamIDs).Find(&teams); err != nil {
			return n, err
		}
		for _, t := range teams {
			n.ExemptTeams = append(n.ExemptTeams, t.Name)
		}
		slices.Sort(n.ExemptTeams)
	}
	return n, nil
}

// ErrBranchTypeRequired is returned for a new branch name the branching model's "require a branch type" refuses.
type ErrBranchTypeRequired struct {
	Name       string
	Prefixes   []string // the prefixes of the enabled types and the release prefixes
	Exceptions []string
	SetBy      string // the organization whose model applies, "" for the repository's own
}

func (e ErrBranchTypeRequired) Error() string {
	return fmt.Sprintf("branch %q needs a branch type", e.Name)
}

// Text says why the branch is refused, naming the allowed prefixes and at most maxRefusedListed exceptions. It is
// plain text: escape it before it goes into HTML.
func (e ErrBranchTypeRequired) Text(l translation.Locale) string {
	prefixes := e.Prefixes
	if len(prefixes) > refusedPrefixList {
		prefixes = prefixes[:refusedPrefixList]
	}
	var text string
	switch {
	case len(e.Exceptions) == 0 && len(prefixes) == 0:
		text = l.TrString("repo.branch.type_required_none", e.Name)
	case len(e.Exceptions) == 0:
		text = l.TrString("repo.branch.type_required", e.Name, strings.Join(prefixes, ", "))
	default:
		listed := e.Exceptions
		if len(listed) > maxRefusedListed {
			listed = listed[:maxRefusedListed]
		}
		exc := strings.Join(listed, ", ")
		if more := len(e.Exceptions) - len(listed); more > 0 {
			exc = l.TrString("repo.branch.type_required_more", exc, more)
		}
		text = l.TrString("repo.branch.type_required_exceptions", e.Name, strings.Join(prefixes, ", "), exc)
	}
	if e.SetBy != "" {
		text += " " + l.TrString("repo.branch.type_required_set_by", e.SetBy)
	}
	return text
}

// namingAllows tells if the model lets a new branch have this name without an exemption: an enabled type or release
// prefix followed by more, one of the model's branches, or an exception.
func namingAllows(repo *repo_model.Repository, e EffectiveModel, name string) bool {
	m := e.Model
	if name == repo.DefaultBranch || name == e.DevelopmentBranch(repo) || name == m.ProductionBranch || name == m.DefaultPRTarget {
		return true
	}
	if _, ok := MatchType(m, name); ok {
		return true
	}
	if slices.ContainsFunc(m.Types, func(t repo_model.BranchType) bool {
		return !t.Off && t.Base == repo_model.BranchTypeBaseBranch && t.BaseBranch == name
	}) {
		return true
	}
	return slices.ContainsFunc(m.BranchExceptions, func(p string) bool {
		g, err := compileException(p)
		return err == nil && g.Match(name)
	})
}

// IsExemptFromNaming tells if the user may create any branch name: named in the model's exempt users, or a member
// of one of its exempt teams (of the repository's owner). A deploy key, the Actions user and token identities
// (userID <= 0) are never exempt, and an exemption is no permission to write.
func IsExemptFromNaming(ctx context.Context, repo *repo_model.Repository, m repo_model.BranchingModel, userID int64) (bool, error) {
	if userID <= 0 {
		return false, nil
	}
	if slices.Contains(m.ExemptUserIDs, userID) {
		return true, nil
	}
	if len(m.ExemptTeamIDs) == 0 {
		return false, nil
	}
	return db.GetEngine(ctx).Table("team_user").Where("uid = ? AND org_id = ?", userID, repo.OwnerID).In("team_id", m.ExemptTeamIDs).Exist()
}

// CheckNewBranch is the one check of a new branch name, used by the pre-receive hook (every push that creates a
// branch), by branch creation on the web and the API and by renaming. It refuses with ErrBranchTypeRequired when the
// model requires a type and the name has none; exempt is true when only the user's exemption lets it through, so the
// caller records it. userID is the pusher; viaDeployKey says a deploy key pushes (never exempt, whoever the owner is).
// An unreadable model is an error: it never counts as "no model".
func CheckNewBranch(ctx context.Context, repo *repo_model.Repository, userID int64, viaDeployKey bool, name string) (exempt bool, err error) {
	e, err := GetEffectiveModel(ctx, repo)
	if err != nil || !e.Model.RequireBranchType || namingAllows(repo, e, name) {
		return false, err
	}
	if !viaDeployKey {
		if exempt, err = IsExemptFromNaming(ctx, repo, e.Model, userID); err != nil || exempt {
			return exempt, err
		}
	}
	refused := ErrBranchTypeRequired{Name: name, Exceptions: e.Model.BranchExceptions, SetBy: e.SetBy}
	refused.Prefixes = slices.Clone(e.Model.ReleasePrefixes)
	for _, t := range e.Model.Types {
		if !t.Off {
			refused.Prefixes = append(refused.Prefixes, t.Prefix)
		}
	}
	return false, refused
}

// RecordNamingExempt records that an exemption let a user create or rename a branch to a name the model refuses; via
// is "push" or "rename". The audit entry is the trail of every exempt branch, so a failed write refuses the change.
func RecordNamingExempt(ctx context.Context, repo *repo_model.Repository, name, via string) error {
	return repo_model.RecordRepoTarget(ctx, repo, audit_model.Event{
		Action: "repo.branch.type_exempt", TargetType: "branch", TargetName: name, Data: map[string]any{"via": via},
	})
}

// TypeChoice is a branch type the create dialog offers and the branch it starts from.
type TypeChoice struct {
	Name   string `json:"name"`
	Prefix string `json:"prefix"`
	Base   string `json:"base"`
	// BaseNote is "" when Base is what the type names, else the branch that was named and doesn't exist
	Missing string `json:"missing,omitempty"`
}

// CreateChoices are what the create-branch dialog needs from the model: the enabled types (the first release prefix
// stands for Release), the development branch, whether a type is required of this user and who set the model.
type CreateChoices struct {
	Types       []TypeChoice              `json:"types"`
	Development string                    `json:"development"`
	Required    bool                      `json:"required"`
	Exempt      bool                      `json:"exempt"` // the user is exempt from a required type
	SetBy       string                    `json:"-"`
	Model       repo_model.BranchingModel `json:"-"`
}

// DialogChoices builds the choices for doer in repo. A base that doesn't exist falls back to the development branch.
func DialogChoices(ctx context.Context, repo *repo_model.Repository, doer *user_model.User) (CreateChoices, error) {
	e, err := GetEffectiveModel(ctx, repo)
	if err != nil {
		return CreateChoices{}, err
	}
	m := e.Model
	c := CreateChoices{Types: []TypeChoice{}, Development: e.DevelopmentBranch(repo), SetBy: e.SetBy, Model: m}
	missing, err := MissingBases(ctx, repo, m)
	if err != nil {
		return c, err
	}
	base := func(t repo_model.BranchType) (string, string) {
		name := c.Development
		switch t.Base {
		case repo_model.BranchTypeBaseProduction:
			name = cmp.Or(m.ProductionBranch, c.Development)
		case repo_model.BranchTypeBaseBranch:
			name = t.BaseBranch
		}
		if slices.Contains(missing, name) {
			return c.Development, name
		}
		return name, ""
	}
	if len(m.ReleasePrefixes) > 0 {
		c.Types = append(c.Types, TypeChoice{Name: ReleaseTypeName, Prefix: m.ReleasePrefixes[0], Base: c.Development})
	}
	for _, t := range m.Types {
		if !t.Off {
			b, miss := base(t)
			c.Types = append(c.Types, TypeChoice{Name: t.Name, Prefix: t.Prefix, Base: b, Missing: miss})
		}
	}
	if m.RequireBranchType && doer != nil {
		if c.Exempt, err = IsExemptFromNaming(ctx, repo, m, doer.ID); err != nil {
			return c, err
		}
	}
	c.Required = m.RequireBranchType && !c.Exempt
	return c, nil
}

// TypeFilter returns the condition on the name of the branch table for the branches of one type, or for those with
// no type (untyped), by the rules of MatchType: the longest enabled prefix wins and a name is typed only when
// something follows the prefix. typeName is "Release" or the name of a type, compared case-insensitively; a type
// that doesn't exist matches nothing. It returns nil when no filter is asked for.
func TypeFilter(m repo_model.BranchingModel, typeName string, untyped bool) builder.Cond {
	type prefix struct{ typeName, p string }
	var all []prefix
	for _, p := range m.ReleasePrefixes {
		all = append(all, prefix{ReleaseTypeName, p})
	}
	for _, t := range m.Types {
		if !t.Off {
			all = append(all, prefix{t.Name, t.Prefix})
		}
	}
	// hasPrefix is the branches MatchType gives to the prefix p, ignoring longer prefixes
	hasPrefix := func(p string) builder.Cond {
		return builder.And(builder.Expr("SUBSTR(name, 1, ?) = ?", utf8.RuneCountInString(p), p), builder.Neq{"name": p})
	}
	switch {
	case untyped:
		cond := builder.NewCond()
		for _, a := range all {
			cond = cond.And(builder.Not{hasPrefix(a.p)})
		}
		return cond
	case typeName == "":
		return nil
	}
	cond := builder.NewCond()
	found := false
	for _, a := range all {
		if !strings.EqualFold(a.typeName, typeName) {
			continue
		}
		c := hasPrefix(a.p)
		// a longer prefix of another type takes the branches that start with it
		for _, b := range all {
			if len(b.p) > len(a.p) && strings.HasPrefix(b.p, a.p) && !strings.EqualFold(b.typeName, typeName) {
				c = c.And(builder.Not{hasPrefix(b.p)})
			}
		}
		cond, found = cond.Or(c), true
	}
	if !found {
		return builder.Expr("1 = 0")
	}
	return cond
}
