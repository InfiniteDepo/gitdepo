// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"context"
	"errors"
	"slices"

	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/dependency"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/util"
	"forgejo.org/modules/vulnerability"

	"xorm.io/builder"
)

// MaxUsageCandidates is how many rows a range search reads before it answers "too many" (a variable for tests).
var MaxUsageCandidates = 20000

// SearchScope says whose repositories a search covers and who asks.
type SearchScope struct {
	Org        *organization.Organization // nil: every owner (the instance routes)
	Doer       *user_model.User
	Admin      bool         // doer acts as a site admin or auditor: sees every repository that is not hidden by a rule of the instance
	TokenRepos builder.Cond // what the credential may read (Reducer().RepoReadAccessFilter()); defense in depth, the routes already refuse restricted tokens
	Project    string       // org only: a project of the organization
	Owner      string       // instance only: an owner name
}

// RepoCond is the one visibility rule of the org and instance searches, on the repository table: the runs list's
// rule (not trashed, a Code unit the policy and the organization allow, readable by the doer, not hidden by a
// two-factor requirement) and the dependency graph being on. empty is true when a project or owner filter names
// nothing, so the answer is an empty list (cond is then not to be used). It reads dynamic settings: call it before building a session.
func (s SearchScope) RepoCond(ctx context.Context) (cond builder.Cond, empty bool, err error) {
	if s.Org == nil && !s.Admin {
		return builder.NewCond(), false, errors.New("a search of every owner is for site admins only")
	}
	if !SiteEnabled(ctx) {
		return builder.NewCond(), true, nil
	}
	var ownerID int64
	if s.Org != nil {
		ownerID = s.Org.ID
	}
	cond = repo_model.OrgUnitRepoCond(ctx, ownerID, s.Doer, s.Admin, unit.TypeCode).And(builder.Not{repo_model.DependencyGraphOffCond()})
	if s.TokenRepos != nil {
		cond = cond.And(s.TokenRepos)
	}
	if s.Project != "" && s.Org != nil {
		group, err := repo_model.GetRepoGroupByName(ctx, s.Org.ID, s.Project)
		if errors.Is(err, repo_model.ErrRepoGroupNotExist) {
			return builder.NewCond(), true, nil
		} else if err != nil {
			return nil, false, err
		}
		cond = cond.And(builder.Eq{"`repository`.group_id": group.ID})
	}
	if s.Owner != "" && s.Org == nil {
		owner, err := user_model.GetUserByName(ctx, s.Owner)
		if user_model.IsErrUserNotExist(err) {
			return builder.NewCond(), true, nil
		} else if err != nil {
			return nil, false, err
		}
		cond = cond.And(builder.Eq{"`repository`.owner_id": owner.ID})
	}
	return cond, false, nil
}

// ValidateSearchPackage checks the package filters shared by the usage and the alert search.
func ValidateSearchPackage(ecosystem, name, version string) error {
	switch {
	case ecosystem != "" && !dependency.IsEcosystem(ecosystem):
		return util.NewInvalidArgumentErrorf("unknown ecosystem")
	case version != "" && name == "":
		return util.NewInvalidArgumentErrorf("version needs a name")
	case len(name) > vulnerability.MaxNameLen:
		return util.NewInvalidArgumentErrorf("name is too long")
	case len(version) > dependency.MaxVersionLen:
		return util.NewInvalidArgumentErrorf("version is too long")
	}
	return nil
}

// UsageFilter narrows the dependency search. Ecosystem and Name are exact; Version or Range (not both) narrow the
// version.
type UsageFilter struct {
	Ecosystem, Name, Version, Range string
	Direct                          optional.Option[bool]
}

// UsageRow is one dependency of one repository in a search result.
type UsageRow struct {
	*repo_model.Dependency
	Repo      *repo_model.Repository
	Uncertain bool // the row has no version and its requirement overlaps the range
}

// ErrTooMany is a search with too many rows to answer; the errors that wrap it also wrap util.ErrInvalidArgument.
var ErrTooMany = errors.New("too many matches")

type tooManyError string

func (e tooManyError) Error() string { return string(e) }

func (e tooManyError) Is(target error) bool {
	return target == ErrTooMany || target == util.ErrInvalidArgument
}

// ErrTooManyCandidates is the ErrTooMany of a range search that reads more than MaxUsageCandidates rows.
var ErrTooManyCandidates = errors.New("too many candidates")

type tooManyCandidatesError struct{ tooManyError }

func (e tooManyCandidatesError) Is(target error) bool {
	return target == ErrTooManyCandidates || e.tooManyError.Is(target)
}

// TooManyMatches is an export with too many rows; it names the filter the route has, unless it is given.
func TooManyMatches(scope SearchScope) error {
	return tooManyError("too many matches, " + scopeAdvice(scope) + "narrow by version or range")
}

// scopeAdvice is "add a project filter, " (organization routes) or "add an owner filter, " (instance routes) while
// the filter is not given, else "".
func scopeAdvice(scope SearchScope) string {
	switch {
	case scope.Org != nil && scope.Project == "":
		return "add a project filter, "
	case scope.Org == nil && scope.Owner == "":
		return "add an owner filter, "
	}
	return ""
}

// tooManyCandidates is a range search that reads more than MaxUsageCandidates rows.
func tooManyCandidates(scope SearchScope) error {
	advice := "give an exact version"
	if a := scopeAdvice(scope); a != "" {
		advice = a + "or give an exact version"
	}
	return tooManyCandidatesError{tooManyError("too many candidates for a range search: " + advice)}
}

// RepoBatches splits rows (the repositories' rows are contiguous) into batches of at least size rows that end on a
// repository boundary, so a batch holds whole repositories.
func RepoBatches[T any](rows []T, repoID func(T) int64, size int) [][]T {
	var out [][]T
	start := 0
	for i := 1; i <= len(rows); i++ {
		if i == len(rows) || (i-start >= size && repoID(rows[i]) != repoID(rows[i-1])) {
			out = append(out, rows[start:i])
			start = i
		}
	}
	return out
}

// usagePlan is a validated dependency search: the options, and for a range search the rows inside the range.
type usagePlan struct {
	opts      *repo_model.DependencyUsageOptions
	kept      []*repo_model.Dependency // range search: the candidates inside the range, in order
	uncertain map[int64]bool
	ranged    bool
	filter    *vulnerability.RangeFilter
	total     int64
}

// planUsage validates f and counts the rows. With a range, the candidates (by package) are read up to
// MaxUsageCandidates and filtered by version in Go.
func planUsage(ctx context.Context, scope SearchScope, f UsageFilter) (*usagePlan, error) {
	if err := ValidateSearchPackage(f.Ecosystem, f.Name, f.Version); err != nil {
		return nil, err
	}
	if f.Ecosystem == "" || f.Name == "" {
		return nil, util.NewInvalidArgumentErrorf("ecosystem and name are required")
	}
	if f.Version != "" && f.Range != "" {
		return nil, util.NewInvalidArgumentErrorf("version and range exclude each other")
	}
	var filter *vulnerability.RangeFilter
	if f.Range != "" {
		var ok bool
		if filter, ok = vulnerability.ParseRangeFilter(f.Ecosystem, f.Range); !ok {
			return nil, util.NewInvalidArgumentErrorf("range is not a requirement of the ecosystem")
		}
	}
	repoCond, empty, err := scope.RepoCond(ctx)
	if err != nil || empty {
		return &usagePlan{}, err
	}
	p := &usagePlan{opts: &repo_model.DependencyUsageOptions{RepoCond: repoCond, Ecosystem: f.Ecosystem, Name: f.Name, Version: f.Version, Direct: f.Direct}}
	if filter == nil {
		p.total, err = repo_model.CountDependencyUsage(ctx, p.opts)
		return p, err
	}
	candidates, err := repo_model.FindDependencyUsageCandidates(ctx, p.opts, MaxUsageCandidates+1)
	if err != nil {
		return nil, err
	}
	if len(candidates) > MaxUsageCandidates {
		return nil, tooManyCandidates(scope)
	}
	p.ranged, p.filter, p.uncertain = true, filter, map[int64]bool{}
	for _, d := range candidates {
		if in, unsure := filter.Match(d.Version, d.Requirement); in {
			p.kept = append(p.kept, d)
			p.uncertain[d.ID] = unsure
		}
	}
	p.total = int64(len(p.kept))
	return p, nil
}

// page loads the rows from skip on, at most take (all if 0), with their repositories.
func (p *usagePlan) page(ctx context.Context, skip, take int) ([]*UsageRow, error) {
	if p.total == 0 {
		return nil, nil
	}
	var rows []*repo_model.Dependency
	if !p.ranged {
		var err error
		if rows, err = repo_model.FindDependencyUsage(ctx, p.opts, skip, take); err != nil {
			return nil, err
		}
	} else {
		kept := p.kept[min(skip, len(p.kept)):]
		if take > 0 && len(kept) > take {
			kept = kept[:take]
		}
		pageIDs := make([]int64, len(kept))
		for i, d := range kept {
			pageIDs[i] = d.ID
		}
		var err error
		if rows, err = loadDependencies(ctx, pageIDs); err != nil {
			return nil, err
		}
	}
	return p.withRepos(ctx, rows)
}

// loadDependencies loads the rows by ID in that order; a row deleted by a scan since the query is dropped.
func loadDependencies(ctx context.Context, ids []int64) ([]*repo_model.Dependency, error) {
	full, err := repo_model.GetDependenciesByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	rows := make([]*repo_model.Dependency, 0, len(ids))
	for _, id := range ids {
		if row := full[id]; row != nil {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// withRepos pairs the rows with their repositories, dropping those whose repository is gone.
func (p *usagePlan) withRepos(ctx context.Context, rows []*repo_model.Dependency) ([]*UsageRow, error) {
	ids := make([]int64, 0, len(rows))
	for _, d := range rows {
		if !slices.Contains(ids, d.RepoID) {
			ids = append(ids, d.RepoID)
		}
	}
	repos, err := repo_model.GetRepositoriesMapByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]*UsageRow, 0, len(rows))
	for _, d := range rows {
		if repo := repos[d.RepoID]; repo != nil { // gone since the query: dropped
			out = append(out, &UsageRow{Dependency: d, Repo: repo, Uncertain: p.uncertain[d.ID]})
		}
	}
	return out, nil
}

// UsageResult is a page of a dependency search with its totals: all rows, and the repositories and owners they touch.
type UsageResult struct {
	Rows                 []*UsageRow
	Total, Repos, Owners int64
}

// SearchUsage lists the dependency rows of the repositories in scope that match f, and how many there are. The
// errors that wrap util.ErrInvalidArgument are the caller's mistakes (a 422). With a range, the rows are filtered
// by version in Go before they are counted and paged.
func SearchUsage(ctx context.Context, scope SearchScope, f UsageFilter, lo db.ListOptions) ([]*UsageRow, int64, error) {
	r, err := searchUsage(ctx, scope, f, lo, false)
	return r.Rows, r.Total, err
}

// SearchUsageSummary is SearchUsage with the counts of repositories and owners (owners for the instance search only).
func SearchUsageSummary(ctx context.Context, scope SearchScope, f UsageFilter, lo db.ListOptions) (*UsageResult, error) {
	return searchUsage(ctx, scope, f, lo, true)
}

func searchUsage(ctx context.Context, scope SearchScope, f UsageFilter, lo db.ListOptions, summary bool) (*UsageResult, error) {
	p, err := planUsage(ctx, scope, f)
	if err != nil || p.total == 0 {
		return &UsageResult{}, err
	}
	lo.SetDefaultValues()
	skip, take := lo.GetSkipTake()
	res := &UsageResult{Total: p.total}
	if res.Rows, err = p.page(ctx, skip, take); err != nil || !summary {
		return res, err
	}
	if !p.ranged {
		c, err := repo_model.CountDependencyUsageRepos(ctx, p.opts)
		res.Repos, res.Owners = c.Repos, c.Owners
		return res, err
	}
	seen := map[int64]bool{}
	var repoIDs []int64
	for _, d := range p.kept {
		if !seen[d.RepoID] {
			seen[d.RepoID] = true
			repoIDs = append(repoIDs, d.RepoID)
		}
	}
	res.Repos = int64(len(repoIDs))
	if scope.Org == nil {
		res.Owners, err = repo_model.CountDistinctOwners(ctx, repoIDs)
	}
	return res, err
}

// MaxExportRows is the most rows an export holds (a variable for tests); above it the export is refused.
var MaxExportRows = 100_000

// ExportBatch is how many rows an export loads at a time (a variable for tests).
var ExportBatch = 500

// afterExportBatch is called after each batch of an export, afterExportSnapshot once the snapshot is read (hooks for tests).
var afterExportBatch, afterExportSnapshot func()

// loadBatch loads the rows of one batch of the snapshot, in its order, as the plan selects them now: by ID and
// the plan's conditions (a repository moved out of reach, a row that left the filter, is dropped). A repository
// whose snapshot rows are not all there (a scan replaced them) is read again as a whole.
func (p *usagePlan) loadBatch(ctx context.Context, batch []*repo_model.Dependency) ([]*repo_model.Dependency, error) {
	ids := make([]int64, len(batch))
	for i, d := range batch {
		ids[i] = d.ID
	}
	loaded, err := repo_model.GetDependencyUsageByIDs(ctx, p.opts, ids)
	if err != nil {
		return nil, err
	}
	// the repositories of the batch with a snapshot row that is gone (a scan replaced them) are read again as a whole, in one query
	var stale []int64
	for _, d := range batch {
		if loaded[d.ID] == nil && !slices.Contains(stale, d.RepoID) {
			stale = append(stale, d.RepoID)
		}
	}
	current, err := repo_model.FindDependencyUsageOfRepos(ctx, p.opts, stale)
	if err != nil {
		return nil, err
	}
	var out []*repo_model.Dependency
	for start := 0; start < len(batch); {
		end := start
		for end < len(batch) && batch[end].RepoID == batch[start].RepoID {
			end++
		}
		rows := current[batch[start].RepoID]
		if !slices.Contains(stale, batch[start].RepoID) {
			rows = nil
			for _, d := range batch[start:end] {
				rows = append(rows, loaded[d.ID])
			}
		}
		for _, d := range rows {
			if !p.ranged {
				out = append(out, d)
			} else if in, unsure := p.filter.Match(d.Version, d.Requirement); in {
				p.uncertain[d.ID] = unsure
				out = append(out, d)
			}
		}
		start = end
	}
	return out, nil
}

// ExportUsage lists every row SearchUsage would, in the same order. It reads the ordered IDs once, so the cap and
// the count come from one snapshot, and loads the rows batch by batch, each batch holding whole repositories: a
// row deleted meanwhile is dropped, a repository rescanned meanwhile is exported with its current rows, no other
// row is skipped or repeated. start is called once with the count before the first emit (not at all if the count
// is above MaxExportRows or the filter is wrong, which are errors wrapping util.ErrInvalidArgument); a start
// error is returned as it is.
func ExportUsage(ctx context.Context, scope SearchScope, f UsageFilter, start func(total int64) error, emit func([]*UsageRow) error) error {
	p, err := planUsage(ctx, scope, f)
	if err != nil {
		return err
	}
	if p.total > int64(MaxExportRows) {
		return TooManyMatches(scope)
	}
	snapshot := p.kept
	if p.total > 0 && !p.ranged {
		if snapshot, err = repo_model.FindDependencyUsageSnapshot(ctx, p.opts, MaxExportRows+1); err != nil {
			return err
		}
	}
	if len(snapshot) > MaxExportRows {
		return TooManyMatches(scope)
	}
	if err := start(int64(len(snapshot))); err != nil {
		return err
	}
	if afterExportSnapshot != nil {
		afterExportSnapshot()
	}
	for _, batch := range RepoBatches(snapshot, func(d *repo_model.Dependency) int64 { return d.RepoID }, ExportBatch) {
		deps, err := p.loadBatch(ctx, batch)
		if err != nil {
			return err
		}
		rows, err := p.withRepos(ctx, deps)
		if err != nil {
			return err
		}
		if err := emit(rows); err != nil {
			return err
		}
		if afterExportBatch != nil {
			afterExportBatch()
		}
	}
	return nil
}
