// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"context"
	"maps"
	"slices"

	"forgejo.org/models/db"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/vulnerability"

	"xorm.io/builder"
)

// DependencyUsageOptions selects the dependency rows of many repositories (the repositories that use a package).
type DependencyUsageOptions struct {
	// RepoCond is the visibility rule on the repository table; the caller builds it (and so reads the dynamic settings)
	// before the session, and it is always ANDed.
	RepoCond  builder.Cond
	Ecosystem string
	Name      string // compared as vulnerability.NormalizeName makes it; needs Ecosystem
	Version   string // exact
	Direct    optional.Option[bool]
}

func (o *DependencyUsageOptions) cond() builder.Cond {
	cond := o.RepoCond
	if o.Ecosystem != "" {
		cond = cond.And(builder.Eq{"`repo_dependency`.ecosystem": o.Ecosystem})
	}
	if o.Name != "" {
		// the lowercased and PyPI-normalized forms are expressions, so the (ecosystem, name) index serves their first
		// column only, as in the match of repositories against advisories (RepoIDsUsing)
		cond = cond.And(builder.Expr(vulnerability.SQLNormalizedName(o.Ecosystem, "`repo_dependency`.name")+" = ?", vulnerability.NormalizeName(o.Ecosystem, o.Name)))
	}
	if o.Version != "" {
		cond = cond.And(builder.Eq{"`repo_dependency`.version": o.Version})
	}
	if o.Direct.Has() {
		cond = cond.And(builder.Eq{"`repo_dependency`.direct": o.Direct.ValueOrDefault(false)})
	}
	return cond
}

// dependencyUsageOrder is the order of the search: repository (RepoNameOrder, then its ID), manifest path, name, version.
const dependencyUsageOrder = RepoNameOrder + ", `repository`.id, `repo_dependency`.manifest_path, `repo_dependency`.name, `repo_dependency`.version, `repo_dependency`.id"

// RepoNameOrder sorts joined rows by owner, then project or name, then name: a root repository sorts by its own name
// where a repository in a project sorts by the project's (no concatenation in SQL, which differs per database).
const RepoNameOrder = "LOWER(`repository`.owner_name), CASE WHEN `repository`.group_name = '' THEN `repository`.lower_name ELSE LOWER(`repository`.group_name) END, `repository`.lower_name"

// CountDependencyUsage counts the rows.
func CountDependencyUsage(ctx context.Context, o *DependencyUsageOptions) (int64, error) {
	return db.GetEngine(ctx).Table("repo_dependency").Join("INNER", "repository", "`repository`.id = `repo_dependency`.repo_id").Where(o.cond()).Count()
}

// FindDependencyUsageCandidates is FindDependencyUsage for a range search, which reads up to limit rows only to
// decide whether each is inside the range: only id, repo_id, version and requirement are loaded.
func FindDependencyUsageCandidates(ctx context.Context, o *DependencyUsageOptions, limit int) ([]*Dependency, error) {
	var rows []*Dependency
	return rows, db.GetEngine(ctx).Select("`repo_dependency`.id, `repo_dependency`.repo_id, `repo_dependency`.version, `repo_dependency`.requirement").
		Join("INNER", "repository", "`repository`.id = `repo_dependency`.repo_id").Where(o.cond()).
		OrderBy(dependencyUsageOrder).Limit(limit).Find(&rows)
}

// GetDependenciesByIDs loads full rows by ID.
func GetDependenciesByIDs(ctx context.Context, ids []int64) (map[int64]*Dependency, error) {
	rows := make(map[int64]*Dependency, len(ids))
	if len(ids) == 0 {
		return rows, nil
	}
	return rows, db.GetEngine(ctx).In("id", ids).Find(&rows)
}

// FindDependencyUsage returns the rows ordered by repository full name, manifest path, name, version, skipping skip
// and returning at most limit (all if 0).
func FindDependencyUsage(ctx context.Context, o *DependencyUsageOptions, skip, limit int) ([]*Dependency, error) {
	sess := db.GetEngine(ctx).Select("`repo_dependency`.*").Join("INNER", "repository", "`repository`.id = `repo_dependency`.repo_id").Where(o.cond()).
		OrderBy(dependencyUsageOrder)
	if limit > 0 {
		sess = sess.Limit(limit, skip)
	}
	var rows []*Dependency
	return rows, sess.Find(&rows)
}

// FindDependencyUsageSnapshot returns the rows in the order of FindDependencyUsage, at most limit, with only id and
// repo_id loaded: the snapshot an export streams from.
func FindDependencyUsageSnapshot(ctx context.Context, o *DependencyUsageOptions, limit int) ([]*Dependency, error) {
	var rows []*Dependency
	return rows, db.GetEngine(ctx).Select("`repo_dependency`.id, `repo_dependency`.repo_id").Join("INNER", "repository", "`repository`.id = `repo_dependency`.repo_id").Where(o.cond()).
		OrderBy(dependencyUsageOrder).Limit(limit).Find(&rows)
}

// UsageChunk is how many IDs one IN list of the export queries holds (SQLite allows 32766 variables per statement).
const UsageChunk = 500

// GetDependencyUsageByIDs loads the rows with the given IDs that o still selects (same visibility, same filters).
func GetDependencyUsageByIDs(ctx context.Context, o *DependencyUsageOptions, ids []int64) (map[int64]*Dependency, error) {
	rows := make(map[int64]*Dependency, len(ids))
	for chunk := range slices.Chunk(ids, UsageChunk) {
		part := map[int64]*Dependency{}
		if err := db.GetEngine(ctx).Select("`repo_dependency`.*").Join("INNER", "repository", "`repository`.id = `repo_dependency`.repo_id").
			Where(o.cond().And(builder.In("`repo_dependency`.id", chunk))).Find(&part); err != nil {
			return nil, err
		}
		maps.Copy(rows, part)
	}
	return rows, nil
}

// FindDependencyUsageOfRepos returns the current rows o selects in the given repositories, grouped by repository, each
// group in the order of FindDependencyUsage.
func FindDependencyUsageOfRepos(ctx context.Context, o *DependencyUsageOptions, repoIDs []int64) (map[int64][]*Dependency, error) {
	out := make(map[int64][]*Dependency, len(repoIDs))
	for chunk := range slices.Chunk(repoIDs, UsageChunk) {
		var rows []*Dependency
		n := *o
		n.RepoCond = o.RepoCond.And(builder.In("`repository`.id", chunk))
		if err := db.GetEngine(ctx).Select("`repo_dependency`.*").Join("INNER", "repository", "`repository`.id = `repo_dependency`.repo_id").Where(n.cond()).
			OrderBy(dependencyUsageOrder).Find(&rows); err != nil {
			return nil, err
		}
		for _, d := range rows {
			out[d.RepoID] = append(out[d.RepoID], d)
		}
	}
	return out, nil
}

// UsageRepoCounts is how many repositories, and how many owners of them, a search result touches.
type UsageRepoCounts struct {
	Repos  int64 `xorm:"repos"`
	Owners int64 `xorm:"owners"`
}

// CountDependencyUsageRepos counts the distinct repositories and owners of the rows o selects.
func CountDependencyUsageRepos(ctx context.Context, o *DependencyUsageOptions) (c UsageRepoCounts, err error) {
	_, err = db.GetEngine(ctx).Table("repo_dependency").Join("INNER", "repository", "`repository`.id = `repo_dependency`.repo_id").Where(o.cond()).
		Select("COUNT(DISTINCT `repo_dependency`.repo_id) AS repos, COUNT(DISTINCT `repository`.owner_id) AS owners").Get(&c)
	return c, err
}

// CountDistinctOwners counts the distinct owners of the repositories with the given IDs.
func CountDistinctOwners(ctx context.Context, repoIDs []int64) (int64, error) {
	owners := map[int64]bool{}
	for chunk := range slices.Chunk(repoIDs, UsageChunk) {
		var ids []int64
		if err := db.GetEngine(ctx).Table("repository").Distinct("owner_id").In("id", chunk).Find(&ids); err != nil {
			return 0, err
		}
		for _, id := range ids {
			owners[id] = true
		}
	}
	return int64(len(owners)), nil
}
