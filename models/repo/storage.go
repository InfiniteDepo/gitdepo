// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"forgejo.org/models/db"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"

	"github.com/dustin/go-humanize"
	"xorm.io/builder"
)

// repoStorageSelect sums the repository table: trashed repositories only count as trash.
const repoStorageSelect = `SUM(CASE WHEN trashed_unix = 0 THEN 1 ELSE 0 END) AS num_repos,
	SUM(CASE WHEN trashed_unix = 0 THEN git_size ELSE 0 END) AS git_size,
	SUM(CASE WHEN trashed_unix = 0 THEN lfs_size ELSE 0 END) AS lfs_size,
	SUM(CASE WHEN trashed_unix = 0 THEN wiki_size ELSE 0 END) AS wiki_size,
	0 AS attachments_size, 0 AS packages_size, 0 AS artifacts_size, 0 AS logs_size,
	SUM(CASE WHEN trashed_unix = 0 THEN 0 ELSE git_size + lfs_size + wiki_size END) AS trash_size`

// storageUnion has, per owner, one row for each storage type; sum it by owner_id. Its one parameter is false.
// Packages count each blob once per owner; artifact statuses 4-6 are expired, pending deletion and deleted.
const storageUnion = "SELECT owner_id, " + repoStorageSelect + " FROM `repository` GROUP BY owner_id" + `
	UNION ALL SELECT ` + "`repository`" + `.owner_id, 0, 0, 0, 0, SUM(` + "`attachment`" + `.size), 0, 0, 0, 0
		FROM ` + "`attachment` INNER JOIN `repository` ON `repository`.id = `attachment`.repo_id GROUP BY `repository`.owner_id" + `
	UNION ALL SELECT owner_id, 0, 0, 0, 0, 0, SUM(blob_size), 0, 0, 0
		FROM (SELECT DISTINCT ` + "`package`.owner_id AS owner_id, `package_blob`.id AS blob_id, `package_blob`.size AS blob_size FROM `package`" + `
			INNER JOIN ` + "`package_version` ON `package_version`.package_id = `package`.id" + `
			INNER JOIN ` + "`package_file` ON `package_file`.version_id = `package_version`.id" + `
			INNER JOIN ` + "`package_blob` ON `package_blob`.id = `package_file`.blob_id) blobs GROUP BY owner_id" + `
	UNION ALL SELECT ` + "`repository`" + `.owner_id, 0, 0, 0, 0, 0, 0, SUM(` + "`action_artifact`" + `.file_compressed_size), 0, 0
		FROM ` + "`action_artifact` INNER JOIN `repository` ON `repository`.id = `action_artifact`.repo_id" + `
		WHERE ` + "`action_artifact`" + `.status NOT IN (4, 5, 6) GROUP BY ` + "`repository`" + `.owner_id
	UNION ALL SELECT ` + "`repository`" + `.owner_id, 0, 0, 0, 0, 0, 0, 0, SUM(` + "`action_task`" + `.log_size), 0
		FROM ` + "`action_task` INNER JOIN `repository` ON `repository`.id = `action_task`.repo_id" + `
		WHERE ` + "`action_task`" + `.log_expired = ? GROUP BY ` + "`repository`" + `.owner_id`

// storageSums sums each column of the per-owner rows.
const storageSums = `COALESCE(SUM(num_repos), 0) AS num_repos, COALESCE(SUM(git_size), 0) AS git_size,
	COALESCE(SUM(lfs_size), 0) AS lfs_size, COALESCE(SUM(wiki_size), 0) AS wiki_size,
	COALESCE(SUM(attachments_size), 0) AS attachments_size, COALESCE(SUM(packages_size), 0) AS packages_size,
	COALESCE(SUM(artifacts_size), 0) AS artifacts_size, COALESCE(SUM(logs_size), 0) AS logs_size,
	COALESCE(SUM(trash_size), 0) AS trash_size`

// StorageStats sums the storage of a set of repositories or owners, in bytes.
type StorageStats struct {
	NumRepos        int64 `xorm:"num_repos"`
	GitSize         int64 `xorm:"git_size"`
	LFSSize         int64 `xorm:"lfs_size"`
	WikiSize        int64 `xorm:"wiki_size"`
	AttachmentsSize int64 `xorm:"attachments_size"` // issue and release attachments
	PackagesSize    int64 `xorm:"packages_size"`
	ArtifactsSize   int64 `xorm:"artifacts_size"`
	LogsSize        int64 `xorm:"logs_size"`
	TrashSize       int64 `xorm:"trash_size"` // git, LFS and wiki of repositories in the trash
}

// Size returns every type of storage combined, except the trash.
func (s StorageStats) Size() int64 {
	return s.GitSize + s.LFSSize + s.WikiSize + s.AttachmentsSize + s.PackagesSize + s.ArtifactsSize + s.LogsSize
}

// AverageRepoSize returns the mean git and LFS size per repository, the same measure as GetMedianRepoSize. It is not
// Size()/NumRepos: wiki, attachments, packages, artifacts and logs are not a property of the repository (packages
// belong to the owner), so the average and the median describe the repository itself.
func (s StorageStats) AverageRepoSize() int64 {
	return (s.GitSize + s.LFSSize) / max(s.NumRepos, 1)
}

// Percent returns the share of total, in percent, that s uses.
func (s StorageStats) Percent(total StorageStats) float64 {
	if total.Size() == 0 {
		return 0
	}
	return float64(s.Size()) * 100 / float64(total.Size())
}

// GetStorageTotals returns the storage used on the instance. Unlike the sum of the owners, it counts a package
// blob that several owners use once.
func GetStorageTotals(ctx context.Context) (StorageStats, error) {
	var stats StorageStats
	if _, err := db.GetEngine(ctx).SQL("SELECT "+storageSums+" FROM ("+storageUnion+") s", false).Get(&stats); err != nil {
		return stats, err
	}
	_, err := db.GetEngine(ctx).Table("package_blob").
		Where(builder.In("id", builder.Select("blob_id").From("package_file"))).
		Select("COALESCE(SUM(size), 0)").Get(&stats.PackagesSize)
	return stats, err
}

// GetOwnerStorageTotals returns the storage used by the repositories of one owner (repository count, git, LFS,
// wiki and trash).
func GetOwnerStorageTotals(ctx context.Context, ownerID int64) (StorageStats, error) {
	var stats StorageStats
	_, err := db.GetEngine(ctx).Table("repository").Where("owner_id = ?", ownerID).Select(repoStorageSelect).Get(&stats)
	return stats, err
}

// AssetSizesByRepo returns, per repository ID, the size of its attachments, artifacts and logs; repositories
// without any are left out.
func AssetSizesByRepo(ctx context.Context) (map[int64]*StorageStats, error) {
	type row struct {
		RepoID int64 `xorm:"repo_id"`
		Size   int64 `xorm:"size"`
	}
	sizes := map[int64]*StorageStats{}
	for _, q := range []struct {
		table, column string
		cond          builder.Cond
		field         func(*StorageStats) *int64
	}{
		{"attachment", "size", builder.Gt{"repo_id": 0}, func(s *StorageStats) *int64 { return &s.AttachmentsSize }},
		{"action_artifact", "file_compressed_size", builder.NotIn("status", 4, 5, 6), func(s *StorageStats) *int64 { return &s.ArtifactsSize }},
		{"action_task", "log_size", builder.Eq{"log_expired": false}, func(s *StorageStats) *int64 { return &s.LogsSize }},
	} {
		var rows []row
		if err := db.GetEngine(ctx).Table(q.table).Where(q.cond).Select("repo_id, SUM(" + q.column + ") AS size").GroupBy("repo_id").Find(&rows); err != nil {
			return nil, err
		}
		for _, r := range rows {
			if sizes[r.RepoID] == nil {
				sizes[r.RepoID] = &StorageStats{}
			}
			*q.field(sizes[r.RepoID]) = r.Size
		}
	}
	return sizes, nil
}

// GetMedianRepoSize returns the median git and LFS size of the repositories outside the trash (numRepos of them),
// rounded down to whole bytes.
func GetMedianRepoSize(ctx context.Context, numRepos int64) (int64, error) {
	if numRepos == 0 {
		return 0, nil
	}
	offset, limit := (numRepos-1)/2, 1
	if numRepos%2 == 0 {
		offset, limit = numRepos/2-1, 2
	}
	var sizes []int64
	if err := db.GetEngine(ctx).Table("repository").Where("trashed_unix = 0").Select("git_size + lfs_size AS total_size").
		OrderBy("git_size + lfs_size, id").Limit(limit, int(offset)).Find(&sizes); err != nil {
		return 0, err
	}
	var sum int64
	for _, size := range sizes {
		sum += size
	}
	return sum / int64(max(len(sizes), 1)), nil
}

// sizeFilterColumns maps the fields of a SizeFilter to their SQL expression.
var sizeFilterColumns = map[string]string{
	"git":   "git_size",
	"lfs":   "lfs_size",
	"total": "git_size + lfs_size",
}

// SizeFilter limits repositories to a size range of one field, in bytes. A zero Field filters nothing.
type SizeFilter struct {
	Field    string // a key of sizeFilterColumns
	Min, Max optional.Option[int64]
}

// ParseSizeFilter parses a field ("git", "lfs" or "total") and inclusive bounds such as "10 GB"; empty bounds are open.
func ParseSizeFilter(field, minSize, maxSize string) (SizeFilter, error) {
	if field == "" && minSize == "" && maxSize == "" {
		return SizeFilter{}, nil
	}
	if _, ok := sizeFilterColumns[field]; !ok {
		return SizeFilter{}, errors.New("unknown size field")
	}
	parse := func(s string) (optional.Option[int64], error) {
		if s == "" {
			return optional.None[int64](), nil
		}
		n, err := humanize.ParseBytes(s)
		if err != nil {
			return optional.None[int64](), err
		}
		if n > math.MaxInt64 {
			return optional.None[int64](), errors.New("size too large")
		}
		return optional.Some(int64(n)), nil
	}
	f := SizeFilter{Field: field}
	var err error
	if f.Min, err = parse(minSize); err != nil {
		return SizeFilter{}, err
	}
	if f.Max, err = parse(maxSize); err != nil {
		return SizeFilter{}, err
	}
	if f.Min.Has() && f.Max.Has() && f.Min.ValueOrDefault(0) > f.Max.ValueOrDefault(0) {
		return SizeFilter{}, errors.New("minimum size is above the maximum")
	}
	return f, nil
}

// Cond returns the condition of the filter.
func (f SizeFilter) Cond() builder.Cond {
	cond := builder.NewCond()
	column, ok := sizeFilterColumns[f.Field]
	if !ok {
		return cond
	}
	if has, v := f.Min.Get(); has {
		cond = cond.And(builder.Expr(column+" >= ?", v))
	}
	if has, v := f.Max.Get(); has {
		cond = cond.And(builder.Expr(column+" <= ?", v))
	}
	return cond
}

// OwnerStorage is the storage used by the repositories of one owner.
type OwnerStorage struct {
	OwnerID      int64 `xorm:"owner_id"`
	StorageStats `xorm:"extends"`
	Owner        *user_model.User `xorm:"-"`
}

// ownerStorageTotal is the ORDER BY expression of StorageStats.Size.
const ownerStorageTotal = "SUM(git_size) + SUM(lfs_size) + SUM(wiki_size) + SUM(attachments_size) + SUM(packages_size) + SUM(artifacts_size) + SUM(logs_size)"

// OwnerStorageOrderBy maps the sort keys of the storage report to their ORDER BY clause.
var OwnerStorageOrderBy = map[string]string{
	"size":                   ownerStorageTotal + " ASC",
	"reversesize":            ownerStorageTotal + " DESC",
	"gitsize":                "SUM(git_size) ASC",
	"reversegitsize":         "SUM(git_size) DESC",
	"lfssize":                "SUM(lfs_size) ASC",
	"reverselfssize":         "SUM(lfs_size) DESC",
	"wikisize":               "SUM(wiki_size) ASC",
	"reversewikisize":        "SUM(wiki_size) DESC",
	"attachmentssize":        "SUM(attachments_size) ASC",
	"reverseattachmentssize": "SUM(attachments_size) DESC",
	"packagessize":           "SUM(packages_size) ASC",
	"reversepackagessize":    "SUM(packages_size) DESC",
	"artifactssize":          "SUM(artifacts_size) ASC",
	"reverseartifactssize":   "SUM(artifacts_size) DESC",
	"logssize":               "SUM(logs_size) ASC",
	"reverselogssize":        "SUM(logs_size) DESC",
	"trashsize":              "SUM(trash_size) ASC",
	"reversetrashsize":       "SUM(trash_size) DESC",
	"fewestrepos":            "SUM(num_repos) ASC",
	"mostrepos":              "SUM(num_repos) DESC",
}

// FindOwnerStorageOptions filters and sorts FindOwnerStorage.
type FindOwnerStorageOptions struct {
	db.ListOptions // PageSize 0 returns all owners
	Keyword        string
	OwnerType      optional.Option[user_model.UserType]
	OrderBy        string // a key of OwnerStorageOrderBy, anything else sorts by "reversesize"
}

// FindOwnerStorage returns the storage used per owner, and the number of owners. An owner with only packages, or
// only trashed repositories, is listed too.
func FindOwnerStorage(ctx context.Context, opts FindOwnerStorageOptions) ([]*OwnerStorage, int64, error) {
	cond := builder.NewCond()
	if opts.Keyword != "" || opts.OwnerType.Has() {
		userCond := builder.NewCond()
		if opts.Keyword != "" {
			userCond = userCond.And(builder.Like{"lower_name", strings.ToLower(opts.Keyword)})
		}
		if has, ownerType := opts.OwnerType.Get(); has {
			userCond = userCond.And(builder.Eq{"type": ownerType})
		}
		cond = builder.In("owner_id", builder.Select("id").From("`user`").Where(userCond))
	}
	where, whereArgs, err := builder.ToSQL(cond)
	if err != nil {
		return nil, 0, err
	}
	if where != "" {
		where = " WHERE " + where
	}
	args := append([]any{false}, whereArgs...)

	var count int64
	if _, err := db.GetEngine(ctx).SQL("SELECT COUNT(DISTINCT owner_id) FROM ("+storageUnion+") s"+where, args...).Get(&count); err != nil {
		return nil, 0, err
	}

	orderBy, ok := OwnerStorageOrderBy[opts.OrderBy]
	if !ok {
		orderBy = OwnerStorageOrderBy["reversesize"]
	}
	query := "SELECT owner_id, " + storageSums +
		" FROM (" + storageUnion + ") s" + where + " GROUP BY owner_id ORDER BY " + orderBy + ", owner_id ASC"
	if opts.PageSize > 0 {
		skip, limit := opts.GetSkipTake()
		query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, skip)
	}
	owners := make([]*OwnerStorage, 0, opts.PageSize)
	if err := db.GetEngine(ctx).SQL(query, args...).Find(&owners); err != nil {
		return nil, 0, err
	}

	ids := make([]int64, len(owners))
	for i, o := range owners {
		ids[i] = o.OwnerID
	}
	users := make(map[int64]*user_model.User, len(ids))
	if err := db.GetEngine(ctx).In("id", ids).Find(&users); err != nil {
		return nil, 0, err
	}
	for _, o := range owners {
		o.Owner = users[o.OwnerID]
		if o.Owner == nil {
			o.Owner = user_model.NewGhostUser()
		}
	}
	return owners, count, nil
}
