// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"fmt"
	"time"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/timeutil"

	"xorm.io/builder"
)

// UsageGroup is what the job minutes of the instance usage are summed per.
type UsageGroup string

const (
	UsageGroupOrg    UsageGroup = "org" // the owner of the repository, which is not always an organization
	UsageGroupRepo   UsageGroup = "repo"
	UsageGroupRunner UsageGroup = "runner"
)

const (
	// UsageMaxRange is the longest period the usage is computed for.
	UsageMaxRange = 366 * 24 * time.Hour
	// UsageMaxEntries is the most entries a usage list returns.
	UsageMaxEntries    = 200
	usageDefaultPeriod = 30 * 24 * time.Hour
)

// UsageEntry is the usage of one owner, repository or runner (ID 0 is "no runner", -1 a runner that was deleted).
type UsageEntry struct {
	ID         int64
	Name       string
	Seconds    int64 // run time of the finished jobs
	Jobs       int64 // finished jobs
	FailedJobs int64
	FailedRuns int64 // only set by TopReposByFailures
}

// Minutes is the run time of the finished jobs in minutes.
func (e UsageEntry) Minutes() float64 { return float64(e.Seconds) / 60 }

// ParseUsageGroup validates the group_by parameter.
func ParseUsageGroup(s string) (UsageGroup, error) {
	switch g := UsageGroup(s); g {
	case UsageGroupOrg, UsageGroupRepo, UsageGroupRunner:
		return g, nil
	}
	return "", fmt.Errorf("invalid group_by %q, want org, repo or runner", s)
}

// ParseUsageRange reads from and to (RFC 3339 or YYYY-MM-DD). The default is the 30 days up to now; the range may
// not be inverted or longer than 366 days.
func ParseUsageRange(fromStr, toStr string, now timeutil.TimeStamp) (from, to timeutil.TimeStamp, err error) {
	if from, err = parseOrgRunTime(fromStr, false); err != nil {
		return 0, 0, err
	}
	if to, err = parseOrgRunTime(toStr, true); err != nil {
		return 0, 0, err
	}
	period := timeutil.TimeStamp(usageDefaultPeriod / time.Second)
	switch {
	case from == 0 && to == 0:
		to = now
		from = now - period
	case from == 0:
		from = to - period
	case to == 0:
		to = now
	}
	if to < from {
		return 0, 0, fmt.Errorf("from is after to")
	}
	if time.Duration(to-from)*time.Second > UsageMaxRange {
		return 0, 0, fmt.Errorf("the range is longer than 366 days")
	}
	return from, to, nil
}

type usageRow struct {
	ID        int64
	N1, N2    string
	GroupID   int64 // the project of a repository
	GroupName string
	Seconds   int64
	Jobs      int64
	Failed    int64
}

// usageName is the owner, or the full path of a repository (owner/project/name for one in a project).
func usageName(owner, name string, groupID int64, groupName string) string {
	if name == "" {
		return owner
	}
	return (&repo_model.Repository{OwnerName: owner, Name: name, GroupID: groupID, GroupName: groupName}).FullName()
}

func (r usageRow) entry() UsageEntry {
	return UsageEntry{ID: r.ID, Name: usageName(r.N1, r.N2, r.GroupID, r.GroupName), Seconds: r.Seconds, Jobs: r.Jobs, FailedJobs: r.Failed}
}

// GetUsage sums the run time of the jobs that started in [from, to] and have finished, per group, most seconds
// first, in one query. Only repositories orgRunRepoCond lets a site admin see count (tokenRepos limits them
// further); the owner is the repository's, never the job's. A job that never got a runner counts under runner 0, one whose runner is gone under -1.
func GetUsage(ctx context.Context, group UsageGroup, from, to timeutil.TimeStamp, tokenRepos builder.Cond, limit int) ([]UsageEntry, error) {
	id, n1, n2, groupBy := "`repository`.id", "`repository`.owner_name", "`repository`.name", "`repository`.id, `repository`.owner_name, `repository`.name, `repository`.group_id, `repository`.group_name"
	gid, gname := "`repository`.group_id", "`repository`.group_name"
	repoCond := orgRunRepoCond(ctx, nil, nil, true, tokenRepos) // before building the session (reads a setting)
	sess := db.GetEngine(ctx).Table("action_run_job").Join("INNER", "repository", "`repository`.id = `action_run_job`.repo_id")
	switch group {
	case UsageGroupOrg:
		id, n1, n2, groupBy = "`repository`.owner_id", "`user`.name", "''", "`repository`.owner_id, `user`.name"
		gid, gname = "0", "''"
		sess = sess.Join("INNER", "`user`", "`user`.id = `repository`.owner_id")
	case UsageGroupRunner:
		// 0: the job never got a task; -1: its runner is gone (one bucket, not one per job)
		id = "CASE WHEN `action_task`.id IS NULL THEN 0 WHEN `action_runner`.id IS NULL THEN -1 ELSE `action_runner`.id END"
		n1, n2, groupBy = "COALESCE(`action_runner`.name, '')", "''", id+", COALESCE(`action_runner`.name, '')"
		gid, gname = "0", "''"
		sess = sess.Join("LEFT", "action_task", "`action_task`.id = `action_run_job`.task_id").
			Join("LEFT", "action_runner", "`action_runner`.id = `action_task`.runner_id")
	}
	// updated >= from never drops a job (a job is updated when it stops) but lets the updated index narrow the scan
	var rows []usageRow
	err := sess.Where(repoCond).
		And("`action_run_job`.started >= ? AND `action_run_job`.started <= ? AND `action_run_job`.stopped >= `action_run_job`.started AND `action_run_job`.updated >= ?", from, to, from).
		Select(fmt.Sprintf("%s AS id, %s AS n1, %s AS n2, %s AS group_id, %s AS group_name, SUM(`action_run_job`.stopped - `action_run_job`.started) AS seconds, COUNT(*) AS jobs, "+
			"SUM(CASE WHEN `action_run_job`.status = %d THEN 1 ELSE 0 END) AS failed", id, n1, n2, gid, gname, actions_model.StatusFailure)).
		GroupBy(groupBy).OrderBy("seconds DESC, id").Limit(min(limit, UsageMaxEntries)).Find(&rows)
	if err != nil {
		return nil, err
	}
	entries := make([]UsageEntry, len(rows))
	for i, r := range rows {
		entries[i] = r.entry()
	}
	return entries, nil
}

// TopReposByFailures lists the repositories with the most runs that failed, created in [from, to].
func TopReposByFailures(ctx context.Context, from, to timeutil.TimeStamp, tokenRepos builder.Cond, limit int) ([]UsageEntry, error) {
	var rows []struct {
		ID         int64
		N1, N2     string
		GroupID    int64
		GroupName  string
		FailedRuns int64
	}
	repoCond := orgRunRepoCond(ctx, nil, nil, true, tokenRepos)
	err := db.GetEngine(ctx).Table("action_run").Join("INNER", "repository", "`repository`.id = `action_run`.repo_id").
		Where(repoCond).
		And("`action_run`.status = ? AND `action_run`.created >= ? AND `action_run`.created <= ?", actions_model.StatusFailure, from, to).
		Select("`repository`.id AS id, `repository`.owner_name AS n1, `repository`.name AS n2, `repository`.group_id AS group_id, `repository`.group_name AS group_name, COUNT(*) AS failed_runs").
		GroupBy("`repository`.id, `repository`.owner_name, `repository`.name, `repository`.group_id, `repository`.group_name").OrderBy("failed_runs DESC, id").
		Limit(min(limit, UsageMaxEntries)).Find(&rows)
	if err != nil {
		return nil, err
	}
	entries := make([]UsageEntry, len(rows))
	for i, r := range rows {
		entries[i] = UsageEntry{ID: r.ID, Name: usageName(r.N1, r.N2, r.GroupID, r.GroupName), FailedRuns: r.FailedRuns}
	}
	return entries, nil
}

// UsageReport is what the usage page and endpoint show: the entries per group and the top repositories.
type UsageReport struct {
	Entries, TopByMinutes, TopByFailures []UsageEntry
}

// GetUsageReport runs the three queries of the usage views.
func GetUsageReport(ctx context.Context, group UsageGroup, from, to timeutil.TimeStamp, tokenRepos builder.Cond, limit int) (r UsageReport, err error) {
	if r.Entries, err = GetUsage(ctx, group, from, to, tokenRepos, limit); err != nil {
		return r, err
	}
	if r.TopByMinutes, err = GetUsage(ctx, UsageGroupRepo, from, to, tokenRepos, 10); err != nil {
		return r, err
	}
	r.TopByFailures, err = TopReposByFailures(ctx, from, to, tokenRepos, 10)
	return r, err
}
