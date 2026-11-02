// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"fmt"
	"time"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/timeutil"

	"xorm.io/builder"
)

const (
	day  = 24 * 3600
	week = 7 * day
)

// visibleRepoCond limits col (a repo_id column) to the repositories orgRunRepoCond lets doer see, so every query of
// the overview applies the rule of the runs list. Ownership is the repository's, never the owner_id of a run or job.
func visibleRepoCond(ctx context.Context, col string, org *organization.Organization, doer *user_model.User, admin bool, tokenRepos builder.Cond) builder.Cond {
	return builder.And(
		repo_model.NotTrashedCond(col),
		builder.In(col, builder.Select("id").From("repository").Where(orgRunRepoCond(ctx, org, doer, admin, tokenRepos))),
	)
}

// OrgOverview holds the numbers of the cards of the overview of an organization.
type OrgOverview struct {
	Runs24h, Runs7d int64
	// Failed7d and Finished7d (success or failure) give the failure rate of the last 7 days
	Failed7d, Finished7d int64
	Running              int64 // runs running now
	Queued               int64 // jobs waiting for a runner now
	// AvgQueue is the mean time the jobs started in the last 7 days waited for a runner; it is only a sample when
	// HasQueueSample. Re-run jobs (attempt 2 and up) are left out, as their creation time is the first attempt's.
	AvgQueue       time.Duration
	HasQueueSample bool
}

// FailurePercent is the share of failed runs among the finished ones, rounded; 0 when none finished.
func (o *OrgOverview) FailurePercent() int64 {
	if o.Finished7d == 0 {
		return 0
	}
	return (o.Failed7d*100 + o.Finished7d/2) / o.Finished7d
}

// GetOrgOverview counts the runs and jobs of the repositories of org that doer may see, at time now.
func GetOrgOverview(ctx context.Context, org *organization.Organization, doer *user_model.User, admin bool, tokenRepos builder.Cond, now timeutil.TimeStamp) (*OrgOverview, error) {
	e := db.GetEngine(ctx)
	runCond := visibleRepoCond(ctx, "repo_id", org, doer, admin, tokenRepos)
	jobCond := visibleRepoCond(ctx, "repo_id", org, doer, admin, tokenRepos)
	o := new(OrgOverview)

	// the timestamps are numbers of our own, so they go into the SQL as such
	count := func(since int64) string {
		return fmt.Sprintf("COALESCE(SUM(CASE WHEN created >= %d THEN 1 ELSE 0 END), 0)", since)
	}
	finished := fmt.Sprintf("status IN (%d, %d)", actions_model.StatusSuccess, actions_model.StatusFailure)
	if _, err := e.Table("action_run").Where(runCond).And("created >= ?", int64(now)-week).Select(fmt.Sprintf(
		"%s, COUNT(*), COALESCE(SUM(CASE WHEN %s AND status = %d THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN %s THEN 1 ELSE 0 END), 0)",
		count(int64(now)-day), finished, actions_model.StatusFailure, finished,
	)).Get(&o.Runs24h, &o.Runs7d, &o.Failed7d, &o.Finished7d); err != nil {
		return nil, err
	}
	var err error
	if o.Running, err = e.Where(runCond).And("status = ?", actions_model.StatusRunning).Count(new(actions_model.ActionRun)); err != nil {
		return nil, err
	}
	if o.Queued, err = e.Where(jobCond).And("status = ? AND task_id = 0", actions_model.StatusWaiting).Count(new(actions_model.ActionRunJob)); err != nil {
		return nil, err
	}
	var avg float64
	var samples int64
	if _, err = e.Table("action_run_job").Where(jobCond).And("started >= ? AND attempt <= 1", int64(now)-week).
		Select("COALESCE(AVG(started - created), 0), COUNT(*)").Get(&avg, &samples); err != nil {
		return nil, err
	}
	o.HasQueueSample = samples > 0
	o.AvgQueue = time.Duration(avg * float64(time.Second))
	return o, nil
}

// FindOrgFailingNow lists, newest first, the runs of the default branches that are the latest finished (success or
// failure) run of their repository and workflow and failed, and how many there are. Later cancelled or running
// runs neither hide nor create an entry. Repositories without a default branch have none.
func FindOrgFailingNow(ctx context.Context, org *organization.Organization, doer *user_model.User, admin bool, tokenRepos builder.Cond, limit int) (actions_model.RunList, int64, error) {
	cond := builder.And(
		visibleRepoCond(ctx, "`action_run`.repo_id", org, doer, admin, tokenRepos),
		builder.Eq{"`action_run`.status": actions_model.StatusFailure},
		builder.Expr("`repository`.default_branch <> '' AND SUBSTR(`action_run`.ref, 1, 11) = 'refs/heads/' AND SUBSTR(`action_run`.ref, 12) = `repository`.default_branch"),
		builder.Expr("`action_run`.id = (SELECT MAX(r2.id) FROM action_run r2 WHERE r2.repo_id = `action_run`.repo_id AND r2.workflow_id = `action_run`.workflow_id AND r2.ref = `action_run`.ref AND r2.status IN (?, ?))",
			actions_model.StatusSuccess, actions_model.StatusFailure),
	)
	e := db.GetEngine(ctx)
	total, err := e.Table("action_run").Join("INNER", "repository", "`repository`.id = `action_run`.repo_id").Where(cond).Count()
	if err != nil {
		return nil, 0, err
	}
	var runs actions_model.RunList
	err = e.Table("action_run").Join("INNER", "repository", "`repository`.id = `action_run`.repo_id").Where(cond).
		Select("`action_run`.*").Desc("`action_run`.id").Limit(limit).Find(&runs)
	if err != nil {
		return nil, 0, err
	}
	runs, err = LoadOrgRunRepos(ctx, runs)
	return runs, total, err
}

// QueuedJob is a job waiting for a runner. HasRunner is whether an online runner could take it; nothing else about
// the runners is told, as they may belong to someone the viewer can't see.
type QueuedJob struct {
	Job       *actions_model.ActionRunJob
	Run       *actions_model.ActionRun
	Repo      *repo_model.Repository
	HasRunner bool
}

// FindOrgQueue lists, oldest first, the jobs waiting for a runner and how many there are. A runner matches as the
// dispatcher matches it: it is online, its labels cover the job's runs-on and it is global, or belongs to the
// organization (the owner of the repository), or to the repository of the job.
func FindOrgQueue(ctx context.Context, org *organization.Organization, doer *user_model.User, admin bool, tokenRepos builder.Cond, limit int, now timeutil.TimeStamp) ([]*QueuedJob, int64, error) {
	e := db.GetEngine(ctx)
	cond := builder.And(visibleRepoCond(ctx, "repo_id", org, doer, admin, tokenRepos), builder.Eq{"status": actions_model.StatusWaiting, "task_id": 0})
	total, err := e.Where(cond).Count(new(actions_model.ActionRunJob))
	if err != nil || total == 0 {
		return nil, 0, err
	}
	var jobs []*actions_model.ActionRunJob
	if err := e.Where(cond).Omit("workflow_payload").Asc("created", "id").Limit(limit).Find(&jobs); err != nil {
		return nil, 0, err
	}
	runIDs, repoIDs := make([]int64, len(jobs)), make([]int64, len(jobs))
	for i, job := range jobs {
		runIDs[i], repoIDs[i] = job.RunID, job.RepoID
	}
	runs := map[int64]*actions_model.ActionRun{}
	if err := e.In("id", runIDs).Omit("event_payload").Find(&runs); err != nil {
		return nil, 0, err
	}
	repos, err := repo_model.GetRepositoriesMapByIDs(ctx, repoIDs)
	if err != nil {
		return nil, 0, err
	}
	var runners []*actions_model.ActionRunner
	if err := e.Cols("owner_id", "repo_id", "agent_labels").
		Where("last_online >= ?", int64(now)-int64(actions_model.RunnerOfflineTime/time.Second)).
		And(builder.Or(
			builder.Eq{"owner_id": 0, "repo_id": 0},
			builder.Eq{"owner_id": org.ID, "repo_id": 0},
			builder.In("repo_id", repoIDs),
		)).Find(&runners); err != nil {
		return nil, 0, err
	}

	queue := make([]*QueuedJob, 0, len(jobs))
	for _, job := range jobs {
		repo, run := repos[job.RepoID], runs[job.RunID]
		if repo == nil || run == nil { // went away since the query
			continue
		}
		run.Repo = repo // for its link
		q := &QueuedJob{Job: job, Run: run, Repo: repo}
		for _, r := range runners {
			if (r.RepoID == 0 || r.RepoID == job.RepoID) && (r.OwnerID == 0 || r.OwnerID == repo.OwnerID) && job.ItRunsOn(r.AgentLabels) {
				q.HasRunner = true
				break
			}
		}
		queue = append(queue, q)
	}
	return queue, total, nil
}
