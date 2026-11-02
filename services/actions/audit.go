// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"

	"xorm.io/builder"
)

// recordRunDeleted records repo.actions_run.deleted for run with what goes with it, before anything is deleted.
func recordRunDeleted(ctx context.Context, run *actions_model.ActionRun) error {
	repo, err := repo_model.GetRepositoryByID(ctx, run.RepoID)
	if err != nil {
		return err
	}
	e := db.GetEngine(ctx)
	jobs, err := e.Where("run_id = ?", run.ID).Count(new(actions_model.ActionRunJob))
	if err != nil {
		return err
	}
	tasks, err := e.Where(builder.In("job_id", builder.Select("id").From("action_run_job").Where(builder.Eq{"run_id": run.ID}))).Count(new(actions_model.ActionTask))
	if err != nil {
		return err
	}
	artifacts, err := e.Where("run_id = ? AND status < ?", run.ID, actions_model.ArtifactStatusPendingDeletion).Count(new(actions_model.ActionArtifact))
	if err != nil {
		return err
	}
	return repo_model.RecordRepoTarget(ctx, repo, audit_model.Event{
		Action: "repo.actions_run.deleted", TargetType: "actions_run", TargetID: run.ID, TargetName: run.WorkflowID,
		Data: map[string]any{
			"index": run.Index, "workflow": run.WorkflowID,
			"counts": map[string]any{"jobs": jobs, "tasks": tasks, "artifacts": artifacts},
		},
	})
}

// recordRunsDeleted records action (repo.actions_runs.deleted_old or .cleaned) for runIDs of repo.
func recordRunsDeleted(ctx context.Context, action string, repo *repo_model.Repository, days int64, runIDs []int64) error {
	return repo_model.RecordRepoTarget(ctx, repo, audit_model.Event{
		Action: action, TargetType: "actions_runs",
		Data: map[string]any{"older_than_days": days, "count": len(runIDs), "run_ids": runIDs},
	})
}

// recordExpired records action (admin.actions.logs_expired or .artifacts_expired) with count, when there was any.
func recordExpired(ctx context.Context, action string, count int) error {
	if count == 0 {
		return nil
	}
	return audit_model.Record(ctx, audit_model.Event{
		Action: action, Result: audit_model.ResultSuccess, TargetType: "actions_cleanup",
		Data: map[string]any{"count": count},
	})
}
