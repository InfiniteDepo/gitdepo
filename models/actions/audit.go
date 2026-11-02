// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"maps"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
)

// RunnerScope returns the owner and project a runner or registration token of ownerID or repoID is recorded under,
// and its level (global, user, org or repo). A repository-level one has no owner of its own: it comes from the
// repository row, which may be in the trash or being deleted.
func RunnerScope(ctx context.Context, ownerID, repoID int64) (owner, group int64, level string, err error) {
	switch {
	case repoID != 0:
		_, err = db.GetEngine(ctx).Table("repository").Where("id = ?", repoID).Cols("owner_id", "group_id").Get(&owner, &group)
		return owner, group, "repo", err
	case ownerID != 0:
		var typ user_model.UserType
		if _, err = db.GetEngine(ctx).Table("user").Where("id = ?", ownerID).Cols("type").Get(&typ); err != nil {
			return 0, 0, "", err
		}
		if typ == user_model.UserTypeOrganization {
			return ownerID, 0, "org", nil
		}
		return ownerID, 0, "user", nil
	}
	return 0, 0, "global", nil
}

func runnerFields(r *ActionRunner, level string) map[string]any {
	return map[string]any{"name": r.Name, "labels": r.AgentLabels, "level": level, "ephemeral": r.Ephemeral}
}

// recordRunner records a change of the runner, never its secret.
func recordRunner(ctx context.Context, action string, r *ActionRunner, extra map[string]any) error {
	owner, group, level, err := RunnerScope(ctx, r.OwnerID, r.RepoID)
	if err != nil {
		return err
	}
	data := runnerFields(r, level)
	maps.Copy(data, extra)
	return audit_model.RecordCredential(ctx, audit_model.Event{
		Action: action, OwnerID: owner, GroupID: group, RepoID: r.RepoID,
		TargetType: "runner", TargetID: r.ID, TargetName: r.Name, Data: data,
	})
}

// recordRunnerToken records a new registration token by its row: the token itself is never recorded.
func recordRunnerToken(ctx context.Context, t *ActionRunnerToken) error {
	repoID := t.RepoID.ValueOrDefault(0)
	owner, group, level, err := RunnerScope(ctx, t.OwnerID.ValueOrDefault(0), repoID)
	if err != nil {
		return err
	}
	return audit_model.RecordCredential(ctx, audit_model.Event{
		Action: "credential.runner_token.reset", OwnerID: owner, GroupID: group, RepoID: repoID,
		TargetType: "runner_token", TargetID: t.ID, Data: map[string]any{"level": level},
	})
}

// DeleteArtifactOfRun marks the artifact name of the run of repo for deletion, as a user asked, and records
// repo.actions_artifact.deleted when there was one to delete.
func DeleteArtifactOfRun(ctx context.Context, repo *repo_model.Repository, runID int64, name string) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		n, err := db.GetEngine(ctx).Where("run_id=? AND artifact_name=? AND status = ?", runID, name, ArtifactStatusUploadConfirmed).Cols("status").Update(&ActionArtifact{Status: int64(ArtifactStatusPendingDeletion)})
		if err != nil || n == 0 {
			return err
		}
		return repo_model.RecordRepoTarget(ctx, repo, audit_model.Event{
			Action: "repo.actions_artifact.deleted", TargetType: "actions_artifact", TargetName: name,
			Data: map[string]any{"name": name, "run_id": runID},
		})
	})
}
