// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"context"
	"strconv"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	user_model "forgejo.org/models/user"
)

// AuditFields are the settings the audit log keeps before/after for a repository (audit_model.Fields["repo"]).
func (repo *Repository) AuditFields() map[string]any {
	return map[string]any{
		"is_private": repo.IsPrivate, "is_template": repo.IsTemplate, "default_branch": repo.DefaultBranch, "is_mirror": repo.IsMirror,
		"dependency_graph": !repo.DependencyGraphDisabled, "secret_scanning": !repo.SecretScanningDisabled,
	}
}

// RecordRepo records action about repo, scoped to its owner, project and itself.
func RecordRepo(ctx context.Context, action string, repo *Repository, data map[string]any) error {
	return RecordRepoTarget(ctx, repo, audit_model.Event{
		Action: action, TargetType: "repo", TargetID: repo.ID, TargetName: repo.FullName(), Data: data,
	})
}

// RecordRepoTarget records ev, whose action and target (a collaborator, branch or tag) the caller sets, in the scope
// of repo.
func RecordRepoTarget(ctx context.Context, repo *Repository, ev audit_model.Event) error {
	ev.Result, ev.OwnerID, ev.GroupID, ev.RepoID = audit_model.ResultSuccess, repo.OwnerID, repo.GroupID, repo.ID
	return audit_model.Record(ctx, ev)
}

// RecordRepoChange records repo.repository.updated with the settings of repo that differ from the stored row, which
// it reads in ctx's transaction (call it before the write), and nothing when none does.
func RecordRepoChange(ctx context.Context, repo *Repository) error {
	stored := new(Repository)
	if has, err := db.GetEngine(ctx).ID(repo.ID).Get(stored); err != nil || !has {
		return err
	}
	if changes := audit_model.Changes(stored.AuditFields(), repo.AuditFields()); changes != nil {
		return RecordRepo(ctx, "repo.repository.updated", repo, changes)
	}
	return nil
}

// RecordProject records action about the project group of its organization.
func RecordProject(ctx context.Context, action string, group *RepoGroup, data map[string]any) error {
	return audit_model.Record(ctx, audit_model.Event{
		Action: action, Result: audit_model.ResultSuccess, OwnerID: group.OwnerID, GroupID: group.ID,
		TargetType: "project", TargetID: group.ID, TargetName: group.Name, Data: data,
	})
}

// AuditFields are the settings the audit log keeps before/after for a pull mirror; of the LFS endpoint only the origin.
func (m *Mirror) AuditFields() map[string]any {
	return map[string]any{
		"interval": m.Interval.String(), "enable_prune": m.EnablePrune, "branch_filter": m.BranchFilter,
		"tag_filter": m.TagFilter, "lfs": m.LFS, "lfs_endpoint": audit_model.Origin(m.LFSEndpoint),
	}
}

// UpdateMirrorSettings writes the cols of m that its owner sets, and records repo.mirror.updated with the settings
// that differ from the stored row.
func UpdateMirrorSettings(ctx context.Context, m *Mirror, cols ...string) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		stored := new(Mirror)
		if has, err := db.GetEngine(ctx).ID(m.ID).Get(stored); err != nil {
			return err
		} else if has {
			if changes := audit_model.Changes(stored.AuditFields(), m.AuditFields()); changes != nil {
				repo, err := GetRepositoryByID(ctx, m.RepoID)
				if err != nil {
					return err
				}
				if err := RecordRepo(ctx, "repo.mirror.updated", repo, changes); err != nil {
					return err
				}
			}
		}
		return UpdateMirrorCols(ctx, m, cols...)
	})
}

// AuditFields are the settings the audit log keeps before/after for a push mirror; of its address only the origin,
// never the private key.
func (m *PushMirror) AuditFields() map[string]any {
	return map[string]any{
		"remote_name": m.RemoteName, "address": audit_model.Origin(m.RemoteAddress), "interval": m.Interval.String(),
		"sync_on_commit": m.SyncOnCommit, "branch_filter": m.BranchFilter, "use_ssh": m.PublicKey != "",
	}
}

func recordPushMirror(ctx context.Context, action string, m *PushMirror, data map[string]any) error {
	repo := m.Repo
	if repo == nil {
		var err error
		if repo, err = GetRepositoryByIDIncludingTrashed(ctx, m.RepoID); err != nil {
			return err
		}
	}
	return RecordRepoTarget(ctx, repo, audit_model.Event{
		Action: action, TargetType: "push_mirror", TargetID: m.ID, TargetName: m.RemoteName, Data: data,
	})
}

// RecordScoped records the action of actions for the level of a setting that belongs to the repository repoID, the
// project groupID of the organization ownerID, the organization or user ownerID, or the instance (all zero).
func RecordScoped(ctx context.Context, actions audit_model.LevelActions, ownerID, groupID, repoID int64, ev audit_model.Event) error {
	ev.Result, ev.OwnerID, ev.GroupID, ev.RepoID = audit_model.ResultSuccess, ownerID, groupID, repoID
	switch {
	case repoID != 0:
		// only the scope is needed: a change to an object of a trashed repository is recorded all the same
		repo, err := GetRepositoryByIDIncludingTrashed(ctx, repoID)
		if err != nil {
			return err
		}
		ev.Action = actions.Repo
		return RecordRepoTarget(ctx, repo, ev)
	case ownerID != 0:
		owner, err := user_model.GetUserByIDIncludingTrashed(ctx, ownerID)
		if err != nil {
			return err
		}
		ev.Action = actions.Org
		if !owner.IsOrganization() {
			ev.Action, ev.SubjectUserID = actions.Account, ownerID
		}
	default:
		ev.Action = actions.Admin
	}
	return audit_model.Record(ctx, ev)
}

// RecordPushRefused records a push to repo that the server refused, with its reason ("protected_branch", "force_push",
// "push_rule", "size_lock", "org_policy", "deploy_key", "read_only_key", "permission", "merge_queue", "branch_type") and the ref, if one was refused. It is activity:
// a failed write is logged and counted.
func RecordPushRefused(ctx context.Context, repo *Repository, reason, ref string) {
	data := map[string]any{"reason": reason}
	if ref != "" {
		data["ref"] = ref
	}
	key := strconv.FormatInt(repo.ID, 10) + "|" + reason
	if a := audit_model.ActorFromContext(ctx); a != nil {
		key += "|" + audit_model.IPKey(a, 48) + "|" + a.Credential.Type + ":" + strconv.FormatInt(a.Credential.ID, 10)
	}
	audit_model.RecordAggregated(ctx, audit_model.Event{
		Action: "activity.git.push.refused", Result: audit_model.ResultRefused, OwnerID: repo.OwnerID, GroupID: repo.GroupID,
		RepoID: repo.ID, TargetType: "git_push_refused", TargetID: repo.ID, TargetName: repo.FullName(), Data: data,
	}, key)
}
