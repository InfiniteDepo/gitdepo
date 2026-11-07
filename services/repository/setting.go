// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"
	"slices"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	"forgejo.org/modules/log"
	actions_service "forgejo.org/services/actions"
)

// TextUnitsTurnedOn runs after a committed change of a repository's units that turned its Issues or Pull requests unit
// on (UpdateRepositoryUnits reset its secret scanning text scan in the same transaction). Secret scanning sets it to
// queue the repository: services/secretscan's tests import this package, so it can't be imported here. Known limit:
// lifting the site unit policy or an organization's unit setting doesn't reset the text scan (text kept while the
// unit was hidden is read only by a Rescan).
var TextUnitsTurnedOn = func(context.Context, *repo_model.Repository) {}

// UpdateRepositoryUnits updates a repository's units
func UpdateRepositoryUnits(ctx context.Context, repo *repo_model.Repository, units []repo_model.RepoUnit, deleteUnitTypes []unit.Type) (err error) {
	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	// Delete existing settings of units before adding again
	for _, u := range units {
		deleteUnitTypes = append(deleteUnitTypes, u.Type)
	}

	if slices.Contains(deleteUnitTypes, unit.TypeActions) {
		if err := actions_service.CleanRepoScheduleTasks(ctx, repo, true); err != nil {
			log.Error("CleanRepoScheduleTasks: %v", err)
		}
	}

	for _, u := range units {
		if u.Type == unit.TypeActions {
			if err := actions_service.DetectAndHandleSchedules(ctx, repo); err != nil {
				log.Error("DetectAndHandleSchedules: %v", err)
			}
			break
		}
	}

	var stored []unit.Type
	if err = db.GetEngine(ctx).Table("repo_unit").Where("repo_id = ?", repo.ID).Cols("type").Find(&stored); err != nil {
		return err
	}
	after := slices.DeleteFunc(slices.Clone(stored), func(t unit.Type) bool { return slices.Contains(deleteUnitTypes, t) })
	for _, u := range units {
		after = append(after, u.Type)
	}
	// text in an Issues or Pull requests unit that was off was not scanned for secrets: its text scan starts again
	textOn := false
	for _, t := range []unit.Type{unit.TypeIssues, unit.TypePullRequests} {
		if slices.Contains(after, t) && !slices.Contains(stored, t) {
			textOn = true
		}
	}
	if textOn {
		if err := secretscan_model.ResetTextScans(ctx, repo.ID); err != nil {
			return err
		}
	}
	if b, a := unitNames(stored), unitNames(after); !slices.Equal(b, a) {
		if err = repo_model.RecordRepo(ctx, "repo.units.changed", repo, map[string]any{
			"before": map[string]any{"units": b}, "after": map[string]any{"units": a},
		}); err != nil {
			return err
		}
	}

	// the units forms own neither the branching model nor the audit of the delete-after-merge mode: the model is
	// carried over from the stored row, and a changed mode is recorded here, so every writer (web, API) is covered
	for _, u := range units {
		if u.Type != unit.TypePullRequests {
			continue
		}
		newCfg, ok := u.Config.(*repo_model.PullRequestsConfig)
		if !ok {
			continue
		}
		old := &repo_model.RepoUnit{}
		if has, err := db.GetEngine(ctx).Where("repo_id = ? AND type = ?", repo.ID, unit.TypePullRequests).Get(old); err != nil {
			return err
		} else if !has {
			continue
		}
		oldCfg := old.PullRequestsConfig()
		newCfg.BranchingModel = oldCfg.BranchingModel
		if changes := audit_model.Changes(map[string]any{"mode": oldCfg.GetDeleteBranchAfterMerge().String()}, map[string]any{"mode": newCfg.GetDeleteBranchAfterMerge().String()}); changes != nil {
			if err := repo_model.RecordRepo(ctx, "repo.branch_workflow.changed", repo, changes); err != nil {
				return err
			}
		}
	}

	if _, err = db.GetEngine(ctx).Where("repo_id = ?", repo.ID).In("type", deleteUnitTypes).Delete(new(repo_model.RepoUnit)); err != nil {
		return err
	}

	if len(units) > 0 {
		if err = db.Insert(ctx, units); err != nil {
			return err
		}
	}

	if err := committer.Commit(); err != nil {
		return err
	}
	if textOn {
		TextUnitsTurnedOn(ctx, repo)
	}
	return nil
}

// SetArchiveRepoState archives or unarchives repo, and records the change.
func SetArchiveRepoState(ctx context.Context, repo *repo_model.Repository, isArchived bool) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if repo.IsArchived != isArchived {
			action := "repo.repository.unarchived"
			if isArchived {
				action = "repo.repository.archived"
			}
			if err := repo_model.RecordRepo(ctx, action, repo, nil); err != nil {
				return err
			}
		}
		return repo_model.SetArchiveRepoState(ctx, repo, isArchived)
	})
}

// unitNames are the sorted audit names of the unit types, without duplicates.
func unitNames(types []unit.Type) []string {
	names := make([]string, 0, len(types))
	for _, t := range types {
		names = append(names, organization.UnitName(t))
	}
	slices.Sort(names)
	return slices.Compact(names)
}
