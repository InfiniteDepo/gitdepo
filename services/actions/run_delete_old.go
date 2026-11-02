// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"fmt"

	actions_model "forgejo.org/models/actions"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
)

// MaxDeleteOldRuns is the most runs one "delete runs older than" request removes, so that it can't hold the database.
const MaxDeleteOldRuns = 100

// CountOldRuns counts the completed runs of the repository that DeleteOldRuns would delete, kept runs and the latest
// run of each workflow on the default branch not included.
func CountOldRuns(ctx context.Context, repo *repo_model.Repository, days int64) (int64, error) {
	exclude, err := actions_model.GetLatestDefaultBranchRunIDs(ctx, repo.ID)
	if err != nil {
		return 0, fmt.Errorf("could not retrieve latest runs: %w", err)
	}
	return actions_model.CountOldDoneRunsOfRepo(ctx, repo.ID, actions_model.RetentionCutoff(days), exclude)
}

// DeleteOldRuns deletes the completed runs of the repository older than the given number of days, at most
// MaxDeleteOldRuns, and reports whether more are left. Kept runs, running and waiting runs and the latest run of each
// workflow on the default branch are never deleted; a run kept after it was selected is spared. A run with an
// unfinished job is skipped and stays selected by the next call, so callers stop when nothing was deleted.
func DeleteOldRuns(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, days int64) (deleted int, more bool, err error) {
	exclude, err := actions_model.GetLatestDefaultBranchRunIDs(ctx, repo.ID)
	if err != nil {
		return 0, false, fmt.Errorf("could not retrieve latest runs: %w", err)
	}
	ids, err := actions_model.FindOldDoneRunIDsOfRepo(ctx, repo.ID, actions_model.RetentionCutoff(days), exclude, MaxDeleteOldRuns+1)
	if err != nil {
		return 0, false, fmt.Errorf("could not retrieve runs to delete: %w", err)
	}
	if more = len(ids) > MaxDeleteOldRuns; more {
		ids = ids[:MaxDeleteOldRuns]
	}
	if len(ids) > 0 {
		// recorded before anything is deleted, so a failed record deletes nothing
		if err := recordRunsDeleted(ctx, "repo.actions_runs.deleted_old", repo, days, ids); err != nil {
			return 0, false, err
		}
	}
	for _, id := range ids {
		if err := DeleteRunUnlessKept(ctx, id); err != nil {
			if !errors.Is(err, ErrRunKept) {
				log.Error("Failed to delete run %d: %v", id, err)
			}
			continue
		}
		deleted++
	}
	log.Info("User %d deleted %d runs older than %d days from repository %d", doer.ID, deleted, days, repo.ID)
	return deleted, more, nil
}
