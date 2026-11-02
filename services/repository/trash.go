// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"forgejo.org/models"
	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	code_indexer "forgejo.org/modules/indexer/code"
	issue_indexer "forgejo.org/modules/indexer/issues"
	"forgejo.org/modules/log"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/sync"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	actions_service "forgejo.org/services/actions"
)

var trashLocks sync.MutexMap

// LockTrash serializes the trash, restore and purge of one item within this process; kind is "repo" or
// "org". Across processes the conditional UPDATEs on trashed_unix decide, so that only one of them wins.
func LockTrash(kind string, id int64) func() {
	return trashLocks.Lock(fmt.Sprintf("%s-%d", kind, id))
}

// TrashRepository moves repo to the trash: it keeps all data but is hidden from everyone but site admins until
// it is restored or purged (see services/trash). The row, its ID and its name stay, so the name stays reserved.
func TrashRepository(ctx context.Context, doer *user_model.User, repo *repo_model.Repository) error {
	if err := cancelPendingRuns(ctx, repo); err != nil {
		return err
	}
	if err := db.WithTx(ctx, func(ctx context.Context) error {
		return trashRepositoryRows(ctx, doer, repo, false)
	}); err != nil {
		return err
	}
	afterTrash(ctx, repo)
	return nil
}

// TrashOwnerRepositories trashes every live repository of owner in one transaction, together with inTx, which
// trashes the owner itself. Their restore and purge follow the owner's (TrashedWithOwner).
func TrashOwnerRepositories(ctx context.Context, doer, owner *user_model.User, inTx func(context.Context) error) error {
	var repos []*repo_model.Repository
	if err := db.GetEngine(ctx).Where("owner_id = ? AND trashed_unix = 0", owner.ID).Find(&repos); err != nil {
		return err
	}
	for _, repo := range repos {
		if err := cancelPendingRuns(ctx, repo); err != nil {
			return err
		}
	}
	if err := db.WithTx(ctx, func(ctx context.Context) error {
		if err := inTx(ctx); err != nil {
			return err
		}
		for _, repo := range repos {
			if err := trashRepositoryRows(ctx, doer, repo, true); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for _, repo := range repos {
		afterTrash(ctx, repo)
	}
	return nil
}

// cancelPendingRuns stops what is running while the repository can still be loaded by the Actions code.
func cancelPendingRuns(ctx context.Context, repo *repo_model.Repository) error {
	runs, err := db.Find[actions_model.ActionRun](ctx, actions_model.FindRunOptions{RepoID: repo.ID, Status: actions_model.PendingStatuses()})
	if err != nil {
		return fmt.Errorf("find pending runs: %w", err)
	}
	for _, run := range runs {
		if err := actions_service.CancelRun(ctx, run); err != nil {
			return fmt.Errorf("cancel run %d: %w", run.ID, err)
		}
	}
	return nil
}

func trashRepositoryRows(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, withOwner bool) error {
	if repo.Status == repo_model.RepositoryPendingTransfer { // the transfer is gone, so the repository is ready again after a restore
		repo.Status = repo_model.RepositoryReady
		if err := repo_model.UpdateRepositoryCols(ctx, repo, "status"); err != nil {
			return err
		}
	}
	// (before the repository is hidden: the update reads it back)
	n, err := db.GetEngine(ctx).Where("id = ? AND trashed_unix = 0", repo.ID).
		Cols("trashed_unix", "trashed_by_id", "trashed_by_name", "trashed_owner_name", "trashed_name", "trashed_with_owner").
		Update(&repo_model.Repository{
			TrashedUnix:      timeutil.TimeStampNow(),
			TrashedByID:      doer.ID,
			TrashedByName:    doer.Name,
			TrashedOwnerName: repo.OwnerName,
			TrashedName:      repo.Name,
			TrashedWithOwner: withOwner,
		})
	if err != nil {
		return err
	} else if n == 0 {
		return repo_model.ErrRepoNotExist{ID: repo.ID}
	}
	if _, err := db.Exec(ctx, "UPDATE `user` SET num_repos=num_repos-1 WHERE id=?", repo.OwnerID); err != nil {
		return err
	}
	if err := organization.AddTeamRepoCounts(ctx, repo.ID, -1); err != nil {
		return err
	}
	if !withOwner { // one trashed with its owner is counted on the owner's entry
		if err := repo_model.RecordRepo(ctx, "repo.repository.trashed", repo, nil); err != nil {
			return err
		}
	}
	if _, err := models.DeleteRepositoryTransfer(ctx, repo.ID); err != nil {
		return err
	}
	// forget what was indexed, so that a restore indexes the code again
	if _, err := db.GetEngine(ctx).Where("repo_id = ? AND indexer_type = ?", repo.ID, repo_model.RepoIndexerTypeCode).Delete(new(repo_model.RepoIndexerStatus)); err != nil {
		return err
	}
	return repo_model.DeleteIndexerBranches(ctx, repo.ID)
}

func afterTrash(ctx context.Context, repo *repo_model.Repository) {
	issue_indexer.DeleteRepoIssueIndexer(ctx, repo.ID)
	if setting.Indexer.RepoIndexerEnabled {
		code_indexer.UpdateRepoIndexer(repo) // the indexer drops the documents of a repository it can't load
	}
}

// MoveTrashedRepository renames the repository in the trash to newName (if not empty) and moves it to newOwner
// (if not nil, a live owner), keeping it hidden until the caller restores it. The old owner may be a
// trashed organization or a tombstone, so the owner is loaded including the trash.
func MoveTrashedRepository(ctx context.Context, doer, newOwner *user_model.User, repo *repo_model.Repository, newName string) error {
	owner, err := user_model.GetUserByIDIncludingTrashed(ctx, repo.OwnerID)
	if err != nil {
		return err
	}
	repo.Owner = owner

	unlock, err := lockRepo(ctx, repo)
	if err != nil {
		return err
	}
	defer unlock()

	// The row is touched first, if it is still in the trash as the caller saw it: the write lock it takes is held
	// until the end, so a purge claiming it meanwhile waits and then deletes the repository where it is now, and
	// one that claimed it before makes this fail before a file moved.
	seen := repo.TrashedUnix
	repo.TrashedUnix = 0 // the update in transferOwnership writes non-zero fields only: it can't re-trash or overwrite a claim
	return db.WithTx(ctx, func(ctx context.Context) error {
		res, err := db.Exec(ctx, "UPDATE `repository` SET trashed_unix=trashed_unix WHERE id=? AND trashed_unix=?", repo.ID, seen)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return ErrTrashConflict
		}
		return moveTrashedRepository(ctx, doer, newOwner, repo, owner, newName)
	})
}

// ErrTrashConflict is returned when the repository is not in the trash any more, or is claimed by a purge.
var ErrTrashConflict = errors.New("the repository is not in the trash, or is being restored or purged already")

func moveTrashedRepository(ctx context.Context, doer, newOwner *user_model.User, repo *repo_model.Repository, owner *user_model.User, newName string) (err error) {
	oldName, finalName, target := repo.Name, repo.Name, owner
	if newName != "" {
		finalName = newName
	}
	if newOwner != nil {
		if newOwner.IsOrganization() && newOwner.IsArchived {
			return organization.ErrOrgArchived{Name: newOwner.Name}
		}
		if err := repo_module.CheckPersonalRepoPolicy(ctx, doer, newOwner, repo.IsPrivate); err != nil {
			return err
		}
		if err := repo_module.CheckPersonalRepoLimit(ctx, newOwner); err != nil {
			return err
		}
		target = newOwner
	}
	// The final place is checked before any file moves, so that a refusal leaves the repository where it is.
	if (newOwner != nil || finalName != oldName) && !(newOwner == nil && strings.EqualFold(finalName, oldName)) {
		if err := repo_model.IsUsableRepoName(strings.ToLower(finalName)); err != nil {
			return err
		}
		groupID := repo.GroupID
		if newOwner != nil { // a transfer puts it at the root of the new owner
			groupID = 0
		}
		// a name taken by a project is refused when the claim is written
		if has, err := repo_model.IsRepositoryModelExistInGroup(ctx, target.ID, groupID, finalName); err != nil {
			return err
		} else if has {
			return repo_model.ErrRepoAlreadyExist{Uname: target.Name, Name: finalName}
		}
	}

	// whatever moved is moved back if a later step fails, as the database changes are rolled back
	renamed, transferred := false, false
	oldRepoPath, oldWikiPath := repo.RepoPath(), repo.WikiPath() // in the repository's project, if any
	// after the rename, before the transfer
	renamedRepoPath := filepath.Join(filepath.Dir(oldRepoPath), strings.ToLower(finalName)+".git")
	renamedWikiPath := filepath.Join(filepath.Dir(oldWikiPath), strings.ToLower(finalName)+".wiki.git")
	defer func() {
		if err == nil {
			return
		}
		if transferred { // to the root of the new owner
			moveDirsBack(repo_model.RepoPath(newOwner.Name, finalName), renamedRepoPath)
			moveDirsBack(repo_model.WikiPath(newOwner.Name, finalName), renamedWikiPath)
		}
		if renamed {
			moveDirsBack(renamedRepoPath, oldRepoPath)
			moveDirsBack(renamedWikiPath, oldWikiPath)
		}
	}()

	if finalName != oldName {
		if err := changeRepositoryName(ctx, repo, finalName); err != nil {
			return err
		}
		renamed = true
		repo.Name = finalName
		repo.LowerName = strings.ToLower(finalName)
		if err := repo_model.UpdateRepositoryCols(ctx, repo, "name", "lower_name"); err != nil {
			return err
		}
	}
	if newOwner == nil {
		return nil
	}
	// Moving the repository takes it off the old owner and its teams once more, and puts it on the new ones, but a
	// trashed repository was taken off already when it was trashed and the restore that follows counts it in.
	if err := organization.AddTeamRepoCounts(ctx, repo.ID, 1); err != nil {
		return err
	}
	if _, err := db.Exec(ctx, "UPDATE `user` SET num_repos=num_repos+1 WHERE id=?", owner.ID); err != nil {
		return err
	}
	if _, err := db.Exec(ctx, "UPDATE `user` SET num_repos=num_repos-1 WHERE id=?", newOwner.ID); err != nil {
		return err
	}
	if err := transferOwnership(ctx, doer, newOwner.Name, repo); err != nil {
		return err
	}
	transferred = true
	return organization.AddTeamRepoCounts(ctx, repo.ID, -1) // the teams of the new owner
}

// moveDirsBack moves a repository or wiki directory back after a failure, if it exists; a failure here is logged only.
func moveDirsBack(from, to string) {
	if ok, _ := util.IsExist(from); !ok {
		return
	}
	if err := util.Rename(from, to); err != nil {
		log.Critical("Unable to move %s back to %s: %v", from, to, err)
	}
}

// TrashUserRepositories moves every live repository of a user who is being deleted to the trash, each as a
// separate item recorded as deleted by the user.
func TrashUserRepositories(ctx context.Context, owner *user_model.User) error {
	var repos []*repo_model.Repository
	if err := db.GetEngine(ctx).Where("owner_id = ? AND trashed_unix = 0", owner.ID).Find(&repos); err != nil {
		return err
	}
	for _, repo := range repos {
		if err := TrashRepository(ctx, owner, repo); err != nil {
			return fmt.Errorf("unable to trash repository %s for %s[%d]. Error: %w", repo.Name, owner.Name, owner.ID, err)
		}
	}
	return nil
}
