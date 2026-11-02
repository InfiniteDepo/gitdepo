// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"context"
	"fmt"
	"os"
	"path"
	"slices"

	"forgejo.org/models"
	asymkey_model "forgejo.org/models/asymkey"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	"forgejo.org/modules/util"
	notify_service "forgejo.org/services/notify"
	pull_service "forgejo.org/services/pull"
)

// ErrRepoMoved is returned when the repository changed its project while a change of it waited for its locks.
var ErrRepoMoved = fmt.Errorf("%w: the repository was moved meanwhile", util.ErrInvalidArgument)

func groupLockKey(id int64) string {
	return fmt.Sprintf("group-%d", id)
}

// lockRepo takes the process locks for a change of the repository: those of its project and of the projects in
// groupIDs by ascending ID, then the repository's. RenameRepoGroup takes its project's lock, then those of its
// repositories by ascending ID: one order everywhere, so two changes never wait for each other. The repository's
// project is read again once locked: ErrRepoMoved if it changed meanwhile, and its name is refreshed.
func lockRepo(ctx context.Context, repo *repo_model.Repository, groupIDs ...int64) (func(), error) {
	ids := append([]int64{repo.GroupID}, groupIDs...)
	slices.Sort(ids)
	var unlocks []func()
	for _, id := range slices.Compact(ids) {
		if id != 0 {
			unlocks = append(unlocks, repoWorkingPool.Lock(groupLockKey(id)))
		}
	}
	unlocks = append(unlocks, repoWorkingPool.Lock(fmt.Sprint(repo.ID)))
	unlock := func() {
		for _, unlock := range slices.Backward(unlocks) {
			unlock()
		}
	}
	var row struct {
		GroupID   int64
		GroupName string
	}
	if _, err := db.GetEngine(ctx).Table("repository").Where("id = ?", repo.ID).Cols("group_id", "group_name").Get(&row); err != nil {
		unlock()
		return nil, err
	} else if row.GroupID != repo.GroupID {
		unlock()
		return nil, ErrRepoMoved
	}
	repo.GroupName = row.GroupName // the project may have been renamed meanwhile
	return unlock, nil
}

// MoveRepository moves a repository of an organization into the organization's project groupID, or to its root
// (0). Only an acting owner of the organization or a site admin may. The old path redirects to the new one, and the
// move is recorded in the feed like a transfer.
func MoveRepository(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, groupID int64) error {
	if err := repo.LoadOwner(ctx); err != nil {
		return err
	}
	owner := repo.Owner
	if !owner.IsOrganization() {
		return repo_model.ErrRepoGroupNotExist
	}
	if !doer.IsAdmin {
		if isOwner, err := organization.OrgFromUser(owner).IsActingOwner(ctx, doer); err != nil {
			return err
		} else if !isOwner {
			return util.ErrPermissionDenied
		}
	}
	if owner.IsArchived {
		return organization.ErrOrgArchived{Name: owner.Name}
	}
	if err := models.TestRepositoryReadyForTransfer(repo.Status); err != nil {
		return err
	}
	if groupID == repo.GroupID {
		return util.NewInvalidArgumentErrorf("the repository is there already")
	}

	unlock, err := lockRepo(ctx, repo, groupID)
	if err != nil {
		return err
	}
	defer unlock()
	oldPlace := path.Dir(repo.FullName())
	if err := moveRepository(ctx, repo, groupID); err != nil {
		return err
	}
	notify_service.TransferRepository(ctx, doer, repo, oldPlace)
	// the project's branch rules apply now: their protected files are stored per pull request
	if err := pull_service.CheckPRsForRepo(ctx, repo.ID); err != nil {
		log.Error("CheckPRsForRepo: %v", err)
	}
	return nil
}

// moveRepository changes the project of the repository and moves its directories, in one transaction: the database
// changes are rolled back and the directories moved back if any step fails.
func moveRepository(ctx context.Context, repo *repo_model.Repository, groupID int64) (err error) {
	oldGroupID, oldGroupName := repo.GroupID, repo.GroupName
	oldRepoPath, oldWikiPath := repo.RepoPath(), repo.WikiPath()
	var moved [][2]string
	defer func() {
		if err == nil {
			return
		}
		repo.GroupID, repo.GroupName = oldGroupID, oldGroupName
		for _, p := range slices.Backward(moved) {
			moveDirsBack(p[1], p[0])
		}
	}()

	return db.WithTx(ctx, func(ctx context.Context) error {
		// both project rows stay locked until the end, by ascending ID: a concurrent DeleteRepoGroup sees the
		// repository or this sees no project, and a link or unlink of either project runs before or after the move
		groupName := ""
		for _, id := range slices.Sorted(slices.Values([]int64{oldGroupID, groupID})) {
			if id == 0 {
				continue
			}
			group, err := repo_model.LockRepoGroup(ctx, repo.OwnerID, id)
			if err != nil {
				return err
			}
			if id == groupID {
				groupName = group.Name
			}
		}
		// a name held by a project is refused when the claim is written; the unique key decides races
		if has, err := repo_model.IsRepositoryModelExistInGroup(ctx, repo.OwnerID, groupID, repo.Name); err != nil {
			return err
		} else if has {
			return repo_model.ErrRepoAlreadyExist{Uname: repo.OwnerName, Name: repo.Name}
		}
		if err := repo_model.ReleaseRepoName(ctx, repo); err != nil {
			return err
		}
		oldKeys, err := asymkey_model.FindOrgDeployKeysCoveringRepo(ctx, repo)
		if err != nil {
			return err
		}
		oldKeyIDs := make([]int64, 0, len(oldKeys))
		for _, k := range oldKeys {
			if k.GroupID != 0 {
				oldKeyIDs = append(oldKeyIDs, k.KeyID)
			}
		}
		repo.GroupID, repo.GroupName = groupID, groupName
		if err := repo_model.ClaimRepoName(ctx, repo); err != nil {
			return err
		}
		if err := repo_model.TakeRedirectPath(ctx, repo.Owner, groupID, repo.Name, repo.ID); err != nil {
			return err
		}
		if err := repo_model.UpdateRepositoryCols(ctx, repo, "group_id", "group_name"); err != nil {
			return err
		}
		if err := repo_model.RecordRepo(ctx, "repo.repository.moved", repo, map[string]any{
			"before": map[string]any{"group_id": oldGroupID, "group_name": oldGroupName},
			"after":  map[string]any{"group_id": groupID, "group_name": groupName},
		}); err != nil {
			return err
		}
		// the old project's deploy keys stop applying: drop them from the protection rules unless another key of the
		// same public key still writes to the repository
		if err := git_model.DropDeployKeyIDsNotWriting(ctx, repo, oldKeyIDs); err != nil {
			return err
		}
		if err := repo_model.NewRedirect(ctx, repo.OwnerID, oldGroupID, repo.ID, repo.Name); err != nil {
			return err
		}
		if err := syncRepoGroupTeams(ctx, repo); err != nil {
			return err
		}

		if groupID != 0 {
			if err := os.MkdirAll(repo_model.GroupPath(repo.OwnerName, groupName), os.ModePerm); err != nil {
				return err
			}
		}
		for i, p := range [][2]string{{oldRepoPath, repo.RepoPath()}, {oldWikiPath, repo.WikiPath()}} {
			if i == 1 { // a repository without a wiki
				if isExist, err := util.IsExist(p[0]); err != nil || !isExist {
					return err
				}
			}
			if isExist, err := util.IsExist(p[1]); err != nil {
				return err
			} else if isExist {
				return repo_model.ErrRepoFilesAlreadyExist{Uname: repo.OwnerName, Name: repo.Name}
			}
			if err := util.Rename(p[0], p[1]); err != nil {
				return fmt.Errorf("move repository directory: %w", err)
			}
			moved = append(moved, p)
		}
		return nil
	})
}
