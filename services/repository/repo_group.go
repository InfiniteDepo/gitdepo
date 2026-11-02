// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"context"
	"fmt"
	"os"

	asymkey_model "forgejo.org/models/asymkey"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	"forgejo.org/modules/util"

	"xorm.io/builder"
)

// RenameRepoGroup renames a project and moves its directory. Like a repository rename, the directory moves
// before the database changes and back if they fail; the working-copy locks of all its repositories (trashed
// ones too) are held meanwhile, so no rename, transfer or trash restore of one of them runs in this process.
// Pushes don't take these locks: a push running during the rename fails (its path disappears), as it does
// during a repository rename.
func RenameRepoGroup(ctx context.Context, owner *user_model.User, group *repo_model.RepoGroup, newName string) (err error) {
	if group.OwnerID != owner.ID {
		return repo_model.ErrRepoGroupNotExist
	}
	if err := repo_model.IsUsableGroupName(newName); err != nil { // before the name reaches a path
		return err
	}
	// the project's lock first, then its repositories' by ascending ID, the order of lockRepo
	defer repoWorkingPool.Lock(groupLockKey(group.ID))()
	var repoIDs []int64
	if err := db.GetEngine(ctx).Table("repository").Where("owner_id = ? AND group_id = ?", owner.ID, group.ID).
		OrderBy("id").Cols("id").Find(&repoIDs); err != nil {
		return err
	}
	for _, id := range repoIDs {
		defer repoWorkingPool.Lock(fmt.Sprint(id))()
	}

	oldPath, newPath := repo_model.GroupPath(owner.Name, group.Name), repo_model.GroupPath(owner.Name, newName)
	moved := false
	if oldPath != newPath {
		if isExist, err := util.IsExist(newPath); err != nil {
			return err
		} else if isExist {
			return repo_model.ErrRepoFilesAlreadyExist{Uname: owner.Name, Name: newName}
		}
		if isExist, err := util.IsExist(oldPath); err != nil {
			return err
		} else if isExist {
			if err := util.Rename(oldPath, newPath); err != nil {
				return fmt.Errorf("rename project directory: %w", err)
			}
			moved = true
		}
	}
	if err = repo_model.RenameRepoGroup(ctx, owner, group, newName); err != nil && moved {
		moveDirsBack(newPath, oldPath)
	}
	return err
}

// DeleteRepoGroup deletes an empty project, its deploy keys and its directory.
func DeleteRepoGroup(ctx context.Context, owner *user_model.User, group *repo_model.RepoGroup) error {
	if group.OwnerID != owner.ID {
		return repo_model.ErrRepoGroupNotExist
	}
	var deletedPublicKey bool
	if err := db.WithTx(ctx, func(ctx context.Context) error {
		// the project row before its keys' rows, as every change of a project key (models/repo can't import asymkey)
		if _, err := repo_model.LockRepoGroup(ctx, group.OwnerID, group.ID); err != nil {
			return err
		}
		counts, err := projectDeleteCounts(ctx, group)
		if err != nil {
			return err
		}
		if err := repo_model.RecordProject(ctx, "org.project.deleted", group, map[string]any{"counts": counts}); err != nil {
			return err
		}
		if deletedPublicKey, err = asymkey_model.DeleteProjectDeployKeys(ctx, group.OwnerID, group.ID); err != nil {
			return err
		}
		if err := auth_model.DeleteOwnedAccessTokens(ctx, auth_model.AccessTokenOwnerProject, group.OwnerID, group.ID); err != nil {
			return err
		}
		return repo_model.DeleteRepoGroup(ctx, group)
	}); err != nil {
		return err
	}
	if deletedPublicKey {
		if err := asymkey_model.RewriteAllPublicKeys(ctx); err != nil {
			log.Error("RewriteAllPublicKeys: %v", err)
		}
	}
	if err := os.Remove(repo_model.GroupPath(owner.Name, group.Name)); err != nil && !os.IsNotExist(err) {
		log.Error("Unable to remove the directory of project %s/%s: %v", owner.Name, group.Name, err)
	}
	return nil
}

// projectDeleteCounts counts the rows deleting the project group removes with it, for its audit entry.
func projectDeleteCounts(ctx context.Context, group *repo_model.RepoGroup) (map[string]int64, error) {
	scope := builder.Eq{"owner_id": group.OwnerID, "group_id": group.ID}
	counts := map[string]int64{}
	for _, c := range []struct {
		name, table string
		cond        builder.Cond
	}{
		{"teams", "team_group", builder.Eq{"group_id": group.ID}},
		{"branch_rules", "protected_branch", builder.Eq{"repo_id": 0, "org_id": group.OwnerID, "group_id": group.ID}},
		{"webhooks", "webhook", scope},
		{"secrets", "secret", scope},
		{"variables", "action_variable", scope},
		{"deploy_keys", "org_deploy_key", builder.Eq{"org_id": group.OwnerID, "group_id": group.ID}},
		{"access_tokens", "access_token", builder.Eq{"owner_type": auth_model.AccessTokenOwnerProject, "owner_id": group.OwnerID, "group_id": group.ID}},
	} {
		n, err := db.GetEngine(ctx).Table(c.table).Where(c.cond).Count()
		if err != nil {
			return nil, err
		}
		counts[c.name] = n
	}
	return counts, nil
}
