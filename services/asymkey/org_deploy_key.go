// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package asymkey

import (
	"context"

	asymkey_model "forgejo.org/models/asymkey"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
)

// SetOrgDeployKeyRepos changes what the deploy key of the organization covers. A repository it no longer writes
// to loses the key in its protection rules.
func SetOrgDeployKeyRepos(ctx context.Context, orgID, id int64, includesAllRepos bool, repoIDs []int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		key, err := asymkey_model.SetOrgDeployKeyRepos(ctx, orgID, id, includesAllRepos, repoIDs)
		if err != nil {
			return err
		}
		return git_model.DropDeployKeyIDFromOwnerRepos(ctx, orgID, key.KeyID)
	})
}

// DeleteOrgDeployKey deletes the deploy key of the organization (groupID 0) or of its project groupID; the
// repositories it no longer writes to lose it in their protection rules.
func DeleteOrgDeployKey(ctx context.Context, orgID, groupID, id int64) error {
	var deletedPublicKey bool
	if err := db.WithTx(ctx, func(ctx context.Context) error {
		if groupID != 0 { // the project row before the key's, as in AddOrgDeployKey and DeleteRepoGroup
			if _, err := repo_model.LockRepoGroup(ctx, orgID, groupID); err != nil {
				return err
			}
		}
		key, err := asymkey_model.GetOrgDeployKey(ctx, orgID, groupID, id)
		if err != nil {
			return err
		}
		if deletedPublicKey, err = asymkey_model.DeleteOrgDeployKey(ctx, key); err != nil {
			return err
		}
		return git_model.DropDeployKeyIDFromOwnerRepos(ctx, orgID, key.KeyID)
	}); err != nil {
		return err
	}
	if !deletedPublicKey {
		return nil
	}
	return asymkey_model.RewriteAllPublicKeys(ctx)
}

// AddOrgDeployKeyRepo adds the repository to the selection of the deploy key.
func AddOrgDeployKeyRepo(ctx context.Context, orgID, id int64, repo *repo_model.Repository) error {
	_, err := asymkey_model.AddOrgDeployKeyRepo(ctx, orgID, id, repo.ID)
	return err
}

// RemoveOrgDeployKeyRepo removes the repository from the selection of the deploy key, and the key from its
// protection rules unless it still writes to it.
func RemoveOrgDeployKeyRepo(ctx context.Context, orgID, id int64, repo *repo_model.Repository) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		key, err := asymkey_model.RemoveOrgDeployKeyRepo(ctx, orgID, id, repo.ID)
		if err != nil {
			return err
		}
		return git_model.DropDeployKeyIDsNotWriting(ctx, repo, []int64{key.KeyID})
	})
}

// SetOrgDeployKeyAllRepos switches the deploy key to all repositories or back to its selection; the repositories it
// no longer writes to lose it in their protection rules.
func SetOrgDeployKeyAllRepos(ctx context.Context, orgID, id int64, includesAllRepos bool) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		key, err := asymkey_model.SetOrgDeployKeyAllRepos(ctx, orgID, id, includesAllRepos)
		if err != nil || includesAllRepos {
			return err
		}
		return git_model.DropDeployKeyIDFromOwnerRepos(ctx, orgID, key.KeyID)
	})
}
