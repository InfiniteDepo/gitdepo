// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package asymkey

import (
	"context"
	"time"

	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"xorm.io/builder"
)

// OrgDeployKey is a deploy key of an organization: it covers all its repositories or the selected ones
// (OrgDeployKeyRepo), or, with GroupID set, the repositories of that project of the organization (a project key has
// neither). It shares the PublicKey (KeyTypeDeploy) with repository deploy keys of the same key.
type OrgDeployKey struct {
	ID               int64 `xorm:"pk autoincr"`
	KeyID            int64 `xorm:"UNIQUE(s) INDEX"`
	OrgID            int64 `xorm:"UNIQUE(s) INDEX"`
	GroupID          int64 `xorm:"UNIQUE(s) NOT NULL DEFAULT 0"` // 0 = the organization's own key
	Name             string
	Fingerprint      string
	Mode             perm.AccessMode    `xorm:"NOT NULL DEFAULT 1"`
	IncludesAllRepos bool               `xorm:"NOT NULL DEFAULT false"`
	ExpiresUnix      timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"` // 0 = never

	CreatedUnix       timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix       timeutil.TimeStamp `xorm:"updated"`
	HasRecentActivity bool               `xorm:"-"`
	HasUsed           bool               `xorm:"-"`
}

// OrgDeployKeyRepo is a repository selected for an organization deploy key.
type OrgDeployKeyRepo struct {
	ID             int64 `xorm:"pk autoincr"`
	OrgDeployKeyID int64 `xorm:"UNIQUE(s) INDEX"`
	RepoID         int64 `xorm:"UNIQUE(s) INDEX"`
}

func init() {
	db.RegisterModel(new(OrgDeployKey))
	db.RegisterModel(new(OrgDeployKeyRepo))
}

// AfterLoad is invoked from XORM after setting the values of all fields of this object.
func (key *OrgDeployKey) AfterLoad() {
	key.HasUsed = key.UpdatedUnix > key.CreatedUnix
	key.HasRecentActivity = key.UpdatedUnix.AddDuration(7*24*time.Hour) > timeutil.TimeStampNow()
}

// IsExpired reports whether the key has an expiry date that has passed.
func (key *OrgDeployKey) IsExpired() bool {
	return key.ExpiresUnix != 0 && timeutil.TimeStampNow() >= key.ExpiresUnix
}

// IsReadOnly reports whether the key can only read, used by the templates.
func (key *OrgDeployKey) IsReadOnly() bool {
	return key.Mode == perm.AccessModeRead
}

// AddOrgDeployKey adds a deploy key to the organization, for all its repositories or the selected ones, or, with
// groupID set, for the repositories of that project of the organization.
func AddOrgDeployKey(ctx context.Context, orgID, groupID int64, name, content string, readOnly, includesAllRepos bool, repoIDs []int64, expires timeutil.TimeStamp) (*OrgDeployKey, error) {
	fingerprint, err := CalcFingerprint(content)
	if err != nil {
		return nil, err
	}
	mode := perm.AccessModeRead
	if !readOnly {
		mode = perm.AccessModeWrite
	}

	var key *OrgDeployKey
	var pkey *PublicKey
	var added bool
	err = db.WithTx(ctx, func(ctx context.Context) error {
		if groupID != 0 {
			// the project row first, so that a concurrent DeleteRepoGroup runs before or after this
			if _, err := repo_model.LockRepoGroup(ctx, orgID, groupID); err != nil {
				return err
			}
			if includesAllRepos || len(repoIDs) > 0 {
				return util.NewInvalidArgumentErrorf("a project key covers the repositories of its project")
			}
		}
		if isOrg, err := db.GetEngine(ctx).Table("user").
			Where("id = ? AND type = ? AND trashed_unix = 0", orgID, user_model.UserTypeOrganization).Exist(); err != nil {
			return err
		} else if !isOrg {
			return util.NewInvalidArgumentErrorf("%d is not an organization", orgID)
		}
		repoIDs = container.SetOf(repoIDs...).Values()
		if groupID == 0 && !includesAllRepos && len(repoIDs) == 0 {
			return util.NewInvalidArgumentErrorf("select at least one repository")
		}
		if err := checkOrgDeployKeyRepos(ctx, orgID, repoIDs); err != nil {
			return err
		}
		if has, err := db.GetEngine(ctx).Where(builder.Eq{"org_id": orgID, "group_id": groupID, "name": name}).Exist(new(OrgDeployKey)); err != nil {
			return err
		} else if has {
			return ErrDeployKeyNameAlreadyUsed{Name: name}
		}

		var err error
		if pkey, added, err = getOrAddDeployPublicKey(ctx, name, content, fingerprint, mode); err != nil {
			return err
		}
		if has, err := db.GetEngine(ctx).Where(builder.Eq{"org_id": orgID, "group_id": groupID, "key_id": pkey.ID}).Exist(new(OrgDeployKey)); err != nil {
			return err
		} else if has {
			return ErrDeployKeyAlreadyExist{KeyID: pkey.ID}
		}

		key = &OrgDeployKey{
			KeyID:            pkey.ID,
			OrgID:            orgID,
			GroupID:          groupID,
			Name:             name,
			Fingerprint:      fingerprint,
			Mode:             mode,
			IncludesAllRepos: includesAllRepos,
			ExpiresUnix:      expires,
		}
		if err := db.Insert(ctx, key); err != nil {
			return err
		}
		for _, repoID := range repoIDs {
			if err := db.Insert(ctx, &OrgDeployKeyRepo{OrgDeployKeyID: key.ID, RepoID: repoID}); err != nil {
				return err
			}
		}
		return recordOrgDeployKey(ctx, "credential.org_deploy_key.created", "credential.project_deploy_key.created", key, map[string]any{
			"all_repos": includesAllRepos, "repo_ids": repoIDs,
		})
	})
	if err != nil || !added {
		return key, err
	}
	return key, appendKeyAfterCommit(pkey)
}

// checkOrgDeployKeyRepos refuses repositories that aren't live repositories of the organization.
func checkOrgDeployKeyRepos(ctx context.Context, orgID int64, repoIDs []int64) error {
	if len(repoIDs) == 0 {
		return nil
	}
	n, err := db.GetEngine(ctx).Table("repository").In("id", repoIDs).
		And("owner_id = ? AND trashed_unix = 0", orgID).Count()
	if err != nil {
		return err
	} else if n != int64(len(repoIDs)) {
		return util.NewInvalidArgumentErrorf("a selected repository is not a repository of the organization")
	}
	return nil
}

// EffectiveDeployKey is the deploy key that applies when a public key is used on a repository:
// exactly one of RepoKey and OrgKey is set.
type EffectiveDeployKey struct {
	KeyID       int64 // public key ID
	Name        string
	Mode        perm.AccessMode
	ExpiresUnix timeutil.TimeStamp
	RepoKey     *DeployKey
	OrgKey      *OrgDeployKey
}

// IsExpired reports whether the key has an expiry date that has passed.
func (key *EffectiveDeployKey) IsExpired() bool {
	return key.ExpiresUnix != 0 && timeutil.TimeStampNow() >= key.ExpiresUnix
}

// GetEffectiveDeployKey returns the deploy key the public key has on the repository: its deploy key of the
// repository or a deploy key of the repository owner (its project's or its own) that covers it. Unexpired keys come
// first, then the higher mode, then the more specific key (repository, project, organization). An expired key is
// only returned when no other applies.
func GetEffectiveDeployKey(ctx context.Context, keyID int64, repo *repo_model.Repository) (*EffectiveDeployKey, error) {
	var candidates []*EffectiveDeployKey
	if key, has, err := db.Get[DeployKey](ctx, builder.Eq{"key_id": keyID, "repo_id": repo.ID}); err != nil {
		return nil, err
	} else if has {
		candidates = append(candidates, &EffectiveDeployKey{KeyID: keyID, Name: key.Name, Mode: key.Mode, ExpiresUnix: key.ExpiresUnix, RepoKey: key})
	}
	orgKeys := make([]*OrgDeployKey, 0, 2)
	if err := db.GetEngine(ctx).Where(builder.Eq{"key_id": keyID}.And(orgDeployKeyCoversCond(repo))).OrderBy("group_id DESC").Find(&orgKeys); err != nil {
		return nil, err
	}
	for _, key := range orgKeys { // the project's key before the organization's
		candidates = append(candidates, &EffectiveDeployKey{KeyID: keyID, Name: key.Name, Mode: key.Mode, ExpiresUnix: key.ExpiresUnix, OrgKey: key})
	}

	var best *EffectiveDeployKey
	for _, c := range candidates {
		if best == nil || best.IsExpired() && !c.IsExpired() || best.IsExpired() == c.IsExpired() && c.Mode > best.Mode {
			best = c
		}
	}
	if best == nil {
		return nil, ErrDeployKeyNotExist{0, keyID, repo.ID}
	}
	return best, nil
}

// FindOrgDeployKeysCoveringRepo returns the deploy keys of the repository owner that cover the repository.
func FindOrgDeployKeysCoveringRepo(ctx context.Context, repo *repo_model.Repository) ([]*OrgDeployKey, error) {
	keys := make([]*OrgDeployKey, 0, 2)
	return keys, db.GetEngine(ctx).Where(orgDeployKeyCoversCond(repo)).OrderBy("name").Find(&keys)
}

// OrgDeployKeyOnRepo is an organization deploy key and a repository it covers.
type OrgDeployKeyOnRepo struct {
	OrgDeployKey `xorm:"extends"`
	RepoID       int64
}

// FindOrgDeployKeysCoveringRepos returns the organization deploy keys that cover each of the repositories, with
// the same rule as FindOrgDeployKeysCoveringRepo, in one query.
func FindOrgDeployKeysCoveringRepos(ctx context.Context, repoIDs []int64) ([]*OrgDeployKeyOnRepo, error) {
	keys := make([]*OrgDeployKeyOnRepo, 0, 2)
	if len(repoIDs) == 0 {
		return keys, nil
	}
	return keys, db.GetEngine(ctx).Table("org_deploy_key").Select("org_deploy_key.*, repository.id AS repo_id").
		Join("INNER", "repository", orgDeployKeyCoversCond(nil)).In("repository.id", repoIDs).
		OrderBy("org_deploy_key.name").Find(&keys)
}

// orgDeployKeyCoversCond matches the deploy keys of the repository owner that cover the repository: the given one,
// or, if repo is nil, the joined repository row. The owner condition is part of it, so no caller can leave it out:
// a key never covers a repository of another owner, whatever is selected. A project key covers the repositories
// that are in its project now, and the organization's keys are only those with group_id 0.
func orgDeployKeyCoversCond(repo *repo_model.Repository) builder.Cond {
	owner, selected := builder.Expr("org_deploy_key.org_id = repository.owner_id"), builder.Expr("org_deploy_key_repo.repo_id = repository.id")
	project := builder.Expr("org_deploy_key.group_id = repository.group_id")
	if repo != nil {
		owner, selected = builder.Eq{"org_deploy_key.org_id": repo.OwnerID}, builder.Eq{"org_deploy_key_repo.repo_id": repo.ID}
		project = builder.Eq{"org_deploy_key.group_id": repo.GroupID}
	}
	return owner.And(builder.Or(
		builder.Eq{"org_deploy_key.group_id": 0}.And(builder.Or(
			builder.Eq{"org_deploy_key.includes_all_repos": true},
			builder.In("org_deploy_key.id", builder.Select("org_deploy_key_repo.org_deploy_key_id").From("org_deploy_key_repo").Where(selected)),
		)),
		builder.Neq{"org_deploy_key.group_id": 0}.And(project),
	))
}

// GetOrgDeployKey returns the deploy key with the ID of the organization (groupID 0) or of its project groupID; a
// key of another organization or level is not found.
func GetOrgDeployKey(ctx context.Context, orgID, groupID, id int64) (*OrgDeployKey, error) {
	key, has, err := db.Get[OrgDeployKey](ctx, builder.Eq{"id": id, "org_id": orgID, "group_id": groupID})
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrDeployKeyNotExist{ID: id}
	}
	return key, nil
}

// FindOrgDeployKeys returns the deploy keys of the organization (groupID 0) or of its project groupID.
func FindOrgDeployKeys(ctx context.Context, orgID, groupID int64) ([]*OrgDeployKey, error) {
	keys := make([]*OrgDeployKey, 0, 2)
	return keys, db.GetEngine(ctx).Where(builder.Eq{"org_id": orgID, "group_id": groupID}).OrderBy("name").Find(&keys)
}

// GetOrgDeployKeyRepoIDs returns the selected repositories of each key.
func GetOrgDeployKeyRepoIDs(ctx context.Context, keyIDs []int64) (map[int64][]int64, error) {
	rows := make([]*OrgDeployKeyRepo, 0, len(keyIDs))
	if err := db.GetEngine(ctx).In("org_deploy_key_id", keyIDs).OrderBy("repo_id").Find(&rows); err != nil {
		return nil, err
	}
	ids := make(map[int64][]int64, len(keyIDs))
	for _, r := range rows {
		ids[r.OrgDeployKeyID] = append(ids[r.OrgDeployKeyID], r.RepoID)
	}
	return ids, nil
}

// SetOrgDeployKeyRepos replaces what the deploy key of the organization covers: all its repositories or the
// selected ones, which must be live repositories of the organization.
func SetOrgDeployKeyRepos(ctx context.Context, orgID, id int64, includesAllRepos bool, repoIDs []int64) (*OrgDeployKey, error) {
	var key *OrgDeployKey
	err := db.WithTx(ctx, func(ctx context.Context) error {
		var err error
		if key, err = lockOrgDeployKey(ctx, orgID, 0, id); err != nil {
			return err
		}
		repoIDs = container.SetOf(repoIDs...).Values()
		if !includesAllRepos && len(repoIDs) == 0 {
			return util.NewInvalidArgumentErrorf("select at least one repository")
		}
		if err := checkOrgDeployKeyRepos(ctx, orgID, repoIDs); err != nil {
			return err
		}
		var oldIDs []int64
		if err := db.GetEngine(ctx).Table("org_deploy_key_repo").Where("org_deploy_key_id = ?", key.ID).Cols("repo_id").Find(&oldIDs); err != nil {
			return err
		}
		if _, err := db.GetEngine(ctx).Where("org_deploy_key_id = ?", key.ID).Delete(new(OrgDeployKeyRepo)); err != nil {
			return err
		}
		for _, repoID := range repoIDs {
			if err := db.Insert(ctx, &OrgDeployKeyRepo{OrgDeployKeyID: key.ID, RepoID: repoID}); err != nil {
				return err
			}
		}
		wasAllRepos := key.IncludesAllRepos
		key.IncludesAllRepos = includesAllRepos
		if _, err = db.GetEngine(ctx).ID(key.ID).Cols("includes_all_repos").NoAutoTime().Update(key); err != nil {
			return err
		}
		oldSet, newSet := container.SetOf(oldIDs...), container.SetOf(repoIDs...)
		added, removed := []int64{}, []int64{}
		for _, id := range repoIDs {
			if !oldSet.Contains(id) {
				added = append(added, id)
			}
		}
		for _, id := range oldIDs {
			if !newSet.Contains(id) {
				removed = append(removed, id)
			}
		}
		if wasAllRepos == includesAllRepos && len(added) == 0 && len(removed) == 0 {
			return nil
		}
		return recordOrgDeployKey(ctx, "credential.org_deploy_key.updated", "", key, map[string]any{
			"before": map[string]any{"all_repos": wasAllRepos}, "after": map[string]any{"all_repos": includesAllRepos},
			"repos_added": added, "repos_removed": removed,
		})
	})
	return key, err
}

// lockOrgDeployKey loads the key of the organization (groupID 0) or its project for a change, taking its row lock
// first, so concurrent changes of one key run one after the other.
func lockOrgDeployKey(ctx context.Context, orgID, groupID, id int64) (*OrgDeployKey, error) {
	if _, err := db.Exec(ctx, "UPDATE org_deploy_key SET includes_all_repos = includes_all_repos WHERE id = ? AND org_id = ? AND group_id = ?", id, orgID, groupID); err != nil {
		return nil, err
	}
	return GetOrgDeployKey(ctx, orgID, groupID, id)
}

// AddOrgDeployKeyRepo adds a live repository of the organization to the selection of the key.
func AddOrgDeployKeyRepo(ctx context.Context, orgID, id, repoID int64) (*OrgDeployKey, error) {
	var key *OrgDeployKey
	err := db.WithTx(ctx, func(ctx context.Context) error {
		var err error
		if key, err = lockOrgDeployKey(ctx, orgID, 0, id); err != nil {
			return err
		}
		if key.IncludesAllRepos {
			return util.NewInvalidArgumentErrorf("the key covers all repositories")
		}
		if err := checkOrgDeployKeyRepos(ctx, orgID, []int64{repoID}); err != nil {
			return err
		}
		if has, err := db.GetEngine(ctx).Exist(&OrgDeployKeyRepo{OrgDeployKeyID: key.ID, RepoID: repoID}); err != nil || has {
			return err
		}
		if err := db.Insert(ctx, &OrgDeployKeyRepo{OrgDeployKeyID: key.ID, RepoID: repoID}); err != nil {
			return err
		}
		return recordOrgDeployKey(ctx, "credential.org_deploy_key.updated", "", key, map[string]any{"repos_added": []int64{repoID}})
	})
	return key, err
}

// RemoveOrgDeployKeyRepo removes a repository from the selection of the key; the last one can't be removed.
func RemoveOrgDeployKeyRepo(ctx context.Context, orgID, id, repoID int64) (*OrgDeployKey, error) {
	var key *OrgDeployKey
	err := db.WithTx(ctx, func(ctx context.Context) error {
		var err error
		if key, err = lockOrgDeployKey(ctx, orgID, 0, id); err != nil {
			return err
		}
		if key.IncludesAllRepos {
			return util.NewInvalidArgumentErrorf("the key covers all repositories")
		}
		n, err := db.GetEngine(ctx).Where("org_deploy_key_id = ?", key.ID).Count(new(OrgDeployKeyRepo))
		if err != nil {
			return err
		}
		if has, err := db.GetEngine(ctx).Exist(&OrgDeployKeyRepo{OrgDeployKeyID: key.ID, RepoID: repoID}); err != nil {
			return err
		} else if !has {
			return util.NewNotExistErrorf("the repository is not selected")
		} else if n <= 1 {
			return util.NewInvalidArgumentErrorf("select at least one repository")
		}
		if _, err = db.GetEngine(ctx).Delete(&OrgDeployKeyRepo{OrgDeployKeyID: key.ID, RepoID: repoID}); err != nil {
			return err
		}
		return recordOrgDeployKey(ctx, "credential.org_deploy_key.updated", "", key, map[string]any{"repos_removed": []int64{repoID}})
	})
	return key, err
}

// SetOrgDeployKeyAllRepos switches the key to all repositories, or back to its selection, which must not be empty.
func SetOrgDeployKeyAllRepos(ctx context.Context, orgID, id int64, includesAllRepos bool) (*OrgDeployKey, error) {
	var key *OrgDeployKey
	err := db.WithTx(ctx, func(ctx context.Context) error {
		var err error
		if key, err = lockOrgDeployKey(ctx, orgID, 0, id); err != nil {
			return err
		}
		if !includesAllRepos {
			if has, err := db.GetEngine(ctx).Exist(&OrgDeployKeyRepo{OrgDeployKeyID: key.ID}); err != nil {
				return err
			} else if !has {
				return util.NewInvalidArgumentErrorf("select at least one repository")
			}
		}
		if key.IncludesAllRepos == includesAllRepos {
			return nil
		}
		key.IncludesAllRepos = includesAllRepos
		if _, err = db.GetEngine(ctx).ID(key.ID).Cols("includes_all_repos").NoAutoTime().Update(key); err != nil {
			return err
		}
		return recordOrgDeployKey(ctx, "credential.org_deploy_key.updated", "", key, map[string]any{
			"before": map[string]any{"all_repos": !includesAllRepos}, "after": map[string]any{"all_repos": includesAllRepos},
		})
	})
	return key, err
}

// FindOrgDeployKeyRepos returns a page of the live repositories selected for the key.
func FindOrgDeployKeyRepos(ctx context.Context, keyID int64, opts db.ListOptions) ([]*repo_model.Repository, int64, error) {
	repos := make([]*repo_model.Repository, 0, opts.PageSize)
	sess := db.GetEngine(ctx).Where(builder.In("id", builder.Select("repo_id").From("org_deploy_key_repo").Where(builder.Eq{"org_deploy_key_id": keyID}))).
		And("trashed_unix = 0").OrderBy("lower_name")
	if opts.Page > 0 {
		sess = db.SetSessionPagination(sess, &opts)
	}
	n, err := sess.FindAndCount(&repos)
	return repos, n, err
}

// DeleteOrgDeployKey deletes the deploy key, its selection and its public key if no other deploy key uses it.
// It reports whether the public key was deleted, so the caller rewrites the authorized_keys file.
func DeleteOrgDeployKey(ctx context.Context, key *OrgDeployKey) (deletedPublicKey bool, err error) {
	// lock the key first, in the same order as every other change of it (a project key's caller locks the project)
	if _, err := lockOrgDeployKey(ctx, key.OrgID, key.GroupID, key.ID); err != nil {
		return false, err
	}
	var repoIDs []int64
	if err := db.GetEngine(ctx).Table("org_deploy_key_repo").Where("org_deploy_key_id = ?", key.ID).Cols("repo_id").Find(&repoIDs); err != nil {
		return false, err
	}
	if _, err := db.GetEngine(ctx).Where("org_deploy_key_id = ?", key.ID).Delete(new(OrgDeployKeyRepo)); err != nil {
		return false, err
	}
	if _, err := db.DeleteByID[OrgDeployKey](ctx, key.ID); err != nil {
		return false, err
	}
	if err := recordOrgDeployKey(ctx, "credential.org_deploy_key.deleted", "credential.project_deploy_key.deleted", key, map[string]any{
		"all_repos": key.IncludesAllRepos, "repo_ids": repoIDs,
	}); err != nil {
		return false, err
	}
	if has, err := IsDeployKeyExistByKeyID(ctx, key.KeyID); err != nil || has {
		return false, err
	}
	_, err = db.DeleteByID[PublicKey](ctx, key.KeyID)
	return err == nil, err
}

// DeleteOrgDeployKeys deletes the deploy keys of the organization, its projects' included, and the public keys no
// other deploy key uses. It reports whether a public key was deleted, so the caller rewrites the authorized_keys file.
func DeleteOrgDeployKeys(ctx context.Context, orgID int64) (deletedPublicKey bool, err error) {
	keys := make([]*OrgDeployKey, 0, 2)
	if err := db.GetEngine(ctx).Where("org_id = ?", orgID).Find(&keys); err != nil {
		return false, err
	}
	return deleteOrgDeployKeys(ctx, keys)
}

// DeleteProjectDeployKeys deletes the deploy keys of the project of the organization, like DeleteOrgDeployKeys. The
// caller locks the project first (repo_model.LockRepoGroup).
func DeleteProjectDeployKeys(ctx context.Context, orgID, groupID int64) (deletedPublicKey bool, err error) {
	if groupID == 0 {
		return false, util.NewInvalidArgumentErrorf("no project")
	}
	keys, err := FindOrgDeployKeys(ctx, orgID, groupID)
	if err != nil {
		return false, err
	}
	return deleteOrgDeployKeys(ctx, keys)
}

func deleteOrgDeployKeys(ctx context.Context, keys []*OrgDeployKey) (deletedPublicKey bool, err error) {
	for _, key := range keys {
		deleted, err := DeleteOrgDeployKey(ctx, key)
		if err != nil {
			return false, err
		}
		deletedPublicKey = deletedPublicKey || deleted
	}
	return deletedPublicKey, nil
}
