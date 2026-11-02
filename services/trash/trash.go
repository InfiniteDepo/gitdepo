// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package trash restores and permanently deletes repositories and organizations that were moved to the trash by
// repo_service.TrashRepository and org_service.TrashOrganization. Only site admins reach it.
package trash

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	quota_model "forgejo.org/models/quota"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	code_indexer "forgejo.org/modules/indexer/code"
	issue_indexer "forgejo.org/modules/indexer/issues"
	"forgejo.org/modules/log"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	dependency_service "forgejo.org/services/dependency"
	org_service "forgejo.org/services/org"
	packages_service "forgejo.org/services/packages"
	repo_service "forgejo.org/services/repository"
	user_service "forgejo.org/services/user"

	"xorm.io/builder"
)

// ErrTrashConflict is returned when the repository is not in the trash (any more): it was restored or
// purged, or another purge is in progress.
var ErrTrashConflict = repo_service.ErrTrashConflict

var (
	// ErrNeedNewOwner is returned when restoring a repository whose owner is in the trash (a trashed organization
	// or the tombstone of a deleted user) without naming a new owner.
	ErrNeedNewOwner = errors.New("the owner of the repository is in the trash, so a new owner is needed")
	// ErrInvalidNewOwner is returned when the new owner does not exist or can't own repositories.
	ErrInvalidNewOwner = errors.New("the new owner does not exist or can't own the repository")
	// ErrTrashedWithOrg is returned when restoring a repository that was trashed together with its organization.
	ErrTrashedWithOrg = errors.New("the repository was deleted together with its organization: restore the organization")
	// ErrOrgHasLiveRepos is returned when purging an organization that got a repository meanwhile.
	ErrOrgHasLiveRepos = errors.New("the organization owns a repository that is not in the trash")
)

// IsBadTarget returns true for the errors of a new owner, repository name or organization name that can't be used
// (taken, reserved, malformed); the message says which.
func IsBadTarget(err error) bool {
	return repo_model.IsErrRepoAlreadyExist(err) || db.IsErrNameReserved(err) || db.IsErrNamePatternNotAllowed(err) ||
		user_model.IsErrUserAlreadyExist(err) || organization.IsErrOrgArchived(err) || errors.Is(err, util.ErrInvalidArgument) ||
		errors.As(err, &repo_module.ErrPersonalRepoPolicy{}) || errors.As(err, &quota_model.ErrPersonalRepoLimit{})
}

// RestoreOptions says where a restored item goes: a new owner (repositories only) and/or a new name.
type RestoreOptions struct {
	NewOwner string
	NewName  string
}

// purgeRetryAfter is how long a purge claim is left alone before the cron job retries it (a crashed purge).
const purgeRetryAfter = 6 * time.Hour

// Item is a trashed repository or organization as listed to site admins.
type Item struct {
	Type          string // "repo" or "org"
	Repo          *repo_model.Repository
	Org           *user_model.User
	RepoCount     int64 // of an organization: its repositories in the trash, restored or purged with it or not
	Size          int64
	DaysRemaining int
	Purging       bool
}

// ListOptions filters List: Type is "repo" (default) or "org".
type ListOptions struct {
	db.ListOptions
	Keyword string
	Type    string
}

func (o ListOptions) cond() builder.Cond {
	cond := builder.Neq{"trashed_unix": 0}
	if o.Keyword == "" {
		return cond
	}
	kw := strings.ToLower(o.Keyword)
	return builder.And(cond, builder.Or(
		builder.Like{"lower(owner_name)", kw},
		builder.Like{"lower_name", kw},
	))
}

// List returns trashed repositories or organizations, newest first, with the number of matches and their total size.
func List(ctx context.Context, opts ListOptions) (items []*Item, count, totalSize int64, err error) {
	if opts.Type == "org" {
		return listOrgs(ctx, opts)
	}
	repos := make([]*repo_model.Repository, 0, opts.PageSize)
	// repositories trashed with their organization are part of its item
	cond := builder.And(opts.cond(), builder.Eq{"trashed_with_owner": false})
	sess := db.GetEngine(ctx).Where(cond)
	if count, err = db.SetSessionPagination(sess, &opts).OrderBy("ABS(trashed_unix) DESC").FindAndCount(&repos); err != nil {
		return nil, 0, 0, err
	}
	size, err := db.GetEngine(ctx).Where(cond).Sum(new(repo_model.Repository), "size")
	if err != nil {
		return nil, 0, 0, err
	}
	totalSize = int64(size)
	for _, repo := range repos {
		items = append(items, &Item{Type: "repo", Repo: repo, Size: repo.Size, DaysRemaining: daysRemaining(repo.TrashedUnix), Purging: repo.TrashedUnix < 0})
	}
	return items, count, totalSize, nil
}

func listOrgs(ctx context.Context, opts ListOptions) (items []*Item, count, totalSize int64, err error) {
	cond := builder.And(builder.Eq{"type": user_model.UserTypeOrganization}, builder.Neq{"trashed_unix": 0})
	if opts.Keyword != "" {
		cond = cond.And(builder.Like{"lower_name", strings.ToLower(opts.Keyword)})
	}
	orgs := make([]*user_model.User, 0, opts.PageSize)
	if count, err = db.SetSessionPagination(db.GetEngine(ctx).Where(cond), &opts).OrderBy("ABS(trashed_unix) DESC").FindAndCount(&orgs); err != nil {
		return nil, 0, 0, err
	}
	ids := make([]int64, len(orgs))
	for i, org := range orgs {
		ids[i] = org.ID
	}
	// one grouped query for the repositories of the whole page
	var rows []struct {
		OwnerID int64
		Count   int64
		Size    int64
	}
	if len(ids) > 0 {
		if err := db.GetEngine(ctx).Table("repository").Select("owner_id, COUNT(*) AS count, SUM(size) AS size").
			Where(builder.Neq{"trashed_unix": 0}).In("owner_id", ids).GroupBy("owner_id").Find(&rows); err != nil {
			return nil, 0, 0, err
		}
	}
	sizes := make(map[int64][2]int64, len(rows))
	for _, r := range rows {
		sizes[r.OwnerID] = [2]int64{r.Count, r.Size}
	}
	for _, org := range orgs {
		items = append(items, &Item{Type: "org", Org: org, RepoCount: sizes[org.ID][0], Size: sizes[org.ID][1], DaysRemaining: daysRemaining(org.TrashedUnix), Purging: org.TrashedUnix < 0})
		totalSize += sizes[org.ID][1]
	}
	return items, count, totalSize, nil
}

// purgeAt is when the repository is deleted automatically, counted from the day it was trashed.
func purgeAt(trashed timeutil.TimeStamp) time.Time {
	return trashed.AsTime().Add(time.Duration(setting.Trash.RetentionDays) * 24 * time.Hour)
}

func daysRemaining(trashed timeutil.TimeStamp) int {
	left := time.Until(purgeAt(trashed))
	if left <= 0 {
		return 0
	}
	return int((left + 24*time.Hour - 1) / (24 * time.Hour))
}

// RestoreRepo takes the repository out of the trash, optionally under a new owner and/or name. A repository
// whose owner is in the trash needs a new owner. The repository stays hidden until it is in place.
func RestoreRepo(ctx context.Context, doer *user_model.User, id int64, opts RestoreOptions) error {
	defer repo_service.LockTrash("repo", id)()
	repo, err := repo_model.GetRepositoryByIDIncludingTrashed(ctx, id)
	if err != nil {
		if repo_model.IsErrRepoNotExist(err) {
			return ErrTrashConflict
		}
		return err
	}
	if repo.TrashedUnix <= 0 {
		return ErrTrashConflict
	}
	if repo.TrashedWithOwner {
		return ErrTrashedWithOrg
	}
	seen, oldOwnerID := repo.TrashedUnix, repo.OwnerID
	owner, err := user_model.GetUserByIDIncludingTrashed(ctx, oldOwnerID)
	if err != nil {
		return err
	}
	if owner.IsTrashed() && opts.NewOwner == "" {
		return ErrNeedNewOwner
	}
	var newOwner *user_model.User
	if opts.NewOwner != "" {
		if newOwner, err = user_model.GetUserByName(ctx, opts.NewOwner); err != nil {
			if user_model.IsErrUserNotExist(err) {
				return ErrInvalidNewOwner
			}
			return err
		}
		if newOwner.ID <= 0 || !(newOwner.IsIndividual() || newOwner.IsOrganization()) || newOwner.IsSystem() {
			return ErrInvalidNewOwner
		}
		if newOwner.ID == oldOwnerID {
			newOwner = nil
		}
	}
	if newOwner != nil || (opts.NewName != "" && opts.NewName != repo.Name) {
		if err := repo_service.MoveTrashedRepository(ctx, doer, newOwner, repo, opts.NewName); err != nil {
			return err
		}
	}

	if err := db.WithTx(ctx, func(ctx context.Context) error {
		res, err := db.Exec(ctx, "UPDATE `repository` SET trashed_unix=0 WHERE id=? AND trashed_unix=?", id, seen)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return ErrTrashConflict
		}
		if _, err = db.Exec(ctx, "UPDATE `user` SET num_repos=num_repos+1 WHERE id=?", repo.OwnerID); err != nil {
			return err
		}
		if err := organization.AddTeamRepoCounts(ctx, repo.ID, 1); err != nil {
			return err
		}
		return repo_model.RecordRepo(ctx, "repo.repository.restored", repo, nil)
	}); err != nil {
		return err
	}

	issue_indexer.UpdateRepoIndexer(ctx, repo.ID)
	if setting.Indexer.RepoIndexerEnabled {
		code_indexer.UpdateRepoIndexer(repo)
	}
	if newOwner != nil { // the new owner's dependency graph switch applies
		dependency_service.ApplyRepo(ctx, repo.ID)
	}
	if owner.IsTrashed() { // a tombstone has nothing left to keep once its last repository is gone
		return removeTombstone(ctx, oldOwnerID)
	}
	return nil
}

// RestoreOrg takes the organization out of the trash together with the repositories that were deleted with it;
// repositories trashed earlier stay in the trash. The organization may get a new name.
func RestoreOrg(ctx context.Context, doer *user_model.User, id int64, opts RestoreOptions) error {
	defer repo_service.LockTrash("org", id)()
	org, err := user_model.GetUserByIDIncludingTrashed(ctx, id)
	if err != nil || !org.IsOrganization() || org.TrashedUnix <= 0 {
		return ErrTrashConflict
	}
	if opts.NewName != "" && opts.NewName != org.Name {
		// renamed while still hidden, so a failure leaves it untouched
		if err := user_service.AdminRenameUser(ctx, org, opts.NewName); err != nil {
			return err
		}
	}
	var repos []*repo_model.Repository
	if err := db.WithTx(ctx, func(ctx context.Context) error {
		res, err := db.Exec(ctx, "UPDATE `user` SET trashed_unix=0 WHERE id=? AND type=? AND trashed_unix=?", id, user_model.UserTypeOrganization, org.TrashedUnix)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return ErrTrashConflict
		}
		if err := db.GetEngine(ctx).Where("owner_id = ? AND trashed_with_owner = ? AND trashed_unix > 0", id, true).Find(&repos); err != nil {
			return err
		}
		for _, repo := range repos {
			if _, err := db.Exec(ctx, "UPDATE `repository` SET trashed_unix=0, trashed_with_owner=? WHERE id=?", false, repo.ID); err != nil {
				return err
			}
			if err := organization.AddTeamRepoCounts(ctx, repo.ID, 1); err != nil {
				return err
			}
		}
		if _, err := db.Exec(ctx, "UPDATE `user` SET num_repos=num_repos+? WHERE id=?", len(repos), id); err != nil {
			return err
		}
		return user_model.RecordOrg(ctx, "org.organization.restored", org, map[string]any{"counts": map[string]int{"repos": len(repos)}})
	}); err != nil {
		return err
	}
	for _, repo := range repos {
		issue_indexer.UpdateRepoIndexer(ctx, repo.ID)
		if setting.Indexer.RepoIndexerEnabled {
			code_indexer.UpdateRepoIndexer(repo)
		}
	}
	return nil
}

// Purge deletes a trashed repository for good.
func Purge(ctx context.Context, doer *user_model.User, id int64) error {
	defer repo_service.LockTrash("repo", id)()
	if err := claimForPurge(ctx, id, builder.And(builder.Gt{"trashed_unix": 0}, builder.Eq{"trashed_with_owner": false})); err != nil {
		return err
	}
	return deleteClaimed(ctx, doer, id)
}

// deleteClaimed deletes the repository claimed by claimForPurge, closing the pull requests from its branches
// into other repositories like any permanent deletion. A deleted user's tombstone goes with its last repository.
func deleteClaimed(ctx context.Context, doer *user_model.User, id int64) error {
	repo, err := repo_model.GetRepositoryByIDIncludingTrashed(ctx, id)
	if err != nil {
		return err
	}
	if err := repo_service.DeleteRepositoryPermanently(ctx, doer, repo, false); err != nil { // its webhooks fired when it was trashed
		return err
	}
	return removeTombstone(ctx, repo.OwnerID)
}

// claimForPurge marks the repository as being purged, minus the time of the claim, so that a second
// restore or purge finds nothing to claim. It stays hidden meanwhile.
func claimForPurge(ctx context.Context, id int64, cond builder.Cond) error {
	n, err := db.GetEngine(ctx).Where(builder.And(builder.Eq{"id": id}, cond)).
		Cols("trashed_unix").Update(&repo_model.Repository{TrashedUnix: -timeutil.TimeStampNow()})
	if err != nil {
		return err
	} else if n == 0 {
		return ErrTrashConflict
	}
	return nil
}

// PurgeOrg deletes a trashed organization for good, with all its repositories in the trash (those deleted with
// it and those trashed earlier): none may outlive their owner.
func PurgeOrg(ctx context.Context, doer *user_model.User, id int64) error {
	defer repo_service.LockTrash("org", id)()
	org, err := user_model.GetUserByIDIncludingTrashed(ctx, id)
	if err != nil || !org.IsOrganization() || org.TrashedUnix <= 0 {
		return ErrTrashConflict
	}
	return purgeOrg(ctx, doer, org)
}

// purgeOrg claims the organization at the trashed_unix it has now and deletes it.
func purgeOrg(ctx context.Context, doer, org *user_model.User) error {
	n, err := db.GetEngine(ctx).Where("id = ? AND type = ? AND trashed_unix = ?", org.ID, user_model.UserTypeOrganization, org.TrashedUnix).
		Cols("trashed_unix").Update(&user_model.User{TrashedUnix: -timeutil.TimeStampNow()})
	if err != nil {
		return err
	} else if n == 0 {
		return ErrTrashConflict
	}
	live, err := db.GetEngine(ctx).Where("owner_id = ? AND trashed_unix = 0", org.ID).Table("repository").Exist()
	if err != nil {
		return err
	} else if live {
		if org.TrashedUnix > 0 { // give the claim back, an admin decides
			if _, err := db.Exec(ctx, "UPDATE `user` SET trashed_unix=? WHERE id=? AND trashed_unix<0", org.TrashedUnix, org.ID); err != nil {
				return err
			}
		}
		return ErrOrgHasLiveRepos
	}
	var ids []int64
	if err := db.GetEngine(ctx).Table("repository").Where("owner_id = ?", org.ID).Cols("id").Find(&ids); err != nil {
		return err
	}
	for _, id := range ids {
		unlock := repo_service.LockTrash("repo", id)
		// an earlier purge that crashed left its claim: take it over, as a purge in progress elsewhere is rare
		err := claimForPurge(ctx, id, builder.And(builder.Neq{"trashed_unix": 0}, builder.Eq{"owner_id": org.ID})) // not one that was moved to another owner meanwhile
		if err == nil {
			err = deleteClaimed(ctx, doer, id)
		}
		unlock()
		if err != nil && !errors.Is(err, ErrTrashConflict) {
			return err
		}
	}
	if setting.Packages.Enabled {
		if _, err := packages_service.RemoveAllPackages(ctx, org.ID); err != nil {
			return err
		}
	}
	return org_service.DeleteOrganization(ctx, organization.OrgFromUser(org), false)
}

// removeTombstone deletes the tombstone of a deleted user once it owns no repository any more. The claim makes
// it happen exactly once; a failure leaves the claim for PurgeExpired to retry.
func removeTombstone(ctx context.Context, ownerID int64) error {
	owner, err := user_model.GetUserByIDIncludingTrashed(ctx, ownerID)
	if err != nil {
		if user_model.IsErrUserNotExist(err) {
			return nil
		}
		return err
	}
	if !owner.IsTrashed() || owner.IsOrganization() {
		return nil
	}
	if count, err := repo_model.CountRepositories(ctx, repo_model.CountRepositoryOptions{OwnerID: ownerID}); err != nil || count > 0 {
		return err
	}
	n, err := db.GetEngine(ctx).Where("id = ? AND trashed_unix > 0", ownerID).Cols("trashed_unix").
		Update(&user_model.User{TrashedUnix: -timeutil.TimeStampNow()})
	if err != nil || n == 0 {
		return err
	}
	owner.TrashedUnix = -timeutil.TimeStampNow()
	return user_service.DeleteUser(ctx, owner, true)
}

// PurgeExpired deletes the repositories and organizations whose retention is over, retries purges that were
// claimed but never finished, and removes tombstones that have no repository left.
func PurgeExpired(ctx context.Context, doer *user_model.User) error {
	now := timeutil.TimeStampNow()
	expired := now.Add(-int64(setting.Trash.RetentionDays) * 86400)
	stale := now.Add(-int64(purgeRetryAfter / time.Second))
	due := builder.Or(
		builder.And(builder.Gt{"trashed_unix": 0}, builder.Lte{"trashed_unix": expired}),
		builder.And(builder.Lt{"trashed_unix": 0}, builder.Gte{"trashed_unix": -stale}),
	)

	var orgs []*user_model.User
	if err := db.GetEngine(ctx).Where(builder.And(due, builder.Eq{"type": user_model.UserTypeOrganization})).Find(&orgs); err != nil {
		return fmt.Errorf("find expired organizations: %w", err)
	}
	for _, org := range orgs {
		unlock := repo_service.LockTrash("org", org.ID)
		err := purgeOrg(ctx, doer, org)
		unlock()
		if err != nil && !errors.Is(err, ErrTrashConflict) {
			log.Error("purge trashed organization %d: %v", org.ID, err)
		}
	}

	var repos []*repo_model.Repository
	if err := db.GetEngine(ctx).Where(due).Cols("id", "trashed_unix").Find(&repos); err != nil {
		return fmt.Errorf("find expired trash: %w", err)
	}
	for _, repo := range repos {
		// the claim only succeeds for whoever sees the same trashed_unix, so two pods never purge the same one
		unlock := repo_service.LockTrash("repo", repo.ID)
		err := claimForPurge(ctx, repo.ID, builder.Eq{"trashed_unix": repo.TrashedUnix})
		if err == nil {
			if err = deleteClaimed(ctx, doer, repo.ID); err != nil {
				log.Error("purge trashed repository %d: %v", repo.ID, err)
			}
		}
		unlock()
		if err != nil && !errors.Is(err, ErrTrashConflict) {
			return err
		}
	}

	// crash recovery: a tombstone whose repositories are all gone, or whose removal was claimed but not finished
	var tombstones []*user_model.User
	if err := db.GetEngine(ctx).Where(builder.And(
		builder.Neq{"type": user_model.UserTypeOrganization},
		builder.Or(builder.Gt{"trashed_unix": 0}, builder.And(builder.Lt{"trashed_unix": 0}, builder.Lt{"trashed_unix": -stale})),
	)).Find(&tombstones); err != nil {
		return fmt.Errorf("find tombstones: %w", err)
	}
	for _, u := range tombstones {
		if u.TrashedUnix < 0 { // an abandoned removal: take it over
			if _, err := db.Exec(ctx, "UPDATE `user` SET trashed_unix=? WHERE id=? AND trashed_unix=?", timeutil.TimeStampNow(), u.ID, u.TrashedUnix); err != nil {
				return err
			}
		}
		if err := removeTombstone(ctx, u.ID); err != nil {
			log.Error("remove tombstone %d: %v", u.ID, err)
		}
	}
	return nil
}
