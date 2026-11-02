// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"forgejo.org/models/db"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	webhook_model "forgejo.org/models/webhook"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"xorm.io/builder"
)

// RepoGroup is a project: one level of grouping for the repositories of an organization, `org/group/repo`. The
// organization stays the owner of its repositories (repository.owner_id); repository.group_id names the group.
type RepoGroup struct { //revive:disable-line:exported
	ID          int64              `xorm:"pk autoincr"`
	OwnerID     int64              `xorm:"UNIQUE(s) INDEX NOT NULL"`
	Name        string             `xorm:"NOT NULL"`
	LowerName   string             `xorm:"UNIQUE(s) NOT NULL"`
	Description string             `xorm:"TEXT"`
	Avatar      string             `xorm:"VARCHAR(64)"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

// RepoGroupNameClaim reserves a name at the root of an owner. Every root repository (trashed ones included) and
// every group holds one, so a group and a root repository never share a name, also across processes. Rows are
// written and released only by ClaimRepoName/ReleaseRepoName and the group functions below, inside the
// transaction that changes the name.
type RepoGroupNameClaim struct { //revive:disable-line:exported
	ID        int64  `xorm:"pk autoincr"`
	OwnerID   int64  `xorm:"UNIQUE(s) NOT NULL"`
	LowerName string `xorm:"UNIQUE(s) NOT NULL"`
}

func init() {
	db.RegisterModel(new(RepoGroup))
	db.RegisterModel(new(RepoGroupNameClaim))
}

var (
	// ErrRepoGroupNotEmpty is returned when deleting a group that still holds repositories, trashed ones included.
	ErrRepoGroupNotEmpty = fmt.Errorf("%w: the project still holds repositories", util.ErrInvalidArgument)
	// ErrRepoGroupNotExist is returned when a group isn't found under the given owner.
	ErrRepoGroupNotExist = fmt.Errorf("%w: project does not exist", util.ErrNotExist)
)

// GroupPath returns the directory of a group: <root>/<owner>/<group>.
func GroupPath(ownerName, groupName string) string {
	return filepath.Join(user_model.UserPath(ownerName), strings.ToLower(groupName))
}

// IsUsableGroupName checks a project name: every repository name rule, and at most 100 characters like the
// repository name in the forms.
func IsUsableGroupName(name string) error {
	if len(name) > 100 {
		return fmt.Errorf("%w: name is longer than 100 characters", util.ErrInvalidArgument)
	}
	return IsUsableRepoName(name)
}

// claimName reserves name at the root of the owner; an existing claim is the generic ErrRepoAlreadyExist, whether
// a repository (of any visibility, or trashed) or a group holds it. A concurrent claim fails on the unique key.
func claimName(ctx context.Context, ownerID int64, ownerName, name string) error {
	has, err := db.GetEngine(ctx).Where("owner_id = ? AND lower_name = ?", ownerID, strings.ToLower(name)).Exist(new(RepoGroupNameClaim))
	if err != nil {
		return err
	} else if has {
		return ErrRepoAlreadyExist{Uname: ownerName, Name: name}
	}
	return db.Insert(ctx, &RepoGroupNameClaim{OwnerID: ownerID, LowerName: strings.ToLower(name)})
}

func releaseName(ctx context.Context, ownerID int64, name string) error {
	_, err := db.GetEngine(ctx).Where("owner_id = ? AND lower_name = ?", ownerID, strings.ToLower(name)).Delete(new(RepoGroupNameClaim))
	return err
}

// ClaimRepoName claims the name of a root repository for its owner; a repository in a group claims nothing.
func ClaimRepoName(ctx context.Context, repo *Repository) error {
	if repo.GroupID != 0 {
		return nil
	}
	return claimName(ctx, repo.OwnerID, repo.OwnerName, repo.Name)
}

// ReleaseRepoName releases the claim of a root repository; for a repository in a group it does nothing, so the
// claim of a root repository or group with the same name stays.
func ReleaseRepoName(ctx context.Context, repo *Repository) error {
	if repo.GroupID != 0 {
		return nil
	}
	return releaseName(ctx, repo.OwnerID, repo.Name)
}

// GetRepoGroupByID returns the group with the given ID of the owner; a group of another owner is not found.
func GetRepoGroupByID(ctx context.Context, ownerID, id int64) (*RepoGroup, error) {
	group := new(RepoGroup)
	has, err := db.GetEngine(ctx).Where("owner_id = ? AND id = ?", ownerID, id).Get(group)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrRepoGroupNotExist
	}
	return group, nil
}

// GetRepoGroupByName returns the group of the owner with the given name (any case).
func GetRepoGroupByName(ctx context.Context, ownerID int64, name string) (*RepoGroup, error) {
	group := new(RepoGroup)
	has, err := db.GetEngine(ctx).Where("owner_id = ? AND lower_name = ?", ownerID, strings.ToLower(name)).Get(group)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrRepoGroupNotExist
	}
	return group, nil
}

// CreateRepoGroup creates a group in an organization. The name follows every repository name rule and must not
// be the name of a root repository or another group of the organization.
func CreateRepoGroup(ctx context.Context, owner *user_model.User, name, description string) (*RepoGroup, error) {
	if !owner.IsOrganization() {
		return nil, fmt.Errorf("%w: only organizations have projects", util.ErrInvalidArgument)
	}
	if err := IsUsableGroupName(name); err != nil {
		return nil, err
	}
	if isExist, err := util.IsExist(GroupPath(owner.Name, name)); err != nil {
		return nil, err
	} else if isExist {
		return nil, ErrRepoFilesAlreadyExist{Uname: owner.Name, Name: name}
	}
	group := &RepoGroup{OwnerID: owner.ID, Name: name, LowerName: strings.ToLower(name), Description: description}
	return group, db.WithTx(ctx, func(ctx context.Context) error {
		if err := claimName(ctx, owner.ID, owner.Name, name); err != nil {
			return err
		}
		// a live redirect of the name is refused, like a taken name
		if err := takeGroupRedirectPath(ctx, owner, name, 0); err != nil {
			return err
		}
		if err := db.Insert(ctx, group); err != nil {
			return err
		}
		return RecordProject(ctx, "org.project.created", group, map[string]any{"name": name})
	})
}

// RenameRepoGroup renames a group in the database and updates the group name copied into its repositories.
// Moving the directory is the caller's job (services/repository).
func RenameRepoGroup(ctx context.Context, owner *user_model.User, group *RepoGroup, newName string) error {
	if group.OwnerID != owner.ID {
		return ErrRepoGroupNotExist
	}
	if err := IsUsableGroupName(newName); err != nil {
		return err
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		if group.Name != newName {
			if err := RecordProject(ctx, "org.project.renamed", group, map[string]any{
				"before": map[string]any{"name": group.Name}, "after": map[string]any{"name": newName},
			}); err != nil {
				return err
			}
		}
		if !strings.EqualFold(group.Name, newName) {
			if err := releaseName(ctx, owner.ID, group.Name); err != nil {
				return err
			}
			if err := claimName(ctx, owner.ID, owner.Name, newName); err != nil {
				return err
			}
			if err := takeGroupRedirectPath(ctx, owner, newName, group.ID); err != nil {
				return err
			}
			if err := db.Insert(ctx, &RepoGroupRedirect{OwnerID: owner.ID, LowerName: group.LowerName, RedirectGroupID: group.ID}); err != nil {
				return err
			}
		}
		group.Name, group.LowerName = newName, strings.ToLower(newName)
		if _, err := db.GetEngine(ctx).ID(group.ID).Cols("name", "lower_name").Update(group); err != nil {
			return err
		}
		_, err := db.GetEngine(ctx).Exec("UPDATE `repository` SET group_name = ? WHERE owner_id = ? AND group_id = ?", newName, owner.ID, group.ID)
		return err
	})
}

// DeleteRepoGroup deletes an empty group; a group that holds any repository, trashed ones included, is refused, so
// that a trashed repository's group still exists when it is restored.
func DeleteRepoGroup(ctx context.Context, group *RepoGroup) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		// the row lock first, so that a repository moving in meanwhile is seen (LockRepoGroup)
		locked, err := LockRepoGroup(ctx, group.OwnerID, group.ID)
		if err != nil {
			return err
		}
		if has, err := db.GetEngine(ctx).Where("owner_id = ? AND group_id = ?", group.OwnerID, group.ID).Exist(new(Repository)); err != nil {
			return err
		} else if has {
			return ErrRepoGroupNotEmpty
		}
		if _, err := db.GetEngine(ctx).Where("owner_id = ? AND id = ?", group.OwnerID, group.ID).Delete(new(RepoGroup)); err != nil {
			return err
		}
		if _, err := db.GetEngine(ctx).Where("owner_id = ? AND group_id = ?", group.OwnerID, group.ID).Delete(new(Redirect)); err != nil {
			return err
		}
		if _, err := db.GetEngine(ctx).Where("owner_id = ? AND group_id = ?", group.OwnerID, group.ID).Delete(new(BitbucketOrigin)); err != nil {
			return err
		}
		if _, err := db.GetEngine(ctx).Where("owner_id = ? AND redirect_group_id = ?", group.OwnerID, group.ID).Delete(new(RepoGroupRedirect)); err != nil {
			return err
		}
		// the teams linked to it; the project is empty, so they have no rows through it
		if _, err := db.Exec(ctx, "DELETE FROM `team_group` WHERE group_id = ?", group.ID); err != nil {
			return err
		}
		// its branch rules (models/git imports this package, so by SQL), with their approval rules and selected repositories
		rules := "SELECT id FROM `protected_branch` WHERE repo_id = 0 AND org_id = ? AND group_id = ?"
		for _, query := range []string{
			"DELETE FROM `approval_rule` WHERE protected_branch_id IN (" + rules + ")",
			"DELETE FROM `protected_branch_repo` WHERE protected_branch_id IN (" + rules + ")",
			"DELETE FROM `protected_branch` WHERE repo_id = 0 AND org_id = ? AND group_id = ?",
		} {
			if _, err := db.Exec(ctx, query, group.OwnerID, group.ID); err != nil {
				return err
			}
		}
		// its webhooks with their deliveries (by ID: MariaDB doesn't use the hook_task key with a subquery)
		hooks := []int64{}
		if err := db.GetEngine(ctx).Table("webhook").Where("owner_id = ? AND group_id = ?", group.OwnerID, group.ID).Cols("id").Find(&hooks); err != nil {
			return err
		}
		if len(hooks) > 0 {
			if _, err := db.GetEngine(ctx).In("hook_id", hooks).Delete(new(webhook_model.HookTask)); err != nil {
				return err
			}
			if _, err := db.GetEngine(ctx).In("id", hooks).Delete(new(webhook_model.Webhook)); err != nil {
				return err
			}
		}
		// its Actions secrets and variables (the packages can't be imported here, so by SQL)
		for _, table := range []string{"secret", "action_variable"} {
			if _, err := db.Exec(ctx, "DELETE FROM `"+table+"` WHERE owner_id = ? AND group_id = ?", group.OwnerID, group.ID); err != nil {
				return err
			}
		}
		return releaseName(ctx, group.OwnerID, locked.Name)
	})
}

// LockRepoGroup locks the row of the group in the transaction of ctx until it ends and returns the group as it is
// then, so that moving a repository into the group and deleting the group run one after the other; a missing group
// is ErrRepoGroupNotExist. (No RowsAffected: MySQL counts a no-op update as 0 rows.)
func LockRepoGroup(ctx context.Context, ownerID, id int64) (*RepoGroup, error) {
	if _, err := db.Exec(ctx, "UPDATE `repo_group` SET owner_id = owner_id WHERE owner_id = ? AND id = ?", ownerID, id); err != nil {
		return nil, err
	}
	return GetRepoGroupByID(ctx, ownerID, id)
}

// Link returns the relative url of the project's home; ownerName is the name of its organization.
func (group *RepoGroup) Link(ownerName string) string {
	return setting.AppSubURL + "/" + url.PathEscape(ownerName) + "/" + url.PathEscape(group.Name)
}

// UpdateRepoGroupDescription stores the description of a group.
func UpdateRepoGroupDescription(ctx context.Context, group *RepoGroup) error {
	_, err := db.GetEngine(ctx).Where("owner_id = ? AND id = ?", group.OwnerID, group.ID).Cols("description").Update(group)
	return err
}

// VisibleRepoGroupCond is the SQL form of the project home's checks on `repo_group` (OrgAssignment and
// CanSeeRepoGroup in services/context), for the projects of organizations that aren't in the trash: every one for a
// site admin; otherwise, in the organizations the doer can see, those of the organizations the doer is an acting
// member of and those holding a repository the doer can see.
func VisibleRepoGroupCond(doer *user_model.User) builder.Cond {
	cond := builder.In("`repo_group`.owner_id", builder.Select("id").From("`user`").Where(builder.Eq{"trashed_unix": 0}))
	if doer != nil && doer.IsAdmin {
		return cond
	}
	// the organization itself must be visible, as in OrgAssignment
	orgVisible := builder.In("`repo_group`.owner_id", builder.Select("id").From("`user`").Where(builder.Eq{"visibility": structs.VisibleTypePublic}))
	if doer != nil {
		isMember := builder.In("`repo_group`.owner_id", builder.Select("org_id").From("org_user").Where(builder.Eq{"uid": doer.ID}))
		orgVisible = isMember
		if !doer.IsRestricted {
			orgVisible = orgVisible.Or(builder.In("`repo_group`.owner_id", builder.Select("id").From("`user`").Where(builder.Neq{"visibility": structs.VisibleTypePrivate})))
		}
	}
	cond = cond.And(orgVisible)

	visible := builder.In("`repo_group`.id", builder.Select("group_id").From("`repository`").Where(builder.And(
		AccessibleRepositoryCondition(doer, unit.TypeInvalid),
		builder.Eq{"`repository`.trashed_unix": 0},
		builder.Neq{"`repository`.group_id": 0},
	)))
	if doer != nil {
		visible = visible.Or(builder.And(
			builder.In("`repo_group`.owner_id", builder.Select("org_id").From("org_user").Where(builder.Eq{"uid": doer.ID})),
			builder.NotIn("`repo_group`.owner_id", TwoFactorBlockingOrgIDs(doer.ID)),
		))
	}
	return cond.And(visible)
}

// FindVisibleRepoGroups returns the projects the doer can see, of one organization (ownerID) or of all, ordered by
// name; keyword narrows them by name.
func FindVisibleRepoGroups(ctx context.Context, doer *user_model.User, ownerID int64, keyword string, listOptions db.ListOptions) ([]*RepoGroup, int64, error) {
	return FindRepoGroups(ctx, VisibleRepoGroupCond(doer), ownerID, keyword, listOptions)
}

// FindRepoGroups returns the projects matching cond, of one organization (ownerID) or of all, ordered by name;
// keyword narrows them by name.
func FindRepoGroups(ctx context.Context, cond builder.Cond, ownerID int64, keyword string, listOptions db.ListOptions) ([]*RepoGroup, int64, error) {
	if ownerID != 0 {
		cond = cond.And(builder.Eq{"`repo_group`.owner_id": ownerID})
	}
	if keyword != "" {
		cond = cond.And(builder.Like{"`repo_group`.lower_name", strings.ToLower(keyword)})
	}
	sess := db.GetEngine(ctx).Where(cond).OrderBy("`repo_group`.lower_name, `repo_group`.id")
	if listOptions.PageSize > 0 {
		sess = db.SetSessionPagination(sess, &listOptions)
	}
	groups := make([]*RepoGroup, 0, listOptions.PageSize)
	count, err := sess.FindAndCount(&groups)
	return groups, count, err
}

// CountReposByGroup returns, for each of the groups, the number of its repositories that a search with opts finds.
func CountReposByGroup(ctx context.Context, opts *SearchRepoOptions, groupIDs []int64) (map[int64]int64, error) {
	counts := make(map[int64]int64, len(groupIDs))
	if len(groupIDs) == 0 {
		return counts, nil
	}
	rows := make([]struct {
		ID    int64 `xorm:"id"`
		Count int64 `xorm:"cnt"`
	}, 0, len(groupIDs))
	if err := db.GetEngine(ctx).Table("repository").Select("group_id AS id, COUNT(*) AS cnt").
		Where(SearchRepositoryCondition(opts)).In("group_id", groupIDs).GroupBy("group_id").Find(&rows); err != nil {
		return nil, err
	}
	for _, r := range rows {
		counts[r.ID] = r.Count
	}
	return counts, nil
}

// GetRepoGroupsByOwnerIDs returns the groups of the given owners, ordered by name.
func GetRepoGroupsByOwnerIDs(ctx context.Context, ownerIDs []int64) ([]*RepoGroup, error) {
	groups := make([]*RepoGroup, 0, len(ownerIDs))
	if len(ownerIDs) == 0 {
		return groups, nil
	}
	return groups, db.GetEngine(ctx).In("owner_id", ownerIDs).OrderBy("lower_name, id").Find(&groups)
}

// CountVisibleRepoGroups counts the projects of the organization that the doer can see.
func CountVisibleRepoGroups(ctx context.Context, doer *user_model.User, ownerID int64) (int64, error) {
	return db.GetEngine(ctx).Where(VisibleRepoGroupCond(doer)).And(builder.Eq{"`repo_group`.owner_id": ownerID}).Count(new(RepoGroup))
}

// IsNameTaken reports, without writing, whether a new project of the owner (groupID 0) or a new repository in its
// project groupID can't take name: a repository, project or claim holds it, or a redirect does (TakeRedirectPath
// refuses a name a redirect holds in an organization).
func IsNameTaken(ctx context.Context, ownerID, groupID int64, name string) (bool, error) {
	lower := strings.ToLower(name)
	if groupID == 0 {
		if has, err := db.GetEngine(ctx).Where("owner_id = ? AND lower_name = ?", ownerID, lower).Exist(new(RepoGroupNameClaim)); err != nil || has {
			return has, err
		}
		if has, err := db.GetEngine(ctx).Where("owner_id = ? AND lower_name = ?", ownerID, lower).Exist(new(RepoGroupRedirect)); err != nil || has {
			return has, err
		}
	} else if has, err := IsRepositoryModelExistInGroup(ctx, ownerID, groupID, name); err != nil || has {
		return has, err
	}
	return db.GetEngine(ctx).Where("owner_id = ? AND group_id = ? AND lower_name = ?", ownerID, groupID, lower).Exist(new(Redirect))
}
