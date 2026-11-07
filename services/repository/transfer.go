// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"forgejo.org/models"
	actions_model "forgejo.org/models/actions"
	asymkey_model "forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/sync"
	"forgejo.org/modules/util"
	notify_service "forgejo.org/services/notify"

	"xorm.io/builder"
)

// repoWorkingPool represents a working pool to order the parallel changes to the same repository
// TODO: use clustered lock (unique queue? or *abuse* cache)
var repoWorkingPool = sync.MutexMap{}

// checkNotArchivedOrg refuses moving a repository out of or into an archived organization. The owners are
// loaded fresh: a pending transfer may be accepted long after the organization was archived.
func checkNotArchivedOrg(ctx context.Context, repo *repo_model.Repository, newOwner *user_model.User) error {
	for _, id := range []int64{repo.OwnerID, newOwner.ID} {
		if owner, err := user_model.GetUserByID(ctx, id); err != nil {
			return err
		} else if owner.IsOrganization() && owner.IsArchived {
			return organization.ErrOrgArchived{Name: owner.Name}
		}
	}
	return nil
}

// TransferOwnership transfers all corresponding setting from old user to new one. The new owner gets the
// repository's settings, environments and secrets, so it is only a person's own act (an admin's transfer, or the
// recipient accepting one).
func TransferOwnership(ctx context.Context, doer, newOwner *user_model.User, repo *repo_model.Repository, teams []*organization.Team) error {
	if err := audit_model.CheckOwnAct(ctx); err != nil {
		return err
	}
	if err := checkNotArchivedOrg(ctx, repo, newOwner); err != nil {
		return err
	}
	if err := repo_module.CheckPersonalRepoPolicy(ctx, doer, newOwner, repo.IsPrivate); err != nil {
		return err
	}
	if err := repo_module.CheckPersonalRepoLimit(ctx, newOwner); err != nil {
		return err
	}
	if err := repo.LoadOwner(ctx); err != nil {
		return err
	}
	for _, team := range teams {
		if newOwner.ID != team.OrgID {
			return fmt.Errorf("team %d does not belong to organization", team.ID)
		}
	}

	oldPlace := path.Dir(repo.FullName()) // the owner, and the project if any

	unlock, err := lockRepo(ctx, repo)
	if err != nil {
		return err
	}
	if err := transferOwnership(ctx, doer, newOwner.Name, repo); err != nil {
		unlock()
		return err
	}
	unlock()

	newRepo, err := repo_model.GetRepositoryByID(ctx, repo.ID)
	if err != nil {
		return err
	}

	for _, team := range teams {
		if err := db.WithTx(ctx, func(ctx context.Context) error {
			if err := models.AddRepository(ctx, team, newRepo); err != nil {
				return err
			}
			return organization.RecordTeamRepo(ctx, "org.team.repo_added", team, newRepo)
		}); err != nil {
			return err
		}
	}

	notify_service.TransferRepository(ctx, doer, repo, oldPlace)

	return nil
}

// transferOwnership transfers all corresponding repository items from old user to new one.
func transferOwnership(ctx context.Context, doer *user_model.User, newOwnerName string, repo *repo_model.Repository) (err error) {
	repoRenamed := false
	wikiRenamed := false
	// the old place, in the repository's project if any; a transfer puts it at the root of the new owner
	oldRepoPath, oldWikiPath, oldGroupID := repo.RepoPath(), repo.WikiPath(), repo.GroupID

	defer func() {
		if !repoRenamed && !wikiRenamed {
			return
		}

		recoverErr := recover()
		if err == nil && recoverErr == nil {
			return
		}

		if repoRenamed {
			if err := util.Rename(repo_model.RepoPath(newOwnerName, repo.Name), oldRepoPath); err != nil {
				log.Critical("Unable to move repository %s directory from %s back to correct place %s: %v", repo.Name,
					repo_model.RepoPath(newOwnerName, repo.Name), oldRepoPath, err)
			}
		}

		if wikiRenamed {
			if err := util.Rename(repo_model.WikiPath(newOwnerName, repo.Name), oldWikiPath); err != nil {
				log.Critical("Unable to move wiki for repository %s directory from %s back to correct place %s: %v", repo.Name,
					repo_model.WikiPath(newOwnerName, repo.Name), oldWikiPath, err)
			}
		}

		if recoverErr != nil {
			log.Error("Panic within TransferOwnership: %v\n%s", recoverErr, log.Stack(2))
			panic(recoverErr)
		}
	}()

	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	sess := db.GetEngine(ctx)

	newOwner, err := user_model.GetUserByName(ctx, newOwnerName)
	if err != nil {
		return fmt.Errorf("get new owner '%s': %w", newOwnerName, err)
	}
	newOwnerName = newOwner.Name // ensure capitalisation matches

	// Check if new owner has repository with same name.
	if has, err := repo_model.IsRepositoryModelOrDirExist(ctx, newOwner, repo.Name); err != nil {
		return fmt.Errorf("IsRepositoryExist: %w", err)
	} else if has {
		return repo_model.ErrRepoAlreadyExist{
			Uname: newOwnerName,
			Name:  repo.Name,
		}
	}

	oldOwner := repo.Owner
	before := map[string]any{"owner_id": oldOwner.ID, "owner_name": oldOwner.Name, "group_id": oldGroupID, "group_name": repo.GroupName}
	counts, err := transferCounts(ctx, repo, oldOwner)
	if err != nil {
		return err
	}

	// the old owner's deploy keys stop applying (the lookup follows the owner); collect them for the protection rules
	oldOrgKeys, err := asymkey_model.FindOrgDeployKeysCoveringRepo(ctx, repo)
	if err != nil {
		return fmt.Errorf("FindOrgDeployKeysCoveringRepo: %w", err)
	}

	if err := repo_model.ReleaseRepoName(ctx, repo); err != nil {
		return err
	}

	// Note: we have to set value here to make sure recalculate accesses is based on
	// new owner.
	repo.OwnerID = newOwner.ID
	repo.Owner = newOwner
	repo.OwnerName = newOwner.Name
	repo.GroupID, repo.GroupName = 0, ""

	if err := repo_model.ClaimRepoName(ctx, repo); err != nil {
		return err
	}
	if err := repo_model.TakeRedirectPath(ctx, newOwner, 0, repo.Name, repo.ID); err != nil {
		return err
	}

	// Update repository.
	if _, err := sess.ID(repo.ID).Update(repo); err != nil {
		return fmt.Errorf("update owner: %w", err)
	}
	if _, err := sess.ID(repo.ID).Cols("group_id", "group_name").Update(repo); err != nil { // zero values
		return fmt.Errorf("update project: %w", err)
	}

	// Drop the selections, so moving back doesn't restore them, and the old owner's keys from the protection
	// rules unless the key still writes to the repository (its own deploy key, or a key of the new owner).
	if err := db.DeleteBeans(ctx, &asymkey_model.OrgDeployKeyRepo{RepoID: repo.ID}); err != nil {
		return fmt.Errorf("delete org deploy key selections: %w", err)
	}
	if err := actions_model.DropEnvironmentRepoSelections(ctx, repo.ID); err != nil {
		return fmt.Errorf("delete environment selections: %w", err)
	}
	if err := auth_model.DropOwnedAccessTokensOfTransferredRepo(ctx, repo.ID); err != nil {
		return fmt.Errorf("DropOwnedAccessTokensOfTransferredRepo: %w", err)
	}
	oldKeyIDs := make([]int64, 0, len(oldOrgKeys))
	for _, key := range oldOrgKeys {
		oldKeyIDs = append(oldKeyIDs, key.KeyID)
	}
	if err := git_model.DropDeployKeyIDsNotWriting(ctx, repo, oldKeyIDs); err != nil {
		return fmt.Errorf("DropDeployKeyIDsNotWriting: %w", err)
	}

	// the teams of the old organization are no reviewers of the new owner's repository (its change of rules is recorded;
	// the environment keeps requiring reviews)
	if err := actions_model.RemoveReviewers(ctx, actions_model.ForeignTeamReviewerCond(repo.ID, newOwner.ID)); err != nil {
		return fmt.Errorf("RemoveReviewers: %w", err)
	}
	if err := actions_model.RefuseTwinsOnTransfer(ctx, repo.ID, newOwner.ID); err != nil {
		return err
	}

	// Remove redundant collaborators.
	collaborators, err := repo_model.GetCollaborators(ctx, repo.ID, db.ListOptions{})
	if err != nil {
		return fmt.Errorf("getCollaborators: %w", err)
	}

	// Dummy object.
	collaboration := &repo_model.Collaboration{RepoID: repo.ID}
	for _, c := range collaborators {
		if c.IsGhost() {
			collaboration.ID = c.Collaboration.ID
			n, err := sess.Delete(collaboration)
			if err != nil {
				return fmt.Errorf("remove collaborator '%d': %w", c.ID, err)
			}
			counts["collaborators"] += n
			collaboration.ID = 0
		}

		if c.ID != newOwner.ID {
			isMember, err := organization.IsOrganizationMember(ctx, newOwner.ID, c.ID)
			if err != nil {
				return fmt.Errorf("IsOrgMember: %w", err)
			} else if !isMember {
				continue
			}
		}
		collaboration.UserID = c.ID
		n, err := sess.Delete(collaboration)
		if err != nil {
			return fmt.Errorf("remove collaborator '%d': %w", c.ID, err)
		}
		counts["collaborators"] += n
		collaboration.UserID = 0
	}

	// Remove old team-repository relations.
	if oldOwner.IsOrganization() {
		if err := organization.RemoveOrgRepo(ctx, oldOwner.ID, repo.ID); err != nil {
			return fmt.Errorf("removeOrgRepo: %w", err)
		}
	}

	if newOwner.IsOrganization() {
		teams, err := organization.FindOrgTeams(ctx, newOwner.ID)
		if err != nil {
			return fmt.Errorf("LoadTeams: %w", err)
		}
		for _, t := range teams {
			if t.IncludesAllRepositories {
				if err := models.AddRepository(ctx, t, repo); err != nil {
					return fmt.Errorf("AddRepository: %w", err)
				}
			}
		}
	} else if err := access_model.RecalculateAccesses(ctx, repo); err != nil {
		// Organization called this in addRepository method.
		return fmt.Errorf("recalculateAccesses: %w", err)
	}

	// Update repository count.
	if _, err := sess.Exec("UPDATE `user` SET num_repos=num_repos+1 WHERE id=?", newOwner.ID); err != nil {
		return fmt.Errorf("increase new owner repository count: %w", err)
	} else if _, err := sess.Exec("UPDATE `user` SET num_repos=num_repos-1 WHERE id=?", oldOwner.ID); err != nil {
		return fmt.Errorf("decrease old owner repository count: %w", err)
	}

	if err := repo_model.WatchRepoExplicitly(ctx, doer.ID, repo.ID, repo_model.WatchAllSelection); err != nil {
		return fmt.Errorf("watchRepo: %w", err)
	}

	// Remove watch for organization.
	if oldOwner.IsOrganization() {
		if err := repo_model.WatchRepoExplicitly(ctx, oldOwner.ID, repo.ID, repo_model.WatchNoneSelection); err != nil {
			return fmt.Errorf("watchRepo [false]: %w", err)
		}
	}

	// Delete labels that belong to the old organization and comments that added these labels
	if oldOwner.IsOrganization() {
		if _, err := sess.Exec(`DELETE FROM issue_label WHERE issue_label.id IN (
			SELECT il_too.id FROM (
				SELECT il_too_too.id
					FROM issue_label AS il_too_too
						INNER JOIN label ON il_too_too.label_id = label.id
						INNER JOIN issue on issue.id = il_too_too.issue_id
					WHERE
						issue.repo_id = ? AND ((label.org_id = 0 AND issue.repo_id != label.repo_id) OR (label.repo_id = 0 AND label.org_id != ?))
		) AS il_too )`, repo.ID, newOwner.ID); err != nil {
			return fmt.Errorf("Unable to remove old org labels: %w", err)
		}

		if _, err := sess.Exec(`DELETE FROM comment WHERE comment.id IN (
			SELECT il_too.id FROM (
				SELECT com.id
					FROM comment AS com
						INNER JOIN label ON com.label_id = label.id
						INNER JOIN issue ON issue.id = com.issue_id
					WHERE
						com.type = ? AND issue.repo_id = ? AND ((label.org_id = 0 AND issue.repo_id != label.repo_id) OR (label.repo_id = 0 AND label.org_id != ?))
		) AS il_too)`, issues_model.CommentTypeLabel, repo.ID, newOwner.ID); err != nil {
			return fmt.Errorf("Unable to remove old org label comments: %w", err)
		}
	}

	// Rename remote repository to new path and delete local copy.
	dir := user_model.UserPath(newOwner.Name)

	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return fmt.Errorf("Failed to create dir %s: %w", dir, err)
	}

	if err := util.Rename(oldRepoPath, repo_model.RepoPath(newOwner.Name, repo.Name)); err != nil {
		return fmt.Errorf("rename repository directory: %w", err)
	}
	repoRenamed = true

	// Rename remote wiki repository to new path and delete local copy.
	wikiPath := oldWikiPath

	if isExist, err := util.IsExist(wikiPath); err != nil {
		log.Error("Unable to check if %s exists. Error: %v", wikiPath, err)
		return err
	} else if isExist {
		if err := util.Rename(wikiPath, repo_model.WikiPath(newOwner.Name, repo.Name)); err != nil {
			return fmt.Errorf("rename repository wiki: %w", err)
		}
		wikiRenamed = true
	}

	accepted, err := models.DeleteRepositoryTransfer(ctx, repo.ID)
	if err != nil {
		return fmt.Errorf("deleteRepositoryTransfer: %w", err)
	}
	// scoped to the previous owner, whose repository leaves it
	action := "repo.repository.transferred"
	if accepted {
		action = "repo.transfer.accepted"
	}
	if err := audit_model.Record(ctx, audit_model.Event{
		Action: action, Result: audit_model.ResultSuccess, RepoID: repo.ID, OwnerID: oldOwner.ID, GroupID: oldGroupID, TargetType: "repo", TargetID: repo.ID,
		TargetName: path.Join(oldOwner.Name, before["group_name"].(string), repo.Name), Data: map[string]any{
			"before": before, "after": map[string]any{"owner_id": newOwner.ID, "owner_name": newOwner.Name, "group_id": int64(0), "group_name": ""},
			"counts": counts,
		},
	}); err != nil {
		return err
	}
	repo.Status = repo_model.RepositoryReady
	if err := repo_model.UpdateRepositoryCols(ctx, repo, "status"); err != nil {
		return err
	}

	if err := repo_model.NewRedirect(ctx, oldOwner.ID, oldGroupID, repo.ID, repo.Name); err != nil {
		return fmt.Errorf("repo_model.NewRedirect: %w", err)
	}

	return committer.Commit()
}

// changeRepositoryName changes all corresponding setting from old repository name to new one.
func changeRepositoryName(ctx context.Context, repo *repo_model.Repository, newRepoName string) (err error) {
	oldRepoName, newName := repo.Name, newRepoName // the name keeps its case, paths and lower_name don't
	newRepoName = strings.ToLower(newRepoName)
	if err = repo_model.IsUsableRepoName(newRepoName); err != nil {
		return err
	}

	if err := repo.LoadOwner(ctx); err != nil {
		return err
	}

	// the new paths are next to the old ones, in the repository's project if it is in one
	newRepoPath := filepath.Join(filepath.Dir(repo.RepoPath()), newRepoName+".git")
	newWikiPath := filepath.Join(filepath.Dir(repo.WikiPath()), newRepoName+".wiki.git")
	has, err := repo_model.IsRepositoryModelExistInGroup(ctx, repo.OwnerID, repo.GroupID, newRepoName)
	if err == nil && !has {
		has, err = util.IsDir(newRepoPath)
	}
	if err != nil {
		return fmt.Errorf("IsRepositoryExist: %w", err)
	} else if has {
		return repo_model.ErrRepoAlreadyExist{
			Uname: repo.Owner.Name,
			Name:  newRepoName,
		}
	}

	oldRepoPath, oldLowerName := repo.RepoPath(), repo.LowerName
	if err = util.Rename(oldRepoPath, newRepoPath); err != nil {
		return fmt.Errorf("rename repository directory: %w", err)
	}

	// the directories go back if the database refuses the name (a project holding it, say)
	wikiPath := repo.WikiPath()
	wikiRenamed := false
	defer func() {
		if err == nil {
			return
		}
		repo.Name, repo.LowerName = oldRepoName, oldLowerName
		moveDirsBack(newRepoPath, oldRepoPath)
		if wikiRenamed {
			moveDirsBack(newWikiPath, wikiPath)
		}
	}()

	isExist, err := util.IsExist(wikiPath)
	if err != nil {
		log.Error("Unable to check if %s exists. Error: %v", wikiPath, err)
		return err
	}
	if isExist {
		if err = util.Rename(wikiPath, newWikiPath); err != nil {
			return fmt.Errorf("rename repository wiki: %w", err)
		}
		wikiRenamed = true
	}

	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	// the name claim and the name change together
	if err = repo_model.ReleaseRepoName(ctx, repo); err != nil {
		return err
	}
	repo.Name, repo.LowerName = newName, newRepoName
	if err = repo_model.ClaimRepoName(ctx, repo); err != nil {
		return err
	}
	if err = repo_model.TakeRedirectPath(ctx, repo.Owner, repo.GroupID, newName, repo.ID); err != nil {
		return err
	}
	if err = repo_model.UpdateRepositoryCols(ctx, repo, "name", "lower_name"); err != nil {
		return err
	}
	if err = repo_model.RecordRepo(ctx, "repo.repository.renamed", repo, map[string]any{
		"before": map[string]any{"name": oldRepoName}, "after": map[string]any{"name": newName},
	}); err != nil {
		return err
	}
	if err = repo_model.NewRedirect(ctx, repo.Owner.ID, repo.GroupID, repo.ID, oldRepoName); err != nil {
		return err
	}

	return committer.Commit()
}

// ChangeRepositoryName changes all corresponding setting from old repository name to new one.
func ChangeRepositoryName(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, newRepoName string) error {
	log.Trace("ChangeRepositoryName: %s/%s -> %s", doer.Name, repo.Name, newRepoName)

	oldRepoName := repo.Name

	// Change repository directory name. We must lock the local copy of the
	// repo so that we can atomically rename the repo path and updates the
	// local copy's origin accordingly.

	unlock, err := lockRepo(ctx, repo)
	if err != nil {
		return err
	}
	if err := changeRepositoryName(ctx, repo, newRepoName); err != nil {
		unlock()
		return err
	}
	unlock()

	repo.Name = newRepoName
	notify_service.RenameRepository(ctx, doer, repo, oldRepoName)

	return nil
}

// StartRepositoryTransfer transfer a repo from one owner to a new one.
// it make repository into pending transfer state, if doer can not create repo for new owner.
// Like TransferOwnership, starting one is only a person's own act.
func StartRepositoryTransfer(ctx context.Context, doer, newOwner *user_model.User, repo *repo_model.Repository, teams []*organization.Team) error {
	if err := audit_model.CheckOwnAct(ctx); err != nil {
		return err
	}
	if err := checkNotArchivedOrg(ctx, repo, newOwner); err != nil {
		return err
	}
	if err := repo_module.CheckPersonalRepoPolicy(ctx, doer, newOwner, repo.IsPrivate); err != nil {
		return err
	}
	if err := repo_module.CheckPersonalRepoLimit(ctx, newOwner); err != nil {
		return err
	}
	if user_model.IsBlocked(ctx, newOwner.ID, doer.ID) {
		return user_model.ErrBlockedByUser
	}

	if err := models.TestRepositoryReadyForTransfer(repo.Status); err != nil {
		return err
	}
	// refused already here, so no pending transfer waits that can't be accepted (accepting checks it again)
	if err := actions_model.RefuseTwinsOnTransfer(ctx, repo.ID, newOwner.ID); err != nil {
		return err
	}

	// Admin is always allowed to transfer || user transfer repo back to his account
	if doer.IsAdmin || doer.ID == newOwner.ID {
		return TransferOwnership(ctx, doer, newOwner, repo, teams)
	}

	// If new owner is an org and user can create repos he can transfer directly too
	if newOwner.IsOrganization() {
		allowed, err := organization.CanCreateOrgRepo(ctx, newOwner.ID, doer.ID)
		if err != nil {
			return err
		}
		if allowed {
			return TransferOwnership(ctx, doer, newOwner, repo, teams)
		}
	}

	// In case the new owner would not have sufficient access to the repo, give access rights for read
	hasAccess, err := access_model.HasAccess(ctx, newOwner.ID, repo)
	if err != nil {
		return err
	}
	if !hasAccess {
		if err := repo_module.AddCollaborator(ctx, repo, newOwner, perm.AccessModeRead); err != nil {
			return err
		}
	}

	// Make repo as pending for transfer
	repo.Status = repo_model.RepositoryPendingTransfer
	if err := models.CreatePendingRepositoryTransfer(ctx, doer, newOwner, repo.ID, teams); err != nil {
		return err
	}

	// notify users who are able to accept / reject transfer
	notify_service.RepoPendingTransfer(ctx, doer, newOwner, repo)

	return nil
}

// CancelRepositoryTransfer marks the repository as ready and remove pending transfer entry,
// thus cancel the transfer process. rejected tells that the recipient refused it, rather than the owner withdrawing it.
func CancelRepositoryTransfer(ctx context.Context, repo *repo_model.Repository, rejected bool) error {
	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	repo.Status = repo_model.RepositoryReady
	if err := repo_model.UpdateRepositoryCols(ctx, repo, "status"); err != nil {
		return err
	}

	if had, err := models.DeleteRepositoryTransfer(ctx, repo.ID); err != nil {
		return err
	} else if had {
		action := "repo.transfer.canceled"
		if rejected {
			action = "repo.transfer.rejected"
		}
		if err := repo_model.RecordRepo(ctx, action, repo, nil); err != nil {
			return err
		}
	}

	return committer.Commit()
}

// transferCounts counts the rows transferring repo away from oldOwner removes, for its audit entry: the
// collaborators who are members of the new owner (or it), the old organization's team rows, the deploy key
// selections, the repository's own access tokens and its selections in organization tokens.
func transferCounts(ctx context.Context, repo *repo_model.Repository, oldOwner *user_model.User) (map[string]int64, error) {
	counts := map[string]int64{"collaborators": 0}
	for _, c := range []struct {
		name, table string
		cond        builder.Cond
	}{
		{"teams", "team_repo", builder.Eq{"repo_id": repo.ID, "org_id": oldOwner.ID}},
		{"deploy_key_selections", "org_deploy_key_repo", builder.Eq{"repo_id": repo.ID}},
		{"environment_selections", "action_environment_repo", builder.Eq{"repo_id": repo.ID}},
		{"access_tokens", "access_token", builder.Eq{"owner_type": auth_model.AccessTokenOwnerRepo, "owner_id": repo.ID}},
		{"token_selections", "access_token_resource_repo", builder.Eq{"repo_id": repo.ID}.And(builder.In("token_id", builder.Select("id").From("access_token").Where(builder.Neq{"owner_type": auth_model.AccessTokenOwnerUser})))},
	} {
		n, err := db.GetEngine(ctx).Table(c.table).Where(c.cond).Count()
		if err != nil {
			return nil, err
		}
		counts[c.name] = n
	}
	return counts, nil
}
