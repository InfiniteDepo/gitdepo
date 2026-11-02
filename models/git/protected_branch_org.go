// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"context"
	"fmt"

	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	"forgejo.org/modules/util"

	"xorm.io/builder"
)

// Every query on an organization or project rule includes repo_id = 0, org_id and group_id (0 for an organization
// rule): a bean with zero fields would match the other levels, because xorm drops zero fields from bean conditions.
func ruleScopeCond(orgID, groupID int64) builder.Eq {
	return builder.Eq{"repo_id": 0, "org_id": orgID, "group_id": groupID}
}

// FindOrgProtectedBranchRules loads the branch protection rules of an organization (groupID 0) or of one of its
// projects.
func FindOrgProtectedBranchRules(ctx context.Context, orgID, groupID int64) (ProtectedBranchRules, error) {
	var rules ProtectedBranchRules
	if err := db.GetEngine(ctx).Where(ruleScopeCond(orgID, groupID)).Asc("created_unix").Find(&rules); err != nil {
		return nil, err
	}
	rules.sort()
	return rules, nil
}

// GetOrgProtectedBranchRuleByName returns the organization or project rule with this name, or nil.
func GetOrgProtectedBranchRuleByName(ctx context.Context, orgID, groupID int64, ruleName string) (*ProtectedBranch, error) {
	cond := ruleScopeCond(orgID, groupID)
	cond["branch_name"] = ruleName
	rule, exist, err := db.Get[ProtectedBranch](ctx, cond)
	if err != nil || !exist {
		return nil, err
	}
	return rule, nil
}

// GetOrgProtectedBranchRuleByID returns the organization or project rule with this ID, or nil if that level has none.
func GetOrgProtectedBranchRuleByID(ctx context.Context, orgID, groupID, id int64) (*ProtectedBranch, error) {
	cond := ruleScopeCond(orgID, groupID)
	cond["id"] = id
	rule, exist, err := db.Get[ProtectedBranch](ctx, cond)
	if err != nil || !exist {
		return nil, err
	}
	return rule, nil
}

// GetOrgProtectedBranchRuleRepoIDs returns the selected repositories of an organization rule.
func GetOrgProtectedBranchRuleRepoIDs(ctx context.Context, ruleID int64) ([]int64, error) {
	ids := []int64{}
	return ids, db.GetEngine(ctx).Table("protected_branch_repo").Where("protected_branch_id = ?", ruleID).Asc("repo_id").Cols("repo_id").Find(&ids)
}

// UpdateOrgProtectBranch saves an organization rule (groupID 0) or a rule of the organization's project groupID,
// inserting it if its ID is 0, with the allow-lists and approval rules of opts and the selected repositories
// repoIDs. Users must be members of the organization, teams and repositories must belong to it, and deploy keys are
// not supported. A project rule covers its whole project, so it has no selected repositories.
func UpdateOrgProtectBranch(ctx context.Context, orgID, groupID int64, protectBranch *ProtectedBranch, opts WhitelistOptions, repoIDs []int64) error {
	if protectBranch.WhitelistDeployKeys || len(opts.DeployKeyIDs)+len(opts.DeleteDeployKeyIDs)+len(opts.ForcePushDeployKeyIDs) > 0 {
		return util.NewInvalidArgumentErrorf("organization rules can't allow deploy keys")
	}
	if groupID != 0 && (protectBranch.ApplyToSelectedRepos || len(repoIDs) > 0) {
		return util.NewInvalidArgumentErrorf("project rules apply to every repository of the project")
	}
	for _, ids := range [][]int64{opts.UserIDs, opts.MergeUserIDs, opts.ApprovalsUserIDs, opts.DeleteUserIDs, opts.ForcePushUserIDs} {
		if err := checkOrgMembers(ctx, orgID, ids); err != nil {
			return err
		}
	}
	for _, ids := range [][]int64{opts.TeamIDs, opts.MergeTeamIDs, opts.ApprovalsTeamIDs, opts.DeleteTeamIDs, opts.ForcePushTeamIDs} {
		if err := checkOrgOwns(ctx, "team", "org_id", orgID, ids); err != nil {
			return err
		}
	}
	if err := checkOrgOwns(ctx, "repository", "owner_id", orgID, repoIDs); err != nil {
		return err
	}

	protectBranch.RepoID, protectBranch.OrgID, protectBranch.GroupID = 0, orgID, groupID
	protectBranch.WhitelistUserIDs, protectBranch.WhitelistTeamIDs = opts.UserIDs, opts.TeamIDs
	protectBranch.MergeWhitelistUserIDs, protectBranch.MergeWhitelistTeamIDs = opts.MergeUserIDs, opts.MergeTeamIDs
	protectBranch.ApprovalsWhitelistUserIDs, protectBranch.ApprovalsWhitelistTeamIDs = opts.ApprovalsUserIDs, opts.ApprovalsTeamIDs
	protectBranch.DeleteAllowlistUserIDs, protectBranch.DeleteAllowlistTeamIDs = opts.DeleteUserIDs, opts.DeleteTeamIDs
	protectBranch.ForcePushAllowlistUserIDs, protectBranch.ForcePushAllowlistTeamIDs = opts.ForcePushUserIDs, opts.ForcePushTeamIDs
	protectBranch.WhitelistDeployKeyIDs, protectBranch.DeleteAllowlistDeployKeyIDs, protectBranch.ForcePushAllowlistDeployKeyIDs = nil, nil, nil

	return db.WithTx(ctx, func(ctx context.Context) error {
		// the project row stays locked until the end, so a concurrent DeleteRepoGroup deletes this rule or runs first
		if groupID != 0 {
			if _, err := repo_model.LockRepoGroup(ctx, orgID, groupID); err != nil {
				return err
			}
		}
		var before map[string]any
		if protectBranch.ID == 0 {
			if _, err := db.GetEngine(ctx).Insert(protectBranch); err != nil {
				return fmt.Errorf("Insert: %w", err)
			}
		} else {
			var err error
			if before, err = storedBranchRule(ctx, protectBranch.ID); err != nil {
				return err
			}
			cond := ruleScopeCond(orgID, groupID)
			cond["id"] = protectBranch.ID
			if n, err := db.GetEngine(ctx).Where(cond).AllCols().Update(protectBranch); err != nil {
				return fmt.Errorf("Update: %w", err)
			} else if n != 1 {
				return util.NewNotExistErrorf("organization rule %d does not exist", protectBranch.ID)
			}
		}

		if _, err := db.GetEngine(ctx).Where("protected_branch_id = ?", protectBranch.ID).Delete(new(ProtectedBranchRepo)); err != nil {
			return err
		}
		for _, repoID := range container.SetOf(repoIDs...).Values() {
			if _, err := db.GetEngine(ctx).Insert(&ProtectedBranchRepo{ProtectedBranchID: protectBranch.ID, RepoID: repoID}); err != nil {
				return err
			}
		}

		if opts.ApprovalRules != nil {
			if err := setApprovalRules(ctx, protectBranch.ID, opts.ApprovalRules, func(r *ApprovalRule) error {
				if err := checkOrgMembers(ctx, orgID, r.UserIDs); err != nil {
					return err
				}
				return checkOrgOwns(ctx, "team", "org_id", orgID, r.TeamIDs)
			}); err != nil {
				return err
			}
		}
		return recordBranchRule(ctx, nil, protectBranch, before)
	})
}

func checkOrgMembers(ctx context.Context, orgID int64, userIDs []int64) error {
	for _, id := range userIDs {
		if member, err := organization.IsOrganizationMember(ctx, orgID, id); err != nil {
			return err
		} else if !member {
			return util.NewInvalidArgumentErrorf("user %d is not a member of the organization", id)
		}
	}
	return nil
}

// checkOrgOwns checks that every ID of ids is a row of table whose ownerCol is orgID.
func checkOrgOwns(ctx context.Context, table, ownerCol string, orgID int64, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	set := container.SetOf(ids...)
	n, err := db.GetEngine(ctx).Table(table).Where(builder.Eq{ownerCol: orgID}.And(builder.In("id", set.Values()))).Count()
	if err != nil {
		return err
	}
	if n != int64(len(set)) {
		return util.NewInvalidArgumentErrorf("every %s must belong to the organization", table)
	}
	return nil
}

// DeleteOrgProtectedBranch deletes an organization or project rule with its approval rules and selected repositories.
func DeleteOrgProtectedBranch(ctx context.Context, orgID, groupID, id int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		cond := ruleScopeCond(orgID, groupID)
		cond["id"] = id
		rule := new(ProtectedBranch)
		if has, err := db.GetEngine(ctx).Where(cond).Get(rule); err != nil {
			return err
		} else if has {
			if err := recordBranchRuleEvent(ctx, "repo.branch_protection.deleted", "org.branch_protection.deleted", nil, rule, map[string]any{"rule_name": rule.RuleName}); err != nil {
				return err
			}
		}
		if n, err := db.GetEngine(ctx).Where(cond).Delete(new(ProtectedBranch)); err != nil {
			return err
		} else if n != 1 {
			return util.NewNotExistErrorf("organization rule %d does not exist", id)
		}
		return deleteRuleChildren(ctx, builder.Eq{"protected_branch_id": id})
	})
}

// DeleteOrgProtectedBranches deletes every rule of a deleted organization, those of its projects included.
func DeleteOrgProtectedBranches(ctx context.Context, orgID int64) error {
	cond := builder.Eq{"repo_id": 0, "org_id": orgID}
	if err := deleteRuleChildren(ctx, builder.In("protected_branch_id", builder.Select("id").From("protected_branch").Where(cond))); err != nil {
		return err
	}
	_, err := db.GetEngine(ctx).Where(cond).Delete(new(ProtectedBranch))
	return err
}

func deleteRuleChildren(ctx context.Context, cond builder.Cond) error {
	if _, err := db.GetEngine(ctx).Where(cond).Delete(new(ApprovalRule)); err != nil {
		return err
	}
	_, err := db.GetEngine(ctx).Where(cond).Delete(new(ProtectedBranchRepo))
	return err
}

// orphanedProtectedBranchesCond matches repository rules whose repository is gone, organization rules whose
// organization is gone and project rules whose project is gone or isn't the organization's.
func orphanedProtectedBranchesCond() builder.Cond {
	return builder.And(builder.Neq{"repo_id": 0}, builder.NotIn("repo_id", builder.Select("id").From("repository"))).
		Or(builder.And(builder.Eq{"repo_id": 0}, builder.NotIn("org_id",
			builder.Select("id").From("`user`").Where(builder.Eq{"type": user_model.UserTypeOrganization})))).
		Or(builder.And(builder.Eq{"repo_id": 0}, builder.Neq{"group_id": 0}, builder.NotIn("group_id",
			builder.Select("id").From("repo_group").Where(builder.Expr("repo_group.owner_id = protected_branch.org_id")))))
}

// CountOrphanedProtectedBranches counts the rules DeleteOrphanedProtectedBranches deletes.
func CountOrphanedProtectedBranches(ctx context.Context) (int64, error) {
	return db.GetEngine(ctx).Where(orphanedProtectedBranchesCond()).Count(new(ProtectedBranch))
}

// DeleteOrphanedProtectedBranches deletes the rules whose repository or organization is gone, with their approval rules and selected repositories.
func DeleteOrphanedProtectedBranches(ctx context.Context) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		ids := []int64{}
		if err := db.GetEngine(ctx).Table("protected_branch").Where(orphanedProtectedBranchesCond()).Cols("id").Find(&ids); err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		if err := deleteRuleChildren(ctx, builder.In("protected_branch_id", ids)); err != nil {
			return err
		}
		_, err := db.GetEngine(ctx).In("id", ids).Delete(new(ProtectedBranch))
		return err
	})
}
