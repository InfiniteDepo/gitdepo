// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"context"
	"fmt"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/util"
)

func ids(s []int64) []int64 {
	if s == nil {
		return []int64{}
	}
	return s
}

// AuditFields are the settings the audit log keeps before/after for a branch rule.
func (protectBranch *ProtectedBranch) AuditFields() map[string]any {
	contexts := protectBranch.StatusCheckContexts
	if contexts == nil {
		contexts = []string{}
	}
	return map[string]any{
		"rule_name": protectBranch.RuleName, "can_push": protectBranch.CanPush, "enable_whitelist": protectBranch.EnableWhitelist,
		"whitelist_user_ids": ids(protectBranch.WhitelistUserIDs), "whitelist_team_ids": ids(protectBranch.WhitelistTeamIDs),
		"enable_merge_whitelist": protectBranch.EnableMergeWhitelist, "whitelist_deploy_keys": protectBranch.WhitelistDeployKeys,
		"whitelist_deploy_key_ids": ids(protectBranch.WhitelistDeployKeyIDs), "merge_whitelist_user_ids": ids(protectBranch.MergeWhitelistUserIDs),
		"merge_whitelist_team_ids": ids(protectBranch.MergeWhitelistTeamIDs), "enable_status_check": protectBranch.EnableStatusCheck,
		"status_check_contexts": contexts, "enable_approvals_whitelist": protectBranch.EnableApprovalsWhitelist,
		"approvals_whitelist_user_ids": ids(protectBranch.ApprovalsWhitelistUserIDs), "approvals_whitelist_team_ids": ids(protectBranch.ApprovalsWhitelistTeamIDs),
		"required_approvals": protectBranch.RequiredApprovals, "block_on_rejected_reviews": protectBranch.BlockOnRejectedReviews,
		"block_on_official_review_requests": protectBranch.BlockOnOfficialReviewRequests, "block_on_outdated_branch": protectBranch.BlockOnOutdatedBranch,
		"dismiss_stale_approvals": protectBranch.DismissStaleApprovals, "ignore_stale_approvals": protectBranch.IgnoreStaleApprovals,
		"ignore_pusher_approvals": protectBranch.IgnorePusherApprovals,
		"require_signed_commits":  protectBranch.RequireSignedCommits, "protected_file_patterns": protectBranch.ProtectedFilePatterns,
		"unprotected_file_patterns": protectBranch.UnprotectedFilePatterns, "apply_to_admins": protectBranch.ApplyToAdmins,
		"block_on_unresolved_conversations": protectBranch.BlockOnUnresolvedConversations, "ignore_outdated_conversations": protectBranch.IgnoreOutdatedConversations,
		"block_on_incomplete_tasks": protectBranch.BlockOnIncompleteTasks, "delete_allowlist_user_ids": ids(protectBranch.DeleteAllowlistUserIDs),
		"delete_allowlist_team_ids": ids(protectBranch.DeleteAllowlistTeamIDs), "delete_allowlist_deploy_key_ids": ids(protectBranch.DeleteAllowlistDeployKeyIDs),
		"force_push_allowlist_user_ids": ids(protectBranch.ForcePushAllowlistUserIDs), "force_push_allowlist_team_ids": ids(protectBranch.ForcePushAllowlistTeamIDs),
		"force_push_allowlist_deploy_key_ids": ids(protectBranch.ForcePushAllowlistDeployKeyIDs), "apply_to_selected_repos": protectBranch.ApplyToSelectedRepos,
		"require_merge_queue": protectBranch.RequireMergeQueue, "merge_queue_merge_style": protectBranch.MergeQueueMergeStyle,
		"merge_queue_build_concurrency": protectBranch.MergeQueueBuildConcurrency, "merge_queue_min_group_size": protectBranch.MergeQueueMinGroupSize,
		"merge_queue_max_group_size": protectBranch.MergeQueueMaxGroupSize, "merge_queue_wait_minutes": protectBranch.MergeQueueWaitMinutes,
		"merge_queue_check_timeout_minutes": protectBranch.MergeQueueCheckTimeoutMinutes,
	}
}

// storedBranchRule is the stored state of rule id for the audit log, with its approval rules (name:required count)
// and, for an organization rule, its selected repositories.
func storedBranchRule(ctx context.Context, id int64) (map[string]any, error) {
	pb := new(ProtectedBranch)
	if has, err := db.GetEngine(ctx).ID(id).Get(pb); err != nil {
		return nil, err
	} else if !has {
		return nil, util.NewNotExistErrorf("branch rule %d does not exist", id)
	}
	fields := pb.AuditFields()
	rules, err := GetApprovalRules(ctx, id)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		name := fmt.Sprintf("%s:%d", r.Name, r.RequiredCount)
		if r.RequestReviews {
			name += fmt.Sprintf(":requests:%q", r.SourceBranchPattern)
		}
		names = append(names, name)
	}
	fields["approval_rules"] = names
	if pb.OrgID != 0 {
		if fields["repo_ids"], err = GetOrgProtectedBranchRuleRepoIDs(ctx, id); err != nil {
			return nil, err
		}
	}
	return fields, nil
}

// recordBranchRule records the save of pb, whose stored state before the write was before (nil: created), with the
// fields that differ; nothing when none does. Call it after the write, in its transaction.
func recordBranchRule(ctx context.Context, repo *repo_model.Repository, pb *ProtectedBranch, before map[string]any) error {
	after, err := storedBranchRule(ctx, pb.ID)
	if err != nil {
		return err
	}
	if before == nil {
		return recordBranchRuleEvent(ctx, "repo.branch_protection.created", "org.branch_protection.created", repo, pb, after)
	}
	if changes := audit_model.Changes(before, after); changes != nil {
		return recordBranchRuleEvent(ctx, "repo.branch_protection.updated", "org.branch_protection.updated", repo, pb, changes)
	}
	return nil
}

// recordBranchRuleEvent records repoAction for a rule of repo, or orgAction for an organization or project rule (repo
// nil).
func recordBranchRuleEvent(ctx context.Context, repoAction, orgAction string, repo *repo_model.Repository, pb *ProtectedBranch, data map[string]any) error {
	ev := audit_model.Event{TargetType: "branch_protection", TargetID: pb.ID, TargetName: pb.RuleName, Data: data}
	if repo != nil {
		ev.Action = repoAction
		return repo_model.RecordRepoTarget(ctx, repo, ev)
	}
	ev.Action, ev.Result, ev.OwnerID, ev.GroupID = orgAction, audit_model.ResultSuccess, pb.OrgID, pb.GroupID
	return audit_model.Record(ctx, ev)
}

// AuditFields are the settings the audit log keeps before/after for a tag rule.
func (pt *ProtectedTag) AuditFields() map[string]any {
	return map[string]any{
		"name_pattern": pt.NamePattern, "allowlist_user_ids": ids(pt.AllowlistUserIDs),
		"allowlist_team_ids": ids(pt.AllowlistTeamIDs), "allowlist_deploy_key_ids": ids(pt.AllowlistDeployKeyIDs),
	}
}

// AuditFields are the settings the audit log keeps before/after for a push rule (patterns are settings, not secrets).
func (r *PushRule) AuditFields() map[string]any {
	return map[string]any{
		"commit_message_regex": r.CommitMessageRegex, "commit_message_banned_regex": r.CommitMessageBannedRegex,
		"branch_name_regex": r.BranchNameRegex, "require_verified_author_email": r.RequireVerifiedAuthorEmail,
		"max_file_size_mb": r.MaxFileSizeMB, "banned_file_patterns": r.BannedFilePatterns, "pr_title_regex": r.PRTitleRegex,
		"pr_title_banned_regex": r.PRTitleBannedRegex, "pr_title_message": r.PRTitleMessage,
		"pr_title_branches": r.PRTitleBranches, "pr_title_block_merge": r.PRTitleBlockMerge,
	}
}

// recordRepoRule records action about a tag or push rule of the repository repoID.
func recordRepoRule(ctx context.Context, action string, repoID int64, ev audit_model.Event) error {
	repo, err := repo_model.GetRepositoryByID(ctx, repoID)
	if err != nil {
		return err
	}
	ev.Action = action
	return repo_model.RecordRepoTarget(ctx, repo, ev)
}

// recordProtectedTag records action about pt with data.
func recordProtectedTag(ctx context.Context, action string, pt *ProtectedTag, data map[string]any) error {
	return recordRepoRule(ctx, action, pt.RepoID, audit_model.Event{
		TargetType: "tag_protection", TargetID: pt.ID, TargetName: pt.NamePattern, Data: data,
	})
}
