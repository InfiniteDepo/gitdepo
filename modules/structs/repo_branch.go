// Copyright 2016 The Gogs Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package structs

import (
	"time"
)

// ApprovalRule is a named approval requirement of a branch protection. All applicable rules must be satisfied to merge.
type ApprovalRule struct {
	// Name of the rule, unique within the branch protection
	Name string `json:"name"`
	// RequiredCount is the number of approvals needed, at least 1; 0 is allowed only with RequestReviews
	RequiredCount int64 `json:"required_count"`
	// Usernames of the users who can approve. Teams are the teams (of the owning organization) whose members can approve.
	// Both may be empty only with RequireCodeOwners, then any user with write access can approve.
	Usernames []string `json:"usernames"`
	Teams     []string `json:"teams"`
	// PathPatterns are globs separated by semicolons; the rule applies only if the pull request changes a matching file.
	// `*` does not match `/`, use `**`. Empty applies to every pull request.
	PathPatterns string `json:"path_patterns"`
	// RequireCodeOwners also requires that for every changed file with owners in CODEOWNERS of the target branch, one of its owners approved
	RequireCodeOwners bool `json:"require_code_owners"`
	// RequestReviews asks the users and teams of the rule for a review when a pull request opens, is retargeted or starts to change a file matching PathPatterns
	RequestReviews bool `json:"request_reviews"`
	// SourceBranchPattern is one glob (`*` does not match `/`) for the head branch of the pull request, empty for any. It only limits who is asked for a review, never the required count.
	SourceBranchPattern string `json:"source_branch_pattern"`
}

// Branch represents a repository branch
type Branch struct {
	Name                          string         `json:"name"`
	Commit                        *PayloadCommit `json:"commit"`
	Protected                     bool           `json:"protected"`
	RequiredApprovals             int64          `json:"required_approvals"`
	EnableStatusCheck             bool           `json:"enable_status_check"`
	StatusCheckContexts           []string       `json:"status_check_contexts"`
	UserCanPush                   bool           `json:"user_can_push"`
	UserCanMerge                  bool           `json:"user_can_merge"`
	EffectiveBranchProtectionName string         `json:"effective_branch_protection_name"`
}

// BranchProtection represents a branch protection for a repository
type BranchProtection struct {
	// Deprecated: true
	BranchName              string   `json:"branch_name"`
	RuleName                string   `json:"rule_name"`
	EnablePush              bool     `json:"enable_push"`
	EnablePushWhitelist     bool     `json:"enable_push_whitelist"`
	PushWhitelistUsernames  []string `json:"push_whitelist_usernames"`
	PushWhitelistTeams      []string `json:"push_whitelist_teams"`
	PushWhitelistDeployKeys bool     `json:"push_whitelist_deploy_keys"`
	// Public key IDs (`key_id` of a deploy key) of the deploy keys allowed to push. IDs which are not
	// write deploy keys of the repository are ignored.
	PushWhitelistDeployKeyIDs     []int64  `json:"push_whitelist_deploy_key_ids"`
	EnableMergeWhitelist          bool     `json:"enable_merge_whitelist"`
	MergeWhitelistUsernames       []string `json:"merge_whitelist_usernames"`
	MergeWhitelistTeams           []string `json:"merge_whitelist_teams"`
	EnableStatusCheck             bool     `json:"enable_status_check"`
	StatusCheckContexts           []string `json:"status_check_contexts"`
	RequiredApprovals             int64    `json:"required_approvals"`
	EnableApprovalsWhitelist      bool     `json:"enable_approvals_whitelist"`
	ApprovalsWhitelistUsernames   []string `json:"approvals_whitelist_username"`
	ApprovalsWhitelistTeams       []string `json:"approvals_whitelist_teams"`
	BlockOnRejectedReviews        bool     `json:"block_on_rejected_reviews"`
	BlockOnOfficialReviewRequests bool     `json:"block_on_official_review_requests"`
	BlockOnOutdatedBranch         bool     `json:"block_on_outdated_branch"`
	DismissStaleApprovals         bool     `json:"dismiss_stale_approvals"`
	IgnoreStaleApprovals          bool     `json:"ignore_stale_approvals"`
	RequireSignedCommits          bool     `json:"require_signed_commits"`
	ProtectedFilePatterns         string   `json:"protected_file_patterns"`
	UnprotectedFilePatterns       string   `json:"unprotected_file_patterns"`
	ApplyToAdmins                 bool     `json:"apply_to_admins"`

	// Do not count approvals of users who pushed to the pull request: commit authors and committers, and whoever pushed to its head branch (Update branch and web edits included). Applies to required approvals, approval rules and code owners.
	IgnorePusherApprovals bool `json:"ignore_pusher_approvals"`

	// Block merging while code review conversations are unresolved, optionally not counting outdated ones.
	BlockOnUnresolvedConversations bool `json:"block_on_unresolved_conversations"`
	IgnoreOutdatedConversations    bool `json:"ignore_outdated_conversations"`
	// Block merging while tasks of the pull request are open.
	BlockOnIncompleteTasks bool `json:"block_on_incomplete_tasks"`

	// Merge pull requests into matching branches only through a merge queue, which tests each one on top of the
	// branch and the pull requests ahead of it. The other settings are used only while it is set; 0 means the default.
	RequireMergeQueue bool `json:"require_merge_queue"`
	// merge style of every pull request in the queue; empty: the one chosen when adding
	// enum: ["", "merge", "rebase", "rebase-merge", "squash"]
	MergeQueueMergeStyle string `json:"merge_queue_merge_style"`
	// pull requests tested at a time, 0 to 100 (default 5)
	MergeQueueBuildConcurrency int `json:"merge_queue_build_concurrency"`
	// passed pull requests to wait for before merging, 0 to 100 (default 1)
	MergeQueueMinGroupSize int `json:"merge_queue_min_group_size"`
	// pull requests merged at once, 0 to 100 (default 5)
	MergeQueueMaxGroupSize int `json:"merge_queue_max_group_size"`
	// longest wait for the minimum group size, from when the first pull request was added, 0 to 1440 (default 5)
	MergeQueueWaitMinutes int `json:"merge_queue_wait_minutes"`
	// time the required checks may take on a test commit before the pull request leaves the queue, 0 to 1440 (default 60)
	MergeQueueCheckTimeoutMinutes int `json:"merge_queue_check_timeout_minutes"`

	// Users, teams and deploy keys (public key IDs) allowed to delete matching branches. Empty lists block everyone.
	// The default branch can never be deleted. IDs which are not write deploy keys of the repository are ignored.
	DeleteAllowlistUsernames    []string `json:"delete_allowlist_usernames"`
	DeleteAllowlistTeams        []string `json:"delete_allowlist_teams"`
	DeleteAllowlistDeployKeyIDs []int64  `json:"delete_allowlist_deploy_key_ids"`
	// Users, teams and deploy keys (public key IDs) allowed to force-push matching branches. Empty lists block everyone.
	// A force push must still pass the other checks of the rule. IDs which are not write deploy keys of the repository are ignored.
	ForcePushAllowlistUsernames    []string `json:"force_push_allowlist_usernames"`
	ForcePushAllowlistTeams        []string `json:"force_push_allowlist_teams"`
	ForcePushAllowlistDeployKeyIDs []int64  `json:"force_push_allowlist_deploy_key_ids"`
	// ApprovalRules are the named approval requirements.
	ApprovalRules []*ApprovalRule `json:"approval_rules"`
	// swagger:strfmt date-time
	Created time.Time `json:"created_at"`
	// swagger:strfmt date-time
	Updated time.Time `json:"updated_at"`
}

// CreateBranchProtectionOption options for creating a branch protection
type CreateBranchProtectionOption struct {
	// Deprecated: true
	BranchName              string   `json:"branch_name"`
	RuleName                string   `json:"rule_name"`
	EnablePush              bool     `json:"enable_push"`
	EnablePushWhitelist     bool     `json:"enable_push_whitelist"`
	PushWhitelistUsernames  []string `json:"push_whitelist_usernames"`
	PushWhitelistTeams      []string `json:"push_whitelist_teams"`
	PushWhitelistDeployKeys bool     `json:"push_whitelist_deploy_keys"`
	// Public key IDs (`key_id` of a deploy key) of the deploy keys allowed to push. IDs which are not
	// write deploy keys of the repository are ignored.
	PushWhitelistDeployKeyIDs     []int64  `json:"push_whitelist_deploy_key_ids"`
	EnableMergeWhitelist          bool     `json:"enable_merge_whitelist"`
	MergeWhitelistUsernames       []string `json:"merge_whitelist_usernames"`
	MergeWhitelistTeams           []string `json:"merge_whitelist_teams"`
	EnableStatusCheck             bool     `json:"enable_status_check"`
	StatusCheckContexts           []string `json:"status_check_contexts"`
	RequiredApprovals             int64    `json:"required_approvals"`
	EnableApprovalsWhitelist      bool     `json:"enable_approvals_whitelist"`
	ApprovalsWhitelistUsernames   []string `json:"approvals_whitelist_username"`
	ApprovalsWhitelistTeams       []string `json:"approvals_whitelist_teams"`
	BlockOnRejectedReviews        bool     `json:"block_on_rejected_reviews"`
	BlockOnOfficialReviewRequests bool     `json:"block_on_official_review_requests"`
	BlockOnOutdatedBranch         bool     `json:"block_on_outdated_branch"`
	DismissStaleApprovals         bool     `json:"dismiss_stale_approvals"`
	IgnoreStaleApprovals          bool     `json:"ignore_stale_approvals"`
	RequireSignedCommits          bool     `json:"require_signed_commits"`
	ProtectedFilePatterns         string   `json:"protected_file_patterns"`
	UnprotectedFilePatterns       string   `json:"unprotected_file_patterns"`
	ApplyToAdmins                 bool     `json:"apply_to_admins"`

	// Do not count approvals of users who pushed to the pull request: commit authors and committers, and whoever pushed to its head branch (Update branch and web edits included). Applies to required approvals, approval rules and code owners.
	IgnorePusherApprovals bool `json:"ignore_pusher_approvals"`

	// Block merging while code review conversations are unresolved, optionally not counting outdated ones.
	BlockOnUnresolvedConversations bool `json:"block_on_unresolved_conversations"`
	IgnoreOutdatedConversations    bool `json:"ignore_outdated_conversations"`
	// Block merging while tasks of the pull request are open.
	BlockOnIncompleteTasks bool `json:"block_on_incomplete_tasks"`

	// Merge pull requests into matching branches only through a merge queue, which tests each one on top of the
	// branch and the pull requests ahead of it. The other settings are used only while it is set; 0 means the default.
	RequireMergeQueue bool `json:"require_merge_queue"`
	// merge style of every pull request in the queue; empty: the one chosen when adding
	// enum: ["", "merge", "rebase", "rebase-merge", "squash"]
	MergeQueueMergeStyle string `json:"merge_queue_merge_style"`
	// pull requests tested at a time, 0 to 100 (default 5)
	MergeQueueBuildConcurrency int `json:"merge_queue_build_concurrency"`
	// passed pull requests to wait for before merging, 0 to 100 (default 1)
	MergeQueueMinGroupSize int `json:"merge_queue_min_group_size"`
	// pull requests merged at once, 0 to 100 (default 5)
	MergeQueueMaxGroupSize int `json:"merge_queue_max_group_size"`
	// longest wait for the minimum group size, from when the first pull request was added, 0 to 1440 (default 5)
	MergeQueueWaitMinutes int `json:"merge_queue_wait_minutes"`
	// time the required checks may take on a test commit before the pull request leaves the queue, 0 to 1440 (default 60)
	MergeQueueCheckTimeoutMinutes int `json:"merge_queue_check_timeout_minutes"`

	// Users, teams and deploy keys (public key IDs) allowed to delete matching branches. Empty lists block everyone.
	// The default branch can never be deleted. IDs which are not write deploy keys of the repository are ignored.
	DeleteAllowlistUsernames    []string `json:"delete_allowlist_usernames"`
	DeleteAllowlistTeams        []string `json:"delete_allowlist_teams"`
	DeleteAllowlistDeployKeyIDs []int64  `json:"delete_allowlist_deploy_key_ids"`
	// Users, teams and deploy keys (public key IDs) allowed to force-push matching branches. Empty lists block everyone.
	// A force push must still pass the other checks of the rule. IDs which are not write deploy keys of the repository are ignored.
	ForcePushAllowlistUsernames    []string `json:"force_push_allowlist_usernames"`
	ForcePushAllowlistTeams        []string `json:"force_push_allowlist_teams"`
	ForcePushAllowlistDeployKeyIDs []int64  `json:"force_push_allowlist_deploy_key_ids"`
	// ApprovalRules are the named approval requirements. On edit, null keeps them and an empty list removes them. At most 20.
	ApprovalRules []*ApprovalRule `json:"approval_rules"`
}

// EditBranchProtectionOption options for editing a branch protection
type EditBranchProtectionOption struct {
	EnablePush              *bool    `json:"enable_push"`
	EnablePushWhitelist     *bool    `json:"enable_push_whitelist"`
	PushWhitelistUsernames  []string `json:"push_whitelist_usernames"`
	PushWhitelistTeams      []string `json:"push_whitelist_teams"`
	PushWhitelistDeployKeys *bool    `json:"push_whitelist_deploy_keys"`
	// Public key IDs (`key_id` of a deploy key) of the deploy keys allowed to push. IDs which are not
	// write deploy keys of the repository are ignored.
	PushWhitelistDeployKeyIDs     []int64  `json:"push_whitelist_deploy_key_ids"`
	EnableMergeWhitelist          *bool    `json:"enable_merge_whitelist"`
	MergeWhitelistUsernames       []string `json:"merge_whitelist_usernames"`
	MergeWhitelistTeams           []string `json:"merge_whitelist_teams"`
	EnableStatusCheck             *bool    `json:"enable_status_check"`
	StatusCheckContexts           []string `json:"status_check_contexts"`
	RequiredApprovals             *int64   `json:"required_approvals"`
	EnableApprovalsWhitelist      *bool    `json:"enable_approvals_whitelist"`
	ApprovalsWhitelistUsernames   []string `json:"approvals_whitelist_username"`
	ApprovalsWhitelistTeams       []string `json:"approvals_whitelist_teams"`
	BlockOnRejectedReviews        *bool    `json:"block_on_rejected_reviews"`
	BlockOnOfficialReviewRequests *bool    `json:"block_on_official_review_requests"`
	BlockOnOutdatedBranch         *bool    `json:"block_on_outdated_branch"`
	DismissStaleApprovals         *bool    `json:"dismiss_stale_approvals"`
	IgnoreStaleApprovals          *bool    `json:"ignore_stale_approvals"`
	IgnorePusherApprovals         *bool    `json:"ignore_pusher_approvals"`
	RequireSignedCommits          *bool    `json:"require_signed_commits"`
	ProtectedFilePatterns         *string  `json:"protected_file_patterns"`
	UnprotectedFilePatterns       *string  `json:"unprotected_file_patterns"`
	ApplyToAdmins                 *bool    `json:"apply_to_admins"`

	// Block merging while code review conversations are unresolved, optionally not counting outdated ones.
	BlockOnUnresolvedConversations *bool `json:"block_on_unresolved_conversations"`
	IgnoreOutdatedConversations    *bool `json:"ignore_outdated_conversations"`
	// Block merging while tasks of the pull request are open.
	BlockOnIncompleteTasks *bool `json:"block_on_incomplete_tasks"`

	// see BranchProtection
	RequireMergeQueue             *bool   `json:"require_merge_queue"`
	MergeQueueMergeStyle          *string `json:"merge_queue_merge_style"`
	MergeQueueBuildConcurrency    *int    `json:"merge_queue_build_concurrency"`
	MergeQueueMinGroupSize        *int    `json:"merge_queue_min_group_size"`
	MergeQueueMaxGroupSize        *int    `json:"merge_queue_max_group_size"`
	MergeQueueWaitMinutes         *int    `json:"merge_queue_wait_minutes"`
	MergeQueueCheckTimeoutMinutes *int    `json:"merge_queue_check_timeout_minutes"`

	// Users, teams and deploy keys (public key IDs) allowed to delete matching branches. Empty lists block everyone.
	// The default branch can never be deleted. IDs which are not write deploy keys of the repository are ignored.
	DeleteAllowlistUsernames    []string `json:"delete_allowlist_usernames"`
	DeleteAllowlistTeams        []string `json:"delete_allowlist_teams"`
	DeleteAllowlistDeployKeyIDs []int64  `json:"delete_allowlist_deploy_key_ids"`
	// Users, teams and deploy keys (public key IDs) allowed to force-push matching branches. Empty lists block everyone.
	// A force push must still pass the other checks of the rule. IDs which are not write deploy keys of the repository are ignored.
	ForcePushAllowlistUsernames    []string `json:"force_push_allowlist_usernames"`
	ForcePushAllowlistTeams        []string `json:"force_push_allowlist_teams"`
	ForcePushAllowlistDeployKeyIDs []int64  `json:"force_push_allowlist_deploy_key_ids"`
	// ApprovalRules are the named approval requirements. On edit, null keeps them and an empty list removes them. At most 20.
	ApprovalRules []*ApprovalRule `json:"approval_rules"`
}

// OrgBranchProtection represents a branch protection rule of an organization. It applies to the
// repositories of the organization in addition to their own rules.
type OrgBranchProtection struct {
	BranchProtection
	// Apply the rule to the repositories in `repos` only, instead of all repositories of the organization
	ApplyToSelectedRepos bool `json:"apply_to_selected_repos"`
	// Names of the selected repositories
	Repos []string `json:"repos"`
}

// CreateOrgBranchProtectionOption options for creating a branch protection rule of an organization.
// Deploy keys are not supported.
type CreateOrgBranchProtectionOption struct {
	CreateBranchProtectionOption
	ApplyToSelectedRepos bool     `json:"apply_to_selected_repos"`
	Repos                []string `json:"repos"`
}

// EditOrgBranchProtectionOption options for editing a branch protection rule of an organization.
// Only fields that are set are changed.
type EditOrgBranchProtectionOption struct {
	EditBranchProtectionOption
	ApplyToSelectedRepos *bool    `json:"apply_to_selected_repos"`
	Repos                []string `json:"repos"`
}
