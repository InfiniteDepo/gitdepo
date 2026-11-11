// Copyright 2022 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package git

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	asymkey_model "forgejo.org/models/asymkey"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	linearglob "forgejo.org/modules/glob"
	"forgejo.org/modules/log"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"github.com/gobwas/glob"
	"github.com/gobwas/glob/syntax"
	"xorm.io/builder"
)

var ErrBranchIsProtected = errors.New("branch is protected")

// ProtectedBranch struct
type ProtectedBranch struct {
	ID                            int64                  `xorm:"pk autoincr"`
	RepoID                        int64                  `xorm:"UNIQUE(s)"`                          // 0 for organization rules
	OrgID                         int64                  `xorm:"UNIQUE(s) INDEX NOT NULL DEFAULT 0"` // set for organization and project rules only
	GroupID                       int64                  `xorm:"UNIQUE(s) NOT NULL DEFAULT 0"`       // set for project rules only
	Repo                          *repo_model.Repository `xorm:"-"`
	RuleName                      string                 `xorm:"'branch_name' UNIQUE(s)"` // a branch name or a glob match to branch name
	globRule                      *regexp.Regexp         `xorm:"-"`
	isPlainName                   bool                   `xorm:"-"`
	CanPush                       bool                   `xorm:"NOT NULL DEFAULT false"`
	EnableWhitelist               bool
	WhitelistUserIDs              []int64  `xorm:"JSON TEXT"`
	WhitelistTeamIDs              []int64  `xorm:"JSON TEXT"`
	EnableMergeWhitelist          bool     `xorm:"NOT NULL DEFAULT false"`
	WhitelistDeployKeys           bool     `xorm:"NOT NULL DEFAULT false"`
	WhitelistDeployKeyIDs         []int64  `xorm:"JSON TEXT"` // public key IDs of the deploy keys allowed to push
	MergeWhitelistUserIDs         []int64  `xorm:"JSON TEXT"`
	MergeWhitelistTeamIDs         []int64  `xorm:"JSON TEXT"`
	EnableStatusCheck             bool     `xorm:"NOT NULL DEFAULT false"`
	StatusCheckContexts           []string `xorm:"JSON TEXT"`
	EnableApprovalsWhitelist      bool     `xorm:"NOT NULL DEFAULT false"`
	ApprovalsWhitelistUserIDs     []int64  `xorm:"JSON TEXT"`
	ApprovalsWhitelistTeamIDs     []int64  `xorm:"JSON TEXT"`
	RequiredApprovals             int64    `xorm:"NOT NULL DEFAULT 0"`
	BlockOnRejectedReviews        bool     `xorm:"NOT NULL DEFAULT false"`
	BlockOnOfficialReviewRequests bool     `xorm:"NOT NULL DEFAULT false"`
	BlockOnOutdatedBranch         bool     `xorm:"NOT NULL DEFAULT false"`
	DismissStaleApprovals         bool     `xorm:"NOT NULL DEFAULT false"`
	IgnoreStaleApprovals          bool     `xorm:"NOT NULL DEFAULT false"`
	IgnorePusherApprovals         bool     `xorm:"NOT NULL DEFAULT false"`
	RequireSignedCommits          bool     `xorm:"NOT NULL DEFAULT false"`
	ProtectedFilePatterns         string   `xorm:"TEXT"`
	UnprotectedFilePatterns       string   `xorm:"TEXT"`
	ApplyToAdmins                 bool     `xorm:"NOT NULL DEFAULT false"`

	// Block merging while code review conversations are unresolved, optionally not counting outdated ones.
	BlockOnUnresolvedConversations bool `xorm:"NOT NULL DEFAULT false"`
	IgnoreOutdatedConversations    bool `xorm:"NOT NULL DEFAULT false"`
	// Block merging while tasks of the pull request are open.
	BlockOnIncompleteTasks bool `xorm:"NOT NULL DEFAULT false"`

	// Users, teams and deploy keys (public key IDs) allowed to delete or force-push matching branches.
	// Empty lists block everyone.
	DeleteAllowlistUserIDs         []int64 `xorm:"JSON TEXT"`
	DeleteAllowlistTeamIDs         []int64 `xorm:"JSON TEXT"`
	DeleteAllowlistDeployKeyIDs    []int64 `xorm:"JSON TEXT"`
	ForcePushAllowlistUserIDs      []int64 `xorm:"JSON TEXT"`
	ForcePushAllowlistTeamIDs      []int64 `xorm:"JSON TEXT"`
	ForcePushAllowlistDeployKeyIDs []int64 `xorm:"JSON TEXT"`

	// Organization rules only: apply to the repositories in protected_branch_repo instead of all repositories of the organization.
	ApplyToSelectedRepos bool `xorm:"NOT NULL DEFAULT false"`

	// Merges go through the merge queue, which tests each pull request combined with the ones ahead of it.
	// A zero number means its default, see MergeQueueConfig.
	RequireMergeQueue             bool   `xorm:"NOT NULL DEFAULT false"`
	MergeQueueBuildConcurrency    int    `xorm:"NOT NULL DEFAULT 0"`
	MergeQueueMinGroupSize        int    `xorm:"NOT NULL DEFAULT 0"`
	MergeQueueMaxGroupSize        int    `xorm:"NOT NULL DEFAULT 0"`
	MergeQueueWaitMinutes         int    `xorm:"NOT NULL DEFAULT 0"`
	MergeQueueCheckTimeoutMinutes int    `xorm:"NOT NULL DEFAULT 0"`
	MergeQueueMergeStyle          string `xorm:"VARCHAR(30) NOT NULL DEFAULT ''"` // "" = the style chosen for the pull request

	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

// ProtectedBranchRepo is a repository an organization rule with ApplyToSelectedRepos applies to.
type ProtectedBranchRepo struct {
	ID                int64 `xorm:"pk autoincr"`
	ProtectedBranchID int64 `xorm:"UNIQUE(s) INDEX NOT NULL"`
	RepoID            int64 `xorm:"UNIQUE(s) INDEX NOT NULL"`
}

func init() {
	db.RegisterModel(new(ProtectedBranch))
	db.RegisterModel(new(ProtectedBranchRepo))
}

// IsRuleNameSpecial return true if it contains special character
func IsRuleNameSpecial(ruleName string) bool {
	for i := 0; i < len(ruleName); i++ {
		if syntax.Special(ruleName[i]) {
			return true
		}
	}
	return false
}

func (protectBranch *ProtectedBranch) loadGlob() {
	if protectBranch.isPlainName || protectBranch.globRule != nil {
		return
	}
	// detect if it is not glob
	if !IsRuleNameSpecial(protectBranch.RuleName) {
		protectBranch.isPlainName = true
		return
	}
	// now we load the glob
	var err error
	protectBranch.globRule, err = linearglob.CompileExact(protectBranch.RuleName, '/')
	if err != nil {
		log.Warn("Invalid glob rule for ProtectedBranch[%d]: %s %v", protectBranch.ID, protectBranch.RuleName, err)
		protectBranch.globRule = regexp.MustCompile(`\A` + regexp.QuoteMeta(protectBranch.RuleName) + `\z`)
	}
}

// Match tests if branchName matches the rule
func (protectBranch *ProtectedBranch) Match(branchName string) bool {
	protectBranch.loadGlob()
	if protectBranch.isPlainName {
		return strings.EqualFold(protectBranch.RuleName, branchName)
	}

	return protectBranch.globRule.MatchString(branchName)
}

func (protectBranch *ProtectedBranch) LoadRepo(ctx context.Context) (err error) {
	if protectBranch.Repo != nil {
		return nil
	}
	if protectBranch.RepoID == 0 {
		return fmt.Errorf("organization rule %d has no repository loaded", protectBranch.ID)
	}
	protectBranch.Repo, err = repo_model.GetRepositoryByID(ctx, protectBranch.RepoID)
	return err
}

// CanUserPush returns if some user could push to this protected branch
func (protectBranch *ProtectedBranch) CanUserPush(ctx context.Context, user *user_model.User) bool {
	if !protectBranch.CanPush {
		return false
	}

	if !protectBranch.EnableWhitelist {
		if err := protectBranch.LoadRepo(ctx); err != nil {
			log.Error("LoadRepo: %v", err)
			return false
		}

		writeAccess, err := access_model.HasAccessUnit(ctx, user, protectBranch.Repo, unit.TypeCode, perm.AccessModeWrite)
		if err != nil {
			log.Error("HasAccessUnit: %v", err)
			return false
		}
		return writeAccess
	}

	if slices.Contains(protectBranch.WhitelistUserIDs, user.ID) {
		return true
	}

	if len(protectBranch.WhitelistTeamIDs) == 0 {
		return false
	}

	in, err := organization.IsUserInTeams(ctx, user.ID, protectBranch.WhitelistTeamIDs)
	if err != nil {
		log.Error("IsUserInTeams: %v", err)
		return false
	}
	return in
}

// CanDeployKeyPush returns if the deploy key with the given public key ID could push to this protected branch.
// The caller must check that the deploy key has write access to the repository.
func (protectBranch *ProtectedBranch) CanDeployKeyPush(keyID int64) bool {
	if !protectBranch.CanPush {
		return false
	}

	if !protectBranch.EnableWhitelist {
		return true
	}

	return protectBranch.WhitelistDeployKeys || slices.Contains(protectBranch.WhitelistDeployKeyIDs, keyID)
}

// CanUserDelete returns if the user is in the delete allow-list of this protected branch.
// The caller must check that the user has write access to the repository.
func (protectBranch *ProtectedBranch) CanUserDelete(ctx context.Context, user *user_model.User) bool {
	return isUserInAllowlist(ctx, user, protectBranch.DeleteAllowlistUserIDs, protectBranch.DeleteAllowlistTeamIDs)
}

// CanUserForcePush returns if the user is in the force push allow-list of this protected branch.
// The caller must still check that the user may push to the branch.
func (protectBranch *ProtectedBranch) CanUserForcePush(ctx context.Context, user *user_model.User) bool {
	return isUserInAllowlist(ctx, user, protectBranch.ForcePushAllowlistUserIDs, protectBranch.ForcePushAllowlistTeamIDs)
}

// CanDeployKeyDelete returns if the deploy key with the given public key ID may delete this protected branch.
// The caller must check that the deploy key has write access to the repository.
func (protectBranch *ProtectedBranch) CanDeployKeyDelete(keyID int64) bool {
	return slices.Contains(protectBranch.DeleteAllowlistDeployKeyIDs, keyID)
}

// CanDeployKeyForcePush returns if the deploy key with the given public key ID may force-push this protected branch.
// The caller must still check that the deploy key may push to the branch.
func (protectBranch *ProtectedBranch) CanDeployKeyForcePush(keyID int64) bool {
	return slices.Contains(protectBranch.ForcePushAllowlistDeployKeyIDs, keyID)
}

func isUserInAllowlist(ctx context.Context, user *user_model.User, userIDs, teamIDs []int64) bool {
	if slices.Contains(userIDs, user.ID) {
		return true
	}
	if len(teamIDs) == 0 {
		return false
	}
	in, err := organization.IsUserInTeams(ctx, user.ID, teamIDs)
	if err != nil {
		log.Error("IsUserInTeams: %v", err)
		return false
	}
	return in
}

// IsAdminExempt returns whether user may skip the rule because it doesn't apply to admins:
// repository admins for a repository rule, organization owners for an organization rule.
func (protectBranch *ProtectedBranch) IsAdminExempt(ctx context.Context, user *user_model.User, isRepoAdmin bool) (bool, error) {
	if protectBranch.ApplyToAdmins || user == nil {
		return false, nil
	}
	if protectBranch.OrgID == 0 {
		return isRepoAdmin, nil
	}
	org, err := organization.GetOrgByID(ctx, protectBranch.OrgID)
	if err != nil {
		return false, err
	}
	return org.IsActingOwner(ctx, user)
}

// IsUserMergeWhitelisted checks if some user is whitelisted to merge to this branch
func IsUserMergeWhitelisted(ctx context.Context, protectBranch *ProtectedBranch, userID int64, permissionInRepo access_model.Permission) bool {
	if !protectBranch.EnableMergeWhitelist {
		// Then we need to fall back on whether the user has write permission
		return permissionInRepo.CanWrite(unit.TypeCode)
	}

	if slices.Contains(protectBranch.MergeWhitelistUserIDs, userID) {
		return true
	}

	if len(protectBranch.MergeWhitelistTeamIDs) == 0 {
		return false
	}

	in, err := organization.IsUserInTeams(ctx, userID, protectBranch.MergeWhitelistTeamIDs)
	if err != nil {
		log.Error("IsUserInTeams: %v", err)
		return false
	}
	return in
}

// IsUserOfficialReviewer check if user is official reviewer for the branch (counts towards required approvals)
func IsUserOfficialReviewer(ctx context.Context, protectBranch *ProtectedBranch, user *user_model.User) (bool, error) {
	if err := protectBranch.LoadRepo(ctx); err != nil {
		return false, err
	}

	if !protectBranch.EnableApprovalsWhitelist {
		// Anyone with write access is considered official reviewer, for an organization rule only members of the organization
		writeAccess, err := access_model.HasAccessUnit(ctx, user, protectBranch.Repo, unit.TypeCode, perm.AccessModeWrite)
		if err != nil || !writeAccess || protectBranch.OrgID == 0 {
			return writeAccess, err
		}
		return organization.IsOrganizationMember(ctx, protectBranch.OrgID, user.ID)
	}

	if slices.Contains(protectBranch.ApprovalsWhitelistUserIDs, user.ID) {
		return true, nil
	}

	inTeam, err := organization.IsUserInTeams(ctx, user.ID, protectBranch.ApprovalsWhitelistTeamIDs)
	if err != nil {
		return false, err
	}

	return inTeam, nil
}

// GetProtectedFilePatterns parses a semicolon separated list of protected file patterns and returns a glob.Glob slice
func (protectBranch *ProtectedBranch) GetProtectedFilePatterns() []glob.Glob {
	return getFilePatterns(protectBranch.ProtectedFilePatterns)
}

// GetUnprotectedFilePatterns parses a semicolon separated list of unprotected file patterns and returns a glob.Glob slice
func (protectBranch *ProtectedBranch) GetUnprotectedFilePatterns() []glob.Glob {
	return getFilePatterns(protectBranch.UnprotectedFilePatterns)
}

func getFilePatterns(filePatterns string) []glob.Glob {
	extarr := make([]glob.Glob, 0, 10)
	for expr := range strings.SplitSeq(strings.ToLower(filePatterns), ";") {
		expr = strings.TrimSpace(expr)
		if expr != "" {
			if g, err := glob.Compile(expr, '.', '/'); err != nil {
				log.Info("Invalid glob expression '%s' (skipped): %v", expr, err)
			} else {
				extarr = append(extarr, g)
			}
		}
	}
	return extarr
}

// ChangedProtectedFiles returns the files of changedFiles that this rule protects.
func (protectBranch *ProtectedBranch) ChangedProtectedFiles(changedFiles []string) []string {
	patterns := protectBranch.GetProtectedFilePatterns()
	if len(patterns) == 0 {
		return nil
	}
	return slices.DeleteFunc(slices.Clone(changedFiles), func(file string) bool { return !protectBranch.IsProtectedFile(patterns, file) })
}

// MergeBlockedByProtectedFiles returns true if merge is blocked by protected files change
func (protectBranch *ProtectedBranch) MergeBlockedByProtectedFiles(changedProtectedFiles []string) bool {
	glob := protectBranch.GetProtectedFilePatterns()
	if len(glob) == 0 {
		return false
	}

	return len(changedProtectedFiles) > 0
}

// IsProtectedFile return if path is protected
func (protectBranch *ProtectedBranch) IsProtectedFile(patterns []glob.Glob, path string) bool {
	if len(patterns) == 0 {
		patterns = protectBranch.GetProtectedFilePatterns()
		if len(patterns) == 0 {
			return false
		}
	}

	lpath := strings.ToLower(strings.TrimSpace(path))

	r := false
	for _, pat := range patterns {
		if pat.Match(lpath) {
			r = true
			break
		}
	}

	return r
}

// IsUnprotectedFile return if path is unprotected
func (protectBranch *ProtectedBranch) IsUnprotectedFile(patterns []glob.Glob, path string) bool {
	if len(patterns) == 0 {
		patterns = protectBranch.GetUnprotectedFilePatterns()
		if len(patterns) == 0 {
			return false
		}
	}

	lpath := strings.ToLower(strings.TrimSpace(path))

	r := false
	for _, pat := range patterns {
		if pat.Match(lpath) {
			r = true
			break
		}
	}

	return r
}

// GetProtectedBranchRuleByName getting protected branch rule by name
func GetProtectedBranchRuleByName(ctx context.Context, repoID int64, ruleName string) (*ProtectedBranch, error) {
	// branch_name is legacy name, it actually is rule name
	rel, exist, err := db.Get[ProtectedBranch](ctx, builder.Eq{"repo_id": repoID, "branch_name": ruleName})
	if err != nil {
		return nil, err
	} else if !exist {
		return nil, nil
	}
	return rel, nil
}

// GetProtectedBranchRuleByID getting protected branch rule by rule ID
func GetProtectedBranchRuleByID(ctx context.Context, repoID, ruleID int64) (*ProtectedBranch, error) {
	rel, exist, err := db.Get[ProtectedBranch](ctx, builder.Eq{"repo_id": repoID, "id": ruleID})
	if err != nil {
		return nil, err
	} else if !exist {
		return nil, nil
	}
	return rel, nil
}

// WhitelistOptions represent all sorts of whitelists used for protected branches
type WhitelistOptions struct {
	UserIDs      []int64
	TeamIDs      []int64
	DeployKeyIDs []int64

	MergeUserIDs []int64
	MergeTeamIDs []int64

	ApprovalsUserIDs []int64
	ApprovalsTeamIDs []int64

	DeleteUserIDs      []int64
	DeleteTeamIDs      []int64
	DeleteDeployKeyIDs []int64

	ForcePushUserIDs      []int64
	ForcePushTeamIDs      []int64
	ForcePushDeployKeyIDs []int64

	// ApprovalRules replace the approval rules, nil keeps them
	ApprovalRules []*ApprovalRule
}

// UpdateProtectBranch saves branch protection options of repository.
// If ID is 0, it creates a new record. Otherwise, updates existing record.
// This function also performs check if whitelist user and team's IDs have been changed
// to avoid unnecessary whitelist delete and regenerate.
func UpdateProtectBranch(ctx context.Context, repo *repo_model.Repository, protectBranch *ProtectedBranch, opts WhitelistOptions) (err error) {
	err = repo.MustNotBeArchived()
	if err != nil {
		return err
	}

	if err = repo.LoadOwner(ctx); err != nil {
		return fmt.Errorf("LoadOwner: %v", err)
	}

	whitelist, err := updateUserWhitelist(ctx, repo, protectBranch.WhitelistUserIDs, opts.UserIDs)
	if err != nil {
		return err
	}
	protectBranch.WhitelistUserIDs = whitelist

	whitelist, err = updateUserWhitelist(ctx, repo, protectBranch.MergeWhitelistUserIDs, opts.MergeUserIDs)
	if err != nil {
		return err
	}
	protectBranch.MergeWhitelistUserIDs = whitelist

	whitelist, err = updateApprovalWhitelist(ctx, repo, protectBranch.ApprovalsWhitelistUserIDs, opts.ApprovalsUserIDs)
	if err != nil {
		return err
	}
	protectBranch.ApprovalsWhitelistUserIDs = whitelist

	// if the repo is in an organization
	whitelist, err = updateTeamWhitelist(ctx, repo, protectBranch.WhitelistTeamIDs, opts.TeamIDs)
	if err != nil {
		return err
	}
	protectBranch.WhitelistTeamIDs = whitelist

	whitelist, err = updateTeamWhitelist(ctx, repo, protectBranch.MergeWhitelistTeamIDs, opts.MergeTeamIDs)
	if err != nil {
		return err
	}
	protectBranch.MergeWhitelistTeamIDs = whitelist

	whitelist, err = updateTeamWhitelist(ctx, repo, protectBranch.ApprovalsWhitelistTeamIDs, opts.ApprovalsTeamIDs)
	if err != nil {
		return err
	}
	protectBranch.ApprovalsWhitelistTeamIDs = whitelist

	whitelist, err = updateDeployKeyWhitelist(ctx, repo, protectBranch.WhitelistDeployKeyIDs, opts.DeployKeyIDs)
	if err != nil {
		return err
	}
	protectBranch.WhitelistDeployKeyIDs = whitelist

	if protectBranch.DeleteAllowlistUserIDs, err = updateUserWhitelist(ctx, repo, protectBranch.DeleteAllowlistUserIDs, opts.DeleteUserIDs); err != nil {
		return err
	}
	if protectBranch.DeleteAllowlistTeamIDs, err = updateTeamWhitelist(ctx, repo, protectBranch.DeleteAllowlistTeamIDs, opts.DeleteTeamIDs); err != nil {
		return err
	}
	if protectBranch.DeleteAllowlistDeployKeyIDs, err = updateDeployKeyWhitelist(ctx, repo, protectBranch.DeleteAllowlistDeployKeyIDs, opts.DeleteDeployKeyIDs); err != nil {
		return err
	}
	if protectBranch.ForcePushAllowlistUserIDs, err = updateUserWhitelist(ctx, repo, protectBranch.ForcePushAllowlistUserIDs, opts.ForcePushUserIDs); err != nil {
		return err
	}
	if protectBranch.ForcePushAllowlistTeamIDs, err = updateTeamWhitelist(ctx, repo, protectBranch.ForcePushAllowlistTeamIDs, opts.ForcePushTeamIDs); err != nil {
		return err
	}
	if protectBranch.ForcePushAllowlistDeployKeyIDs, err = updateDeployKeyWhitelist(ctx, repo, protectBranch.ForcePushAllowlistDeployKeyIDs, opts.ForcePushDeployKeyIDs); err != nil {
		return err
	}

	return db.WithTx(ctx, func(ctx context.Context) error {
		var before map[string]any
		// Make sure protectBranch.ID is not 0 for whitelists
		if protectBranch.ID == 0 {
			if _, err = db.GetEngine(ctx).Insert(protectBranch); err != nil {
				return fmt.Errorf("Insert: %v", err)
			}
		} else {
			if before, err = storedBranchRule(ctx, protectBranch.ID); err != nil {
				return err
			}
			if _, err = db.GetEngine(ctx).ID(protectBranch.ID).AllCols().Update(protectBranch); err != nil {
				return fmt.Errorf("Update: %v", err)
			}
		}

		if opts.ApprovalRules != nil {
			if err := SetApprovalRules(ctx, repo, protectBranch.ID, opts.ApprovalRules); err != nil {
				return err
			}
		}
		return recordBranchRule(ctx, repo, protectBranch, before)
	})
}

// updateApprovalWhitelist checks whether the user whitelist changed and returns a whitelist with
// the users from newWhitelist which have explicit read or write access to the repo.
func updateApprovalWhitelist(ctx context.Context, repo *repo_model.Repository, currentWhitelist, newWhitelist []int64) (whitelist []int64, err error) {
	hasUsersChanged := !util.SliceSortedEqual(currentWhitelist, newWhitelist)
	if !hasUsersChanged {
		return currentWhitelist, nil
	}

	whitelist = make([]int64, 0, len(newWhitelist))
	for _, userID := range newWhitelist {
		if reader, err := access_model.IsRepoReader(ctx, repo, userID); err != nil {
			return nil, err
		} else if !reader {
			continue
		}
		whitelist = append(whitelist, userID)
	}

	return whitelist, err
}

// updateUserWhitelist checks whether the user whitelist changed and returns a whitelist with
// the users from newWhitelist which have write access to the repo.
func updateUserWhitelist(ctx context.Context, repo *repo_model.Repository, currentWhitelist, newWhitelist []int64) (whitelist []int64, err error) {
	hasUsersChanged := !util.SliceSortedEqual(currentWhitelist, newWhitelist)
	if !hasUsersChanged {
		return currentWhitelist, nil
	}

	whitelist = make([]int64, 0, len(newWhitelist))
	for _, userID := range newWhitelist {
		getUser := user_model.GetUserByID
		if user_model.IsAccessTokenBotID(userID) { // a token of an organization, a project or the repository
			getUser = user_model.GetAccessTokenBot
		}
		user, err := getUser(ctx, userID)
		if user_model.IsAccessTokenBotID(userID) && user_model.IsErrUserNotExist(err) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("GetUserByID [user_id: %d, repo_id: %d]: %v", userID, repo.ID, err)
		}
		perm, err := access_model.GetUserRepoPermission(ctx, repo, user)
		if err != nil {
			return nil, fmt.Errorf("GetUserRepoPermission [user_id: %d, repo_id: %d]: %v", userID, repo.ID, err)
		}

		if !perm.CanWrite(unit.TypeCode) {
			continue // Drop invalid user ID
		}

		whitelist = append(whitelist, userID)
	}

	return whitelist, err
}

// updateTeamWhitelist checks whether the team whitelist changed and returns a whitelist with
// the teams from newWhitelist which have write access to the repo.
func updateTeamWhitelist(ctx context.Context, repo *repo_model.Repository, currentWhitelist, newWhitelist []int64) (whitelist []int64, err error) {
	hasTeamsChanged := !util.SliceSortedEqual(currentWhitelist, newWhitelist)
	if !hasTeamsChanged {
		return currentWhitelist, nil
	}

	teams, err := organization.GetTeamsWithAccessToRepo(ctx, repo.OwnerID, repo.ID, perm.AccessModeRead)
	if err != nil {
		return nil, fmt.Errorf("GetTeamsWithAccessToRepo [org_id: %d, repo_id: %d]: %v", repo.OwnerID, repo.ID, err)
	}

	whitelist = make([]int64, 0, len(teams))
	for i := range teams {
		if slices.Contains(newWhitelist, teams[i].ID) {
			whitelist = append(whitelist, teams[i].ID)
		}
	}

	return whitelist, err
}

// updateDeployKeyWhitelist checks whether the deploy key whitelist changed and returns a whitelist with
// the public key IDs from newWhitelist which belong to a write deploy key of the repo.
func updateDeployKeyWhitelist(ctx context.Context, repo *repo_model.Repository, currentWhitelist, newWhitelist []int64) (whitelist []int64, err error) {
	hasKeysChanged := !util.SliceSortedEqual(currentWhitelist, newWhitelist)
	if !hasKeysChanged {
		return currentWhitelist, nil
	}

	return FilterWriteDeployKeyIDs(ctx, repo, newWhitelist)
}

// FilterWriteDeployKeyIDs returns the public key IDs from keyIDs which belong to a deploy key
// of the repository, or an organization deploy key covering it, with write access.
func FilterWriteDeployKeyIDs(ctx context.Context, repo *repo_model.Repository, keyIDs []int64) ([]int64, error) {
	filtered := make([]int64, 0, len(keyIDs))
	if len(keyIDs) == 0 {
		return filtered, nil
	}

	keys, err := db.Find[asymkey_model.DeployKey](ctx, asymkey_model.ListDeployKeysOptions{
		ListOptions: db.ListOptionsAll,
		RepoID:      repo.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("ListDeployKeys [repo_id: %d]: %w", repo.ID, err)
	}
	orgKeys, err := asymkey_model.FindOrgDeployKeysCoveringRepo(ctx, repo)
	if err != nil {
		return nil, err
	}

	add := func(mode perm.AccessMode, keyID int64) {
		if mode >= perm.AccessModeWrite && slices.Contains(keyIDs, keyID) && !slices.Contains(filtered, keyID) {
			filtered = append(filtered, keyID)
		}
	}
	for _, key := range keys {
		add(key.Mode, key.KeyID)
	}
	for _, key := range orgKeys {
		add(key.Mode, key.KeyID)
	}

	return filtered, nil
}

// DeleteProtectedBranch removes ProtectedBranch relation between the user and repository.
func DeleteProtectedBranch(ctx context.Context, repo *repo_model.Repository, id int64) (err error) {
	err = repo.MustNotBeArchived()
	if err != nil {
		return err
	}

	return db.WithTx(ctx, func(ctx context.Context) error {
		protectedBranch := &ProtectedBranch{}
		if has, err := db.GetEngine(ctx).Where("id = ? AND repo_id = ?", id, repo.ID).Get(protectedBranch); err != nil {
			return err
		} else if !has {
			return fmt.Errorf("delete protected branch ID(%v) failed", id)
		}
		if err := recordBranchRuleEvent(ctx, "repo.branch_protection.deleted", "org.branch_protection.deleted", repo, protectedBranch, map[string]any{"rule_name": protectedBranch.RuleName}); err != nil {
			return err
		}

		if affected, err := db.GetEngine(ctx).Delete(&ProtectedBranch{RepoID: repo.ID, ID: id}); err != nil {
			return err
		} else if affected != 1 {
			return fmt.Errorf("delete protected branch ID(%v) failed", id)
		}

		_, err := db.GetEngine(ctx).Where("protected_branch_id = ?", id).Delete(new(ApprovalRule))
		return err
	})
}

// RemoveUserIDFromProtectedBranch remove all user ids from protected branch options
func RemoveUserIDFromProtectedBranch(ctx context.Context, p *ProtectedBranch, userID int64) error {
	if removeFromLists(userID, &p.WhitelistUserIDs, &p.ApprovalsWhitelistUserIDs, &p.MergeWhitelistUserIDs,
		&p.DeleteAllowlistUserIDs, &p.ForcePushAllowlistUserIDs) {
		if _, err := db.GetEngine(ctx).ID(p.ID).Cols(
			"whitelist_user_i_ds",
			"merge_whitelist_user_i_ds",
			"approvals_whitelist_user_i_ds",
			"delete_allowlist_user_i_ds",
			"force_push_allowlist_user_i_ds",
		).Update(p); err != nil {
			return fmt.Errorf("updateProtectedBranches: %v", err)
		}
	}
	return nil
}

// RemoveTeamIDFromProtectedBranch remove all team ids from protected branch options
func RemoveTeamIDFromProtectedBranch(ctx context.Context, p *ProtectedBranch, teamID int64) error {
	if removeFromLists(teamID, &p.WhitelistTeamIDs, &p.ApprovalsWhitelistTeamIDs, &p.MergeWhitelistTeamIDs,
		&p.DeleteAllowlistTeamIDs, &p.ForcePushAllowlistTeamIDs) {
		if _, err := db.GetEngine(ctx).ID(p.ID).Cols(
			"whitelist_team_i_ds",
			"merge_whitelist_team_i_ds",
			"approvals_whitelist_team_i_ds",
			"delete_allowlist_team_i_ds",
			"force_push_allowlist_team_i_ds",
		).Update(p); err != nil {
			return fmt.Errorf("updateProtectedBranches: %v", err)
		}
	}
	return nil
}

// removeFromLists removes id from each list and reports whether any list changed.
func removeFromLists(id int64, lists ...*[]int64) bool {
	changed := false
	for _, list := range lists {
		n := len(*list)
		*list = util.SliceRemoveAll(*list, id)
		changed = changed || n != len(*list)
	}
	return changed
}

// DropDeployKeyIDsNotWriting removes from the protection rules of the repository the public key IDs that no longer
// belong to a deploy key with write access to it (its own, or one of its owner covering it).
func DropDeployKeyIDsNotWriting(ctx context.Context, repo *repo_model.Repository, keyIDs []int64) error {
	still, err := FilterWriteDeployKeyIDs(ctx, repo, keyIDs)
	if err != nil {
		return err
	}
	for _, keyID := range keyIDs {
		if !slices.Contains(still, keyID) {
			if err := RemoveDeployKeyIDFromProtectionRules(ctx, repo.ID, keyID); err != nil {
				return err
			}
		}
	}
	return nil
}

// DropDeployKeyIDFromOwnerRepos runs DropDeployKeyIDsNotWriting on every repository of the owner with protection
// rules, those in the trash included: they come back with their rules when restored.
func DropDeployKeyIDFromOwnerRepos(ctx context.Context, ownerID, keyID int64) error {
	repos := make([]*repo_model.Repository, 0, 10)
	if err := db.GetEngine(ctx).Where("owner_id = ?", ownerID).And(builder.Or(
		builder.In("id", builder.Select("repo_id").From("protected_branch")),
		builder.In("id", builder.Select("repo_id").From("protected_tag")),
	)).Find(&repos); err != nil {
		return err
	}
	for _, repo := range repos {
		if err := DropDeployKeyIDsNotWriting(ctx, repo, []int64{keyID}); err != nil {
			return err
		}
	}
	return nil
}

// RemoveDeployKeyIDFromProtectionRules removes the public key ID of a deleted deploy key
// from the branch and tag protection rules of the repository.
func RemoveDeployKeyIDFromProtectionRules(ctx context.Context, repoID, keyID int64) error {
	branches, err := FindRepoProtectedBranchRules(ctx, repoID)
	if err != nil {
		return err
	}
	for _, p := range branches {
		if !removeFromLists(keyID, &p.WhitelistDeployKeyIDs, &p.DeleteAllowlistDeployKeyIDs, &p.ForcePushAllowlistDeployKeyIDs) {
			continue
		}
		if _, err := db.GetEngine(ctx).ID(p.ID).Cols(
			"whitelist_deploy_key_i_ds",
			"delete_allowlist_deploy_key_i_ds",
			"force_push_allowlist_deploy_key_i_ds",
		).Update(p); err != nil {
			return fmt.Errorf("update protected branch: %w", err)
		}
	}

	tags, err := GetProtectedTags(ctx, repoID)
	if err != nil {
		return err
	}
	for _, pt := range tags {
		if !slices.Contains(pt.AllowlistDeployKeyIDs, keyID) {
			continue
		}
		pt.AllowlistDeployKeyIDs = util.SliceRemoveAll(pt.AllowlistDeployKeyIDs, keyID)
		if _, err := db.GetEngine(ctx).ID(pt.ID).Cols("allowlist_deploy_key_i_ds").Update(pt); err != nil {
			return fmt.Errorf("update protected tag: %w", err)
		}
	}
	return nil
}
