// Copyright 2017 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	asymkey_model "forgejo.org/models/asymkey"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/routers/web/repo"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	"forgejo.org/services/forms"
	pull_service "forgejo.org/services/pull"
	"forgejo.org/services/repository"

	"github.com/gobwas/glob"
)

const (
	tplProtectedBranch base.TplName = "repo/settings/protected_branch"
)

// ProtectedBranchRules render the page to protect the repository
func ProtectedBranchRules(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("repo.settings.branches")
	ctx.Data["PageIsSettingsBranches"] = true

	rules, err := git_model.FindRepoProtectedBranchRules(ctx, ctx.Repo.Repository.ID)
	if err != nil {
		ctx.ServerError("GetProtectedBranches", err)
		return
	}
	ctx.Data["ProtectedBranches"] = rules

	// the organization rules that apply to the repository, shown read-only
	applying, err := git_model.FindProtectedBranchRulesForRepo(ctx, ctx.Repo.Repository)
	if err != nil {
		ctx.ServerError("FindProtectedBranchRulesForRepo", err)
		return
	}
	ctx.Data["OrgProtectedBranches"] = slices.DeleteFunc(applying, func(rule *git_model.ProtectedBranch) bool { return rule.OrgID == 0 })

	repo.PrepareBranchList(ctx)
	if ctx.Written() {
		return
	}

	ctx.HTML(http.StatusOK, tplBranches)
}

// SettingsProtectedBranch renders the protected branch setting page
func SettingsProtectedBranch(c *context.Context) {
	ruleName := c.FormString("rule_name")
	var rule *git_model.ProtectedBranch
	if ruleName != "" {
		var err error
		rule, err = git_model.GetProtectedBranchRuleByName(c, c.Repo.Repository.ID, ruleName)
		if err != nil {
			c.ServerError("GetProtectBranchOfRepoByName", err)
			return
		}
	}

	if rule == nil {
		// No options found, create defaults.
		rule = &git_model.ProtectedBranch{}
	}

	c.Data["PageIsSettingsBranches"] = true
	c.Data["Title"] = c.Locale.TrString("repo.settings.protected_branch") + " - " + rule.RuleName

	users, err := access_model.GetRepoReaders(c, c.Repo.Repository)
	if err != nil {
		c.ServerError("Repo.Repository.GetReaders", err)
		return
	}
	c.Data["Users"] = users
	c.Data["whitelist_users"] = joinIDs(user_model.WithoutTokenIDs(rule.WhitelistUserIDs))
	c.Data["merge_whitelist_users"] = strings.Join(base.Int64sToStrings(rule.MergeWhitelistUserIDs), ",")
	c.Data["approvals_whitelist_users"] = strings.Join(base.Int64sToStrings(rule.ApprovalsWhitelistUserIDs), ",")
	deployKeys, err := getWriteDeployKeys(c)
	if err != nil {
		c.ServerError("getWriteDeployKeys", err)
		return
	}
	c.Data["DeployKeys"] = deployKeys
	tokens, err := getWriteTokens(c)
	if err != nil {
		c.ServerError("getWriteTokens", err)
		return
	}
	c.Data["AllowlistTokens"] = tokens
	// the deploy key pickers also hold the tokens, which the rule stores as their identities' user IDs
	c.Data["whitelist_deploy_key_ids"] = joinIDs(append(slices.Clone(rule.WhitelistDeployKeyIDs), user_model.TokenIDsOnly(rule.WhitelistUserIDs)...))
	c.Data["delete_allowlist_users"] = joinIDs(user_model.WithoutTokenIDs(rule.DeleteAllowlistUserIDs))
	c.Data["delete_allowlist_deploy_key_ids"] = joinIDs(append(slices.Clone(rule.DeleteAllowlistDeployKeyIDs), user_model.TokenIDsOnly(rule.DeleteAllowlistUserIDs)...))
	c.Data["force_push_allowlist_users"] = joinIDs(user_model.WithoutTokenIDs(rule.ForcePushAllowlistUserIDs))
	c.Data["force_push_allowlist_deploy_key_ids"] = joinIDs(append(slices.Clone(rule.ForcePushAllowlistDeployKeyIDs), user_model.TokenIDsOnly(rule.ForcePushAllowlistUserIDs)...))
	c.Data["status_check_contexts"] = strings.Join(rule.StatusCheckContexts, "\n")
	contexts, _ := git_model.FindRepoRecentCommitStatusContexts(c, c.Repo.Repository.ID, 7*24*time.Hour) // Find last week status check contexts
	c.Data["recent_status_checks"] = contexts

	if c.Repo.Owner.IsOrganization() {
		teams, err := organization.OrgFromUser(c.Repo.Owner).TeamsWithAccessToRepo(c, c.Repo.Repository.ID, perm.AccessModeRead)
		if err != nil {
			c.ServerError("Repo.Owner.TeamsWithAccessToRepo", err)
			return
		}
		c.Data["Teams"] = teams
		c.Data["whitelist_teams"] = strings.Join(base.Int64sToStrings(rule.WhitelistTeamIDs), ",")
		c.Data["merge_whitelist_teams"] = strings.Join(base.Int64sToStrings(rule.MergeWhitelistTeamIDs), ",")
		c.Data["approvals_whitelist_teams"] = strings.Join(base.Int64sToStrings(rule.ApprovalsWhitelistTeamIDs), ",")
		c.Data["delete_allowlist_teams"] = strings.Join(base.Int64sToStrings(rule.DeleteAllowlistTeamIDs), ",")
		c.Data["force_push_allowlist_teams"] = strings.Join(base.Int64sToStrings(rule.ForcePushAllowlistTeamIDs), ",")
	}

	// the existing approval rules; the form adds new ones in the browser
	rows := []*api.ApprovalRule{}
	if rule.ID != 0 {
		rows = convert.ToBranchProtection(c, rule, c.Repo.Repository).ApprovalRules
		warnings, err := pull_service.BranchRuleWarnings(c, c.Repo.Repository, rule)
		if err != nil {
			c.ServerError("BranchRuleWarnings", err)
			return
		}
		c.Data["RuleWarnings"] = warnings
	}
	c.Data["ApprovalRules"] = rows
	c.Data["MaxApprovalRules"] = git_model.MaxApprovalRules

	c.Data["Rule"] = rule
	c.HTML(http.StatusOK, tplProtectedBranch)
}

// SettingsProtectedBranchPost updates the protected branch settings
func SettingsProtectedBranchPost(ctx *context.Context) {
	f := web.GetForm(ctx).(*forms.ProtectBranchForm)
	var protectBranch *git_model.ProtectedBranch
	if f.RuleName == "" {
		ctx.Flash.Error(ctx.Tr("repo.settings.protected_branch_required_rule_name"))
		ctx.Redirect(fmt.Sprintf("%s/settings/branches/edit", ctx.Repo.RepoLink))
		return
	}

	var err error
	if f.RuleID > 0 {
		// If the RuleID isn't 0, it must be an edit operation. So we get rule by id.
		protectBranch, err = git_model.GetProtectedBranchRuleByID(ctx, ctx.Repo.Repository.ID, f.RuleID)
		if err != nil {
			ctx.ServerError("GetProtectBranchOfRepoByID", err)
			return
		}
		if protectBranch != nil && protectBranch.RuleName != f.RuleName {
			// RuleName changed. We need to check if there is a rule with the same name.
			// If a rule with the same name exists, an error should be returned.
			sameNameProtectBranch, err := git_model.GetProtectedBranchRuleByName(ctx, ctx.Repo.Repository.ID, f.RuleName)
			if err != nil {
				ctx.ServerError("GetProtectBranchOfRepoByName", err)
				return
			}
			if sameNameProtectBranch != nil {
				ctx.Flash.Error(ctx.Tr("repo.settings.protected_branch_duplicate_rule_name"))
				ctx.Redirect(fmt.Sprintf("%s/settings/branches/edit?rule_name=%s", ctx.Repo.RepoLink, protectBranch.RuleName))
				return
			}
		}
	} else {
		// Check if a rule already exists with this rulename, if so redirect to it.
		protectBranch, err = git_model.GetProtectedBranchRuleByName(ctx, ctx.Repo.Repository.ID, f.RuleName)
		if err != nil {
			ctx.ServerError("GetProtectedBranchRuleByName", err)
			return
		}
		if protectBranch != nil {
			ctx.Flash.Error(ctx.Tr("repo.settings.protected_branch_duplicate_rule_name"))
			ctx.Redirect(fmt.Sprintf("%s/settings/branches/edit?rule_name=%s", ctx.Repo.RepoLink, protectBranch.RuleName))
			return
		}
	}
	if protectBranch == nil {
		// No options found, create defaults.
		protectBranch = &git_model.ProtectedBranch{
			RepoID:   ctx.Repo.Repository.ID,
			RuleName: f.RuleName,
		}
	}

	opts, errMsg := ProtectBranchFromForm(ctx, f, protectBranch, ctx.Repo.Owner)
	if errMsg != "" {
		ctx.Flash.Error(errMsg)
		ctx.Redirect(fmt.Sprintf("%s/settings/branches/edit?rule_name=%s", ctx.Repo.RepoLink, url.QueryEscape(f.RuleName)))
		return
	}
	err = git_model.UpdateProtectBranch(ctx, ctx.Repo.Repository, protectBranch, opts)
	if errors.Is(err, util.ErrInvalidArgument) {
		ctx.Flash.Error(ctx.Tr("repo.settings.approval_rules_invalid", err.Error()))
		ctx.Redirect(fmt.Sprintf("%s/settings/branches/edit?rule_name=%s", ctx.Repo.RepoLink, url.QueryEscape(protectBranch.RuleName)))
		return
	} else if err != nil {
		ctx.ServerError("UpdateProtectBranch", err)
		return
	}

	// FIXME: since we only need to recheck files protected rules, we could improve this
	matchedBranches, err := git_model.FindAllMatchedBranches(ctx, ctx.Repo.Repository.ID, protectBranch.RuleName)
	if err != nil {
		ctx.ServerError("FindAllMatchedBranches", err)
		return
	}
	for _, branchName := range matchedBranches {
		if err = pull_service.CheckPRsForBaseBranch(ctx, ctx.Repo.Repository, branchName); err != nil {
			ctx.ServerError("CheckPRsForBaseBranch", err)
			return
		}
	}

	ctx.Flash.Success(ctx.Tr("repo.settings.update_protect_branch_success", protectBranch.RuleName))
	ctx.Redirect(fmt.Sprintf("%s/settings/branches?rule_name=%s", ctx.Repo.RepoLink, protectBranch.RuleName))
}

// ProtectBranchFromForm sets the fields of protectBranch from the form and returns its allow-lists, teams and
// approval rules looked up in owner. It returns a message instead if the form is invalid.
func ProtectBranchFromForm(ctx *context.Context, f *forms.ProtectBranchForm, protectBranch *git_model.ProtectedBranch, owner *user_model.User) (opts git_model.WhitelistOptions, errMsg template.HTML) {
	var whitelistDeployKeys []int64
	var whitelistUsers, whitelistTeams, mergeWhitelistUsers, mergeWhitelistTeams, approvalsWhitelistUsers, approvalsWhitelistTeams []int64
	protectBranch.RuleName = f.RuleName
	if f.RequiredApprovals < 0 {
		return opts, ctx.Tr("repo.settings.protected_branch_required_approvals_min")
	}

	switch f.EnablePush {
	case "all":
		protectBranch.CanPush = true
		protectBranch.EnableWhitelist = false
		protectBranch.WhitelistDeployKeys = false
	case "whitelist":
		protectBranch.CanPush = true
		protectBranch.EnableWhitelist = true
		protectBranch.WhitelistDeployKeys = f.WhitelistDeployKeys
		if strings.TrimSpace(f.WhitelistUsers) != "" {
			whitelistUsers, _ = base.StringsToInt64s(strings.Split(f.WhitelistUsers, ","))
		}
		if strings.TrimSpace(f.WhitelistTeams) != "" {
			whitelistTeams, _ = base.StringsToInt64s(strings.Split(f.WhitelistTeams, ","))
		}
		if strings.TrimSpace(f.WhitelistDeployKeyIDs) != "" {
			whitelistDeployKeys, _ = base.StringsToInt64s(strings.Split(f.WhitelistDeployKeyIDs, ","))
		}
		pushTokens, err := writeTokenIDs(ctx, whitelistDeployKeys)
		if err != nil {
			return opts, ctx.Tr("error.occurred")
		}
		whitelistUsers = append(user_model.WithoutTokenIDs(whitelistUsers), pushTokens...)
		whitelistDeployKeys = keyIDsOnly(whitelistDeployKeys)
	default:
		protectBranch.CanPush = false
		protectBranch.EnableWhitelist = false
		protectBranch.WhitelistDeployKeys = false
	}

	protectBranch.EnableMergeWhitelist = f.EnableMergeWhitelist
	if f.EnableMergeWhitelist {
		if strings.TrimSpace(f.MergeWhitelistUsers) != "" {
			mergeWhitelistUsers, _ = base.StringsToInt64s(strings.Split(f.MergeWhitelistUsers, ","))
		}
		if strings.TrimSpace(f.MergeWhitelistTeams) != "" {
			mergeWhitelistTeams, _ = base.StringsToInt64s(strings.Split(f.MergeWhitelistTeams, ","))
		}
	}

	protectBranch.EnableStatusCheck = f.EnableStatusCheck
	if f.EnableStatusCheck {
		patterns := strings.Split(strings.ReplaceAll(f.StatusCheckContexts, "\r", "\n"), "\n")
		validPatterns := make([]string, 0, len(patterns))
		for _, pattern := range patterns {
			trimmed := strings.TrimSpace(pattern)
			if trimmed == "" {
				continue
			}
			if _, err := glob.Compile(trimmed); err != nil {
				return opts, ctx.Tr("repo.settings.protect_invalid_status_check_pattern", pattern)
			}
			validPatterns = append(validPatterns, trimmed)
		}
		if len(validPatterns) == 0 {
			// if status check is enabled, patterns slice is not allowed to be empty
			return opts, ctx.Tr("repo.settings.protect_no_valid_status_check_patterns")
		}
		protectBranch.StatusCheckContexts = validPatterns
	} else {
		protectBranch.StatusCheckContexts = nil
	}

	protectBranch.RequiredApprovals = f.RequiredApprovals
	protectBranch.EnableApprovalsWhitelist = f.EnableApprovalsWhitelist
	if f.EnableApprovalsWhitelist {
		if strings.TrimSpace(f.ApprovalsWhitelistUsers) != "" {
			approvalsWhitelistUsers, _ = base.StringsToInt64s(strings.Split(f.ApprovalsWhitelistUsers, ","))
		}
		if strings.TrimSpace(f.ApprovalsWhitelistTeams) != "" {
			approvalsWhitelistTeams, _ = base.StringsToInt64s(strings.Split(f.ApprovalsWhitelistTeams, ","))
		}
	}
	protectBranch.BlockOnRejectedReviews = f.BlockOnRejectedReviews
	protectBranch.BlockOnOfficialReviewRequests = f.BlockOnOfficialReviewRequests
	protectBranch.DismissStaleApprovals = f.DismissStaleApprovals
	protectBranch.IgnoreStaleApprovals = f.IgnoreStaleApprovals
	protectBranch.IgnorePusherApprovals = f.IgnorePusherApprovals
	protectBranch.RequireSignedCommits = f.RequireSignedCommits
	protectBranch.ProtectedFilePatterns = f.ProtectedFilePatterns
	protectBranch.UnprotectedFilePatterns = f.UnprotectedFilePatterns
	protectBranch.BlockOnOutdatedBranch = f.BlockOnOutdatedBranch
	protectBranch.BlockOnUnresolvedConversations = f.BlockOnUnresolvedConversations
	protectBranch.IgnoreOutdatedConversations = f.IgnoreOutdatedConversations
	protectBranch.BlockOnIncompleteTasks = f.BlockOnIncompleteTasks
	protectBranch.ApplyToAdmins = f.ApplyToAdmins
	protectBranch.RequireMergeQueue = f.RequireMergeQueue
	protectBranch.MergeQueueMergeStyle = f.MergeQueueMergeStyle
	protectBranch.MergeQueueBuildConcurrency = f.MergeQueueBuildConcurrency
	protectBranch.MergeQueueMinGroupSize = f.MergeQueueMinGroupSize
	protectBranch.MergeQueueMaxGroupSize = f.MergeQueueMaxGroupSize
	protectBranch.MergeQueueWaitMinutes = f.MergeQueueWaitMinutes
	protectBranch.MergeQueueCheckTimeoutMinutes = f.MergeQueueCheckTimeoutMinutes
	if cfgErr, ok := errors.AsType[*git_model.MergeQueueConfigError](protectBranch.ValidateMergeQueue()); ok {
		return opts, ctx.Tr("repo.settings.merge_queue.invalid." + cfgErr.Field)
	}

	approvalRules, err := approvalRulesFromForm(ctx, owner)
	if err != nil {
		return opts, ctx.Tr("repo.settings.approval_rules_invalid", err.Error())
	}

	deleteTokens, err := writeTokenIDs(ctx, parseIDList(f.DeleteAllowlistDeployKeyIDs))
	if err != nil {
		return opts, ctx.Tr("error.occurred")
	}
	forcePushTokens, err := writeTokenIDs(ctx, parseIDList(f.ForcePushAllowlistDeployKeyIDs))
	if err != nil {
		return opts, ctx.Tr("error.occurred")
	}

	return git_model.WhitelistOptions{
		ApprovalRules:    approvalRules,
		UserIDs:          whitelistUsers,
		TeamIDs:          whitelistTeams,
		DeployKeyIDs:     whitelistDeployKeys,
		MergeUserIDs:     mergeWhitelistUsers,
		MergeTeamIDs:     mergeWhitelistTeams,
		ApprovalsUserIDs: approvalsWhitelistUsers,
		ApprovalsTeamIDs: approvalsWhitelistTeams,

		DeleteUserIDs:         append(user_model.WithoutTokenIDs(parseIDList(f.DeleteAllowlistUsers)), deleteTokens...),
		DeleteTeamIDs:         parseIDList(f.DeleteAllowlistTeams),
		DeleteDeployKeyIDs:    keyIDsOnly(parseIDList(f.DeleteAllowlistDeployKeyIDs)),
		ForcePushUserIDs:      append(user_model.WithoutTokenIDs(parseIDList(f.ForcePushAllowlistUsers)), forcePushTokens...),
		ForcePushTeamIDs:      parseIDList(f.ForcePushAllowlistTeams),
		ForcePushDeployKeyIDs: keyIDsOnly(parseIDList(f.ForcePushAllowlistDeployKeyIDs)),
	}, ""
}

// DeleteProtectedBranchRulePost delete protected branch rule by id
func DeleteProtectedBranchRulePost(ctx *context.Context) {
	ruleID := ctx.ParamsInt64("id")
	if ruleID <= 0 {
		ctx.Flash.Error(ctx.Tr("repo.settings.remove_protected_branch_failed", fmt.Sprintf("%d", ruleID)))
		ctx.JSONRedirect(fmt.Sprintf("%s/settings/branches", ctx.Repo.RepoLink))
		return
	}

	rule, err := git_model.GetProtectedBranchRuleByID(ctx, ctx.Repo.Repository.ID, ruleID)
	if err != nil {
		ctx.Flash.Error(ctx.Tr("repo.settings.remove_protected_branch_failed", fmt.Sprintf("%d", ruleID)))
		ctx.JSONRedirect(fmt.Sprintf("%s/settings/branches", ctx.Repo.RepoLink))
		return
	}

	if rule == nil {
		ctx.Flash.Error(ctx.Tr("repo.settings.remove_protected_branch_failed", fmt.Sprintf("%d", ruleID)))
		ctx.JSONRedirect(fmt.Sprintf("%s/settings/branches", ctx.Repo.RepoLink))
		return
	}

	if err := git_model.DeleteProtectedBranch(ctx, ctx.Repo.Repository, ruleID); err != nil {
		ctx.Flash.Error(ctx.Tr("repo.settings.remove_protected_branch_failed", rule.RuleName))
		ctx.JSONRedirect(fmt.Sprintf("%s/settings/branches", ctx.Repo.RepoLink))
		return
	}

	ctx.Flash.Success(ctx.Tr("repo.settings.remove_protected_branch_success", rule.RuleName))
	ctx.JSONRedirect(fmt.Sprintf("%s/settings/branches", ctx.Repo.RepoLink))
}

// RenameBranchPost responses for rename a branch
func RenameBranchPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.RenameBranchForm)

	if !ctx.Repo.CanCreateBranch() {
		ctx.NotFound("RenameBranch", nil)
		return
	}

	if ctx.HasError() {
		ctx.Flash.Error(ctx.GetErrMsg())
		ctx.Redirect(fmt.Sprintf("%s/branches", ctx.Repo.RepoLink))
		return
	}

	msg, err := repository.RenameBranch(ctx, ctx.Repo.Repository, ctx.Doer, ctx.Repo.GitRepo, form.From, form.To)
	if err != nil {
		if errors.Is(err, git_model.ErrBranchIsProtected) {
			ctx.Flash.Error(ctx.Tr("repo.settings.rename_branch_failed_protected", form.To))
			ctx.Redirect(fmt.Sprintf("%s/branches", ctx.Repo.RepoLink))
		} else if git_model.IsErrBranchAlreadyExists(err) {
			ctx.Flash.Error(ctx.Tr("repo.branch.branch_already_exists", form.To))
			ctx.Redirect(fmt.Sprintf("%s/branches", ctx.Repo.RepoLink))
		} else {
			ctx.ServerError("RenameBranch", err)
		}
		return
	}

	if msg == "target_exist" {
		ctx.Flash.Error(ctx.Tr("repo.settings.rename_branch_failed_exist", form.To))
		ctx.Redirect(fmt.Sprintf("%s/branches", ctx.Repo.RepoLink))
		return
	}

	if msg == "from_not_exist" {
		ctx.Flash.Error(ctx.Tr("repo.settings.rename_branch_failed_not_exist", form.From))
		ctx.Redirect(fmt.Sprintf("%s/branches", ctx.Repo.RepoLink))
		return
	}

	if msg == "push_rule" {
		ctx.Flash.Error(ctx.Tr("repo.settings.push_rules.rename_branch_failed", form.To))
		ctx.Redirect(fmt.Sprintf("%s/branches", ctx.Repo.RepoLink))
		return
	}

	ctx.Flash.Success(ctx.Tr("repo.settings.rename_branch_success", form.From, form.To))
	ctx.Redirect(fmt.Sprintf("%s/branches", ctx.Repo.RepoLink))
}

// getWriteDeployKeys returns the deploy keys of the repository which have write access, and those of its owner
// organization covering it, the ones which can be selected in branch and tag protection rules. The templates only
// read KeyID and Name, so an organization key is given as a DeployKey with those.
func getWriteDeployKeys(ctx *context.Context) ([]*asymkey_model.DeployKey, error) {
	keys, err := db.Find[asymkey_model.DeployKey](ctx, asymkey_model.ListDeployKeysOptions{
		ListOptions: db.ListOptionsAll,
		RepoID:      ctx.Repo.Repository.ID,
	})
	if err != nil {
		return nil, err
	}
	keys = slices.DeleteFunc(keys, func(key *asymkey_model.DeployKey) bool { return key.IsReadOnly() })
	orgKeys, err := asymkey_model.FindOrgDeployKeysCoveringRepo(ctx, ctx.Repo.Repository)
	if err != nil {
		return nil, err
	}
	for _, k := range orgKeys {
		if !k.IsReadOnly() && !slices.ContainsFunc(keys, func(key *asymkey_model.DeployKey) bool { return key.KeyID == k.KeyID }) {
			keys = append(keys, &asymkey_model.DeployKey{KeyID: k.KeyID, Name: k.Name, Mode: k.Mode})
		}
	}
	return keys, nil
}

// allowlistToken is a token of the repository, or of its organization or project covering it, with write or admin
// permission: what branch and tag protection may allow beside deploy keys. In the deploy key pickers its value is
// its identity's user ID (negative, unlike a key ID), and the rule stores it with the users.
type allowlistToken struct {
	BotID     int64
	Name      string
	OwnerType auth_model.AccessTokenOwnerType
	Expired   bool // still listed so a stored selection shows and can be removed; an expired token is refused at push
}

// getWriteTokens returns the tokens branch and tag protection rules of the repository may allow, expired ones
// included (a revoked token is gone).
func getWriteTokens(ctx *context.Context) ([]*allowlistToken, error) {
	repo := ctx.Repo.Repository
	tokens, err := db.Find[auth_model.AccessToken](ctx, auth_model.FindOwnedAccessTokensOptions{
		ListOptions: db.ListOptionsAll, OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: repo.ID,
	})
	if err != nil {
		return nil, err
	}
	covering, err := auth_model.FindOwnedAccessTokensCoveringRepo(ctx, repo.ID, repo.OwnerID, repo.GroupID)
	if err != nil {
		return nil, err
	}
	var out []*allowlistToken
	for _, t := range append(tokens, covering...) {
		if t.Mode >= perm.AccessModeWrite && !t.IsRevoked() {
			out = append(out, &allowlistToken{BotID: user_model.AccessTokenBotID(t.ID), Name: t.Name, OwnerType: t.OwnerType, Expired: t.IsExpired()})
		}
	}
	return out, nil
}

// writeTokenIDs keeps the token identities among ids that getWriteTokens offers for the repository of the page: no
// other token can be allowed, and an organization rule (no repository, no picker) takes none.
func writeTokenIDs(ctx *context.Context, ids []int64) ([]int64, error) {
	ids = user_model.TokenIDsOnly(ids)
	if len(ids) == 0 || ctx.Repo.Repository == nil {
		return nil, nil
	}
	tokens, err := getWriteTokens(ctx)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(ids, func(id int64) bool {
		return !slices.ContainsFunc(tokens, func(t *allowlistToken) bool { return t.BotID == id })
	}), nil
}

func joinIDs(ids []int64) string {
	return strings.Join(base.Int64sToStrings(ids), ",")
}

// keyIDsOnly keeps the deploy key IDs a picker sent.
func keyIDsOnly(ids []int64) []int64 {
	return slices.DeleteFunc(slices.Clone(ids), func(id int64) bool { return id <= 0 })
}

// parseIDList parses the comma-separated IDs of a dropdown. An invalid list gives no IDs.
func parseIDList(s string) []int64 {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	ids, _ := base.StringsToInt64s(strings.Split(s, ","))
	return ids
}

// approvalRulesFromForm reads the rows approval_rule_* of the form, one value per row. A row without a name is
// dropped. nil keeps the rules, for a form that has no rows at all.
func approvalRulesFromForm(ctx *context.Context, owner *user_model.User) ([]*git_model.ApprovalRule, error) {
	form := ctx.Req.PostForm
	names, sent := form["approval_rule_name"]
	if !sent {
		return nil, nil
	}
	field := func(key string, i int) string {
		if values := form[key]; i < len(values) {
			return strings.TrimSpace(values[i])
		}
		return ""
	}
	list := func(value string) (items []string) {
		for item := range strings.SplitSeq(value, ",") {
			if item = strings.TrimSpace(item); item != "" {
				items = append(items, item)
			}
		}
		return items
	}
	rules := []*api.ApprovalRule{}
	for i, name := range names {
		if strings.TrimSpace(name) == "" {
			continue
		}
		count, _ := strconv.ParseInt(field("approval_rule_count", i), 10, 64)
		rules = append(rules, &api.ApprovalRule{
			Name: name, RequiredCount: count,
			Usernames:         list(field("approval_rule_users", i)),
			Teams:             list(field("approval_rule_teams", i)),
			PathPatterns:      field("approval_rule_paths", i),
			RequireCodeOwners: field("approval_rule_code_owners", i) == "true",
		})
	}
	return pull_service.ApprovalRulesFromAPI(ctx, owner, rules)
}
