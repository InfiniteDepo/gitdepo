// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	git_model "forgejo.org/models/git"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/base"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	repo_setting "forgejo.org/routers/web/repo/setting"
	shared_user "forgejo.org/routers/web/shared/user"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	"forgejo.org/services/forms"
	pull_service "forgejo.org/services/pull"
)

const (
	tplSettingsBranches        base.TplName = "org/settings/branches"
	tplSettingsProtectedBranch base.TplName = "repo/settings/protected_branch"
)

// ruleScope returns the project of the page (0 for the organization's own rules) and the page listing its rules.
// The project's rules are listed on its settings page.
func ruleScope(ctx *context.Context) (int64, string) {
	if group, ok := ctx.Data["RepoGroup"].(*repo_model.RepoGroup); ok {
		ctx.Data["RepoGroupLink"] = group.Link(ctx.Org.Organization.Name)
		return group.ID, group.Link(ctx.Org.Organization.Name) + "/-/settings"
	}
	return 0, ctx.Org.OrgLink + "/settings/branches"
}

// ProtectedBranchRules lists the branch protection rules of the organization.
func ProtectedBranchRules(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("org.settings.branches")
	ctx.Data["PageIsOrgSettings"] = true
	ctx.Data["PageIsOrgSettingsBranches"] = true
	rules, err := git_model.FindOrgProtectedBranchRules(ctx, ctx.Org.Organization.ID, 0)
	if err != nil {
		ctx.ServerError("FindOrgProtectedBranchRules", err)
		return
	}
	ctx.Data["ProtectedBranches"] = rules
	ctx.HTML(http.StatusOK, tplSettingsBranches)
}

// SettingsProtectedBranch renders the form of a new or existing organization or project rule, using the repository
// form.
func SettingsProtectedBranch(ctx *context.Context) {
	org := ctx.Org.Organization
	groupID, _ := ruleScope(ctx)
	rule := &git_model.ProtectedBranch{}
	if ruleName := ctx.FormString("rule_name"); ruleName != "" {
		existing, err := git_model.GetOrgProtectedBranchRuleByName(ctx, org.ID, groupID, ruleName)
		if err != nil {
			ctx.ServerError("GetOrgProtectedBranchRuleByName", err)
			return
		}
		if existing != nil {
			rule = existing
		}
	}

	ctx.Data["Title"] = ctx.Locale.TrString("repo.settings.protected_branch") + " - " + rule.RuleName
	if groupID != 0 { // the project's settings page and its header
		if err := shared_user.LoadHeaderCount(ctx); err != nil {
			ctx.ServerError("LoadHeaderCount", err)
			return
		}
		ctx.Data["PageIsViewRepoGroups"] = true
	} else {
		ctx.Data["PageIsOrgSettings"] = true
		ctx.Data["PageIsOrgSettingsBranches"] = true
	}
	ctx.Data["IsOrgRule"] = true
	ctx.Data["Owner"] = org.AsUser()

	users, _, err := org.GetMembers(ctx, ctx.Doer)
	if err != nil {
		ctx.ServerError("GetMembers", err)
		return
	}
	teams, err := organization.FindOrgTeams(ctx, org.ID)
	if err != nil {
		ctx.ServerError("FindOrgTeams", err)
		return
	}
	repos, err := organization.GetOrgRepositories(ctx, org.ID)
	if err != nil {
		ctx.ServerError("GetOrgRepositories", err)
		return
	}
	repoIDs := []int64{}
	rows := []*api.ApprovalRule{}
	if rule.ID != 0 {
		if repoIDs, err = git_model.GetOrgProtectedBranchRuleRepoIDs(ctx, rule.ID); err != nil {
			ctx.ServerError("GetOrgProtectedBranchRuleRepoIDs", err)
			return
		}
		rows = convert.ToOrgBranchProtection(ctx, rule, nil).ApprovalRules
		report, err := pull_service.BranchRuleWarnings(ctx, nil, rule, pull_service.OwnerViewer{})
		if err != nil {
			ctx.ServerError("BranchRuleWarnings", err)
			return
		}
		ctx.Data["RuleReport"] = report
	}

	ids := func(list []int64) string { return strings.Join(base.Int64sToStrings(list), ",") }
	ctx.Data["Users"] = users
	ctx.Data["Teams"] = teams
	ctx.Data["Repos"] = repos
	ctx.Data["selected_repo_ids"] = ids(repoIDs)
	ctx.Data["whitelist_users"] = ids(rule.WhitelistUserIDs)
	ctx.Data["merge_whitelist_users"] = ids(rule.MergeWhitelistUserIDs)
	ctx.Data["approvals_whitelist_users"] = ids(rule.ApprovalsWhitelistUserIDs)
	ctx.Data["delete_allowlist_users"] = ids(rule.DeleteAllowlistUserIDs)
	ctx.Data["force_push_allowlist_users"] = ids(rule.ForcePushAllowlistUserIDs)
	ctx.Data["whitelist_teams"] = ids(rule.WhitelistTeamIDs)
	ctx.Data["merge_whitelist_teams"] = ids(rule.MergeWhitelistTeamIDs)
	ctx.Data["approvals_whitelist_teams"] = ids(rule.ApprovalsWhitelistTeamIDs)
	ctx.Data["delete_allowlist_teams"] = ids(rule.DeleteAllowlistTeamIDs)
	ctx.Data["force_push_allowlist_teams"] = ids(rule.ForcePushAllowlistTeamIDs)
	ctx.Data["status_check_contexts"] = strings.Join(rule.StatusCheckContexts, "\n")
	ctx.Data["ApprovalRules"] = rows
	ctx.Data["MaxApprovalRules"] = git_model.MaxApprovalRules
	ctx.Data["Rule"] = rule
	ctx.HTML(http.StatusOK, tplSettingsProtectedBranch)
}

// SettingsProtectedBranchPost creates or updates an organization or project rule.
func SettingsProtectedBranchPost(ctx *context.Context) {
	f := web.GetForm(ctx).(*forms.ProtectBranchForm)
	org := ctx.Org.Organization
	groupID, listLink := ruleScope(ctx)
	editLink := ctx.Org.OrgLink + "/settings/branches/edit"
	if groupID != 0 {
		editLink = listLink + "/branches/edit"
	}
	if f.RuleName == "" {
		ctx.Flash.Error(ctx.Tr("repo.settings.protected_branch_required_rule_name"))
		ctx.Redirect(editLink)
		return
	}

	// a rule is only ever loaded within the organization and project of the page
	rule := &git_model.ProtectedBranch{}
	if f.RuleID > 0 {
		existing, err := git_model.GetOrgProtectedBranchRuleByID(ctx, org.ID, groupID, f.RuleID)
		if err != nil {
			ctx.ServerError("GetOrgProtectedBranchRuleByID", err)
			return
		}
		if existing == nil {
			ctx.NotFound("GetOrgProtectedBranchRuleByID", nil)
			return
		}
		rule = existing
	}
	if rule.RuleName != f.RuleName {
		same, err := git_model.GetOrgProtectedBranchRuleByName(ctx, org.ID, groupID, f.RuleName)
		if err != nil {
			ctx.ServerError("GetOrgProtectedBranchRuleByName", err)
			return
		}
		if same != nil {
			ctx.Flash.Error(ctx.Tr("repo.settings.protected_branch_duplicate_rule_name"))
			ctx.Redirect(editLink + "?rule_name=" + url.QueryEscape(same.RuleName))
			return
		}
	}

	opts, errMsg := repo_setting.ProtectBranchFromForm(ctx, f, rule, org.AsUser())
	if errMsg != "" {
		ctx.Flash.Error(errMsg)
		ctx.Redirect(editLink + "?rule_name=" + url.QueryEscape(f.RuleName))
		return
	}
	rule.ApplyToSelectedRepos = f.ApplyToSelectedRepos
	var repoIDs []int64
	if strings.TrimSpace(f.SelectedRepoIDs) != "" {
		var err error
		if repoIDs, err = base.StringsToInt64s(strings.Split(f.SelectedRepoIDs, ",")); err != nil {
			ctx.Flash.Error(ctx.Tr("repo.settings.approval_rules_invalid", err.Error()))
			ctx.Redirect(editLink + "?rule_name=" + url.QueryEscape(f.RuleName))
			return
		}
	}

	err := git_model.UpdateOrgProtectBranch(ctx, org.ID, groupID, rule, opts, repoIDs)
	if errors.Is(err, util.ErrInvalidArgument) {
		ctx.Flash.Error(ctx.Tr("repo.settings.approval_rules_invalid", err.Error()))
		ctx.Redirect(editLink + "?rule_name=" + url.QueryEscape(f.RuleName))
		return
	} else if errors.Is(err, util.ErrNotExist) { // the project or the rule was deleted meanwhile
		ctx.NotFound("UpdateOrgProtectBranch", err)
		return
	} else if err != nil {
		ctx.ServerError("UpdateOrgProtectBranch", err)
		return
	}
	if err := pull_service.CheckPRsForOrgRule(ctx, rule); err != nil {
		ctx.ServerError("CheckPRsForOrgRule", err)
		return
	}

	ctx.Flash.Success(ctx.Tr("repo.settings.update_protect_branch_success", rule.RuleName))
	ctx.Redirect(listLink)
}

// DeleteProtectedBranchRulePost deletes an organization or project rule.
func DeleteProtectedBranchRulePost(ctx *context.Context) {
	org := ctx.Org.Organization
	groupID, listLink := ruleScope(ctx)
	rule, err := git_model.GetOrgProtectedBranchRuleByID(ctx, org.ID, groupID, ctx.ParamsInt64("rule"))
	if err != nil {
		ctx.ServerError("GetOrgProtectedBranchRuleByID", err)
		return
	}
	if rule == nil {
		ctx.NotFound("GetOrgProtectedBranchRuleByID", nil)
		return
	}
	if err := git_model.DeleteOrgProtectedBranch(ctx, org.ID, groupID, rule.ID); err != nil {
		ctx.ServerError("DeleteOrgProtectedBranch", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("repo.settings.remove_protected_branch_success", rule.RuleName))
	ctx.JSONRedirect(listLink)
}
