// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"net/http"

	git_model "forgejo.org/models/git"
	"forgejo.org/modules/base"
	"forgejo.org/modules/web"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
)

const tplPushRules base.TplName = "repo/settings/push_rules"

// PushRules renders the repository's push rule
func PushRules(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("repo.settings.push_rules")
	ctx.Data["PageIsSettingsPushRules"] = true
	rule, err := git_model.GetPushRule(ctx, ctx.Repo.Repository.ID)
	if err != nil {
		ctx.ServerError("GetPushRule", err)
		return
	}
	if rule == nil {
		rule = &git_model.PushRule{}
	}
	ctx.Data["Rule"] = rule
	ctx.HTML(http.StatusOK, tplPushRules)
}

// PushRulesPost saves the repository's push rule
func PushRulesPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.PushRuleForm)
	ctx.Data["Title"] = ctx.Tr("repo.settings.push_rules")
	ctx.Data["PageIsSettingsPushRules"] = true
	rule := &git_model.PushRule{
		RepoID:                     ctx.Repo.Repository.ID,
		CommitMessageRegex:         form.CommitMessageRegex,
		CommitMessageBannedRegex:   form.CommitMessageBannedRegex,
		BranchNameRegex:            form.BranchNameRegex,
		RequireVerifiedAuthorEmail: form.RequireVerifiedAuthorEmail,
		MaxFileSizeMB:              form.MaxFileSizeMB,
		BannedFilePatterns:         form.BannedFilePatterns,
		PRTitleRegex:               form.PRTitleRegex,
		PRTitleBannedRegex:         form.PRTitleBannedRegex,
		PRTitleMessage:             form.PRTitleMessage,
		PRTitleBranches:            form.PRTitleBranches,
		PRTitleBlockMerge:          form.PRTitleBlockMerge,
	}
	ctx.Data["Rule"] = rule
	if ctx.HasError() {
		ctx.RenderWithErr(ctx.GetErrMsg(), tplPushRules, nil)
		return
	}
	if err := rule.Compile(); err != nil {
		ctx.RenderWithErr(ctx.Tr("repo.settings.push_rules.invalid", err.Error()), tplPushRules, nil)
		return
	}
	if err := git_model.UpsertPushRule(ctx, rule); err != nil {
		ctx.ServerError("UpsertPushRule", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("repo.settings.update_settings_success"))
	ctx.Redirect(ctx.Repo.RepoLink + "/settings/push_rules")
}
