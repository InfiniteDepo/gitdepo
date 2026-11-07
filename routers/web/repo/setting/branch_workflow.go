// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/base"
	"forgejo.org/modules/web"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
	repo_service "forgejo.org/services/repository"
)

const tplBranchWorkflow base.TplName = "repo/settings/branch_workflow"

// BranchWorkflow renders the repository's branch workflow settings.
func BranchWorkflow(ctx *context.Context) {
	if !prepareBranchWorkflow(ctx) || !PrepareMergedBranches(ctx, repo_service.MergedBranchScope{Repo: ctx.Repo.Repository}, ctx.Repo.RepoLink+"/settings/branch_workflow", false) {
		return
	}
	ctx.HTML(http.StatusOK, tplBranchWorkflow)
}

// BranchWorkflowDeleteMerged renders the branch workflow settings with the merged branches that would be deleted.
func BranchWorkflowDeleteMerged(ctx *context.Context) {
	if !prepareBranchWorkflow(ctx) || !PrepareMergedBranches(ctx, repo_service.MergedBranchScope{Repo: ctx.Repo.Repository}, ctx.Repo.RepoLink+"/settings/branch_workflow", true) {
		return
	}
	ctx.HTML(http.StatusOK, tplBranchWorkflow)
}

// BranchWorkflowDeleteMergedPost deletes the repository's merged branches.
func BranchWorkflowDeleteMergedPost(ctx *context.Context) {
	DeleteMergedBranchesPost(ctx, repo_service.MergedBranchScope{Repo: ctx.Repo.Repository}, ctx.Repo.RepoLink+"/settings/branch_workflow")
}

// PrepareMergedBranches sets the data of the "delete merged branches" section of the settings page at back, and the
// first MaxDeleteMergedBranches branches it may delete when preview is set. It deletes nothing.
func PrepareMergedBranches(ctx *context.Context, scope repo_service.MergedBranchScope, back string, preview bool) bool {
	ctx.Data["MergedLink"] = back + "/delete_merged"
	ctx.Data["MergedBackLink"] = back
	ctx.Data["MergedShowRepos"] = scope.Repo == nil
	ctx.Data["MergedConfirmName"] = mergedConfirmName(ctx, scope)
	if hours, ok := branchworkflow.RestoreWindow(); ok {
		if hours == 0 {
			ctx.Data["RestoreText"] = ctx.Tr("repo.settings.delete_merged.restore")
		} else {
			ctx.Data["RestoreText"] = ctx.Locale.TrPluralString(hours, "repo.settings.delete_merged.restore_hours", hours)
		}
	}
	if !preview {
		return true
	}
	found, more, err := repo_service.FindMergedBranches(ctx, scope, repo_service.MaxDeleteMergedBranches)
	if err != nil {
		ctx.ServerError("FindMergedBranches", err)
		return false
	}
	count := 0
	for _, f := range found {
		count += len(f.Branches)
	}
	ctx.Data["MergedPreview"] = true
	ctx.Data["MergedBranches"] = found
	ctx.Data["MergedCount"] = count
	ctx.Data["MergedMore"] = more
	ctx.Data["MaxDeleteMerged"] = repo_service.MaxDeleteMergedBranches
	return true
}

// mergedConfirmName is what the doer types to confirm a run over several repositories: the organization's name, or
// "org/project". A single repository needs none.
func mergedConfirmName(ctx *context.Context, scope repo_service.MergedBranchScope) string {
	switch {
	case scope.Group != nil:
		return ctx.Org.Organization.Name + "/" + scope.Group.Name
	case scope.Org != nil:
		return scope.Org.Name
	}
	return ""
}

// DeleteMergedBranchesPost deletes the branches ticked in the preview ("<repo id>:<name>") that are still merged
// branches of the scope. It returns to the preview while more are left, else to the settings page at back.
func DeleteMergedBranchesPost(ctx *context.Context, scope repo_service.MergedBranchScope, back string) {
	if name := mergedConfirmName(ctx, scope); name != "" && !strings.EqualFold(strings.TrimSpace(ctx.FormString("confirm_name")), name) {
		ctx.Flash.Error(ctx.Tr("repo.settings.delete_merged.confirm_mismatch"))
		ctx.Redirect(back + "/delete_merged#delete-merged")
		return
	}
	selected := map[int64][]string{}
	for _, v := range ctx.FormStrings("branch") {
		id, name, _ := strings.Cut(v, ":")
		if repoID, err := strconv.ParseInt(id, 10, 64); err == nil && name != "" {
			selected[repoID] = append(selected[repoID], name)
		}
	}
	deleted, failed, err := repo_service.DeleteMergedBranches(ctx, ctx.Doer, scope, selected)
	if err != nil {
		ctx.ServerError("DeleteMergedBranches", err)
		return
	}
	ctx.Flash.Success(ctx.Locale.TrPluralString(deleted, "repo.settings.delete_merged.done", deleted))
	if failed > 0 {
		ctx.Flash.Warning(ctx.Locale.TrPluralString(failed, "repo.settings.delete_merged.failed", failed))
	}
	if ctx.FormBool("more") {
		ctx.Redirect(back + "/delete_merged#delete-merged")
		return
	}
	ctx.Redirect(back)
}

func prepareBranchWorkflow(ctx *context.Context) bool {
	ctx.Data["Title"] = ctx.Tr("repo.settings.branch_workflow")
	ctx.Data["PageIsSettingsBranchWorkflow"] = true
	eff, err := branchworkflow.GetEffective(ctx, ctx.Repo.Repository)
	if err != nil {
		ctx.ServerError("GetEffective", err)
		return false
	}
	shown := eff.Configured
	if eff.Locked {
		shown = eff.Mode
		ctx.Data["SetBy"] = branchworkflow.SetByText(ctx.Locale, eff)
	}
	ctx.Data["DeleteAfterMerge"] = shown.String()
	ctx.Data["Locked"] = eff.Locked
	ctx.Data["OwnerIsOrg"] = ctx.Repo.Owner.IsOrganization()

	model, err := branchworkflow.GetEffectiveModel(ctx, ctx.Repo.Repository)
	if err != nil {
		ctx.ServerError("GetEffectiveModel", err)
		return false
	}
	shownModel := model.Model
	if !model.Locked && model.Configured != nil {
		shownModel = *model.Configured
	}
	ctx.Data["ModelInherit"] = model.Configured == nil
	ctx.Data["ModelLocked"] = model.Locked
	if model.Source == branchworkflow.SourceOrg {
		ctx.Data["ModelSetBy"] = ctx.Locale.TrString("repo.pulls.delete_after_merge.set_by_org", model.SetBy)
	}
	if model.Org != nil {
		ctx.Data["ModelInheritDesc"] = ctx.Locale.TrString("repo.settings.branching_model.inherit_desc_org", ctx.Repo.Owner.Name)
	}
	ctx.Data["DevelopmentBranch"] = shownModel.DevelopmentBranch
	ctx.Data["ReleasePrefixes"] = strings.Join(shownModel.ReleasePrefixes, ", ")
	ctx.Data["MergeForward"] = shownModel.MergeForward
	ctx.Data["MergeForwardNeverBypass"] = shownModel.MergeForwardNeverBypass
	ctx.Data["MergeForwardAnyoneMaySkip"] = shownModel.MergeForwardAnyoneMaySkip
	ctx.Data["ProductionBranch"] = shownModel.ProductionBranch
	ctx.Data["ModelTypes"] = shownModel.Types
	ctx.Data["DefaultPRTarget"] = shownModel.DefaultPRTarget
	if model.Locked && ctx.Doer != nil {
		isOwner, err := organization.OrgFromUser(ctx.Repo.Owner).IsActingOwner(ctx, ctx.Doer)
		if err != nil {
			ctx.ServerError("IsActingOwner", err)
			return false
		}
		if isOwner || ctx.Doer.IsAdmin {
			ctx.Data["ModelSettingsLink"] = ctx.Repo.Owner.OrganisationLink() + "/settings/branch_workflow#branching-model"
		}
	}
	missing, err := branchworkflow.MissingBases(ctx, ctx.Repo.Repository, shownModel)
	if err != nil {
		ctx.ServerError("MissingBases", err)
		return false
	}
	ctx.Data["MissingBases"] = missing
	counts, err := branchworkflow.CountUntyped(ctx, ctx.Repo.Repository, shownModel)
	if err != nil {
		ctx.ServerError("CountUntyped", err)
		return false
	}
	type untyped struct {
		Prefix string
		Count  int
	}
	var lost []untyped
	for _, t := range shownModel.Types {
		if counts[t.Prefix] > 0 {
			lost = append(lost, untyped{t.Prefix, counts[t.Prefix]})
		}
	}
	ctx.Data["UntypedCounts"] = lost
	chain, err := branchworkflow.GetChain(ctx, ctx.Repo.Repository, model)
	if err != nil {
		ctx.ServerError("GetChain", err)
		return false
	}
	ctx.Data["HasModel"] = len(model.Model.ReleasePrefixes) > 0 || model.Model.ProductionBranch != ""
	if len(chain.Ignored) > maxIgnoredShown {
		ctx.Data["IgnoredMore"] = len(chain.Ignored) - maxIgnoredShown
		chain.Ignored = chain.Ignored[:maxIgnoredShown]
	}
	ctx.Data["Chain"] = chain
	return true
}

// maxIgnoredShown caps the ignored branches the chain preview lists.
const maxIgnoredShown = 20

// BranchingModelPost saves the repository's branching model.
func BranchingModelPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.BranchingModelForm)
	var model *repo_model.BranchingModel
	if !form.Inherit || !ctx.Repo.Owner.IsOrganization() {
		model = form.Model()
	}
	err := branchworkflow.SetRepoModel(ctx, ctx.Repo.Repository, model)
	if value, ok := branchworkflow.IsInvalidBranchingModel(err); ok {
		ctx.Flash.Error(ctx.Tr("repo.settings.branching_model.invalid", value))
	} else {
		switch {
		case errors.Is(err, branchworkflow.ErrTooManyReleasePrefixes):
			ctx.Flash.Error(ctx.Tr("repo.settings.branching_model.too_many_prefixes"))
		case errors.Is(err, branchworkflow.ErrTooManyBranchTypes):
			ctx.Flash.Error(ctx.Tr("repo.settings.branching_model.too_many_types"))
		case errors.Is(err, branchworkflow.ErrLocked):
			ctx.Error(http.StatusForbidden, ctx.Locale.TrString("repo.settings.branching_model.locked"))
			return
		case errors.Is(err, branchworkflow.ErrNoPullRequests):
			ctx.Flash.Error(ctx.Tr("repo.settings.branch_workflow.pulls_disabled"))
		case err != nil:
			ctx.ServerError("SetRepoModel", err)
			return
		default:
			ctx.Flash.Success(ctx.Tr("repo.settings.update_settings_success"))
		}
	}
	ctx.Redirect(ctx.Repo.RepoLink + "/settings/branch_workflow")
}

// BranchWorkflowPost saves the repository's branch workflow settings.
func BranchWorkflowPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.BranchWorkflowForm)
	mode, ok := repo_model.ParseDeleteBranchMode(form.DeleteAfterMerge)
	if !ok {
		ctx.Flash.Error(ctx.Tr("repo.settings.branch_workflow.invalid_value"))
		ctx.Redirect(ctx.Repo.RepoLink + "/settings/branch_workflow")
		return
	}
	switch err := branchworkflow.SetRepo(ctx, ctx.Repo.Repository, mode); {
	case errors.Is(err, branchworkflow.ErrLocked):
		ctx.Error(http.StatusForbidden, ctx.Locale.TrString("repo.settings.branch_workflow.locked"))
		return
	case errors.Is(err, branchworkflow.ErrNoPullRequests):
		ctx.Flash.Error(ctx.Tr("repo.settings.branch_workflow.pulls_disabled"))
	case err != nil:
		ctx.ServerError("SetRepo", err)
		return
	default:
		ctx.Flash.Success(ctx.Tr("repo.settings.update_settings_success"))
	}
	ctx.Redirect(ctx.Repo.RepoLink + "/settings/branch_workflow")
}
