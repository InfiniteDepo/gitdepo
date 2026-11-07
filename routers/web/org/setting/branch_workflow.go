// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"errors"
	"net/http"
	"strings"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/base"
	"forgejo.org/modules/web"
	repo_setting "forgejo.org/routers/web/repo/setting"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
	repo_service "forgejo.org/services/repository"
)

const tplSettingsBranchWorkflow base.TplName = "org/settings/branch_workflow"

// BranchWorkflow renders the organization's branch workflow settings.
func BranchWorkflow(ctx *context.Context) {
	renderBranchWorkflow(ctx, false)
}

// BranchWorkflowDeleteMerged renders the branch workflow settings with the merged branches that would be deleted.
func BranchWorkflowDeleteMerged(ctx *context.Context) {
	renderBranchWorkflow(ctx, true)
}

// BranchWorkflowDeleteMergedPost deletes the merged branches of every repository of the organization.
func BranchWorkflowDeleteMergedPost(ctx *context.Context) {
	repo_setting.DeleteMergedBranchesPost(ctx, repo_service.MergedBranchScope{Org: ctx.Org.Organization.AsUser()}, ctx.Org.OrgLink+"/settings/branch_workflow")
}

func renderBranchWorkflow(ctx *context.Context, preview bool) {
	ctx.Data["Title"] = ctx.Tr("org.settings.branch_workflow")
	ctx.Data["PageIsOrgSettings"] = true
	ctx.Data["PageIsOrgSettingsBranchWorkflow"] = true
	mode, locked, err := branchworkflow.GetOrg(ctx, ctx.Org.Organization.AsUser())
	if err != nil {
		ctx.ServerError("GetOrg", err)
		return
	}
	ctx.Data["DeleteAfterMerge"] = mode.String()
	ctx.Data["Enforce"] = locked
	model, modelLocked, err := branchworkflow.GetOrgModel(ctx, ctx.Org.Organization.AsUser())
	if err != nil {
		ctx.ServerError("GetOrgModel", err)
		return
	}
	if model != nil {
		ctx.Data["DevelopmentBranch"] = model.DevelopmentBranch
		ctx.Data["ReleasePrefixes"] = strings.Join(model.ReleasePrefixes, ", ")
		ctx.Data["MergeForward"] = model.MergeForward
		ctx.Data["MergeForwardNeverBypass"] = model.MergeForwardNeverBypass
		ctx.Data["MergeForwardAnyoneMaySkip"] = model.MergeForwardAnyoneMaySkip
		ctx.Data["ProductionBranch"] = model.ProductionBranch
		ctx.Data["ModelTypes"] = model.Types
		ctx.Data["DefaultPRTarget"] = model.DefaultPRTarget
	}
	ctx.Data["EnforceModel"] = modelLocked
	if !repo_setting.PrepareMergedBranches(ctx, repo_service.MergedBranchScope{Org: ctx.Org.Organization.AsUser()}, ctx.Org.OrgLink+"/settings/branch_workflow", preview) {
		return
	}
	ctx.HTML(http.StatusOK, tplSettingsBranchWorkflow)
}

// BranchWorkflowPost saves the organization's branch workflow settings.
func BranchWorkflowPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.BranchWorkflowForm)
	mode, ok := repo_model.ParseDeleteBranchMode(form.DeleteAfterMerge)
	if !ok {
		ctx.Flash.Error(ctx.Tr("repo.settings.branch_workflow.invalid_value"))
		ctx.Redirect(ctx.Org.OrgLink + "/settings/branch_workflow")
		return
	}
	switch err := branchworkflow.SetOrg(ctx, ctx.Org.Organization.AsUser(), mode, form.Enforce); {
	case errors.Is(err, branchworkflow.ErrLockWithoutValue):
		ctx.Flash.Error(ctx.Tr("org.settings.branch_workflow.enforce_needs_value"))
	case err != nil:
		ctx.ServerError("SetOrg", err)
		return
	default:
		ctx.Flash.Success(ctx.Tr("org.settings.update_setting_success"))
	}
	ctx.Redirect(ctx.Org.OrgLink + "/settings/branch_workflow")
}

// BranchingModelPost saves the organization's branching model.
func BranchingModelPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.BranchingModelForm)
	err := branchworkflow.SetOrgModel(ctx, ctx.Org.Organization.AsUser(), form.Model(), form.EnforceModel)
	if value, ok := branchworkflow.IsInvalidBranchingModel(err); ok {
		ctx.Flash.Error(ctx.Tr("repo.settings.branching_model.invalid", value))
	} else {
		switch {
		case errors.Is(err, branchworkflow.ErrTooManyReleasePrefixes):
			ctx.Flash.Error(ctx.Tr("repo.settings.branching_model.too_many_prefixes"))
		case errors.Is(err, branchworkflow.ErrTooManyBranchTypes):
			ctx.Flash.Error(ctx.Tr("repo.settings.branching_model.too_many_types"))
		case errors.Is(err, branchworkflow.ErrLockWithoutValue):
			ctx.Flash.Error(ctx.Tr("org.settings.branching_model.enforce_needs_value"))
		case err != nil:
			ctx.ServerError("SetOrgModel", err)
			return
		default:
			ctx.Flash.Success(ctx.Tr("org.settings.update_setting_success"))
		}
	}
	ctx.Redirect(ctx.Org.OrgLink + "/settings/branch_workflow")
}
