// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"errors"
	"net/http"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/web"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/context"
)

// GetBranchWorkflow returns the branch workflow settings of an organization
func GetBranchWorkflow(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/branch-workflow organization orgGetBranchWorkflow
	// ---
	// summary: Get the branch workflow settings of an organization
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/OrgBranchWorkflow"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if !orgWideToken(ctx) {
		return
	}

	mode, locked, err := branchworkflow.GetOrg(ctx, ctx.Org().Organization.AsUser())
	if err != nil {
		ctx.ServerError("GetOrg", err)
		return
	}
	ctx.JSON(http.StatusOK, &api.OrgBranchWorkflow{DeleteBranchAfterMerge: mode.String(), EnforceDeleteBranchAfterMerge: locked})
}

// EditBranchWorkflow changes the branch workflow settings of an organization
func EditBranchWorkflow(ctx *context.APIContext) {
	// swagger:operation PUT /orgs/{org}/branch-workflow organization orgEditBranchWorkflow
	// ---
	// summary: Change the branch workflow settings of an organization
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/OrgBranchWorkflow"
	// responses:
	//   "200":
	//     "$ref": "#/responses/OrgBranchWorkflow"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if !orgWideToken(ctx) {
		return
	}

	form := web.GetForm(ctx).(*api.OrgBranchWorkflow)
	mode, ok := repo_model.ParseDeleteBranchMode(form.DeleteBranchAfterMerge)
	if !ok {
		ctx.Error(http.StatusUnprocessableEntity, "DeleteBranchAfterMerge", "must be one of inherit, off, default-on, always")
		return
	}
	if err := branchworkflow.SetOrg(ctx, ctx.Org().Organization.AsUser(), mode, form.EnforceDeleteBranchAfterMerge); err != nil {
		if errors.Is(err, branchworkflow.ErrLockWithoutValue) {
			ctx.Error(http.StatusUnprocessableEntity, "EnforceDeleteBranchAfterMerge", err)
		} else {
			ctx.ServerError("SetOrg", err)
		}
		return
	}
	ctx.JSON(http.StatusOK, form)
}

func renderBranchingModel(ctx *context.APIContext) {
	model, locked, err := branchworkflow.GetOrgModel(ctx, ctx.Org().Organization.AsUser())
	if err != nil {
		ctx.ServerError("GetOrgModel", err)
		return
	}
	res := &api.OrgBranchingModel{ReleasePrefixes: []string{}, Types: []api.BranchType{}, Enforce: locked}
	if model != nil {
		res.DevelopmentBranch = model.DevelopmentBranch
		res.ReleasePrefixes = append(res.ReleasePrefixes, model.ReleasePrefixes...)
		res.MergeForward = model.MergeForward
		res.MergeForwardNeverBypass = model.MergeForwardNeverBypass
		res.MergeForwardAnyoneMaySkip = model.MergeForwardAnyoneMaySkip
		res.ProductionBranch = model.ProductionBranch
		res.Types = branchworkflow.TypesToAPI(model.Types)
		res.DefaultPRTarget = model.DefaultPRTarget
	}
	ctx.JSON(http.StatusOK, res)
}

// GetBranchingModel returns the branching model of an organization
func GetBranchingModel(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/branching-model organization orgGetBranchingModel
	// ---
	// summary: Get the branching model of an organization
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/OrgBranchingModel"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if !orgWideToken(ctx) {
		return
	}

	renderBranchingModel(ctx)
}

// EditBranchingModel changes the branching model of an organization
func EditBranchingModel(ctx *context.APIContext) {
	// swagger:operation PUT /orgs/{org}/branching-model organization orgEditBranchingModel
	// ---
	// summary: Change the branching model of an organization
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/OrgBranchingModel"
	// responses:
	//   "200":
	//     "$ref": "#/responses/OrgBranchingModel"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if !orgWideToken(ctx) {
		return
	}

	form := web.GetForm(ctx).(*api.OrgBranchingModel)
	err := branchworkflow.SetOrgModel(ctx, ctx.Org().Organization.AsUser(), &repo_model.BranchingModel{DevelopmentBranch: form.DevelopmentBranch, ReleasePrefixes: form.ReleasePrefixes, ProductionBranch: form.ProductionBranch, Types: branchworkflow.TypesFromAPI(form.Types), DefaultPRTarget: form.DefaultPRTarget, MergeForward: form.MergeForward, MergeForwardNeverBypass: form.MergeForwardNeverBypass, MergeForwardAnyoneMaySkip: form.MergeForwardAnyoneMaySkip}, form.Enforce)
	if e, ok := branchworkflow.IsInvalidBranchingModel(err); ok {
		// the cause code is its own field, the message is for people
		ctx.JSON(http.StatusUnprocessableEntity, map[string]string{"message": e.Error(), "reason": e.Reason, "url": setting.API.SwaggerURL})
		return
	}
	if errors.Is(err, branchworkflow.ErrLockWithoutValue) || errors.Is(err, branchworkflow.ErrTooManyReleasePrefixes) || errors.Is(err, branchworkflow.ErrTooManyBranchTypes) {
		ctx.Error(http.StatusUnprocessableEntity, "SetOrgModel", err)
		return
	}
	if err != nil {
		ctx.ServerError("SetOrgModel", err)
		return
	}
	renderBranchingModel(ctx)
}
