// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"errors"
	"net/http"

	repo_model "forgejo.org/models/repo"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/web"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/context"
)

func renderBranchWorkflow(ctx *context.APIContext) {
	eff, err := branchworkflow.GetEffective(ctx, ctx.Repo().Repository)
	if err != nil {
		ctx.ServerError("GetEffective", err)
		return
	}
	res := &api.RepoBranchWorkflow{
		DeleteBranchAfterMerge:          eff.Configured.String(),
		EffectiveDeleteBranchAfterMerge: eff.Mode.String(),
		Source:                          eff.Source,
		Locked:                          eff.Locked,
	}
	if eff.Locked {
		res.LockedBy = eff.SetBy
	}
	ctx.JSON(http.StatusOK, res)
}

// GetBranchWorkflow returns the branch workflow settings of a repository
func GetBranchWorkflow(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/branch-workflow repository repoGetBranchWorkflow
	// ---
	// summary: Get the branch workflow settings of a repository, with the effective value and where it comes from
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/RepoBranchWorkflow"
	//   "404":
	//     "$ref": "#/responses/notFound"

	renderBranchWorkflow(ctx)
}

// EditBranchWorkflow changes the branch workflow settings of a repository
func EditBranchWorkflow(ctx *context.APIContext) {
	// swagger:operation PUT /repos/{owner}/{repo}/branch-workflow repository repoEditBranchWorkflow
	// ---
	// summary: Change the branch workflow settings of a repository
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/EditRepoBranchWorkflowOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/RepoBranchWorkflow"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	form := web.GetForm(ctx).(*api.EditRepoBranchWorkflowOption)
	mode, ok := repo_model.ParseDeleteBranchMode(form.DeleteBranchAfterMerge)
	if !ok {
		ctx.Error(http.StatusUnprocessableEntity, "DeleteBranchAfterMerge", "must be one of inherit, off, default-on, always")
		return
	}
	switch err := branchworkflow.SetRepo(ctx, ctx.Repo().Repository, mode); {
	case errors.Is(err, branchworkflow.ErrLocked):
		ctx.Error(http.StatusForbidden, "SetRepo", err)
	case errors.Is(err, branchworkflow.ErrNoPullRequests):
		ctx.Error(http.StatusUnprocessableEntity, "SetRepo", err)
	case err != nil:
		ctx.ServerError("SetRepo", err)
	default:
		renderBranchWorkflow(ctx)
	}
}

func renderBranchingModel(ctx *context.APIContext) {
	repo := ctx.Repo().Repository
	eff, err := branchworkflow.GetEffectiveModel(ctx, repo)
	if err != nil {
		ctx.ServerError("GetEffectiveModel", err)
		return
	}
	chain, err := branchworkflow.GetChain(ctx, repo, eff)
	if err != nil {
		ctx.ServerError("GetChain", err)
		return
	}
	res := &api.RepoBranchingModel{
		Inherit: eff.Configured == nil,
		Effective: api.BranchingModel{
			DevelopmentBranch:         eff.DevelopmentBranch(repo),
			ReleasePrefixes:           append([]string{}, eff.Model.ReleasePrefixes...),
			ProductionBranch:          eff.Model.ProductionBranch,
			MergeForward:              eff.Model.MergeForward,
			MergeForwardNeverBypass:   eff.Model.MergeForwardNeverBypass,
			MergeForwardAnyoneMaySkip: eff.Model.MergeForwardAnyoneMaySkip,
		},
		Source:          eff.Source,
		Locked:          eff.Locked,
		ReleaseBranches: append([]string{}, chain.Releases...),
		IgnoredBranches: append([]string{}, chain.Ignored...),
	}
	if eff.Configured != nil {
		res.Own = &api.BranchingModel{DevelopmentBranch: eff.Configured.DevelopmentBranch, ReleasePrefixes: append([]string{}, eff.Configured.ReleasePrefixes...), ProductionBranch: eff.Configured.ProductionBranch, MergeForward: eff.Configured.MergeForward, MergeForwardNeverBypass: eff.Configured.MergeForwardNeverBypass, MergeForwardAnyoneMaySkip: eff.Configured.MergeForwardAnyoneMaySkip}
	}
	if eff.Locked {
		res.LockedBy = eff.SetBy
	}
	ctx.JSON(http.StatusOK, res)
}

// GetBranchingModel returns the branching model of a repository
func GetBranchingModel(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/branching-model repository repoGetBranchingModel
	// ---
	// summary: Get the branching model of a repository, where it comes from, and its release branches in version order
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/RepoBranchingModel"
	//   "404":
	//     "$ref": "#/responses/notFound"

	renderBranchingModel(ctx)
}

// EditBranchingModel changes the branching model of a repository
func EditBranchingModel(ctx *context.APIContext) {
	// swagger:operation PUT /repos/{owner}/{repo}/branching-model repository repoEditBranchingModel
	// ---
	// summary: Change the branching model of a repository
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/EditRepoBranchingModelOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/RepoBranchingModel"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	form := web.GetForm(ctx).(*api.EditRepoBranchingModelOption)
	var model *repo_model.BranchingModel
	if !form.Inherit {
		model = &repo_model.BranchingModel{DevelopmentBranch: form.DevelopmentBranch, ReleasePrefixes: form.ReleasePrefixes, ProductionBranch: form.ProductionBranch, MergeForward: form.MergeForward, MergeForwardNeverBypass: form.MergeForwardNeverBypass, MergeForwardAnyoneMaySkip: form.MergeForwardAnyoneMaySkip}
	}
	err := branchworkflow.SetRepoModel(ctx, ctx.Repo().Repository, model)
	if _, ok := branchworkflow.IsInvalidBranchingModel(err); ok || errors.Is(err, branchworkflow.ErrTooManyReleasePrefixes) {
		ctx.Error(http.StatusUnprocessableEntity, "SetRepoModel", err)
		return
	}
	switch {
	case errors.Is(err, branchworkflow.ErrLocked):
		ctx.Error(http.StatusForbidden, "SetRepoModel", err)
	case errors.Is(err, branchworkflow.ErrNoPullRequests):
		ctx.Error(http.StatusUnprocessableEntity, "SetRepoModel", err)
	case err != nil:
		ctx.ServerError("SetRepoModel", err)
	default:
		renderBranchingModel(ctx)
	}
}
