// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"errors"
	"net/http"

	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/routers/api/v1/repo"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	pull_service "forgejo.org/services/pull"
)

// ListBranchProtections lists the branch protection rules of an organization
func ListBranchProtections(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/branch_protections organization orgListBranchProtection
	// ---
	// summary: List the branch protection rules of an organization
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
	//     "$ref": "#/responses/OrgBranchProtectionList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	listBranchProtections(ctx, 0)
}

// listBranchProtections lists the rules of the organization (groupID 0) or of its project groupID.
func listBranchProtections(ctx *context.APIContext, groupID int64) {
	rules, err := git_model.FindOrgProtectedBranchRules(ctx, ctx.Org().Organization.ID, groupID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "FindOrgProtectedBranchRules", err)
		return
	}
	apiRules := make([]*api.OrgBranchProtection, 0, len(rules))
	for _, rule := range rules {
		apiRule, ok := toOrgBranchProtection(ctx, rule)
		if !ok {
			return
		}
		apiRules = append(apiRules, apiRule)
	}
	ctx.JSON(http.StatusOK, apiRules)
}

// GetBranchProtection gets a branch protection rule of an organization
func GetBranchProtection(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/branch_protections/{name} organization orgGetBranchProtection
	// ---
	// summary: Get a branch protection rule of an organization
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: name
	//   in: path
	//   description: name of the rule
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/OrgBranchProtection"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	getBranchProtection(ctx, 0)
}

func getBranchProtection(ctx *context.APIContext, groupID int64) {
	rule := getOrgRule(ctx, groupID)
	if rule == nil {
		return
	}
	if apiRule, ok := toOrgBranchProtection(ctx, rule); ok {
		ctx.JSON(http.StatusOK, apiRule)
	}
}

// CreateBranchProtection creates a branch protection rule of an organization
func CreateBranchProtection(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/branch_protections organization orgCreateBranchProtection
	// ---
	// summary: Create a branch protection rule of an organization. It applies to the repositories of the organization in addition to their own rules.
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
	//   schema:
	//     "$ref": "#/definitions/CreateOrgBranchProtectionOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/OrgBranchProtection"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	createBranchProtection(ctx, 0)
}

func createBranchProtection(ctx *context.APIContext, groupID int64) {
	form := web.GetForm(ctx).(*api.CreateOrgBranchProtectionOption)
	org := ctx.Org().Organization

	ruleName := form.RuleName
	if ruleName == "" {
		ctx.Error(http.StatusUnprocessableEntity, "", "rule_name is empty")
		return
	}
	if existing, err := git_model.GetOrgProtectedBranchRuleByName(ctx, org.ID, groupID, ruleName); err != nil {
		ctx.Error(http.StatusInternalServerError, "GetOrgProtectedBranchRuleByName", err)
		return
	} else if existing != nil {
		ctx.Error(http.StatusForbidden, "", "Branch protection already exist")
		return
	}

	rule, opts, ok := repo.BranchProtectionFromCreateOption(ctx, org.AsUser(), ruleName, &form.CreateBranchProtectionOption)
	if !ok {
		return
	}
	rule.ApplyToSelectedRepos = form.ApplyToSelectedRepos
	repoIDs, ok := getRepoIDs(ctx, form.Repos)
	if !ok {
		return
	}
	saveOrgRule(ctx, groupID, rule, opts, repoIDs, http.StatusCreated)
}

// EditBranchProtection edits a branch protection rule of an organization
func EditBranchProtection(ctx *context.APIContext) {
	// swagger:operation PATCH /orgs/{org}/branch_protections/{name} organization orgEditBranchProtection
	// ---
	// summary: Edit a branch protection rule of an organization. Only fields that are set will be changed
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
	// - name: name
	//   in: path
	//   description: name of the rule
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/EditOrgBranchProtectionOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/OrgBranchProtection"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	editBranchProtection(ctx, 0)
}

func editBranchProtection(ctx *context.APIContext, groupID int64) {
	form := web.GetForm(ctx).(*api.EditOrgBranchProtectionOption)
	rule := getOrgRule(ctx, groupID)
	if rule == nil {
		return
	}

	opts, ok := repo.ApplyEditBranchProtectionOption(ctx, ctx.Org().Organization.AsUser(), rule, &form.EditBranchProtectionOption)
	if !ok {
		return
	}
	if form.ApplyToSelectedRepos != nil {
		rule.ApplyToSelectedRepos = *form.ApplyToSelectedRepos
	}
	var repoIDs []int64
	if form.Repos != nil {
		repoIDs, ok = getRepoIDs(ctx, form.Repos)
	} else {
		repoIDs, ok = getRuleRepoIDs(ctx, rule)
	}
	if !ok {
		return
	}
	saveOrgRule(ctx, groupID, rule, opts, repoIDs, http.StatusOK)
}

// DeleteBranchProtection deletes a branch protection rule of an organization
func DeleteBranchProtection(ctx *context.APIContext) {
	// swagger:operation DELETE /orgs/{org}/branch_protections/{name} organization orgDeleteBranchProtection
	// ---
	// summary: Delete a branch protection rule of an organization
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: name
	//   in: path
	//   description: name of the rule
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	deleteBranchProtection(ctx, 0)
}

func deleteBranchProtection(ctx *context.APIContext, groupID int64) {
	rule := getOrgRule(ctx, groupID)
	if rule == nil {
		return
	}
	if err := git_model.DeleteOrgProtectedBranch(ctx, ctx.Org().Organization.ID, groupID, rule.ID); err != nil {
		ctx.Error(http.StatusInternalServerError, "DeleteOrgProtectedBranch", err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

// getOrgRule returns the rule of the organization (groupID 0) or of its project groupID named in the path, or writes
// 404 and returns nil.
func getOrgRule(ctx *context.APIContext, groupID int64) *git_model.ProtectedBranch {
	rule, err := git_model.GetOrgProtectedBranchRuleByName(ctx, ctx.Org().Organization.ID, groupID, ctx.Params(":name"))
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetOrgProtectedBranchRuleByName", err)
		return nil
	}
	if rule == nil {
		ctx.NotFound()
	}
	return rule
}

// getRepoIDs resolves the names of repositories of the organization, or writes 422.
func getRepoIDs(ctx *context.APIContext, names []string) ([]int64, bool) {
	ids := make([]int64, 0, len(names))
	for _, name := range names {
		r, err := repo_model.GetRepositoryByName(ctx, ctx.Org().Organization.ID, name)
		if repo_model.IsErrRepoNotExist(err) {
			ctx.Error(http.StatusUnprocessableEntity, "", "Repository does not exist: "+name)
			return nil, false
		} else if err != nil {
			ctx.Error(http.StatusInternalServerError, "GetRepositoryByName", err)
			return nil, false
		}
		ids = append(ids, r.ID)
	}
	return ids, true
}

func getRuleRepoIDs(ctx *context.APIContext, rule *git_model.ProtectedBranch) ([]int64, bool) {
	ids, err := git_model.GetOrgProtectedBranchRuleRepoIDs(ctx, rule.ID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetOrgProtectedBranchRuleRepoIDs", err)
		return nil, false
	}
	return ids, true
}

func saveOrgRule(ctx *context.APIContext, groupID int64, rule *git_model.ProtectedBranch, opts git_model.WhitelistOptions, repoIDs []int64, status int) {
	err := git_model.UpdateOrgProtectBranch(ctx, ctx.Org().Organization.ID, groupID, rule, opts, repoIDs)
	if errors.Is(err, util.ErrInvalidArgument) {
		ctx.Error(http.StatusUnprocessableEntity, "", err.Error())
		return
	} else if err != nil {
		ctx.Error(http.StatusInternalServerError, "UpdateOrgProtectBranch", err)
		return
	}
	if err := pull_service.CheckPRsForOrgRule(ctx, rule); err != nil {
		ctx.Error(http.StatusInternalServerError, "CheckPRsForOrgRule", err)
		return
	}

	// reload to get the stored allow-lists
	rule, err = git_model.GetOrgProtectedBranchRuleByName(ctx, ctx.Org().Organization.ID, groupID, rule.RuleName)
	if err != nil || rule == nil {
		ctx.Error(http.StatusInternalServerError, "GetOrgProtectedBranchRuleByName", err)
		return
	}
	if apiRule, ok := toOrgBranchProtection(ctx, rule); ok {
		ctx.JSON(status, apiRule)
	}
}

func toOrgBranchProtection(ctx *context.APIContext, rule *git_model.ProtectedBranch) (*api.OrgBranchProtection, bool) {
	ids, ok := getRuleRepoIDs(ctx, rule)
	if !ok {
		return nil, false
	}
	repos, err := repo_model.GetRepositoriesMapByIDs(ctx, ids)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetRepositoriesMapByIDs", err)
		return nil, false
	}
	list := make([]*repo_model.Repository, 0, len(ids))
	for _, id := range ids {
		if r, ok := repos[id]; ok {
			list = append(list, r)
		}
	}
	return convert.ToOrgBranchProtection(ctx, rule, list), true
}
