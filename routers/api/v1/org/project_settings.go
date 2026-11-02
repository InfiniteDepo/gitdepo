// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"net/http"

	api "forgejo.org/modules/structs"
	"forgejo.org/modules/web"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/services/context"
	webhook_service "forgejo.org/services/webhook"
)

// The branch protection rules, webhooks, Actions secrets and variables of a project. The routes sit behind
// reqOrgOwnership; ownedProject refuses a token limited to public or specific repositories and finds the project
// within the organization only, and every reader and writer below binds the project's ID.

// ListProjectBranchProtections is the project form of the organization endpoint
func ListProjectBranchProtections(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/projects/{id}/branch_protections organization orgListProjectBranchProtections
	// ---
	// summary: List the branch protection rules of a project
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/OrgBranchProtectionList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if group := ownedProject(ctx); group != nil {
		listBranchProtections(ctx, group.ID)
	}
}

// GetProjectBranchProtection is the project form of the organization endpoint
func GetProjectBranchProtection(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/projects/{id}/branch_protections/{name} organization orgGetProjectBranchProtection
	// ---
	// summary: Get a branch protection rule of a project
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
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

	if group := ownedProject(ctx); group != nil {
		getBranchProtection(ctx, group.ID)
	}
}

// CreateProjectBranchProtection is the project form of the organization endpoint
func CreateProjectBranchProtection(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/projects/{id}/branch_protections organization orgCreateProjectBranchProtection
	// ---
	// summary: Create a branch protection rule of a project. It applies to every repository of the project; repos and apply_to_selected_repos must be empty.
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
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   required: true
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

	if group := ownedProject(ctx); group != nil {
		createBranchProtection(ctx, group.ID)
	}
}

// EditProjectBranchProtection is the project form of the organization endpoint
func EditProjectBranchProtection(ctx *context.APIContext) {
	// swagger:operation PATCH /orgs/{org}/projects/{id}/branch_protections/{name} organization orgEditProjectBranchProtection
	// ---
	// summary: Edit a branch protection rule of a project. Only fields that are set will be changed
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
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: name
	//   in: path
	//   description: name of the rule
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   required: true
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

	if group := ownedProject(ctx); group != nil {
		editBranchProtection(ctx, group.ID)
	}
}

// DeleteProjectBranchProtection is the project form of the organization endpoint
func DeleteProjectBranchProtection(ctx *context.APIContext) {
	// swagger:operation DELETE /orgs/{org}/projects/{id}/branch_protections/{name} organization orgDeleteProjectBranchProtection
	// ---
	// summary: Delete a branch protection rule of a project
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
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

	if group := ownedProject(ctx); group != nil {
		deleteBranchProtection(ctx, group.ID)
	}
}

// ListProjectHooks is the project form of the organization endpoint
func ListProjectHooks(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/projects/{id}/hooks organization orgListProjectHooks
	// ---
	// summary: List the webhooks of a project
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: page
	//   in: query
	//   description: page number of results to return (1-based)
	//   type: integer
	// - name: limit
	//   in: query
	//   description: page size of results
	//   type: integer
	// responses:
	//   "200":
	//     "$ref": "#/responses/HookList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if group := ownedProject(ctx); group != nil {
		utils.ListOwnerHooks(ctx, ctx.User(), group.ID)
	}
}

// GetProjectHook is the project form of the organization endpoint
func GetProjectHook(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/projects/{id}/hooks/{hook_id} organization orgGetProjectHook
	// ---
	// summary: Get a webhook of a project
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: hook_id
	//   in: path
	//   description: id of the hook
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/Hook"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	group := ownedProject(ctx)
	if group == nil {
		return
	}
	hook, err := utils.GetOwnerHook(ctx, ctx.User().ID, group.ID, ctx.ParamsInt64("hook_id"))
	if err != nil {
		return
	}
	apiHook, err := webhook_service.ToHook(ctx.User().HomeLink(), hook)
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	ctx.JSON(http.StatusOK, apiHook)
}

// CreateProjectHook is the project form of the organization endpoint
func CreateProjectHook(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/projects/{id}/hooks organization orgCreateProjectHook
	// ---
	// summary: Create a webhook of a project. It fires for events of the repositories of the project
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
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/CreateHookOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/Hook"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if group := ownedProject(ctx); group != nil {
		utils.AddOwnerHook(ctx, ctx.User(), group.ID, web.GetForm(ctx).(*api.CreateHookOption))
	}
}

// EditProjectHook is the project form of the organization endpoint
func EditProjectHook(ctx *context.APIContext) {
	// swagger:operation PATCH /orgs/{org}/projects/{id}/hooks/{hook_id} organization orgEditProjectHook
	// ---
	// summary: Update a webhook of a project
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
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: hook_id
	//   in: path
	//   description: id of the hook
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/EditHookOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/Hook"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if group := ownedProject(ctx); group != nil {
		utils.EditOwnerHook(ctx, ctx.User(), group.ID, web.GetForm(ctx).(*api.EditHookOption), ctx.ParamsInt64("hook_id"))
	}
}

// DeleteProjectHook is the project form of the organization endpoint
func DeleteProjectHook(ctx *context.APIContext) {
	// swagger:operation DELETE /orgs/{org}/projects/{id}/hooks/{hook_id} organization orgDeleteProjectHook
	// ---
	// summary: Delete a webhook of a project
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: hook_id
	//   in: path
	//   description: id of the hook
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if group := ownedProject(ctx); group != nil {
		utils.DeleteOwnerHook(ctx, ctx.User(), group.ID, ctx.ParamsInt64("hook_id"))
	}
}

// ListProjectActionsSecrets is the project form of the organization endpoint
func ListProjectActionsSecrets(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/projects/{id}/actions/secrets organization orgListProjectActionsSecrets
	// ---
	// summary: List the Actions secrets of a project
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: page
	//   in: query
	//   description: page number of results to return (1-based)
	//   type: integer
	// - name: limit
	//   in: query
	//   description: page size of results
	//   type: integer
	// responses:
	//   "200":
	//     "$ref": "#/responses/SecretList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if group := ownedProject(ctx); group != nil {
		listSecrets(ctx, group.ID)
	}
}

// CreateOrUpdateProjectSecret is the project form of the organization endpoint
func CreateOrUpdateProjectSecret(ctx *context.APIContext) {
	// swagger:operation PUT /orgs/{org}/projects/{id}/actions/secrets/{secretname} organization orgUpdateProjectSecret
	// ---
	// summary: Create or update a secret of a project
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
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: secretname
	//   in: path
	//   description: name of the secret
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/CreateOrUpdateSecretOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/empty"
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "400":
	//     "$ref": "#/responses/error"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if group := ownedProject(ctx); group != nil {
		createOrUpdateSecret(ctx, group.ID)
	}
}

// DeleteProjectSecret is the project form of the organization endpoint
func DeleteProjectSecret(ctx *context.APIContext) {
	// swagger:operation DELETE /orgs/{org}/projects/{id}/actions/secrets/{secretname} organization orgDeleteProjectSecret
	// ---
	// summary: Delete a secret of a project
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: secretname
	//   in: path
	//   description: name of the secret
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "400":
	//     "$ref": "#/responses/error"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if group := ownedProject(ctx); group != nil {
		deleteSecret(ctx, group.ID)
	}
}

// ListProjectVariables is the project form of the organization endpoint
func ListProjectVariables(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/projects/{id}/actions/variables organization orgListProjectActionsVariables
	// ---
	// summary: List the Actions variables of a project
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: page
	//   in: query
	//   description: page number of results to return (1-based)
	//   type: integer
	// - name: limit
	//   in: query
	//   description: page size of results
	//   type: integer
	// responses:
	//   "200":
	//     "$ref": "#/responses/VariableList"
	//   "400":
	//     "$ref": "#/responses/error"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if group := ownedProject(ctx); group != nil {
		listVariables(ctx, group.ID)
	}
}

// GetProjectVariable is the project form of the organization endpoint
func GetProjectVariable(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/projects/{id}/actions/variables/{variablename} organization orgGetProjectVariable
	// ---
	// summary: Get a variable of a project
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: variablename
	//   in: path
	//   description: name of the variable
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/ActionVariable"
	//   "400":
	//     "$ref": "#/responses/error"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if group := ownedProject(ctx); group != nil {
		getVariable(ctx, group.ID)
	}
}

// CreateProjectVariable is the project form of the organization endpoint
func CreateProjectVariable(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/projects/{id}/actions/variables/{variablename} organization orgCreateProjectVariable
	// ---
	// summary: Create a variable of a project
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
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: variablename
	//   in: path
	//   description: name of the variable
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/CreateVariableOption"
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "400":
	//     "$ref": "#/responses/error"
	//   "409":
	//     "$ref": "#/responses/conflict"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if group := ownedProject(ctx); group != nil {
		createVariable(ctx, group.ID)
	}
}

// UpdateProjectVariable is the project form of the organization endpoint
func UpdateProjectVariable(ctx *context.APIContext) {
	// swagger:operation PUT /orgs/{org}/projects/{id}/actions/variables/{variablename} organization orgUpdateProjectVariable
	// ---
	// summary: Update a variable of a project
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
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: variablename
	//   in: path
	//   description: name of the variable
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/UpdateVariableOption"
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "400":
	//     "$ref": "#/responses/error"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if group := ownedProject(ctx); group != nil {
		updateVariable(ctx, group.ID)
	}
}

// DeleteProjectVariable is the project form of the organization endpoint
func DeleteProjectVariable(ctx *context.APIContext) {
	// swagger:operation DELETE /orgs/{org}/projects/{id}/actions/variables/{variablename} organization orgDeleteProjectVariable
	// ---
	// summary: Delete a variable of a project
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: variablename
	//   in: path
	//   description: name of the variable
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "400":
	//     "$ref": "#/responses/error"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if group := ownedProject(ctx); group != nil {
		deleteVariable(ctx, group.ID)
	}
}
