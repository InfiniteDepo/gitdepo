// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	auth_model "forgejo.org/models/auth"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/services/context"
)

// orgTokenOwner names the organization's own tokens; a token limited to public or specific repositories can't manage
// them.
func orgTokenOwner(ctx *context.APIContext) (utils.OwnedTokenOwner, bool) {
	if !orgWideToken(ctx) {
		return utils.OwnedTokenOwner{}, false
	}
	org := ctx.Org().Organization
	return utils.OwnedTokenOwner{Type: auth_model.AccessTokenOwnerOrg, ID: org.ID, OrgName: org.Name}, true
}

// projectTokenOwner names the tokens of the project of the URL.
func projectTokenOwner(ctx *context.APIContext) (utils.OwnedTokenOwner, bool) {
	group := ownedProject(ctx)
	if group == nil {
		return utils.OwnedTokenOwner{}, false
	}
	return utils.OwnedTokenOwner{Type: auth_model.AccessTokenOwnerProject, ID: ctx.Org().Organization.ID, GroupID: group.ID}, true
}

// ListAccessTokens lists the access tokens of an organization
func ListAccessTokens(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/tokens organization orgListAccessTokens
	// ---
	// summary: List the access tokens of an organization
	// description: Tokens that belong to the organization, not to a user. Their values are never shown again.
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
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
	//     "$ref": "#/responses/AccessTokenList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if owner, ok := orgTokenOwner(ctx); ok {
		utils.ListOwnedAccessTokens(ctx, owner)
	}
}

// CreateAccessToken creates an access token of an organization
func CreateAccessToken(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/tokens organization orgCreateAccessToken
	// ---
	// summary: Create an access token of an organization
	// description: The token belongs to the organization, not to a user, and acts as its own identity with the given permission on every repository of the organization, or only on the selected ones. A token creating it must hold every scope it grants and must not expire before it.
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
	//     "$ref": "#/definitions/CreateOwnedAccessTokenOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/AccessToken"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if owner, ok := orgTokenOwner(ctx); ok {
		utils.CreateOwnedAccessToken(ctx, owner)
	}
}

// DeleteAccessToken deletes an access token of an organization
func DeleteAccessToken(ctx *context.APIContext) {
	// swagger:operation DELETE /orgs/{org}/tokens/{id} organization orgDeleteAccessToken
	// ---
	// summary: Delete (revoke) an access token of an organization
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the token
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

	if owner, ok := orgTokenOwner(ctx); ok {
		utils.DeleteOwnedAccessToken(ctx, owner, ctx.ParamsInt64(":id"))
	}
}

// ListProjectAccessTokens lists the access tokens of a project
func ListProjectAccessTokens(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/projects/{id}/tokens organization orgProjectListAccessTokens
	// ---
	// summary: List the access tokens of a project
	// description: Tokens that belong to the project, not to a user. Their values are never shown again.
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
	//     "$ref": "#/responses/AccessTokenList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if owner, ok := projectTokenOwner(ctx); ok {
		utils.ListOwnedAccessTokens(ctx, owner)
	}
}

// CreateProjectAccessToken creates an access token of a project
func CreateProjectAccessToken(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/projects/{id}/tokens organization orgProjectCreateAccessToken
	// ---
	// summary: Create an access token of a project
	// description: The token belongs to the project, not to a user, and acts as its own identity with the given permission on every repository in the project. A token creating it must hold every scope it grants and must not expire before it.
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
	//   schema:
	//     "$ref": "#/definitions/CreateOwnedAccessTokenOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/AccessToken"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if owner, ok := projectTokenOwner(ctx); ok {
		utils.CreateOwnedAccessToken(ctx, owner)
	}
}

// DeleteProjectAccessToken deletes an access token of a project
func DeleteProjectAccessToken(ctx *context.APIContext) {
	// swagger:operation DELETE /orgs/{org}/projects/{id}/tokens/{token_id} organization orgProjectDeleteAccessToken
	// ---
	// summary: Delete (revoke) an access token of a project
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
	// - name: token_id
	//   in: path
	//   description: id of the token
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

	if owner, ok := projectTokenOwner(ctx); ok {
		utils.DeleteOwnedAccessToken(ctx, owner, ctx.ParamsInt64(":token_id"))
	}
}

// RotateAccessToken rotates an access token of an organization
func RotateAccessToken(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/tokens/{id}/rotate organization orgRotateAccessToken
	// ---
	// summary: Rotate an access token of an organization, giving it a new secret shown only in this answer and keeping everything else
	// description: The old secret stops working at once. An expired token may be rotated.
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
	//   description: id of the token
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/RotateOwnedAccessTokenOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/AccessToken"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if owner, ok := orgTokenOwner(ctx); ok {
		utils.RotateOwnedAccessToken(ctx, owner, ctx.ParamsInt64(":id"))
	}
}

// RotateProjectAccessToken rotates an access token of a project
func RotateProjectAccessToken(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/projects/{id}/tokens/{token_id}/rotate organization orgProjectRotateAccessToken
	// ---
	// summary: Rotate an access token of a project, giving it a new secret shown only in this answer and keeping everything else
	// description: The old secret stops working at once. An expired token may be rotated.
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
	// - name: token_id
	//   in: path
	//   description: id of the token
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/RotateOwnedAccessTokenOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/AccessToken"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if owner, ok := projectTokenOwner(ctx); ok {
		utils.RotateOwnedAccessToken(ctx, owner, ctx.ParamsInt64(":token_id"))
	}
}
