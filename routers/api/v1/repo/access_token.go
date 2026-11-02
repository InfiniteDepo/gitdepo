// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	auth_model "forgejo.org/models/auth"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/services/context"
)

func repoTokenOwner(ctx *context.APIContext) utils.OwnedTokenOwner {
	return utils.OwnedTokenOwner{Type: auth_model.AccessTokenOwnerRepo, ID: ctx.Repo().Repository.ID}
}

// ListAccessTokens lists the access tokens of a repository
func ListAccessTokens(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/tokens repository repoListAccessTokens
	// ---
	// summary: List the access tokens of a repository
	// description: Tokens that belong to the repository, not to a user. Their values are never shown again.
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

	utils.ListOwnedAccessTokens(ctx, repoTokenOwner(ctx))
}

// CreateAccessToken creates an access token of a repository
func CreateAccessToken(ctx *context.APIContext) {
	// swagger:operation POST /repos/{owner}/{repo}/tokens repository repoCreateAccessToken
	// ---
	// summary: Create an access token of a repository
	// description: The token belongs to the repository, not to a user, and acts as its own identity with the given permission on this repository only. A token creating it must hold every scope it grants and must not expire before it.
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

	utils.CreateOwnedAccessToken(ctx, repoTokenOwner(ctx))
}

// DeleteAccessToken deletes an access token of a repository
func DeleteAccessToken(ctx *context.APIContext) {
	// swagger:operation DELETE /repos/{owner}/{repo}/tokens/{id} repository repoDeleteAccessToken
	// ---
	// summary: Delete (revoke) an access token of a repository
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

	utils.DeleteOwnedAccessToken(ctx, repoTokenOwner(ctx), ctx.ParamsInt64(":id"))
}

// RotateAccessToken rotates an access token of a repository
func RotateAccessToken(ctx *context.APIContext) {
	// swagger:operation POST /repos/{owner}/{repo}/tokens/{id}/rotate repository repoRotateAccessToken
	// ---
	// summary: Rotate an access token of a repository, giving it a new secret shown only in this answer and keeping everything else
	// description: The old secret stops working at once. An expired token may be rotated.
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

	utils.RotateOwnedAccessToken(ctx, repoTokenOwner(ctx), ctx.ParamsInt64(":id"))
}
