// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	asymkey_model "forgejo.org/models/asymkey"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/routers/api/v1/repo"
	"forgejo.org/routers/api/v1/utils"
	asymkey_service "forgejo.org/services/asymkey"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

func projectDeployKeysLink(ctx *context.APIContext, group *repo_model.RepoGroup) string {
	return setting.AppURL + "api/v1/orgs/" + url.PathEscape(ctx.Org().Organization.Name) + "/projects/" + strconv.FormatInt(group.ID, 10) + "/keys"
}

// getProjectDeployKey loads the project `{id}` and its key `{key_id}`; a key of the organization or another project
// is not found.
func getProjectDeployKey(ctx *context.APIContext) (*repo_model.RepoGroup, *asymkey_model.OrgDeployKey) {
	group := ownedProject(ctx)
	if group == nil {
		return nil, nil
	}
	key, err := asymkey_model.GetOrgDeployKey(ctx, ctx.Org().Organization.ID, group.ID, ctx.ParamsInt64(":key_id"))
	if err != nil {
		orgDeployKeyError(ctx, err)
		return nil, nil
	}
	return group, key
}

func toProjectDeployKey(ctx *context.APIContext, group *repo_model.RepoGroup, key *asymkey_model.OrgDeployKey) (*api.OrgDeployKey, bool) {
	pkey, err := asymkey_model.GetPublicKeyByID(ctx, key.KeyID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetPublicKeyByID", err)
		return nil, false
	}
	return convert.ToOrgDeployKey(projectDeployKeysLink(ctx, group), pkey.Content, key), true
}

// ListProjectDeployKeys lists the deploy keys of a project
func ListProjectDeployKeys(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/projects/{id}/keys organization orgListProjectDeployKeys
	// ---
	// summary: List the deploy keys of a project
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
	//     "$ref": "#/responses/OrgDeployKeyList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	group := ownedProject(ctx)
	if group == nil {
		return
	}
	keys, err := asymkey_model.FindOrgDeployKeys(ctx, ctx.Org().Organization.ID, group.ID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "FindOrgDeployKeys", err)
		return
	}
	ctx.SetTotalCountHeader(int64(len(keys)))
	opts := utils.GetListOptions(ctx)
	if opts.Page < 1 {
		opts.Page = 1
	}
	page := util.PaginateSlice(keys, opts.Page, opts.PageSize).([]*asymkey_model.OrgDeployKey)
	out := make([]*api.OrgDeployKey, 0, len(page))
	for _, key := range page {
		k, ok := toProjectDeployKey(ctx, group, key)
		if !ok {
			return
		}
		out = append(out, k)
	}
	ctx.JSON(http.StatusOK, out)
}

// GetProjectDeployKey gets a deploy key of a project
func GetProjectDeployKey(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/projects/{id}/keys/{key_id} organization orgGetProjectDeployKey
	// ---
	// summary: Get a deploy key of a project
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
	// - name: key_id
	//   in: path
	//   description: id of the key
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/OrgDeployKey"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	group, key := getProjectDeployKey(ctx)
	if key == nil {
		return
	}
	if k, ok := toProjectDeployKey(ctx, group, key); ok {
		ctx.JSON(http.StatusOK, k)
	}
}

// CreateProjectDeployKey adds a deploy key to a project
func CreateProjectDeployKey(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/projects/{id}/keys organization orgCreateProjectDeployKey
	// ---
	// summary: Add a deploy key to a project, for every repository in it
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
	//     "$ref": "#/definitions/CreateKeyOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/OrgDeployKey"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	group := ownedProject(ctx)
	if group == nil {
		return
	}
	form := web.GetForm(ctx).(*api.CreateKeyOption)
	content, err := asymkey_model.CheckPublicKeyString(form.Key)
	if err != nil {
		repo.HandleCheckKeyStringError(ctx, err)
		return
	}
	expires, ok := utils.ValidateExpiry(ctx, setting.DeployKeyExpiry, form.ExpiresAt)
	if !ok {
		return
	}
	key, err := asymkey_model.AddOrgDeployKey(ctx, ctx.Org().Organization.ID, group.ID, strings.TrimSpace(form.Title), content, form.ReadOnly, false, nil, expires)
	if err != nil {
		orgDeployKeyError(ctx, err)
		return
	}
	ctx.JSON(http.StatusCreated, convert.ToOrgDeployKey(projectDeployKeysLink(ctx, group), content, key))
}

// DeleteProjectDeployKey deletes a deploy key of a project
func DeleteProjectDeployKey(ctx *context.APIContext) {
	// swagger:operation DELETE /orgs/{org}/projects/{id}/keys/{key_id} organization orgDeleteProjectDeployKey
	// ---
	// summary: Delete a deploy key of a project
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
	// - name: key_id
	//   in: path
	//   description: id of the key
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

	group := ownedProject(ctx)
	if group == nil {
		return
	}
	if err := asymkey_service.DeleteOrgDeployKey(ctx, ctx.Org().Organization.ID, group.ID, ctx.ParamsInt64(":key_id")); err != nil {
		orgDeployKeyError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}
