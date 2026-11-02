// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	asymkey_model "forgejo.org/models/asymkey"
	"forgejo.org/models/organization"
	access_model "forgejo.org/models/perm/access"
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

// orgWideToken refuses a token limited to public resources or to specific repositories: an organization deploy
// key reaches every repository of the organization, private ones included.
func orgWideToken(ctx *context.APIContext) bool {
	if !utils.IsOrgWideToken(ctx) {
		ctx.Error(http.StatusForbidden, "orgWideToken", "the token must not be limited to public or specific repositories")
		return false
	}
	return true
}

// HideInvisibleOrg answers 404 to a doer who can't see the organization, before the owner check would tell it exists.
func HideInvisibleOrg(ctx *context.APIContext) {
	if !organization.HasOrgOrUserVisible(ctx, ctx.Org().Organization.AsUser(), ctx.Doer()) {
		ctx.NotFound()
	}
}

func orgDeployKeysLink(ctx *context.APIContext) string {
	return setting.AppURL + "api/v1/orgs/" + url.PathEscape(ctx.Org().Organization.Name) + "/keys"
}

func toOrgDeployKey(ctx *context.APIContext, key *asymkey_model.OrgDeployKey) (*api.OrgDeployKey, bool) {
	pkey, err := asymkey_model.GetPublicKeyByID(ctx, key.KeyID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetPublicKeyByID", err)
		return nil, false
	}
	return convert.ToOrgDeployKey(orgDeployKeysLink(ctx), pkey.Content, key), true
}

// getOrgDeployKey loads the key of the URL; a key of another organization is not found.
func getOrgDeployKey(ctx *context.APIContext) *asymkey_model.OrgDeployKey {
	if !orgWideToken(ctx) {
		return nil
	}
	key, err := asymkey_model.GetOrgDeployKey(ctx, ctx.Org().Organization.ID, 0, ctx.ParamsInt64(":id"))
	if err != nil {
		if asymkey_model.IsErrDeployKeyNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetOrgDeployKey", err)
		}
		return nil
	}
	return key
}

// maxOrgDeployKeyRepos caps the repository names of one request.
const maxOrgDeployKeyRepos = 1000

// orgRepoIDs resolves repository names of the organization; a name outside it is refused.
func orgRepoIDs(ctx *context.APIContext, names []string) ([]int64, bool) {
	// names are case-insensitive: dedupe them as stored
	lower := make([]string, 0, len(names))
	for _, name := range names {
		lower = append(lower, strings.ToLower(name))
	}
	names = slices.Compact(slices.Sorted(slices.Values(lower)))
	if len(names) > maxOrgDeployKeyRepos {
		ctx.Error(http.StatusUnprocessableEntity, "", fmt.Sprintf("at most %d repositories", maxOrgDeployKeyRepos))
		return nil, false
	}
	ids := make([]int64, 0, len(names))
	for _, name := range names {
		r, err := repo_model.GetRepositoryByName(ctx, ctx.Org().Organization.ID, name)
		if err != nil {
			if repo_model.IsErrRepoNotExist(err) {
				ctx.Error(http.StatusUnprocessableEntity, "", "repository not found in the organization: "+name)
			} else {
				ctx.Error(http.StatusInternalServerError, "GetRepositoryByName", err)
			}
			return nil, false
		}
		ids = append(ids, r.ID)
	}
	return ids, true
}

// orgRepo loads the repository {repo} of the organization.
func orgRepo(ctx *context.APIContext) *repo_model.Repository {
	r, err := repo_model.GetRepositoryByName(ctx, ctx.Org().Organization.ID, ctx.Params(":repo"))
	if err != nil {
		if repo_model.IsErrRepoNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetRepositoryByName", err)
		}
		return nil
	}
	return r
}

// orgDeployKeyError answers an error of a change of an organization deploy key.
func orgDeployKeyError(ctx *context.APIContext, err error) {
	switch { // the typed errors first: ErrDeployKeyNameAlreadyUsed unwraps to ErrNotExist
	case asymkey_model.IsErrDeployKeyAlreadyExist(err):
		ctx.Error(http.StatusUnprocessableEntity, "", "the organization already has this key")
	case asymkey_model.IsErrDeployKeyNameAlreadyUsed(err):
		ctx.Error(http.StatusUnprocessableEntity, "", "a key with the same name already exists")
	case asymkey_model.IsErrKeyAlreadyExist(err):
		ctx.Error(http.StatusUnprocessableEntity, "", "the key is already used as a user's key")
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Error(http.StatusUnprocessableEntity, "", err.Error())
	case asymkey_model.IsErrDeployKeyNotExist(err), errors.Is(err, util.ErrNotExist):
		ctx.NotFound()
	default:
		ctx.Error(http.StatusInternalServerError, "", err)
	}
}

// ListDeployKeys lists the deploy keys of an organization
func ListDeployKeys(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/keys organization orgListDeployKeys
	// ---
	// summary: List the deploy keys of an organization
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
	//     "$ref": "#/responses/OrgDeployKeyList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if !orgWideToken(ctx) {
		return
	}
	keys, err := asymkey_model.FindOrgDeployKeys(ctx, ctx.Org().Organization.ID, 0)
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
		k, ok := toOrgDeployKey(ctx, key)
		if !ok {
			return
		}
		out = append(out, k)
	}
	ctx.JSON(http.StatusOK, out)
}

// GetDeployKey gets a deploy key of an organization
func GetDeployKey(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/keys/{id} organization orgGetDeployKey
	// ---
	// summary: Get a deploy key of an organization
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

	key := getOrgDeployKey(ctx)
	if key == nil {
		return
	}
	if k, ok := toOrgDeployKey(ctx, key); ok {
		ctx.JSON(http.StatusOK, k)
	}
}

// CreateDeployKey adds a deploy key to an organization
func CreateDeployKey(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/keys organization orgCreateDeployKey
	// ---
	// summary: Add a deploy key to an organization, for all its repositories or the selected ones
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
	//     "$ref": "#/definitions/CreateOrgDeployKeyOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/OrgDeployKey"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if !orgWideToken(ctx) {
		return
	}
	form := web.GetForm(ctx).(*api.CreateOrgDeployKeyOption)
	if form.AllRepositories && len(form.Repositories) > 0 {
		ctx.Error(http.StatusUnprocessableEntity, "", "all_repositories can't be combined with repositories")
		return
	}
	content, err := asymkey_model.CheckPublicKeyString(form.Key)
	if err != nil {
		repo.HandleCheckKeyStringError(ctx, err)
		return
	}
	expires, ok := utils.ValidateExpiry(ctx, setting.DeployKeyExpiry, form.ExpiresAt)
	if !ok {
		return
	}
	repoIDs, ok := orgRepoIDs(ctx, form.Repositories)
	if !ok {
		return
	}
	key, err := asymkey_model.AddOrgDeployKey(ctx, ctx.Org().Organization.ID, 0, strings.TrimSpace(form.Title), content, form.ReadOnly, form.AllRepositories, repoIDs, expires)
	if err != nil {
		orgDeployKeyError(ctx, err)
		return
	}
	ctx.JSON(http.StatusCreated, convert.ToOrgDeployKey(orgDeployKeysLink(ctx), content, key))
}

// EditDeployKey changes which repositories a deploy key of an organization covers
func EditDeployKey(ctx *context.APIContext) {
	// swagger:operation PATCH /orgs/{org}/keys/{id} organization orgEditDeployKey
	// ---
	// summary: Change which repositories a deploy key of an organization covers
	// description: The title, the key, its access mode and its expiry can't be changed. An empty body is refused.
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
	//   description: id of the key
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/EditOrgDeployKeyOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/OrgDeployKey"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	key := getOrgDeployKey(ctx)
	if key == nil {
		return
	}
	form := web.GetForm(ctx).(*api.EditOrgDeployKeyOption)
	orgID := ctx.Org().Organization.ID
	switch {
	case form.AllRepositories == nil && form.Repositories == nil:
		ctx.Error(http.StatusUnprocessableEntity, "", "set all_repositories or repositories")
		return
	case form.Repositories != nil && form.AllRepositories != nil && *form.AllRepositories:
		ctx.Error(http.StatusUnprocessableEntity, "", "all_repositories can't be combined with repositories")
		return
	case form.Repositories != nil:
		repoIDs, ok := orgRepoIDs(ctx, *form.Repositories)
		if !ok {
			return
		}
		if err := asymkey_service.SetOrgDeployKeyRepos(ctx, orgID, key.ID, false, repoIDs); err != nil {
			orgDeployKeyError(ctx, err)
			return
		}
	default: // only all_repositories: switch to all, or back to the existing selection
		if err := asymkey_service.SetOrgDeployKeyAllRepos(ctx, orgID, key.ID, *form.AllRepositories); err != nil {
			orgDeployKeyError(ctx, err)
			return
		}
	}
	if key = getOrgDeployKey(ctx); key == nil {
		return
	}
	if k, ok := toOrgDeployKey(ctx, key); ok {
		ctx.JSON(http.StatusOK, k)
	}
}

// DeleteDeployKey deletes a deploy key of an organization
func DeleteDeployKey(ctx *context.APIContext) {
	// swagger:operation DELETE /orgs/{org}/keys/{id} organization orgDeleteDeployKey
	// ---
	// summary: Delete a deploy key of an organization
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
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

	if !orgWideToken(ctx) {
		return
	}
	if err := asymkey_service.DeleteOrgDeployKey(ctx, ctx.Org().Organization.ID, 0, ctx.ParamsInt64(":id")); err != nil {
		orgDeployKeyError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

// ListDeployKeyRepos lists the selected repositories of a deploy key of an organization
func ListDeployKeyRepos(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/keys/{id}/repos organization orgListDeployKeyRepos
	// ---
	// summary: List the selected repositories of a deploy key of an organization
	// description: A key that covers all repositories has no selected repositories.
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
	//   description: id of the key
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
	//     "$ref": "#/responses/RepositoryList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	key := getOrgDeployKey(ctx)
	if key == nil {
		return
	}
	opts := utils.GetListOptions(ctx)
	if opts.Page < 1 {
		opts.Page = 1
	}
	repos, count, err := asymkey_model.FindOrgDeployKeyRepos(ctx, key.ID, opts)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "FindOrgDeployKeyRepos", err)
		return
	}
	out := make([]*api.Repository, 0, len(repos))
	for _, r := range repos {
		permission, err := access_model.GetUserRepoPermission(ctx, r, ctx.Doer())
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "GetUserRepoPermission", err)
			return
		}
		out = append(out, convert.ToRepo(ctx, r, permission))
	}
	ctx.SetTotalCountHeader(count)
	ctx.JSON(http.StatusOK, out)
}

// AddDeployKeyRepo adds a repository to the selection of a deploy key of an organization
func AddDeployKeyRepo(ctx *context.APIContext) {
	// swagger:operation PUT /orgs/{org}/keys/{id}/repos/{repo} organization orgAddDeployKeyRepo
	// ---
	// summary: Add a repository to the selection of a deploy key of an organization
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the key
	//   type: integer
	//   format: int64
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of a repository of the organization
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	key := getOrgDeployKey(ctx)
	if key == nil {
		return
	}
	r := orgRepo(ctx)
	if r == nil {
		return
	}
	if err := asymkey_service.AddOrgDeployKeyRepo(ctx, ctx.Org().Organization.ID, key.ID, r); err != nil {
		orgDeployKeyError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

// RemoveDeployKeyRepo removes a repository from the selection of a deploy key of an organization
func RemoveDeployKeyRepo(ctx *context.APIContext) {
	// swagger:operation DELETE /orgs/{org}/keys/{id}/repos/{repo} organization orgRemoveDeployKeyRepo
	// ---
	// summary: Remove a repository from the selection of a deploy key of an organization
	// description: The last selected repository can't be removed.
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the key
	//   type: integer
	//   format: int64
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of a repository of the organization
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	key := getOrgDeployKey(ctx)
	if key == nil {
		return
	}
	r := orgRepo(ctx)
	if r == nil {
		return
	}
	if err := asymkey_service.RemoveOrgDeployKeyRepo(ctx, ctx.Org().Organization.ID, key.ID, r); err != nil {
		orgDeployKeyError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}
