// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"net/http"
	"strings"

	actions_model "forgejo.org/models/actions"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/services/context"
	trash_service "forgejo.org/services/trash"
)

// ListTrash lists the repositories or organizations in the trash
func ListTrash(ctx *context.APIContext) {
	// swagger:operation GET /admin/trash admin adminListTrash
	// ---
	// summary: List the deleted repositories or organizations in the trash
	// produces:
	// - application/json
	// parameters:
	// - name: q
	//   in: query
	//   description: keyword to match in the owner or repository name, or the organization name
	//   type: string
	// - name: type
	//   in: query
	//   description: the kind of item, repo (default) or org
	//   type: string
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
	//     "$ref": "#/responses/TrashItemList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	items, count, _, err := trash_service.List(ctx, trash_service.ListOptions{
		ListOptions: utils.GetListOptions(ctx),
		Keyword:     ctx.FormTrim("q"),
		Type:        ctx.FormString("type"),
	})
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "List", err)
		return
	}
	res := make([]*api.TrashItem, len(items))
	for i, item := range items {
		if item.Type == "org" {
			res[i] = &api.TrashItem{
				Type:          "org",
				ID:            item.Org.ID,
				FullName:      item.Org.TrashedName,
				DeletedBy:     item.Org.TrashedByName,
				Deleted:       item.Org.TrashedUnix.AsTime(),
				DaysRemaining: item.DaysRemaining,
				Size:          item.Size,
				Purging:       item.Purging,
				RepoCount:     item.RepoCount,
			}
			continue
		}
		res[i] = &api.TrashItem{
			Type:          "repo",
			ID:            item.Repo.ID,
			FullName:      item.Repo.TrashedFullName(),
			DeletedBy:     item.Repo.TrashedByName,
			Deleted:       item.Repo.TrashedUnix.AsTime(),
			DaysRemaining: item.DaysRemaining,
			Size:          item.Repo.Size,
			Purging:       item.Purging,
		}
	}
	ctx.SetTotalCountHeader(count)
	ctx.JSON(http.StatusOK, res)
}

// trashedItem checks the path: it returns the kind of item ("repo" or "org") and its id if it is in the trash, or
// writes the error response. An unknown kind or an item that is not in the trash is a 404.
func trashedItem(ctx *context.APIContext) (kind string, id int64, ok bool) {
	kind, id = ctx.Params(":type"), ctx.ParamsInt64(":id")
	switch kind {
	case "repo":
		repo, err := repo_model.GetRepositoryByIDIncludingTrashed(ctx, id)
		if err != nil && !repo_model.IsErrRepoNotExist(err) {
			ctx.Error(http.StatusInternalServerError, "GetRepositoryByIDIncludingTrashed", err)
			return "", 0, false
		}
		if err != nil || !repo.IsTrashed() {
			ctx.NotFound()
			return "", 0, false
		}
	case "org":
		org, err := user_model.GetUserByIDIncludingTrashed(ctx, id)
		if err != nil && !user_model.IsErrUserNotExist(err) {
			ctx.Error(http.StatusInternalServerError, "GetUserByIDIncludingTrashed", err)
			return "", 0, false
		}
		if err != nil || !org.IsOrganization() || !org.IsTrashed() {
			ctx.NotFound()
			return "", 0, false
		}
	default:
		ctx.NotFound()
		return "", 0, false
	}
	return kind, id, true
}

func trashError(ctx *context.APIContext, err error) {
	switch {
	case errors.Is(err, trash_service.ErrTrashConflict):
		ctx.Error(http.StatusConflict, "ErrTrashConflict", err)
	case errors.Is(err, trash_service.ErrNeedNewOwner), errors.Is(err, trash_service.ErrInvalidNewOwner),
		errors.Is(err, trash_service.ErrTrashedWithOrg), trash_service.IsBadTarget(err), errors.Is(err, actions_model.ErrEnvironmentTwin):
		ctx.Error(http.StatusUnprocessableEntity, "restore", err)
	case errors.Is(err, trash_service.ErrOrgHasLiveRepos):
		ctx.Error(http.StatusConflict, "ErrOrgHasLiveRepos", err)
	case errors.Is(err, util.ErrPermissionDenied):
		ctx.Error(http.StatusForbidden, "restore", err)
	default:
		ctx.Error(http.StatusInternalServerError, "trash", err)
	}
}

// RestoreTrash restores a repository or organization from the trash
func RestoreTrash(ctx *context.APIContext) {
	// swagger:operation POST /admin/trash/{type}/{id}/restore admin adminRestoreTrash
	// ---
	// summary: Restore a deleted repository or organization from the trash
	// description: A repository can be restored under a new owner and/or name. Its collaborators keep their access, the teams of the old organization do not. A restored organization may have no owner, if its last owner was deleted while it was in the trash; a site admin can add one.
	// consumes:
	// - application/json
	// parameters:
	// - name: type
	//   in: path
	//   description: the kind of item, "repo" or "org"
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the item
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/RestoreTrashOption"
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     "$ref": "#/responses/error"
	//   "422":
	//     "$ref": "#/responses/validationError"
	kind, id, ok := trashedItem(ctx)
	if !ok {
		return
	}
	// the body is optional: a plain restore sends none
	var form api.RestoreTrashOption
	if ctx.Req.ContentLength != 0 {
		if err := json.NewDecoder(ctx.Req.Body).Decode(&form); err != nil {
			ctx.Error(http.StatusUnprocessableEntity, "body", err)
			return
		}
	}
	opts := trash_service.RestoreOptions{NewOwner: strings.TrimSpace(form.NewOwner), NewName: strings.TrimSpace(form.NewName)}
	var err error
	if kind == "org" {
		if opts.NewOwner != "" {
			ctx.Error(http.StatusUnprocessableEntity, "new_owner", "an organization has no owner to change")
			return
		}
		err = trash_service.RestoreOrg(ctx, ctx.Doer(), id, opts)
	} else {
		err = trash_service.RestoreRepo(ctx, ctx.Doer(), id, opts)
	}
	if err != nil {
		trashError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

// PurgeTrash deletes a repository or organization in the trash for good
func PurgeTrash(ctx *context.APIContext) {
	// swagger:operation DELETE /admin/trash/{type}/{id} admin adminPurgeTrash
	// ---
	// summary: Delete a repository or organization in the trash permanently; an organization takes the repositories in the trash it owns with it
	// parameters:
	// - name: type
	//   in: path
	//   description: the kind of item, "repo" or "org"
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the item
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
	//   "409":
	//     "$ref": "#/responses/error"
	kind, id, ok := trashedItem(ctx)
	if !ok {
		return
	}
	var err error
	if kind == "org" {
		err = trash_service.PurgeOrg(ctx, ctx.Doer(), id)
	} else {
		err = trash_service.Purge(ctx, ctx.Doer(), id)
	}
	if err != nil {
		trashError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}
