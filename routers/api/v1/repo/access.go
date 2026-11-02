// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"net/http"

	"forgejo.org/modules/util"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/services/accessreport"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

// GetAccess lists who can access the repository, with what access, and through what
func GetAccess(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/access repository repoGetAccess
	// ---
	// summary: List who can access a repository, with what access, and through what
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
	// - name: mode
	//   in: query
	//   description: only rows with at least this access
	//   type: string
	//   enum: [read, write, admin]
	// - name: unit
	//   in: query
	//   description: only rows with access to this unit, e.g. repo.code
	//   type: string
	// - name: type
	//   in: query
	//   description: only this type of identity
	//   type: string
	//   enum: [person, bot, key]
	// - name: external
	//   in: query
	//   description: only collaborators who aren't members of the owner organization
	//   type: boolean
	// - name: inactive_days
	//   in: query
	//   description: only users who haven't signed in for this many days; applies only for site admins
	//   type: integer
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
	//     "$ref": "#/responses/AccessRowList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	// a restricted token doesn't act as a site admin
	admin := ctx.IsUserSiteAdmin()
	rows, _, err := accessreport.ForRepo(ctx, ctx.Repo().Repository, admin, ctx.Doer(), accessreport.ParseFilter(ctx.FormString))
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	opts := utils.GetListOptions(ctx)
	ctx.SetTotalCountHeader(int64(len(rows)))
	ctx.JSON(http.StatusOK, convert.ToAccessRows(ctx, util.PaginateSlice(rows, opts.Page, opts.PageSize).([]*accessreport.Row), accessreport.AsAdmin(ctx.Doer(), admin)))
}
