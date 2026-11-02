// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"net/http"

	repo_model "forgejo.org/models/repo"
	api "forgejo.org/modules/structs"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

// GetStorageSummary returns the storage used by all repositories
func GetStorageSummary(ctx *context.APIContext) {
	// swagger:operation GET /admin/storage/summary admin adminGetStorageSummary
	// ---
	// summary: Get the storage used by all repositories
	// produces:
	// - application/json
	// responses:
	//   "200":
	//     "$ref": "#/responses/StorageSummary"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	totals, err := repo_model.GetStorageTotals(ctx)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetStorageTotals", err)
		return
	}
	ctx.JSON(http.StatusOK, &api.StorageSummary{
		RepoCount:    totals.NumRepos,
		GitSize:      totals.GitSize,
		LFSSize:      totals.LFSSize,
		StorageSizes: convert.ToStorageSizes(totals),
		TotalSize:    totals.Size(),
		AverageSize:  totals.AverageRepoSize(),
	})
}

// ListStorageOwners lists the storage used per repository owner
func ListStorageOwners(ctx *context.APIContext) {
	// swagger:operation GET /admin/storage/owners admin adminListStorageOwners
	// ---
	// summary: List the storage used per repository owner
	// produces:
	// - application/json
	// parameters:
	// - name: sort
	//   in: query
	//   description: sort owners by the size of one type of storage, or by the total size (default)
	//   type: string
	//   enum: [git, lfs, wiki, attachments, packages, artifacts, logs, trash, total]
	// - name: order
	//   in: query
	//   description: sort order, "asc" or "desc" (default)
	//   type: string
	//   enum: [asc, desc]
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
	//     "$ref": "#/responses/OwnerStorageList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	totals, err := repo_model.GetStorageTotals(ctx)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetStorageTotals", err)
		return
	}

	// unknown keys are not in repo_model.OwnerStorageOrderBy, so they sort by total size, descending
	orderBy := map[string]string{
		"git": "gitsize", "lfs": "lfssize", "wiki": "wikisize", "attachments": "attachmentssize", "packages": "packagessize",
		"artifacts": "artifactssize", "logs": "logssize", "trash": "trashsize", "total": "size",
	}[ctx.FormString("sort")]
	if ctx.FormString("order") != "asc" {
		orderBy = "reverse" + orderBy
	}
	listOptions := utils.GetListOptions(ctx)
	owners, count, err := repo_model.FindOwnerStorage(ctx, repo_model.FindOwnerStorageOptions{ListOptions: listOptions, OrderBy: orderBy})
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "FindOwnerStorage", err)
		return
	}

	result := make([]*api.OwnerStorage, len(owners))
	for i, o := range owners {
		result[i] = convert.ToOwnerStorage(o, totals)
	}

	ctx.SetLinkHeader(int(count), listOptions.PageSize)
	ctx.SetTotalCountHeader(count)
	ctx.JSON(http.StatusOK, result)
}
