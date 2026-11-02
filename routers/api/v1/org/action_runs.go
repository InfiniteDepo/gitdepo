// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"net/http"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	api "forgejo.org/modules/structs"
	"forgejo.org/routers/api/v1/utils"
	actions_service "forgejo.org/services/actions"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

// ListActionRuns lists the workflow runs of the repositories of an organization that the user can read.
func ListActionRuns(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/actions/runs organization orgListActionRuns
	// ---
	// summary: List the workflow runs of an organization's repositories
	// description: >
	//   Lists the runs of the repositories of the organization whose Actions the authenticated user can read, newest
	//   first. The token needs the organization and the repository scope. Unlike a repository's run list, `is_ref_deleted` is not
	//   reported and the run is described by a short form.
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: status
	//   in: query
	//   description: Only return runs with one of these statuses (success, failure, cancelled, running, waiting, skipped, blocked). Repeated values are deduplicated and only the first 20 are used.
	//   type: array
	//   items:
	//     type: string
	//   collectionFormat: multi
	// - name: event
	//   in: query
	//   description: Only return runs triggered by one of these events, for example `push` or `pull_request`. Repeated values are deduplicated and only the first 20 are used; an unknown event matches no run.
	//   type: array
	//   items:
	//     type: string
	//   collectionFormat: multi
	// - name: repo
	//   in: query
	//   description: Only return runs of the repository with this name.
	//   type: string
	// - name: workflow_id
	//   in: query
	//   description: Only return runs of the workflow with this file name.
	//   type: string
	// - name: branch
	//   in: query
	//   description: Only return runs of this branch.
	//   type: string
	// - name: actor
	//   in: query
	//   description: Only return runs triggered by the user with this name.
	//   type: string
	// - name: from
	//   in: query
	//   description: Only return runs created at or after this time (RFC 3339 or YYYY-MM-DD).
	//   type: string
	// - name: to
	//   in: query
	//   description: Only return runs created at or before this time (RFC 3339, or YYYY-MM-DD for the end of that day).
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
	//     "$ref": "#/responses/ActionRunSummaryList"
	//   "400":
	//     "$ref": "#/responses/error"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if !actions_service.OrgRunsEnabled() || repo_model.HiddenUnits(ctx, ctx.Org().Organization.AsUser()).Contains(unit.TypeActions) {
		ctx.NotFound()
		return
	}
	filter, err := actions_service.ParseOrgRunFilter(ctx.Base)
	if err != nil {
		ctx.Error(http.StatusBadRequest, "ParseOrgRunFilter", err)
		return
	}
	lo := utils.GetListOptions(ctx)
	runs, total, err := actions_service.FindOrgRuns(ctx, ctx.Org().Organization, ctx.Doer(), ctx.IsUserSiteAdmin(), ctx.Reducer().RepoReadAccessFilter(), filter, lo)
	if err == nil {
		runs, err = actions_service.LoadOrgRunRepos(ctx, runs)
	}
	if err == nil {
		err = runs.LoadTriggerUser(ctx)
	}
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "FindOrgRuns", err)
		return
	}

	res := &api.ListActionRunSummaryResponse{TotalCount: total, Entries: make([]*api.ActionRunSummary, len(runs))}
	for i, run := range runs {
		res.Entries[i] = convert.ToActionRunSummary(ctx, run, ctx.Doer())
	}
	ctx.SetLinkHeader(int(total), lo.PageSize)
	ctx.SetTotalCountHeader(total)
	ctx.JSON(http.StatusOK, res)
}
