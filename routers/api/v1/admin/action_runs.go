// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"net/http"

	api "forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	"forgejo.org/routers/api/v1/utils"
	actions_service "forgejo.org/services/actions"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

// ListActionRuns lists the workflow runs of all repositories.
func ListActionRuns(ctx *context.APIContext) {
	// swagger:operation GET /admin/actions/runs admin adminListActionRuns
	// ---
	// summary: List the workflow runs of all repositories
	// description: >
	//   Lists the runs of every repository that is not in the trash and has Actions enabled, newest first. Unlike a
	//   repository's run list, `is_ref_deleted` is not reported and the run is described by a short form.
	// produces:
	// - application/json
	// parameters:
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
	//   description: Only return runs of the repository with this name, or this `owner/name`.
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

	if !actions_service.OrgRunsEnabled() {
		ctx.NotFound()
		return
	}
	if !actions_service.IsActiveSiteAdmin(ctx.Doer()) {
		ctx.Error(http.StatusForbidden, "IsActiveSiteAdmin", "site administrators only")
		return
	}
	filter, err := actions_service.ParseOrgRunFilter(ctx.Base)
	if err != nil {
		ctx.Error(http.StatusBadRequest, "ParseOrgRunFilter", err)
		return
	}
	lo := utils.GetListOptions(ctx)
	runs, total, err := actions_service.FindOrgRuns(ctx, nil, ctx.Doer(), true, ctx.Reducer().RepoReadAccessFilter(), filter, lo)
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

// GetActionUsage returns the job minutes of the instance per owner, repository or runner.
func GetActionUsage(ctx *context.APIContext) {
	// swagger:operation GET /admin/actions/usage admin adminGetActionUsage
	// ---
	// summary: Get the Actions usage of the instance
	// description: >
	//   Sums the run time of the jobs that started in the period and have finished (jobs that are still running or
	//   stopped before they started add nothing), most minutes first, and lists the repositories with the most
	//   job minutes and the most failed runs. Repositories in the trash or without Actions are left out. Jobs that
	//   had no runner are listed under runner 0. Lists are cut at `limit` entries.
	// produces:
	// - application/json
	// parameters:
	// - name: group_by
	//   in: query
	//   description: what to sum per. `org` groups by the owner of the repository, which can be a user.
	//   type: string
	//   enum: [org, repo, runner]
	//   required: true
	// - name: from
	//   in: query
	//   description: Start of the period (RFC 3339 or YYYY-MM-DD). Defaults to 30 days before `to`.
	//   type: string
	// - name: to
	//   in: query
	//   description: End of the period (RFC 3339, or YYYY-MM-DD for the end of that day). Defaults to now. The period is at most 366 days.
	//   type: string
	// - name: limit
	//   in: query
	//   description: the most entries per list (default 100, at most 200)
	//   type: integer
	// responses:
	//   "200":
	//     "$ref": "#/responses/ActionUsage"
	//   "400":
	//     "$ref": "#/responses/error"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if !actions_service.OrgRunsEnabled() {
		ctx.NotFound()
		return
	}
	if !actions_service.IsActiveSiteAdmin(ctx.Doer()) {
		ctx.Error(http.StatusForbidden, "IsActiveSiteAdmin", "site administrators only")
		return
	}
	group, err := actions_service.ParseUsageGroup(ctx.FormString("group_by"))
	if err != nil {
		ctx.Error(http.StatusBadRequest, "ParseUsageGroup", err)
		return
	}
	from, to, err := actions_service.ParseUsageRange(ctx.FormString("from"), ctx.FormString("to"), timeutil.TimeStampNow())
	if err != nil {
		ctx.Error(http.StatusBadRequest, "ParseUsageRange", err)
		return
	}
	limit := ctx.FormInt("limit")
	if limit <= 0 {
		limit = 100
	}
	limit = min(limit, actions_service.UsageMaxEntries)

	usage, err := actions_service.GetUsageReport(ctx, group, from, to, ctx.Reducer().RepoReadAccessFilter(), limit)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetUsageReport", err)
		return
	}
	ctx.JSON(http.StatusOK, &api.ActionUsage{
		GroupBy: string(group), From: from.AsTime(), To: to.AsTime(), Entries: toActionUsageEntries(usage.Entries),
		TopReposByMinutes: toActionUsageEntries(usage.TopByMinutes), TopReposByFailures: toActionUsageEntries(usage.TopByFailures),
	})
}

func toActionUsageEntries(entries []actions_service.UsageEntry) []*api.ActionUsageEntry {
	out := make([]*api.ActionUsageEntry, len(entries))
	for i, e := range entries {
		out[i] = &api.ActionUsageEntry{ID: e.ID, Name: e.Name, JobMinutes: e.Minutes(), Jobs: e.Jobs, FailedJobs: e.FailedJobs, FailedRuns: e.FailedRuns}
	}
	return out
}
