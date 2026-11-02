// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"net/http"
	"net/url"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	access_model "forgejo.org/models/perm/access"
	"forgejo.org/models/unit"
	actions_service "forgejo.org/services/actions"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

// runFilterKeys are the query parameters that narrow a runs list.
var runFilterKeys = []string{"status", "event", "repo", "workflow_id", "branch", "actor", "from", "to"}

// LoadRuns finds the runs of org (of every owner if nil, for site admins) that the doer may see, narrowed by the
// query, and sets what the runs list template shows. admin is whether the doer acts as a site admin. runsLink is
// the URL of the page; if exportLink isn't empty the page links to it with the same filters. On an error it
// answers the request and returns false.
func LoadRuns(ctx *context.Context, org *organization.Organization, admin bool, runsLink, exportLink string) bool {
	filter, err := actions_service.ParseOrgRunFilter(ctx.Base)
	if err != nil {
		ctx.Error(http.StatusBadRequest, err.Error())
		return false
	}

	lo := db.ListOptions{Page: max(ctx.FormInt("page"), 1), PageSize: convert.ToCorrectPageSize(ctx.FormInt("limit"))}
	runs, total, err := actions_service.FindOrgRuns(ctx, org, ctx.Doer, admin, nil, filter, lo)
	if err == nil {
		runs, err = actions_service.LoadOrgRunRepos(ctx, runs)
	}
	if err == nil {
		err = runs.LoadTriggerUser(ctx)
	}
	var perms map[int64]*access_model.Permission
	if err == nil && !admin { // a site admin may write everywhere: no lookup per repository
		perms, err = actions_service.OrgRunPermissions(ctx, runs, ctx.Doer)
	}
	if err != nil {
		ctx.ServerError("LoadRuns", err)
		return false
	}

	// the buttons only link to the routes of the repository, which check the permission again
	canWrite := make(map[int64]bool, len(runs))
	for _, run := range runs {
		canWrite[run.ID] = (admin || perms[run.RepoID].CanWrite(unit.TypeActions)) && !run.Repo.IsArchived
	}

	type statusOption struct{ Value, Label string }
	var statuses []statusOption
	for _, info := range actions_model.GetStatusInfoList(ctx, ctx.Locale) {
		statuses = append(statuses, statusOption{actions_model.Status(info.Status).String(), info.DisplayedStatus})
	}
	ctx.Data["RunsLink"] = runsLink
	ctx.Data["Runs"] = runs
	ctx.Data["RunCanWrite"] = canWrite
	ctx.Data["StatusOptions"] = statuses

	pager := context.NewPagination(int(total), lo.PageSize, lo.Page, 5)
	query := url.Values{}
	for _, key := range runFilterKeys {
		ctx.Data["Cur_"+key] = ctx.FormString(key)
		ctx.Data["IsFiltered"] = ctx.Data["IsFiltered"] == true || ctx.FormString(key) != ""
		pager.AddParamString(key, ctx.FormString(key))
		for _, v := range ctx.Req.URL.Query()[key] {
			query.Add(key, v)
		}
	}
	if exportLink != "" {
		ctx.Data["ExportLink"] = exportLink + "?" + query.Encode()
	}
	pager.AddParamString("limit", ctx.FormString("limit"))
	ctx.Data["Page"] = pager
	return true
}
