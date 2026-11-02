// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"errors"
	"net/http"
	"strconv"

	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/routers/common"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	dependency_service "forgejo.org/services/dependency"
	vulnerability_service "forgejo.org/services/vulnerability"
)

// searchFailed answers a search error: the caller's mistakes are 422.
func searchFailed(ctx *context.APIContext, err error) {
	if errors.Is(err, util.ErrInvalidArgument) {
		ctx.Error(http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	if errors.Is(err, common.ErrExportBusy) {
		ctx.Error(http.StatusTooManyRequests, "", err.Error())
		return
	}
	if errors.Is(err, common.ErrExportTimeLimit) { // stopped before the first byte: an ordinary answer, not a fault
		log.Info("serveExport: %v", err)
		ctx.Error(http.StatusInternalServerError, "", err.Error())
		return
	}
	ctx.Error(http.StatusInternalServerError, "search", err)
}

// MustEnableDependencySearch answers 404 to everyone while the dependency graph is off for the site, before any gate
// can tell the caller anything else.
func MustEnableDependencySearch(ctx *context.APIContext) {
	if !dependency_service.SiteEnabled(ctx) {
		ctx.NotFound()
	}
}

// readScopeFilters reads the project filter (organization routes) or the owner filter (instance routes); the one the
// route doesn't take is a 422.
func readScopeFilters(ctx *context.APIContext, scope *dependency_service.SearchScope) bool {
	scope.Project, scope.Owner = ctx.FormString("project"), ctx.FormString("owner")
	switch {
	case scope.Org != nil && scope.Owner != "":
		ctx.Error(http.StatusUnprocessableEntity, "", "owner is a filter of the instance routes")
	case scope.Org == nil && scope.Project != "":
		ctx.Error(http.StatusUnprocessableEntity, "", "project is a filter of the organization routes")
	default:
		return true
	}
	return false
}

// readFormat reads the format parameter: "" is the paged answer, otherwise csv or json.
func readFormat(ctx *context.APIContext) (string, bool) {
	format := ctx.FormString("format")
	if format != "" && format != "csv" && format != "json" {
		ctx.Error(http.StatusUnprocessableEntity, "", "format must be csv or json")
		return "", false
	}
	return format, true
}

// SearchDependencyUsage answers the dependency search of the org and instance routes. The route's gate has decided
// who may ask; scope says which repositories the answer covers.
func SearchDependencyUsage(ctx *context.APIContext, scope dependency_service.SearchScope) {
	f := dependency_service.UsageFilter{
		Ecosystem: ctx.FormString("ecosystem"), Name: ctx.FormString("name"), Version: ctx.FormString("version"), Range: ctx.FormString("range"),
	}
	if v := ctx.FormString("direct"); v != "" {
		direct, err := strconv.ParseBool(v)
		if err != nil {
			ctx.Error(http.StatusUnprocessableEntity, "", "direct must be a boolean")
			return
		}
		f.Direct = optional.Some(direct)
	}
	if !readScopeFilters(ctx, &scope) {
		return
	}
	format, ok := readFormat(ctx)
	if !ok {
		return
	}
	if format != "" {
		if err := common.ExportDependencies(ctx.Base, ctx.Doer(), scope, f, format); err != nil {
			searchFailed(ctx, err)
		}
		return
	}
	lo := utils.GetListOptions(ctx)
	rows, total, err := dependency_service.SearchUsage(ctx, scope, f, lo)
	if err != nil {
		searchFailed(ctx, err)
		return
	}
	out := make([]*api.DependencyUsage, 0, len(rows))
	for _, r := range rows {
		out = append(out, convert.ToDependencyUsage(r))
	}
	common.RecordUsageSearch(ctx.Base, ctx.Doer(), scope, f, total)
	ctx.SetLinkHeader(int(total), lo.PageSize)
	ctx.SetTotalCountHeader(total)
	ctx.JSON(http.StatusOK, out)
}

// SearchVulnerabilityAlerts answers the alert search of the org and instance routes, as SearchDependencyUsage does.
func SearchVulnerabilityAlerts(ctx *context.APIContext, scope dependency_service.SearchScope) {
	f := vulnerability_service.AlertFilter{
		Advisory: ctx.FormString("advisory"), Ecosystem: ctx.FormString("ecosystem"), Name: ctx.FormString("name"), Version: ctx.FormString("version"),
		State: ctx.FormString("state"), Severity: ctx.FormString("severity"),
	}
	if !readScopeFilters(ctx, &scope) {
		return
	}
	format, ok := readFormat(ctx)
	if !ok {
		return
	}
	if format != "" {
		if err := common.ExportAlerts(ctx.Base, ctx.Doer(), scope, f, format); err != nil {
			searchFailed(ctx, err)
		}
		return
	}
	lo := utils.GetListOptions(ctx)
	hits, total, err := vulnerability_service.SearchAlerts(ctx, scope, f, lo)
	if err != nil {
		searchFailed(ctx, err)
		return
	}
	out, err := convert.ToRepoVulnerabilityAlerts(ctx, ctx.Doer(), hits)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "ToAPIVulnerabilityAlerts", err)
		return
	}
	common.RecordAlertSearch(ctx.Base, ctx.Doer(), scope, f, total)
	ctx.SetLinkHeader(int(total), lo.PageSize)
	ctx.SetTotalCountHeader(total)
	ctx.JSON(http.StatusOK, out)
}
