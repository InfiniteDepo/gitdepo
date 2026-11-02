// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"net/http"

	"forgejo.org/routers/api/v1/repo"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/services/context"
	dependency_service "forgejo.org/services/dependency"
)

// SearchDependencies finds the repositories that use a package
func SearchDependencies(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/dependencies organization orgSearchDependencies
	// ---
	// summary: Find the repositories of an organization that use a package
	// description: Lists the dependencies of the organization's repositories, by repository name. Only organization owners (and site admins) with a token for all resources may ask; a repository is listed only where the dependency graph is on and the caller can read its code. A package nobody visible uses gives the empty list.
	// produces:
	// - application/json
	// - text/csv
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: project
	//   in: query
	//   description: only the repositories of this project of the organization
	//   type: string
	// - name: ecosystem
	//   in: query
	//   description: the ecosystem (Go, npm, PyPI, Maven, NuGet, crates.io, RubyGems or Packagist); needed with name
	//   type: string
	// - name: name
	//   in: query
	//   description: the package name, compared as the ecosystem's registry does (at most 512 bytes)
	//   type: string
	// - name: version
	//   in: query
	//   description: an exact version; excludes range
	//   type: string
	// - name: range
	//   in: query
	//   description: a requirement in the ecosystem's syntax (for example ^1.2.0 or >=2,<3); excludes version. Rows without a version whose requirement overlaps it are listed with uncertain set. Answers 422 above 20000 candidate rows.
	//   type: string
	// - name: direct
	//   in: query
	//   description: only the direct (true) or only the transitive (false) dependencies
	//   type: boolean
	// - name: page
	//   in: query
	//   description: page number of results to return (1-based)
	//   type: integer
	// - name: limit
	//   in: query
	//   description: page size of results
	//   type: integer
	// - name: format
	//   in: query
	//   description: csv or json sends every matching row as a download (at most 100000, else 422; no paging) and records an audit entry; without it the answer is paged. Alert export rows leave out the advisory details and references (empty), which the paged answer keeps
	//   type: string
	//   enum: [csv, json]
	// responses:
	//   "200":
	//     "$ref": "#/responses/DependencyUsageList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if !utils.IsOrgWideToken(ctx) {
		ctx.Error(http.StatusForbidden, "", "the token must not be limited to public or specific repositories")
		return
	}
	repo.SearchDependencyUsage(ctx, dependency_service.SearchScope{Org: ctx.Org().Organization, Doer: ctx.Doer(), Admin: ctx.IsUserSiteAdmin(), TokenRepos: ctx.Reducer().RepoReadAccessFilter()})
}

// SearchVulnerabilityAlerts finds the repositories that an advisory or a package affects
func SearchVulnerabilityAlerts(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/vulnerability-alerts organization orgSearchVulnerabilityAlerts
	// ---
	// summary: Find the repositories of an organization that an advisory or a package affects
	// description: Lists the vulnerability alerts of the organization's repositories. Only organization owners (and site admins) with a token for all resources may ask; a repository is listed only where the dependency graph is on and the caller can read its code. An advisory that affects nothing visible, or that is unknown, gives the empty list.
	// produces:
	// - application/json
	// - text/csv
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: project
	//   in: query
	//   description: only the repositories of this project of the organization
	//   type: string
	// - name: advisory
	//   in: query
	//   description: an OSV ID or an alias (CVE-..., GHSA-..., PYSEC-...); an unknown one gives the empty list
	//   type: string
	// - name: ecosystem
	//   in: query
	//   description: the ecosystem (Go, npm, PyPI, Maven, NuGet, crates.io, RubyGems or Packagist); empty matches every ecosystem
	//   type: string
	// - name: name
	//   in: query
	//   description: the package name, compared as the ecosystem's registry does (at most 512 bytes). Without advisory, name is required; without ecosystem it matches in every ecosystem
	//   type: string
	// - name: version
	//   in: query
	//   description: an exact version
	//   type: string
	// - name: state
	//   in: query
	//   description: open (the default), dismissed, fixed or all
	//   type: string
	//   enum: [open, dismissed, fixed, all]
	// - name: severity
	//   in: query
	//   description: only alerts of this severity
	//   type: string
	//   enum: [critical, high, moderate, low, unknown]
	// - name: page
	//   in: query
	//   description: page number of results to return (1-based)
	//   type: integer
	// - name: limit
	//   in: query
	//   description: page size of results
	//   type: integer
	// - name: format
	//   in: query
	//   description: csv or json sends every matching row as a download (at most 100000, else 422; no paging) and records an audit entry; without it the answer is paged. Alert export rows leave out the advisory details and references (empty), which the paged answer keeps
	//   type: string
	//   enum: [csv, json]
	// responses:
	//   "200":
	//     "$ref": "#/responses/RepoVulnerabilityAlertList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if !utils.IsOrgWideToken(ctx) {
		ctx.Error(http.StatusForbidden, "", "the token must not be limited to public or specific repositories")
		return
	}
	repo.SearchVulnerabilityAlerts(ctx, dependency_service.SearchScope{Org: ctx.Org().Organization, Doer: ctx.Doer(), Admin: ctx.IsUserSiteAdmin(), TokenRepos: ctx.Reducer().RepoReadAccessFilter()})
}
