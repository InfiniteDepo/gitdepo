// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"forgejo.org/routers/api/v1/repo"
	"forgejo.org/services/context"
	dependency_service "forgejo.org/services/dependency"
)

// SearchDependencies finds the repositories that use a package
func SearchDependencies(ctx *context.APIContext) {
	// swagger:operation GET /admin/dependencies admin adminSearchDependencies
	// ---
	// summary: Find the repositories on the instance that use a package
	// description: Lists the dependencies of all repositories on the instance, by repository name. Site admins and auditors with a token for all resources only.
	// produces:
	// - application/json
	// - text/csv
	// parameters:
	// - name: owner
	//   in: query
	//   description: only the repositories of this owner
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

	repo.SearchDependencyUsage(ctx, dependency_service.SearchScope{Doer: ctx.Doer(), Admin: true})
}

// SearchVulnerabilityAlerts finds the repositories that an advisory or a package affects
func SearchVulnerabilityAlerts(ctx *context.APIContext) {
	// swagger:operation GET /admin/vulnerability-alerts admin adminSearchVulnerabilityAlerts
	// ---
	// summary: Find the repositories on the instance that an advisory or a package affects
	// description: Lists the vulnerability alerts of all repositories on the instance. Site admins and auditors with a token for all resources only.
	// produces:
	// - application/json
	// - text/csv
	// parameters:
	// - name: owner
	//   in: query
	//   description: only the repositories of this owner
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

	repo.SearchVulnerabilityAlerts(ctx, dependency_service.SearchScope{Doer: ctx.Doer(), Admin: true})
}
