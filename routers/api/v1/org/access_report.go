// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"forgejo.org/routers/common"
	"forgejo.org/services/accessreport"
	"forgejo.org/services/context"
)

// GetAccessReport exports who can access the organization's repositories, with what access, and through what
func GetAccessReport(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/access-report organization orgGetAccessReport
	// ---
	// summary: Export who can access the organization's repositories, one line per path to a unit
	// description: The last sign-in, last push, 2FA, account source and suspended fields are only for site admins.
	// produces:
	// - application/json
	// - text/csv
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: format
	//   in: query
	//   description: format of the export
	//   type: string
	//   enum: [json, csv]
	// - name: mode
	//   in: query
	//   description: only identities with at least this access
	//   type: string
	//   enum: [read, write, admin]
	// - name: unit
	//   in: query
	//   description: only identities with access to this unit, e.g. repo.code
	//   type: string
	// - name: type
	//   in: query
	//   description: only this type of identity
	//   type: string
	//   enum: [person, bot, key]
	// - name: external
	//   in: query
	//   description: only collaborators who aren't members of the organization
	//   type: boolean
	// - name: inactive_days
	//   in: query
	//   description: only users who haven't signed in for this many days; applies only for site admins
	//   type: integer
	// responses:
	//   "200":
	//     "$ref": "#/responses/AccessReportLineList"
	//   "401":
	//     "$ref": "#/responses/unauthorized"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	format := ctx.FormString("format")
	if format != "csv" {
		format = "json"
	}
	report := &common.AccessReport{
		OwnerID: ctx.Org().Organization.ID, Doer: ctx.Doer(), Admin: ctx.IsUserSiteAdmin(),
		Filter: accessreport.ParseFilter(ctx.FormString), Repos: ctx.Reducer().RepoReadAccessFilter(),
	}
	if err := report.Export(ctx.Base, format); err != nil {
		ctx.InternalServerError(err)
	}
}
