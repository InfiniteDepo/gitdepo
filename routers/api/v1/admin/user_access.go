// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"net/http"

	"forgejo.org/services/accessreport"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

// GetUserAccess lists everything that gives a user access
func GetUserAccess(ctx *context.APIContext) {
	// swagger:operation GET /admin/users/{username}/access admin adminGetUserAccess
	// ---
	// summary: List everything that gives a user access
	// produces:
	// - application/json
	// parameters:
	// - name: username
	//   in: path
	//   description: username of the user
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/UserAccess"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	ua, err := accessreport.ForUser(ctx, ctx.User(), nil)
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	ctx.JSON(http.StatusOK, convert.ToUserAccess(ctx, ua, ctx.Doer()))
}
