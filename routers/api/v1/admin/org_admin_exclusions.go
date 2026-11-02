// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"net/http"

	org_model "forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/web"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	usergroup_service "forgejo.org/services/usergroup"
)

// ListOrgAdminExclusions lists the organizations excluded from the organization administrator role
func ListOrgAdminExclusions(ctx *context.APIContext) {
	// swagger:operation GET /admin/roles/org-admin/exclusions admin adminListOrgAdminExclusions
	// ---
	// summary: List the organizations excluded from the organization administrator role
	// produces:
	// - application/json
	// responses:
	//   "200":
	//     "$ref": "#/responses/OrganizationList"
	//   "403":
	//     "$ref": "#/responses/forbidden"

	ids, err := org_model.GetOrgAdminExclusionOrgIDs(ctx)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetOrgAdminExclusionOrgIDs", err)
		return
	}
	orgs := make([]*api.Organization, 0, len(ids))
	for id := range ids {
		org, err := org_model.GetOrgByID(ctx, id)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "GetOrgByID", err)
			return
		}
		orgs = append(orgs, convert.ToOrganization(ctx, org))
	}
	ctx.JSON(http.StatusOK, orgs)
}

// SetOrgAdminExclusions replaces the organizations excluded from the organization administrator role
func SetOrgAdminExclusions(ctx *context.APIContext) {
	// swagger:operation PUT /admin/roles/org-admin/exclusions admin adminSetOrgAdminExclusions
	// ---
	// summary: Replace the organizations excluded from the organization administrator role
	// description: Nothing is changed if an organization is unknown, a name is not an organization, or the change would leave an organization without an owner.
	// consumes:
	// - application/json
	// parameters:
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/SetOrgAdminExclusionsOption"
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     "$ref": "#/responses/error"
	//   "422":
	//     "$ref": "#/responses/validationError"

	form := web.GetForm(ctx).(*api.SetOrgAdminExclusionsOption)
	ids, err := usergroup_service.ResolveOrgIDs(ctx, form.Orgs)
	if err == nil {
		err = usergroup_service.SetOrgAdminExclusions(ctx, ids)
	}
	switch {
	case err == nil:
		ctx.Status(http.StatusNoContent)
	case user_model.IsErrUserNotExist(err):
		ctx.NotFound(err)
	case errors.Is(err, usergroup_service.ErrNotOrganization):
		ctx.Error(http.StatusUnprocessableEntity, "", err)
	case org_model.IsErrLastOrgOwner(err):
		ctx.Error(http.StatusConflict, "", err)
	default:
		ctx.Error(http.StatusInternalServerError, "SetOrgAdminExclusions", err)
	}
}
