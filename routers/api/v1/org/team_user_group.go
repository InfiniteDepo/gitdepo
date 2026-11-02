// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"errors"
	"net/http"

	"forgejo.org/models/organization"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	usergroup_service "forgejo.org/services/usergroup"
)

// getTeamUserGroupFromParams loads the user group named in the {groupname}
// path parameter, writing a 404 response if it does not exist.
func getTeamUserGroupFromParams(ctx *context.APIContext) *organization.UserGroup {
	group, err := organization.GetUserGroupByName(ctx, ctx.Params(":groupname"))
	if err != nil {
		if organization.IsErrUserGroupNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetUserGroupByName", err)
		}
		return nil
	}
	return group
}

// ListTeamUserGroups lists the user groups linked to a team
func ListTeamUserGroups(ctx *context.APIContext) {
	// swagger:operation GET /teams/{id}/groups organization orgListTeamUserGroups
	// ---
	// summary: List the user groups linked to a team
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: id of the team
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/UserGroupList"
	//   "404":
	//     "$ref": "#/responses/notFound"

	isMember, err := organization.IsOrganizationMember(ctx, ctx.Org().Team.OrgID, ctx.Doer().ID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "IsOrganizationMember", err)
		return
	} else if !isMember && !ctx.IsUserSiteAdmin() {
		ctx.NotFound()
		return
	}

	groups, err := organization.GetTeamUserGroups(ctx, ctx.Org().Team.ID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetTeamUserGroups", err)
		return
	}
	apiGroups, err := convert.ToUserGroups(ctx, groups)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "ToUserGroups", err)
		return
	}
	ctx.JSON(http.StatusOK, apiGroups)
}

// LinkTeamUserGroup links a user group to a team
func LinkTeamUserGroup(ctx *context.APIContext) {
	// swagger:operation PUT /teams/{id}/groups/{groupname} organization orgLinkTeamUserGroup
	// ---
	// summary: Link a user group to a team
	// description: The members of the group become members of the team. Linking a group that is already linked does nothing.
	// parameters:
	// - name: id
	//   in: path
	//   description: id of the team
	//   type: integer
	//   format: int64
	//   required: true
	// - name: groupname
	//   in: path
	//   description: name of the user group
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	group := getTeamUserGroupFromParams(ctx)
	if ctx.Written() {
		return
	}
	if err := usergroup_service.LinkTeam(ctx, group, ctx.Org().Team); err != nil && !errors.Is(err, usergroup_service.ErrAlreadyLinked) {
		ctx.Error(http.StatusInternalServerError, "LinkTeam", err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

// UnlinkTeamUserGroup unlinks a user group from a team
func UnlinkTeamUserGroup(ctx *context.APIContext) {
	// swagger:operation DELETE /teams/{id}/groups/{groupname} organization orgUnlinkTeamUserGroup
	// ---
	// summary: Unlink a user group from a team
	// description: The members of the group who were only members of the team through this group are removed from the team.
	// parameters:
	// - name: id
	//   in: path
	//   description: id of the team
	//   type: integer
	//   format: int64
	//   required: true
	// - name: groupname
	//   in: path
	//   description: name of the user group
	//   type: string
	//   required: true
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

	group := getTeamUserGroupFromParams(ctx)
	if ctx.Written() {
		return
	}
	linked, err := organization.IsUserGroupLinkedToTeam(ctx, group.ID, ctx.Org().Team.ID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "IsUserGroupLinkedToTeam", err)
		return
	} else if !linked {
		ctx.NotFound()
		return
	}
	if managed, err := organization.IsTeamUserGroupManaged(ctx, group.ID, ctx.Org().Team.ID); err != nil {
		ctx.Error(http.StatusInternalServerError, "IsTeamUserGroupManaged", err)
		return
	} else if managed {
		ctx.Error(http.StatusUnprocessableEntity, "", "the link is managed by the organization administrator role and cannot be removed")
		return
	}

	if err := usergroup_service.UnlinkTeam(ctx, group, ctx.Org().Team); err != nil {
		if organization.IsErrLastOrgOwner(err) {
			ctx.Error(http.StatusConflict, "", err)
		} else {
			ctx.Error(http.StatusInternalServerError, "UnlinkTeam", err)
		}
		return
	}
	ctx.Status(http.StatusNoContent)
}
