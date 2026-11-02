// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"net/http"

	"forgejo.org/models"
	org_model "forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/web"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	usergroup_service "forgejo.org/services/usergroup"
)

// getUserGroupFromParams loads the user group named in the {groupname} path
// parameter, writing a 404 response if it does not exist.
func getUserGroupFromParams(ctx *context.APIContext) *org_model.UserGroup {
	group, err := org_model.GetUserGroupByName(ctx, ctx.Params(":groupname"))
	if err != nil {
		if org_model.IsErrUserGroupNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetUserGroupByName", err)
		}
		return nil
	}
	return group
}

func respondUserGroup(ctx *context.APIContext, status int, group *org_model.UserGroup) {
	apiGroup, err := convert.ToUserGroup(ctx, group)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "ToUserGroup", err)
		return
	}
	ctx.JSON(status, apiGroup)
}

// ListUserGroups lists the user groups
func ListUserGroups(ctx *context.APIContext) {
	// swagger:operation GET /admin/groups admin adminListUserGroups
	// ---
	// summary: List user groups
	// produces:
	// - application/json
	// parameters:
	// - name: q
	//   in: query
	//   description: keyword to filter the group names with
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
	//     "$ref": "#/responses/UserGroupList"
	//   "403":
	//     "$ref": "#/responses/forbidden"

	listOptions := utils.GetListOptions(ctx)
	listOptions.SetDefaultValues()
	groups, count, err := org_model.SearchUserGroups(ctx, &org_model.SearchUserGroupOptions{
		ListOptions: listOptions,
		Keyword:     ctx.FormTrim("q"),
	})
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "SearchUserGroups", err)
		return
	}

	apiGroups, err := convert.ToUserGroups(ctx, groups)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "ToUserGroups", err)
		return
	}

	ctx.SetLinkHeader(int(count), listOptions.PageSize)
	ctx.SetTotalCountHeader(count)
	ctx.JSON(http.StatusOK, apiGroups)
}

// CreateUserGroup creates a user group
func CreateUserGroup(ctx *context.APIContext) {
	// swagger:operation POST /admin/groups admin adminCreateUserGroup
	// ---
	// summary: Create a user group
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/CreateUserGroupOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/UserGroup"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "409":
	//     "$ref": "#/responses/error"
	//   "422":
	//     "$ref": "#/responses/validationError"

	form := web.GetForm(ctx).(*api.CreateUserGroupOption)
	group := &org_model.UserGroup{
		Name:                     form.Name,
		Description:              form.Description,
		GrantsSiteAdmin:          form.GrantsSiteAdmin,
		GrantsCreateOrganization: form.GrantsCreateOrganization,
		GrantsAuditor:            form.GrantsAuditor,
		GrantsOrgAdmin:           form.GrantsOrgAdmin,
	}
	if err := usergroup_service.CreateGroup(ctx, group); err != nil {
		if org_model.IsErrUserGroupAlreadyExist(err) {
			ctx.Error(http.StatusConflict, "", err)
		} else {
			ctx.Error(http.StatusInternalServerError, "InsertUserGroup", err)
		}
		return
	}
	respondUserGroup(ctx, http.StatusCreated, group)
}

// GetUserGroup gets a user group
func GetUserGroup(ctx *context.APIContext) {
	// swagger:operation GET /admin/groups/{groupname} admin adminGetUserGroup
	// ---
	// summary: Get a user group
	// produces:
	// - application/json
	// parameters:
	// - name: groupname
	//   in: path
	//   description: name of the user group
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/UserGroup"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	group := getUserGroupFromParams(ctx)
	if ctx.Written() {
		return
	}
	respondUserGroup(ctx, http.StatusOK, group)
}

// EditUserGroup edits a user group
func EditUserGroup(ctx *context.APIContext) {
	// swagger:operation PATCH /admin/groups/{groupname} admin adminEditUserGroup
	// ---
	// summary: Edit a user group
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: groupname
	//   in: path
	//   description: name of the user group
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/EditUserGroupOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/UserGroup"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     "$ref": "#/responses/error"
	//   "422":
	//     "$ref": "#/responses/validationError"

	group := getUserGroupFromParams(ctx)
	if ctx.Written() {
		return
	}
	form := web.GetForm(ctx).(*api.EditUserGroupOption)
	if form.Name != nil {
		if *form.Name == "" {
			ctx.Error(http.StatusUnprocessableEntity, "", errors.New("name cannot be empty"))
			return
		}
		group.Name = *form.Name
	}
	if form.Description != nil {
		group.Description = *form.Description
	}
	if form.GrantsSiteAdmin != nil {
		group.GrantsSiteAdmin = *form.GrantsSiteAdmin
	}
	if form.GrantsCreateOrganization != nil {
		group.GrantsCreateOrganization = *form.GrantsCreateOrganization
	}
	if form.GrantsAuditor != nil {
		group.GrantsAuditor = *form.GrantsAuditor
	}
	if form.GrantsOrgAdmin != nil {
		group.GrantsOrgAdmin = *form.GrantsOrgAdmin
	}
	if err := usergroup_service.UpdateGroup(ctx, group); err != nil {
		if org_model.IsErrUserGroupAlreadyExist(err) || models.IsErrDeleteLastAdminUser(err) || org_model.IsErrLastOrgOwner(err) {
			ctx.Error(http.StatusConflict, "", err)
		} else {
			ctx.Error(http.StatusInternalServerError, "UpdateGroup", err)
		}
		return
	}
	respondUserGroup(ctx, http.StatusOK, group)
}

// DeleteUserGroup deletes a user group
func DeleteUserGroup(ctx *context.APIContext) {
	// swagger:operation DELETE /admin/groups/{groupname} admin adminDeleteUserGroup
	// ---
	// summary: Delete a user group
	// description: The group is unlinked from all teams first. Its members lose the team memberships they only had through the group.
	// parameters:
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

	group := getUserGroupFromParams(ctx)
	if ctx.Written() {
		return
	}
	if err := usergroup_service.DeleteGroup(ctx, group); err != nil {
		if org_model.IsErrLastOrgOwner(err) || models.IsErrDeleteLastAdminUser(err) {
			ctx.Error(http.StatusConflict, "", err)
		} else {
			ctx.Error(http.StatusInternalServerError, "DeleteGroup", err)
		}
		return
	}
	ctx.Status(http.StatusNoContent)
}

// ListUserGroupMembers lists the members of a user group
func ListUserGroupMembers(ctx *context.APIContext) {
	// swagger:operation GET /admin/groups/{groupname}/members admin adminListUserGroupMembers
	// ---
	// summary: List the members of a user group
	// produces:
	// - application/json
	// parameters:
	// - name: groupname
	//   in: path
	//   description: name of the user group
	//   type: string
	//   required: true
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
	//     "$ref": "#/responses/UserList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	group := getUserGroupFromParams(ctx)
	if ctx.Written() {
		return
	}
	listOptions := utils.GetListOptions(ctx)
	listOptions.SetDefaultValues()
	members, err := org_model.GetUserGroupMembers(ctx, group.ID, listOptions)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetUserGroupMembers", err)
		return
	}
	if err := group.LoadCounts(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadCounts", err)
		return
	}

	ctx.SetLinkHeader(group.NumMembers, listOptions.PageSize)
	ctx.SetTotalCountHeader(int64(group.NumMembers))
	ctx.JSON(http.StatusOK, convert.ToUsers(ctx, ctx.Doer(), members))
}

// AddUserGroupMember adds a user to a user group
func AddUserGroupMember(ctx *context.APIContext) {
	// swagger:operation PUT /admin/groups/{groupname}/members/{username} admin adminAddUserGroupMember
	// ---
	// summary: Add a user to a user group
	// description: The user is also added to every team the group is linked to. Adding a user who is already a member does nothing.
	// parameters:
	// - name: groupname
	//   in: path
	//   description: name of the user group
	//   type: string
	//   required: true
	// - name: username
	//   in: path
	//   description: username of the user to add
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	group := getUserGroupFromParams(ctx)
	if ctx.Written() {
		return
	}
	user := getUserFromParams(ctx)
	if ctx.Written() {
		return
	}

	switch err := usergroup_service.AddMember(ctx, group, user); {
	case err == nil, errors.Is(err, usergroup_service.ErrAlreadyMember):
		ctx.Status(http.StatusNoContent)
	case errors.Is(err, usergroup_service.ErrOrganizationCannotBeMember):
		ctx.Error(http.StatusUnprocessableEntity, "", err)
	default:
		ctx.Error(http.StatusInternalServerError, "AddMember", err)
	}
}

// RemoveUserGroupMember removes a user from a user group
func RemoveUserGroupMember(ctx *context.APIContext) {
	// swagger:operation DELETE /admin/groups/{groupname}/members/{username} admin adminRemoveUserGroupMember
	// ---
	// summary: Remove a user from a user group
	// description: The user is also removed from the teams they were only a member of through this group.
	// parameters:
	// - name: groupname
	//   in: path
	//   description: name of the user group
	//   type: string
	//   required: true
	// - name: username
	//   in: path
	//   description: username of the user to remove
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

	group := getUserGroupFromParams(ctx)
	if ctx.Written() {
		return
	}
	user := getUserFromParams(ctx)
	if ctx.Written() {
		return
	}

	isMember, err := org_model.IsUserGroupMember(ctx, group.ID, user.ID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "IsUserGroupMember", err)
		return
	} else if !isMember {
		ctx.NotFound()
		return
	}

	if err := usergroup_service.RemoveMember(ctx, group, user.ID); err != nil {
		if org_model.IsErrLastOrgOwner(err) || models.IsErrDeleteLastAdminUser(err) {
			ctx.Error(http.StatusConflict, "", err)
		} else {
			ctx.Error(http.StatusInternalServerError, "RemoveMember", err)
		}
		return
	}
	ctx.Status(http.StatusNoContent)
}

// ListUserGroupTeams lists the teams a user group is linked to
func ListUserGroupTeams(ctx *context.APIContext) {
	// swagger:operation GET /admin/groups/{groupname}/teams admin adminListUserGroupTeams
	// ---
	// summary: List the teams a user group is linked to
	// produces:
	// - application/json
	// parameters:
	// - name: groupname
	//   in: path
	//   description: name of the user group
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/TeamList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	group := getUserGroupFromParams(ctx)
	if ctx.Written() {
		return
	}
	linked, err := org_model.GetUserGroupTeams(ctx, group.ID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetUserGroupTeams", err)
		return
	}
	teams := make([]*org_model.Team, 0, len(linked))
	for _, l := range linked {
		teams = append(teams, l.Team)
	}
	apiTeams, err := convert.ToTeams(ctx, teams, true)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "ToTeams", err)
		return
	}
	ctx.JSON(http.StatusOK, apiTeams)
}

// getUserFromParams loads the user named in the {username} path parameter,
// writing a 404 response if it does not exist.
func getUserFromParams(ctx *context.APIContext) *user_model.User {
	user, err := user_model.GetUserByName(ctx, ctx.Params(":username"))
	if err != nil {
		if user_model.IsErrUserNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetUserByName", err)
		}
		return nil
	}
	return user
}
