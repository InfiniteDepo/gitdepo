// Copyright 2015 The Gogs Authors. All rights reserved.
// Copyright 2018 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package org

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"forgejo.org/models"
	activities_model "forgejo.org/models/activities"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	repo_module "forgejo.org/modules/repository"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/validation"
	"forgejo.org/modules/web"
	"forgejo.org/routers/api/v1/user"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/services/auth"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	org_service "forgejo.org/services/org"
	user_service "forgejo.org/services/user"
	usergroup_service "forgejo.org/services/usergroup"
)

func listUserOrgs(ctx *context.APIContext, u *user_model.User) {
	listOptions := utils.GetListOptions(ctx)
	showPrivate := ctx.IsSigned() && (ctx.IsUserSiteAdmin() || ctx.Doer().ID == u.ID)

	opts := organization.FindOrgOptions{
		ListOptions:    listOptions,
		UserID:         u.ID,
		IncludePrivate: showPrivate,
		IsArchived:     ctx.FormOptionalBool("archived"),
	}
	orgs, maxResults, err := db.FindAndCount[organization.Organization](ctx, opts)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "db.FindAndCount[organization.Organization]", err)
		return
	}

	apiOrgs := make([]*api.Organization, len(orgs))
	for i := range orgs {
		apiOrgs[i] = convert.ToOrganization(ctx, orgs[i])
	}

	ctx.SetLinkHeader(int(maxResults), listOptions.PageSize)
	ctx.SetTotalCountHeader(maxResults)
	ctx.JSON(http.StatusOK, &apiOrgs)
}

// ListMyOrgs list all my orgs
func ListMyOrgs(ctx *context.APIContext) {
	// swagger:operation GET /user/orgs organization orgListCurrentUserOrgs
	// ---
	// summary: List the current user's organizations
	// produces:
	// - application/json
	// parameters:
	// - name: archived
	//   in: query
	//   description: only list archived (true) or non-archived (false) organizations; both when omitted
	//   type: boolean
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
	//     "$ref": "#/responses/OrganizationListWithoutPagination"
	//   "401":
	//     "$ref": "#/responses/unauthorized"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	listUserOrgs(ctx, ctx.Doer())
}

// ListUserOrgs list user's orgs
func ListUserOrgs(ctx *context.APIContext) {
	// swagger:operation GET /users/{username}/orgs organization orgListUserOrgs
	// ---
	// summary: List a user's organizations
	// produces:
	// - application/json
	// parameters:
	// - name: username
	//   in: path
	//   description: username of user
	//   type: string
	//   required: true
	// - name: archived
	//   in: query
	//   description: only list archived (true) or non-archived (false) organizations; both when omitted
	//   type: boolean
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
	//     "$ref": "#/responses/OrganizationListWithoutPagination"
	//   "404":
	//     "$ref": "#/responses/notFound"

	listUserOrgs(ctx, ctx.User())
}

// GetUserOrgsPermissions get user permissions in organization
func GetUserOrgsPermissions(ctx *context.APIContext) {
	// swagger:operation GET /users/{username}/orgs/{org}/permissions organization orgGetUserPermissions
	// ---
	// summary: Get user permissions in organization
	// produces:
	// - application/json
	// parameters:
	// - name: username
	//   in: path
	//   description: username of user
	//   type: string
	//   required: true
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/OrganizationPermissions"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	var o *user_model.User
	if o = user.GetUserByParamsName(ctx, ":org"); o == nil {
		return
	}

	op := api.OrganizationPermissions{}

	if !organization.HasOrgOrUserVisible(ctx, o, ctx.User()) {
		ctx.NotFound("HasOrgOrUserVisible", nil)
		return
	}

	org := organization.OrgFromUser(o)
	authorizeLevel, err := org.GetOrgUserMaxAuthorizeLevel(ctx, ctx.User().ID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetOrgUserAuthorizeLevel", err)
		return
	}
	// teams give nothing to a user the organization's two-factor requirement blocks
	if blocked, err := ctx.User().TwoFactorBlocked(ctx, o); err != nil {
		ctx.Error(http.StatusInternalServerError, "TwoFactorBlocked", err)
		return
	} else if blocked {
		authorizeLevel = perm.AccessModeNone
	}

	if authorizeLevel > perm.AccessModeNone {
		op.CanRead = true
	}
	if authorizeLevel > perm.AccessModeRead {
		op.CanWrite = true
	}
	if authorizeLevel > perm.AccessModeWrite {
		op.IsAdmin = true
	}
	if authorizeLevel > perm.AccessModeAdmin {
		op.IsOwner = true
	}

	op.CanCreateRepository, err = org.CanCreateOrgRepo(ctx, ctx.User().ID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "CanCreateOrgRepo", err)
		return
	}

	ctx.JSON(http.StatusOK, op)
}

// GetAll return list of all public organizations
func GetAll(ctx *context.APIContext) {
	// swagger:operation Get /orgs organization orgGetAll
	// ---
	// summary: List all organizations
	// produces:
	// - application/json
	// parameters:
	// - name: archived
	//   in: query
	//   description: only list archived (true) or non-archived (false) organizations; both when omitted
	//   type: boolean
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
	//     "$ref": "#/responses/OrganizationList"

	vMode := []api.VisibleType{api.VisibleTypePublic}
	if ctx.IsSigned() && !ctx.PublicOnly() && !ctx.Doer().IsAccessTokenBot() {
		vMode = append(vMode, api.VisibleTypeLimited)
		if ctx.IsUserSiteAdmin() {
			vMode = append(vMode, api.VisibleTypePrivate)
		}
	}

	listOptions := utils.GetListOptions(ctx)

	publicOrgs, maxResults, err := user_model.SearchUsers(ctx, &user_model.SearchUserOptions{
		Actor:       ctx.Doer(),
		ListOptions: listOptions,
		Type:        user_model.UserTypeOrganization,
		OrderBy:     db.SearchOrderByAlphabetically,
		Visible:     vMode,
		IsArchived:  ctx.FormOptionalBool("archived"),
	})
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "SearchOrganizations", err)
		return
	}
	orgs := make([]*api.Organization, len(publicOrgs))
	for i := range publicOrgs {
		orgs[i] = convert.ToOrganization(ctx, organization.OrgFromUser(publicOrgs[i]))
	}

	ctx.SetLinkHeader(int(maxResults), listOptions.PageSize)
	ctx.SetTotalCountHeader(maxResults)
	ctx.JSON(http.StatusOK, &orgs)
}

// Create api for create organization
func Create(ctx *context.APIContext) {
	// swagger:operation POST /orgs organization orgCreate
	// ---
	// summary: Create an organization
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: organization
	//   in: body
	//   required: true
	//   schema: { "$ref": "#/definitions/CreateOrgOption" }
	// responses:
	//   "201":
	//     "$ref": "#/responses/Organization"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "422":
	//     "$ref": "#/responses/validationError"
	form := web.GetForm(ctx).(*api.CreateOrgOption)

	visibility := api.VisibleTypePublic
	if form.Visibility != "" {
		visibility = api.VisibilityModes[form.Visibility]
	}

	org := &organization.Organization{
		Name:                      form.UserName,
		FullName:                  form.FullName,
		Email:                     form.Email,
		Description:               form.Description,
		Website:                   form.Website,
		Location:                  form.Location,
		IsActive:                  true,
		Type:                      user_model.UserTypeOrganization,
		Visibility:                visibility,
		RepoAdminChangeTeamAccess: form.RepoAdminChangeTeamAccess,
	}
	if err := usergroup_service.CreateOrganization(ctx, org, ctx.Doer()); err != nil {
		if user_model.IsErrUserAlreadyExist(err) ||
			db.IsErrNameReserved(err) ||
			db.IsErrNameCharsNotAllowed(err) ||
			db.IsErrNamePatternNotAllowed(err) {
			ctx.Error(http.StatusUnprocessableEntity, "", err)
		} else if errors.Is(err, util.ErrPermissionDenied) { // not an own act, or the owner may not create organizations
			ctx.Error(http.StatusForbidden, "", err)
		} else {
			ctx.Error(http.StatusInternalServerError, "CreateOrganization", err)
		}
		return
	}

	ctx.JSON(http.StatusCreated, convert.ToOrganization(ctx, org))
}

// Get get an organization
func Get(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org} organization orgGet
	// ---
	// summary: Get an organization
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization to get
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/Organization"
	//   "404":
	//     "$ref": "#/responses/notFound"

	auditorView := ctx.Doer() != nil && ctx.Doer().IsAuditor && auth.IsHeldByUser(ctx.Authentication())
	if !auditorView && !organization.HasOrgOrUserVisible(ctx, ctx.Org().Organization.AsUser(), ctx.Doer()) {
		ctx.NotFound("HasOrgOrUserVisible", nil)
		return
	}

	org := convert.ToOrganization(ctx, ctx.Org().Organization)

	// Don't show Mail, when User is not logged in
	if ctx.Doer() == nil {
		org.Email = ""
	}

	if !setOwnerFields(ctx, org) {
		return
	}
	ctx.JSON(http.StatusOK, org)
}

// setOwnerFields adds what only the organization's acting owners and site administrators see. It reports false when
// it has already answered.
func setOwnerFields(ctx *context.APIContext, org *api.Organization) bool {
	doer := ctx.Doer()
	if doer == nil {
		return true
	}
	allowed := doer.IsAdmin
	if !allowed {
		var err error
		if allowed, err = ctx.Org().Organization.IsActingOwner(ctx, doer); err != nil {
			ctx.Error(http.StatusInternalServerError, "IsActingOwner", err)
			return false
		}
	}
	if allowed {
		org.RequireTwoFactor = &ctx.Org().Organization.RequireTwoFactor
	}
	return true
}

func Rename(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/rename organization renameOrg
	// ---
	// summary: Rename an organization
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: existing org name
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/RenameOrgOption"
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "422":
	//     "$ref": "#/responses/validationError"

	form := web.GetForm(ctx).(*api.RenameOrgOption)
	orgUser := ctx.Org().Organization.AsUser()
	if err := user_service.RenameUser(ctx, orgUser, form.NewName); err != nil {
		if user_model.IsErrUserAlreadyExist(err) || db.IsErrNameReserved(err) || db.IsErrNamePatternNotAllowed(err) || db.IsErrNameCharsNotAllowed(err) {
			ctx.Error(http.StatusUnprocessableEntity, "RenameOrg", err)
		} else if errors.Is(err, util.ErrPermissionDenied) {
			ctx.Error(http.StatusForbidden, "RenameOrg", err)
		} else {
			ctx.ServerError("RenameOrg", err)
		}
		return
	}
	ctx.Status(http.StatusNoContent)
}

// Edit change an organization's information
func Edit(ctx *context.APIContext) {
	// swagger:operation PATCH /orgs/{org} organization orgEdit
	// ---
	// summary: Edit an organization
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization to edit
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/EditOrgOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/Organization"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/error"

	form := web.GetForm(ctx).(*api.EditOrgOption)

	// the site floor can't be loosened; checked before anything is written
	var forkPolicy *int
	if form.PrivateForkPolicy != nil {
		i := slices.Index(user_model.PrivateForkPolicyNames, *form.PrivateForkPolicy)
		forkPolicy = &i
	}
	if policy := repo_module.OrgPolicyFloorViolation(form.RestrictRepoVisibilityChange, forkPolicy); policy != "" {
		ctx.Error(http.StatusUnprocessableEntity, "OrgPolicyFloorViolation", "blocked by the site policy "+policy)
		return
	}

	// as on the web: turning the requirement on needs two-factor authentication of one's own, or a site admin
	if form.RequireTwoFactor != nil && *form.RequireTwoFactor && !ctx.Doer().IsAdmin {
		has, err := auth_model.HasTwoFactorByUID(ctx, ctx.Doer().ID)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "HasTwoFactorByUID", err)
			return
		} else if !has {
			ctx.Error(http.StatusForbidden, "", "enable two-factor authentication on your own account first")
			return
		}
	}

	if form.Email != nil {
		if *form.Email == "" {
			err := user_model.DeletePrimaryEmailAddressOfUser(ctx, ctx.Org().Organization.ID)
			if err != nil {
				ctx.Error(http.StatusInternalServerError, "DeletePrimaryEmailAddressOfUser", err)
				return
			}
			ctx.Org().Organization.Email = ""
		} else {
			if err := user_service.ReplacePrimaryEmailAddress(ctx, ctx.Org().Organization.AsUser(), *form.Email); err != nil {
				if validation.IsErrEmailInvalid(err) {
					ctx.Error(http.StatusUnprocessableEntity, "ReplacePrimaryEmailAddress", err)
				} else {
					ctx.Error(http.StatusInternalServerError, "ReplacePrimaryEmailAddress", err)
				}
				return
			}
		}
	}

	changeVisibility := optional.None[api.VisibleType]()
	if form.Visibility != nil {
		changeVisibility = optional.Some(api.VisibilityModes[*form.Visibility])
	}

	opts := &user_service.UpdateOptions{
		FullName:                  optional.FromPtr(form.FullName),
		Description:               optional.FromPtr(form.Description),
		Website:                   optional.FromPtr(form.Website),
		Location:                  optional.FromPtr(form.Location),
		Visibility:                changeVisibility,
		RepoAdminChangeTeamAccess: optional.FromPtr(form.RepoAdminChangeTeamAccess),
	}
	opts.RestrictRepoVisibilityChange = optional.FromPtr(form.RestrictRepoVisibilityChange)
	opts.PrivateForkPolicy = optional.FromPtr(forkPolicy)
	opts.RequireTwoFactor = optional.FromPtr(form.RequireTwoFactor)
	if err := user_service.UpdateUser(ctx, ctx.Org().Organization.AsUser(), opts); err != nil {
		ctx.Error(http.StatusInternalServerError, "UpdateUser", err)
		return
	}

	apiOrg := convert.ToOrganization(ctx, ctx.Org().Organization)
	if setOwnerFields(ctx, apiOrg) {
		ctx.JSON(http.StatusOK, apiOrg)
	}
}

// Archive makes an organization and its repositories read-only
func Archive(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/archive organization orgArchive
	// ---
	// summary: Archive an organization, making it and all of its repositories read-only
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization to archive
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/ArchiveOrgOption"
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	form := web.GetForm(ctx).(*api.ArchiveOrgOption)
	if err := org_service.ArchiveOrganization(ctx, ctx.Org().Organization, ctx.Doer(), form.RemoveMembers); err != nil {
		archiveError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

// Unarchive restores an archived organization and the repositories its archive made read-only
func Unarchive(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/unarchive organization orgUnarchive
	// ---
	// summary: Unarchive an organization, restoring the repositories its archive made read-only
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization to unarchive
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

	if err := org_service.UnarchiveOrganization(ctx, ctx.Org().Organization); err != nil {
		archiveError(ctx, err)
		return
	}
	// the org is unarchived already; the next sync heals any membership this missed
	if err := usergroup_service.SyncOrgTeams(ctx, ctx.Org().Organization.ID); err != nil {
		log.Error("SyncOrgTeams(%d) after unarchive: %v", ctx.Org().Organization.ID, err)
	}
	ctx.Status(http.StatusNoContent)
}

func archiveError(ctx *context.APIContext, err error) {
	switch {
	case organization.IsErrOrgArchived(err):
		ctx.Error(http.StatusForbidden, "OrgArchived", err)
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Error(http.StatusUnprocessableEntity, "OrgNotArchived", err)
	default:
		ctx.Error(http.StatusInternalServerError, "ArchiveOrganization", err)
	}
}

// Delete an organization
func Delete(ctx *context.APIContext) {
	// swagger:operation DELETE /orgs/{org} organization orgDelete
	// ---
	// summary: Delete an organization
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: organization that is to be deleted
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if err := org_service.DeleteOrTrashOrganization(ctx, ctx.Doer(), ctx.Org().Organization); err != nil {
		if models.IsErrUserOwnRepos(err) || models.IsErrUserOwnPackages(err) {
			ctx.Error(http.StatusUnprocessableEntity, "", err)
		} else {
			ctx.Error(http.StatusInternalServerError, "DeleteOrganization", err)
		}
		return
	}
	ctx.Status(http.StatusNoContent)
}

func ListOrgActivityFeeds(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/activities/feeds organization orgListActivityFeeds
	// ---
	// summary: List an organization's activity feeds
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the org
	//   type: string
	//   required: true
	// - name: date
	//   in: query
	//   description: the date of the activities to be found
	//   type: string
	//   format: date
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
	//     "$ref": "#/responses/ActivityFeedsList"
	//   "404":
	//     "$ref": "#/responses/notFound"

	includePrivate := false
	if ctx.IsSigned() {
		if ctx.IsUserSiteAdmin() {
			includePrivate = true
		} else {
			org := organization.OrgFromUser(ctx.User())
			isMember, err := org.IsOrgMember(ctx, ctx.Doer().ID)
			if err != nil {
				ctx.Error(http.StatusInternalServerError, "IsOrgMember", err)
				return
			}
			includePrivate = isMember
		}
	}

	listOptions := utils.GetListOptions(ctx)

	opts := activities_model.GetFeedsOptions{
		RequestedUser:  ctx.User(),
		Actor:          ctx.Doer(),
		IncludePrivate: includePrivate,
		Date:           ctx.FormString("date"),
		ListOptions:    listOptions,
	}

	feeds, count, err := activities_model.GetFeeds(ctx, opts)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetFeeds", err)
		return
	}
	ctx.SetTotalCountHeader(count)

	ctx.JSON(http.StatusOK, convert.ToActivities(ctx, feeds, ctx.Doer()))
}

// ListBlockedUsers list the organization's blocked users.
func ListBlockedUsers(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/list_blocked organization orgListBlockedUsers
	// ---
	// summary: List the organization's blocked users
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the org
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
	//     "$ref": "#/responses/BlockedUserList"

	utils.ListUserBlockedUsers(ctx, ctx.User())
}

// BlockUser blocks a user from the organization.
func BlockUser(ctx *context.APIContext) {
	// swagger:operation PUT /orgs/{org}/block/{username} organization orgBlockUser
	// ---
	// summary: Blocks a user from the organization
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the org
	//   type: string
	//   required: true
	// - name: username
	//   in: path
	//   description: username of the user
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if ctx.User().IsOrganization() {
		ctx.Error(http.StatusUnprocessableEntity, "", fmt.Errorf("%s is an organization not a user", ctx.User().Name))
		return
	}

	utils.BlockUser(ctx, ctx.Org().Organization.AsUser(), ctx.User())
}

// UnblockUser unblocks a user from the organization.
func UnblockUser(ctx *context.APIContext) {
	// swagger:operation PUT /orgs/{org}/unblock/{username} organization orgUnblockUser
	// ---
	// summary: Unblock a user from the organization
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the org
	//   type: string
	//   required: true
	// - name: username
	//   in: path
	//   description: username of the user
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if ctx.User().IsOrganization() {
		ctx.Error(http.StatusUnprocessableEntity, "", fmt.Errorf("%s is an organization not a user", ctx.User().Name))
		return
	}

	utils.UnblockUser(ctx, ctx.Org().Organization.AsUser(), ctx.User())
}
