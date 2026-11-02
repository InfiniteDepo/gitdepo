// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"forgejo.org/models"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/web"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
	usergroup_service "forgejo.org/services/usergroup"
)

const (
	tplUserGroups    base.TplName = "admin/user_group/list"
	tplUserGroupNew  base.TplName = "admin/user_group/new"
	tplUserGroupView base.TplName = "admin/user_group/view"
)

func userGroupLink(g *org_model.UserGroup) string {
	return fmt.Sprintf("%s/admin/groups/%d", setting.AppSubURL, g.ID)
}

// UserGroups shows all user groups
func UserGroups(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.user_groups")
	ctx.Data["PageIsAdminUserGroups"] = true

	page := max(ctx.FormInt("page"), 1)
	opts := &org_model.SearchUserGroupOptions{
		ListOptions: db.ListOptions{Page: page, PageSize: setting.UI.Admin.OrgPagingNum},
		Keyword:     ctx.FormTrim("q"),
	}
	groups, count, err := org_model.SearchUserGroups(ctx, opts)
	if err != nil {
		ctx.ServerError("SearchUserGroups", err)
		return
	}
	for _, g := range groups {
		if err := g.LoadCounts(ctx); err != nil {
			ctx.ServerError("LoadCounts", err)
			return
		}
	}

	ctx.Data["Groups"] = groups
	ctx.Data["Total"] = count
	ctx.Data["Keyword"] = opts.Keyword

	pager := context.NewPagination(int(count), opts.PageSize, opts.Page, 5)
	pager.SetDefaultParams(ctx)
	ctx.Data["Page"] = pager

	ctx.HTML(http.StatusOK, tplUserGroups)
}

// NewUserGroup renders the page to create a user group
func NewUserGroup(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.user_groups.new")
	ctx.Data["PageIsAdminUserGroups"] = true
	ctx.HTML(http.StatusOK, tplUserGroupNew)
}

// NewUserGroupPost creates a user group
func NewUserGroupPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.UserGroupForm)
	ctx.Data["Title"] = ctx.Tr("admin.user_groups.new")
	ctx.Data["PageIsAdminUserGroups"] = true

	if ctx.HasError() {
		ctx.HTML(http.StatusOK, tplUserGroupNew)
		return
	}

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
			ctx.Data["Err_Name"] = true
			ctx.RenderWithErr(ctx.Tr("admin.user_groups.name_taken"), tplUserGroupNew, form)
			return
		}
		ctx.ServerError("InsertUserGroup", err)
		return
	}

	ctx.Flash.Success(ctx.Tr("admin.user_groups.created", group.Name))
	ctx.Redirect(userGroupLink(group))
}

func getUserGroup(ctx *context.Context) *org_model.UserGroup {
	group, err := org_model.GetUserGroupByID(ctx, ctx.ParamsInt64(":id"))
	if err != nil {
		ctx.NotFoundOrServerError("GetUserGroupByID", org_model.IsErrUserGroupNotExist, err)
		return nil
	}
	return group
}

// prepareUserGroupView loads the page data of a user group, and returns how
// many members would lose each role the group grants without it.
func prepareUserGroupView(ctx *context.Context, group *org_model.UserGroup) map[org_model.UserGroupRole]int {
	ctx.Data["Title"] = group.Name
	ctx.Data["PageIsAdminUserGroups"] = true
	ctx.Data["Group"] = group
	ctx.Data["GroupLink"] = userGroupLink(group)

	members, err := org_model.GetUserGroupMembers(ctx, group.ID, db.ListOptions{})
	if err != nil {
		ctx.ServerError("GetUserGroupMembers", err)
		return nil
	}
	ctx.Data["Members"] = members

	memberSourceIDs, err := org_model.GetUserGroupMemberLoginSources(ctx, group.ID)
	if err != nil {
		ctx.ServerError("GetUserGroupMemberLoginSources", err)
		return nil
	}
	sourceNames := make(map[int64]string)
	memberSources := make(map[int64]string, len(memberSourceIDs))
	for uid, sourceID := range memberSourceIDs {
		name, ok := sourceNames[sourceID]
		if !ok {
			source, err := auth_model.GetSourceByID(ctx, sourceID)
			if err != nil && !auth_model.IsErrSourceNotExist(err) {
				ctx.ServerError("GetSourceByID", err)
				return nil
			} else if err == nil {
				name = source.Name
			}
			sourceNames[sourceID] = name
		}
		if name != "" {
			memberSources[uid] = name
		}
	}
	ctx.Data["MemberSources"] = memberSources

	teams, err := org_model.GetUserGroupTeams(ctx, group.ID)
	if err != nil {
		ctx.ServerError("GetUserGroupTeams", err)
		return nil
	}
	ctx.Data["LinkedTeams"] = teams

	var roles []org_model.UserGroupRole
	if group.GrantsSiteAdmin {
		roles = append(roles, org_model.UserGroupRoleSiteAdmin)
	}
	if group.GrantsCreateOrganization {
		roles = append(roles, org_model.UserGroupRoleCreateOrganization)
	}
	if group.GrantsAuditor {
		roles = append(roles, org_model.UserGroupRoleAuditor)
	}
	losses, err := org_model.CountUserGroupRoleLosses(ctx, group.ID, roles...)
	if err != nil {
		ctx.ServerError("CountUserGroupRoleLosses", err)
		return nil
	}
	ctx.Data["LoseSiteAdmin"] = losses[org_model.UserGroupRoleSiteAdmin]
	ctx.Data["LoseCreateOrganization"] = losses[org_model.UserGroupRoleCreateOrganization]
	ctx.Data["LoseAuditor"] = losses[org_model.UserGroupRoleAuditor]
	return losses
}

// ViewUserGroup shows a user group with its members and linked teams
func ViewUserGroup(ctx *context.Context) {
	group := getUserGroup(ctx)
	if ctx.Written() {
		return
	}
	prepareUserGroupView(ctx, group)
	if ctx.Written() {
		return
	}
	ctx.Data["name"] = group.Name
	ctx.Data["description"] = group.Description
	ctx.Data["grants_site_admin"] = group.GrantsSiteAdmin
	ctx.Data["grants_create_organization"] = group.GrantsCreateOrganization
	ctx.Data["grants_auditor"] = group.GrantsAuditor
	ctx.Data["grants_org_admin"] = group.GrantsOrgAdmin
	ctx.HTML(http.StatusOK, tplUserGroupView)
}

// EditUserGroupPost updates the name and description of a user group
func EditUserGroupPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.UserGroupForm)
	group := getUserGroup(ctx)
	if ctx.Written() {
		return
	}
	losses := prepareUserGroupView(ctx, group)
	if ctx.Written() {
		return
	}

	if ctx.HasError() {
		ctx.HTML(http.StatusOK, tplUserGroupView)
		return
	}

	// Ask before taking a role away from members, again for each role not yet confirmed.
	var warned []string
	confirm := false
	confirmed := strings.Split(form.ConfirmRoles, ",")
	for role, off := range map[org_model.UserGroupRole]bool{
		org_model.UserGroupRoleSiteAdmin:          group.GrantsSiteAdmin && !form.GrantsSiteAdmin,
		org_model.UserGroupRoleCreateOrganization: group.GrantsCreateOrganization && !form.GrantsCreateOrganization,
		org_model.UserGroupRoleAuditor:            group.GrantsAuditor && !form.GrantsAuditor,
	} {
		if off && losses[role] > 0 {
			warned = append(warned, string(role))
			confirm = confirm || !slices.Contains(confirmed, string(role))
		}
	}
	if confirm {
		slices.Sort(warned)
		ctx.Data["ConfirmRoles"] = strings.Join(warned, ",")
		ctx.Data["WarnSiteAdmin"] = slices.Contains(warned, string(org_model.UserGroupRoleSiteAdmin))
		ctx.Data["WarnCreateOrganization"] = slices.Contains(warned, string(org_model.UserGroupRoleCreateOrganization))
		ctx.Data["WarnAuditor"] = slices.Contains(warned, string(org_model.UserGroupRoleAuditor))
		ctx.HTML(http.StatusOK, tplUserGroupView)
		return
	}

	group.Name = form.Name
	group.Description = form.Description
	group.GrantsSiteAdmin = form.GrantsSiteAdmin
	group.GrantsCreateOrganization = form.GrantsCreateOrganization
	group.GrantsAuditor = form.GrantsAuditor
	group.GrantsOrgAdmin = form.GrantsOrgAdmin
	if err := usergroup_service.UpdateGroup(ctx, group); err != nil {
		switch {
		case org_model.IsErrUserGroupAlreadyExist(err):
			ctx.Data["Err_Name"] = true
			ctx.RenderWithErr(ctx.Tr("admin.user_groups.name_taken"), tplUserGroupView, form)
		case models.IsErrDeleteLastAdminUser(err):
			ctx.Flash.Error(ctx.Tr("auth.last_admin"))
			ctx.Redirect(userGroupLink(group))
		case org_model.IsErrLastOrgOwner(err):
			ctx.Flash.Error(lastOrgOwnerMessage(ctx, err))
			ctx.Redirect(userGroupLink(group))
		default:
			ctx.ServerError("UpdateGroup", err)
		}
		return
	}

	ctx.Flash.Success(ctx.Tr("admin.user_groups.updated"))
	ctx.Redirect(userGroupLink(group))
}

// DeleteUserGroup deletes a user group
func DeleteUserGroup(ctx *context.Context) {
	group := getUserGroup(ctx)
	if ctx.Written() {
		return
	}

	if err := usergroup_service.DeleteGroup(ctx, group); err != nil {
		if org_model.IsErrLastOrgOwner(err) {
			ctx.Flash.Error(lastOrgOwnerMessage(ctx, err))
			ctx.JSONRedirect(userGroupLink(group))
			return
		}
		if models.IsErrDeleteLastAdminUser(err) {
			ctx.Flash.Error(ctx.Tr("auth.last_admin"))
			ctx.JSONRedirect(userGroupLink(group))
			return
		}
		ctx.ServerError("DeleteGroup", err)
		return
	}

	ctx.Flash.Success(ctx.Tr("admin.user_groups.deleted", group.Name))
	ctx.JSONRedirect(setting.AppSubURL + "/admin/groups")
}

// AddUserGroupMember adds a user to a user group
func AddUserGroupMember(ctx *context.Context) {
	group := getUserGroup(ctx)
	if ctx.Written() {
		return
	}

	user, err := user_model.GetUserByName(ctx, ctx.FormTrim("uname"))
	if err != nil {
		if user_model.IsErrUserNotExist(err) {
			ctx.Flash.Error(ctx.Tr("form.user_not_exist"))
			ctx.Redirect(userGroupLink(group))
			return
		}
		ctx.ServerError("GetUserByName", err)
		return
	}

	switch err := usergroup_service.AddMember(ctx, group, user); {
	case err == nil:
		ctx.Flash.Success(ctx.Tr("admin.user_groups.member_added", user.Name))
	case errors.Is(err, usergroup_service.ErrOrganizationCannotBeMember):
		ctx.Flash.Error(ctx.Tr("admin.user_groups.cannot_add_org"))
	case errors.Is(err, usergroup_service.ErrAlreadyMember):
		ctx.Flash.Error(ctx.Tr("admin.user_groups.already_member", user.Name))
	default:
		ctx.ServerError("AddMember", err)
		return
	}
	ctx.Redirect(userGroupLink(group))
}

// RemoveUserGroupMember removes a user from a user group
func RemoveUserGroupMember(ctx *context.Context) {
	group := getUserGroup(ctx)
	if ctx.Written() {
		return
	}

	if err := usergroup_service.RemoveMember(ctx, group, ctx.FormInt64("uid")); err != nil {
		if org_model.IsErrLastOrgOwner(err) {
			ctx.Flash.Error(lastOrgOwnerMessage(ctx, err))
			ctx.Redirect(userGroupLink(group))
			return
		}
		if models.IsErrDeleteLastAdminUser(err) {
			ctx.Flash.Error(ctx.Tr("auth.last_admin"))
			ctx.Redirect(userGroupLink(group))
			return
		}
		ctx.ServerError("RemoveMember", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("admin.user_groups.member_removed"))
	ctx.Redirect(userGroupLink(group))
}
