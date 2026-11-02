// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"html/template"
	"maps"
	"net/http"
	"slices"
	"strings"

	org_model "forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/services/context"
	usergroup_service "forgejo.org/services/usergroup"
)

const tplOrgAdminRole base.TplName = "admin/org_admin_role"

// lastOrgOwnerMessage is the message for an ErrLastOrgOwner, naming the organization.
func lastOrgOwnerMessage(ctx *context.Context, err error) template.HTML {
	var lastOwner org_model.ErrLastOrgOwner
	if errors.As(err, &lastOwner) && lastOwner.OrgID > 0 {
		if org, err := org_model.GetOrgByID(ctx, lastOwner.OrgID); err == nil {
			return ctx.Tr("admin.user_groups.last_org_owner_org", org.Name)
		}
	}
	return ctx.Tr("admin.user_groups.last_org_owner")
}

// OrgAdminRole shows the groups granting the organization administrator role, their members and the excluded organizations
func OrgAdminRole(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.roles.org_admin")
	ctx.Data["PageIsAdminOrgAdminRole"] = true

	groups, err := org_model.GetOrgAdminGroups(ctx)
	if err != nil {
		ctx.ServerError("GetOrgAdminGroups", err)
		return
	}
	if err := org_model.LoadUserGroupsNumMembers(ctx, groups); err != nil {
		ctx.ServerError("LoadUserGroupsNumMembers", err)
		return
	}
	memberIDs := make(map[int64]bool)
	for _, g := range groups {
		ids, err := org_model.GetUserGroupMemberIDs(ctx, g.ID)
		if err != nil {
			ctx.ServerError("GetUserGroupMemberIDs", err)
			return
		}
		for _, id := range ids {
			memberIDs[id] = true
		}
	}
	members, err := user_model.GetUsersByIDs(ctx, slices.Collect(maps.Keys(memberIDs)))
	if err != nil {
		ctx.ServerError("GetUsersByIDs", err)
		return
	}

	excluded, err := org_model.GetOrgAdminExclusionOrgIDs(ctx)
	if err != nil {
		ctx.ServerError("GetOrgAdminExclusionOrgIDs", err)
		return
	}
	names := make([]string, 0, len(excluded))
	for id := range excluded {
		org, err := org_model.GetOrgByID(ctx, id)
		if err != nil {
			ctx.ServerError("GetOrgByID", err)
			return
		}
		names = append(names, org.Name)
	}

	ctx.Data["Groups"] = groups
	ctx.Data["Members"] = members
	slices.Sort(names)
	ctx.Data["Exclusions"] = strings.Join(names, "\n")
	ctx.HTML(http.StatusOK, tplOrgAdminRole)
}

// OrgAdminRoleExclusionsPost replaces the organizations excluded from the role
func OrgAdminRoleExclusionsPost(ctx *context.Context) {
	redirect := setting.AppSubURL + "/admin/roles/org-admin"
	ids, err := usergroup_service.ResolveOrgIDs(ctx, strings.Fields(ctx.FormString("orgs")))
	if err == nil {
		err = usergroup_service.SetOrgAdminExclusions(ctx, ids)
	}
	switch {
	case err == nil:
		ctx.Flash.Success(ctx.Tr("admin.roles.org_admin.saved"))
	case user_model.IsErrUserNotExist(err), errors.Is(err, usergroup_service.ErrNotOrganization):
		ctx.Flash.Error(ctx.Tr("admin.roles.org_admin.unknown_org", err.Error()))
	case org_model.IsErrLastOrgOwner(err):
		ctx.Flash.Error(lastOrgOwnerMessage(ctx, err))
	default:
		ctx.ServerError("SetOrgAdminExclusions", err)
		return
	}
	ctx.Redirect(redirect)
}
