// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"net/http"

	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/services/accessreport"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

const tplMemberAccess base.TplName = "org/member/access"

// MemberAccess shows what gives a member or outside collaborator access to the organization's repositories.
func MemberAccess(ctx *context.Context) {
	org := ctx.Org.Organization
	u, err := user_model.GetUserByName(ctx, ctx.Params(":username"))
	if err != nil {
		ctx.NotFoundOrServerError("GetUserByName", user_model.IsErrUserNotExist, err)
		return
	}
	isMember, err := organization.IsOrganizationMember(ctx, org.ID, u.ID)
	if err != nil {
		ctx.ServerError("IsOrganizationMember", err)
		return
	}
	if !isMember {
		isCollaborator, err := db.GetEngine(ctx).Table("collaboration").
			Join("INNER", "repository", "repository.id = collaboration.repo_id").
			Where("collaboration.user_id = ? AND repository.owner_id = ?", u.ID, org.ID).Exist()
		if err != nil {
			ctx.ServerError("IsCollaborator", err)
			return
		}
		if !isCollaborator {
			ctx.NotFound("MemberAccess", nil)
			return
		}
	}

	ua, err := accessreport.ForUser(ctx, u, org)
	if err != nil {
		ctx.ServerError("ForUser", err)
		return
	}
	ctx.Data["Title"] = ctx.Tr("access_report.title")
	ctx.Data["PageIsOrgMembers"] = true
	ctx.Data["Member"] = u
	ctx.Data["Access"] = convert.ToUserAccess(ctx, ua, ctx.Doer)
	ctx.HTML(http.StatusOK, tplMemberAccess)
}
