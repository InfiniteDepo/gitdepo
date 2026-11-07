// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"html/template"
	"net/http"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/services/context"
	trash_service "forgejo.org/services/trash"
)

const tplTrash base.TplName = "admin/trash"

// Trash lists the repositories or organizations (?type=org) in the trash.
func Trash(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.trash")
	ctx.Data["PageIsAdminTrash"] = true
	ctx.Data["RetentionDays"] = setting.Trash.RetentionDays

	keyword := ctx.FormTrim("q")
	page := max(ctx.FormInt("page"), 1)
	listType := "repo"
	if ctx.FormString("type") == "org" {
		listType = "org"
	}
	ctx.Data["Type"] = listType
	items, count, totalSize, err := trash_service.List(ctx, trash_service.ListOptions{
		ListOptions: db.ListOptions{Page: page, PageSize: setting.UI.Admin.RepoPagingNum},
		Keyword:     keyword,
		Type:        listType,
	})
	if err != nil {
		ctx.ServerError("trash.List", err)
		return
	}
	ctx.Data["Items"] = items
	ctx.Data["Keyword"] = keyword
	ctx.Data["Total"] = count
	ctx.Data["TotalSize"] = totalSize

	pager := context.NewPagination(int(count), setting.UI.Admin.RepoPagingNum, page, 5)
	pager.AddParam(ctx, "q", "Keyword")
	pager.AddParam(ctx, "type", "Type")
	ctx.Data["Page"] = pager

	ctx.HTML(http.StatusOK, tplTrash)
}

// trashedRepo returns the repository in the trash named by the :id path parameter, or writes the response.
func trashedRepo(ctx *context.Context) *repo_model.Repository {
	repo, err := repo_model.GetRepositoryByIDIncludingTrashed(ctx, ctx.ParamsInt64(":id"))
	if err != nil && !repo_model.IsErrRepoNotExist(err) {
		ctx.ServerError("GetRepositoryByIDIncludingTrashed", err)
		return nil
	}
	if err != nil || !repo.IsTrashed() {
		ctx.NotFound("trashedRepo", nil)
		return nil
	}
	return repo
}

func trashDone(ctx *context.Context, err error, success template.HTML) {
	switch {
	case errors.Is(err, trash_service.ErrTrashConflict):
		ctx.Flash.Error(ctx.Tr("admin.trash.conflict"))
	case errors.Is(err, trash_service.ErrNeedNewOwner):
		ctx.Flash.Error(ctx.Tr("admin.trash.need_new_owner"))
	case errors.Is(err, trash_service.ErrInvalidNewOwner):
		ctx.Flash.Error(ctx.Tr("admin.trash.invalid_new_owner"))
	case errors.Is(err, trash_service.ErrTrashedWithOrg):
		ctx.Flash.Error(ctx.Tr("admin.trash.with_org"))
	case errors.Is(err, trash_service.ErrOrgHasLiveRepos):
		ctx.Flash.Error(ctx.Tr("admin.trash.org_live_repos"))
	case errors.Is(err, audit_model.ErrNotOwnAct):
		ctx.Flash.Error(ctx.Tr("settings.credential_not_own_act"))
	case trash_service.IsBadTarget(err):
		ctx.Flash.Error(ctx.Tr("admin.trash.bad_target", err.Error()))
	case err != nil:
		ctx.ServerError("trash", err)
		return
	default:
		ctx.Flash.Success(success)
	}
	ctx.Redirect(setting.AppSubURL + "/admin/trash")
}

// RestoreTrash takes a repository out of the trash, under a new owner and/or name if the form says so.
func RestoreTrash(ctx *context.Context) {
	repo := trashedRepo(ctx)
	if repo == nil {
		return
	}
	trashDone(ctx, trash_service.RestoreRepo(ctx, ctx.Doer, repo.ID, trash_service.RestoreOptions{
		NewOwner: ctx.FormTrim("new_owner"),
		NewName:  ctx.FormTrim("new_name"),
	}), ctx.Tr("admin.trash.restored", repo.TrashedFullName()))
}

// PurgeTrash deletes a repository in the trash for good, after its name was typed.
func PurgeTrash(ctx *context.Context) {
	repo := trashedRepo(ctx)
	if repo == nil {
		return
	}
	if ctx.FormString("confirm_name") != repo.TrashedFullName() {
		ctx.Flash.Error(ctx.Tr("admin.trash.confirm_mismatch"))
		ctx.Redirect(setting.AppSubURL + "/admin/trash")
		return
	}
	trashDone(ctx, trash_service.Purge(ctx, ctx.Doer, repo.ID), ctx.Tr("admin.trash.purged", repo.TrashedFullName()))
}

// trashedOrg returns the organization in the trash named by the :id path parameter, or writes the response.
func trashedOrg(ctx *context.Context) *user_model.User {
	org, err := user_model.GetUserByIDIncludingTrashed(ctx, ctx.ParamsInt64(":id"))
	if err != nil && !user_model.IsErrUserNotExist(err) {
		ctx.ServerError("GetUserByIDIncludingTrashed", err)
		return nil
	}
	if err != nil || !org.IsOrganization() || !org.IsTrashed() {
		ctx.NotFound("trashedOrg", nil)
		return nil
	}
	return org
}

// RestoreTrashOrg takes an organization and the repositories deleted with it out of the trash.
func RestoreTrashOrg(ctx *context.Context) {
	org := trashedOrg(ctx)
	if org == nil {
		return
	}
	trashDone(ctx, trash_service.RestoreOrg(ctx, ctx.Doer, org.ID, trash_service.RestoreOptions{NewName: ctx.FormTrim("new_name")}),
		ctx.Tr("admin.trash.restored", org.TrashedName))
}

// PurgeTrashOrg deletes an organization in the trash and all its repositories in the trash for good, after its
// name was typed.
func PurgeTrashOrg(ctx *context.Context) {
	org := trashedOrg(ctx)
	if org == nil {
		return
	}
	if ctx.FormString("confirm_name") != org.TrashedName {
		ctx.Flash.Error(ctx.Tr("admin.trash.confirm_mismatch"))
		ctx.Redirect(setting.AppSubURL + "/admin/trash?type=org")
		return
	}
	trashDone(ctx, trash_service.PurgeOrg(ctx, ctx.Doer, org.ID), ctx.Tr("admin.trash.purged", org.TrashedName))
}
