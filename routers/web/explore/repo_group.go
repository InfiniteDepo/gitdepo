// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package explore

import (
	"net/http"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	shared_user "forgejo.org/routers/web/shared/user"
	"forgejo.org/services/context"
)

const tplExploreRepoGroups base.TplName = "explore/repo_groups"

// RepoGroups lists every project the viewer can see, `/explore/groups`.
func RepoGroups(ctx *context.Context) {
	ctx.Data["UsersPageIsDisabled"] = setting.Service.Explore.DisableUsersPage
	ctx.Data["OrganizationsPageIsDisabled"] = setting.Service.Explore.DisableOrganizationsPage
	ctx.Data["CodePageIsDisabled"] = setting.Service.Explore.DisableCodePage
	ctx.Data["IsRepoIndexerEnabled"] = setting.Indexer.RepoIndexerEnabled
	ctx.Data["Title"] = ctx.Tr("explore")
	ctx.Data["PageIsExplore"] = true
	ctx.Data["PageIsExploreRepoGroups"] = true

	page := max(ctx.FormInt("page"), 1)
	keyword := ctx.FormTrim("q")
	ctx.Data["Keyword"] = keyword
	groups, count, err := repo_model.FindVisibleRepoGroups(ctx, ctx.Doer, 0, keyword, db.ListOptions{Page: page, PageSize: setting.UI.ExplorePagingNum})
	if err != nil {
		ctx.ServerError("FindVisibleRepoGroups", err)
		return
	}
	ownerIDs := make([]int64, 0, len(groups))
	for _, group := range groups {
		ownerIDs = append(ownerIDs, group.OwnerID)
	}
	users, err := user_model.GetUsersByIDs(ctx, ownerIDs)
	if err != nil {
		ctx.ServerError("GetUsersByIDs", err)
		return
	}
	owners := make(map[int64]*user_model.User, len(users))
	for _, u := range users {
		owners[u.ID] = u
	}
	if !shared_user.PrepareRepoGroupList(ctx, groups, &repo_model.SearchRepoOptions{Actor: ctx.Doer, Private: ctx.IsSigned}, owners) {
		return
	}
	pager := context.NewPagination(int(count), setting.UI.ExplorePagingNum, page, 5)
	pager.SetDefaultParams(ctx)
	ctx.Data["Page"] = pager
	ctx.HTML(http.StatusOK, tplExploreRepoGroups)
}
