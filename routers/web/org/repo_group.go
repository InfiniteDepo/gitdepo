// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"errors"
	"net/http"
	"slices"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	org_model "forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	webhook_model "forgejo.org/models/webhook"
	"forgejo.org/modules/base"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	repo_setting "forgejo.org/routers/web/repo/setting"
	shared_user "forgejo.org/routers/web/shared/user"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
	repo_service "forgejo.org/services/repository"
	webhook_service "forgejo.org/services/webhook"
)

const (
	tplRepoGroupHome     base.TplName = "org/repo_group/home"
	tplRepoGroups        base.TplName = "org/repo_group/list"
	tplRepoGroupNew      base.TplName = "org/repo_group/new"
	tplRepoGroupSettings base.TplName = "org/repo_group/settings"
	tplRepoGroupHooks    base.TplName = "org/repo_group/hooks"
)

// orgRepoSearchOptions are the options of the organization's repository lists, so a project's count is its list.
func orgRepoSearchOptions(ctx *context.Context) *repo_model.SearchRepoOptions {
	return &repo_model.SearchRepoOptions{
		OwnerID:     ctx.Org.Organization.ID,
		Collaborate: optional.Some(false),
		Private:     ctx.IsSigned,
		Actor:       ctx.Doer,
		AuditorView: ctx.IsAuditorView(),
	}
}

// RepoGroups lists the organization's projects the viewer can see, `/org/{org}/groups`.
func RepoGroups(ctx *context.Context) {
	org := ctx.Org.Organization
	page := max(ctx.FormInt("page"), 1)
	keyword := ctx.FormTrim("q")
	groups, count, err := repo_model.FindVisibleRepoGroups(ctx, ctx.Doer, org.ID, keyword, db.ListOptions{Page: page, PageSize: setting.UI.User.RepoPagingNum})
	if err != nil {
		ctx.ServerError("FindVisibleRepoGroups", err)
		return
	}
	if !shared_user.PrepareRepoGroupList(ctx, groups, orgRepoSearchOptions(ctx), map[int64]*user_model.User{org.ID: org.AsUser()}) {
		return
	}
	if err := shared_user.LoadHeaderCount(ctx); err != nil {
		ctx.ServerError("LoadHeaderCount", err)
		return
	}
	ctx.Data["Title"] = ctx.Tr("repo_group.projects")
	ctx.Data["PageIsViewRepoGroups"] = true
	ctx.Data["Keyword"] = keyword
	pager := context.NewPagination(int(count), setting.UI.User.RepoPagingNum, page, 5)
	pager.SetDefaultParams(ctx)
	ctx.Data["Page"] = pager
	ctx.HTML(http.StatusOK, tplRepoGroups)
}

// RepoGroupHome renders the home of a project, `/{org}/{project}`: its repositories the viewer can see.
func RepoGroupHome(ctx *context.Context) {
	org := ctx.Org.Organization
	group := ctx.Data["RepoGroup"].(*repo_model.RepoGroup)

	sortOrder := ctx.FormString("sort")
	if _, ok := repo_model.OrderByFlatMap[sortOrder]; !ok {
		sortOrder = setting.UI.ExploreDefaultSort
	}
	keyword := ctx.FormTrim("q")
	page := max(ctx.FormInt("page"), 1)

	opts := orgRepoSearchOptions(ctx)
	opts.GroupID = group.ID
	opts.ListOptions = db.ListOptions{PageSize: setting.UI.User.RepoPagingNum, Page: page}
	opts.Keyword = keyword
	opts.OrderBy = repo_model.OrderByFlatMap[sortOrder]
	opts.IncludeDescription = setting.UI.SearchRepoDescription
	repos, count, err := repo_model.SearchRepository(ctx, opts)
	if err != nil {
		ctx.ServerError("SearchRepository", err)
		return
	}
	if err := shared_user.LoadHeaderCount(ctx); err != nil {
		ctx.ServerError("LoadHeaderCount", err)
		return
	}
	origin, err := repo_model.GetBitbucketProjectOrigin(ctx, org.ID, group.ID)
	if err != nil {
		ctx.ServerError("GetBitbucketProjectOrigin", err)
		return
	}

	ctx.Data["BitbucketOrigin"] = origin
	ctx.Data["Title"] = org.Name + " / " + group.Name
	ctx.Data["PageIsViewRepoGroups"] = true
	ctx.Data["RepoGroupLink"] = group.Link(org.Name)
	ctx.Data["SortType"] = sortOrder
	ctx.Data["Keyword"] = keyword
	ctx.Data["Repos"] = repos
	ctx.Data["Total"] = count
	pager := context.NewPagination(int(count), setting.UI.User.RepoPagingNum, page, 5)
	pager.SetDefaultParams(ctx)
	ctx.Data["Page"] = pager
	ctx.HTML(http.StatusOK, tplRepoGroupHome)
}

// renderRepoGroupError shows the form again with the message for an error of the name, or fails.
func renderRepoGroupError(ctx *context.Context, err error, tpl base.TplName, form *forms.RepoGroupForm) {
	ctx.Data["Err_Name"] = true
	switch {
	case repo_model.IsErrRepoAlreadyExist(err), repo_model.IsErrRepoFilesAlreadyExist(err):
		ctx.RenderWithErr(ctx.Tr("repo_group.name_taken"), tpl, form)
	case db.IsErrNameReserved(err):
		ctx.RenderWithErr(ctx.Tr("repo_group.name_reserved", err.(db.ErrNameReserved).Name), tpl, form)
	case db.IsErrNamePatternNotAllowed(err):
		ctx.RenderWithErr(ctx.Tr("repo_group.name_pattern_not_allowed", err.(db.ErrNamePatternNotAllowed).Pattern), tpl, form)
	default:
		ctx.ServerError("RepoGroup", err)
	}
}

// prepareRepoGroupForm sets the organization header of the project forms.
func prepareRepoGroupForm(ctx *context.Context, title string) bool {
	if err := shared_user.LoadHeaderCount(ctx); err != nil {
		ctx.ServerError("LoadHeaderCount", err)
		return false
	}
	ctx.Data["Title"] = ctx.Tr(title)
	ctx.Data["PageIsViewRepoGroups"] = true
	return true
}

// NewRepoGroup renders the form to create a project.
func NewRepoGroup(ctx *context.Context) {
	if prepareRepoGroupForm(ctx, "repo_group.new") {
		ctx.HTML(http.StatusOK, tplRepoGroupNew)
	}
}

// NewRepoGroupPost creates a project.
func NewRepoGroupPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.RepoGroupForm)
	if !prepareRepoGroupForm(ctx, "repo_group.new") {
		return
	}
	if ctx.HasError() {
		ctx.HTML(http.StatusOK, tplRepoGroupNew)
		return
	}
	org := ctx.Org.Organization.AsUser()
	group, err := repo_model.CreateRepoGroup(ctx, org, form.Name, form.Description)
	if err != nil {
		renderRepoGroupError(ctx, err, tplRepoGroupNew, form)
		return
	}
	ctx.Redirect(group.Link(org.Name))
}

// RepoGroupSettings renders the settings of a project, `/{org}/{project}/-/settings`.
func RepoGroupSettings(ctx *context.Context) {
	renderRepoGroupSettings(ctx, false)
}

func renderRepoGroupSettings(ctx *context.Context, preview bool) {
	group := ctx.Data["RepoGroup"].(*repo_model.RepoGroup)
	if !prepareRepoGroupForm(ctx, "repo_group.settings") {
		return
	}
	ctx.Data["name"] = group.Name
	ctx.Data["description"] = group.Description
	ctx.Data["RepoGroupLink"] = group.Link(ctx.Org.Organization.Name)
	if !prepareRepoGroupTeams(ctx, group) || !repo_setting.PrepareMergedBranches(ctx, repo_service.MergedBranchScope{Group: group}, group.Link(ctx.Org.Organization.Name)+"/-/settings", preview) {
		return
	}
	ctx.HTML(http.StatusOK, tplRepoGroupSettings)
}

// RepoGroupDeleteMerged renders the settings of a project with the merged branches that would be deleted.
func RepoGroupDeleteMerged(ctx *context.Context) {
	renderRepoGroupSettings(ctx, true)
}

// RepoGroupDeleteMergedPost deletes the merged branches of the project's repositories.
func RepoGroupDeleteMergedPost(ctx *context.Context) {
	group := ctx.Data["RepoGroup"].(*repo_model.RepoGroup)
	repo_setting.DeleteMergedBranchesPost(ctx, repo_service.MergedBranchScope{Group: group}, group.Link(ctx.Org.Organization.Name)+"/-/settings")
}

// prepareRepoGroupTeams lists the teams linked to the project, the other teams of the organization and the
// project's branch rules.
func prepareRepoGroupTeams(ctx *context.Context, group *repo_model.RepoGroup) bool {
	rules, err := git_model.FindOrgProtectedBranchRules(ctx, ctx.Org.Organization.ID, group.ID)
	if err != nil {
		ctx.ServerError("FindOrgProtectedBranchRules", err)
		return false
	}
	ctx.Data["ProtectedBranches"] = rules

	linked, err := org_model.GetRepoGroupTeams(ctx, ctx.Org.Organization.ID, group.ID)
	if err != nil {
		ctx.ServerError("GetRepoGroupTeams", err)
		return false
	}
	teams, err := org_model.FindOrgTeams(ctx, ctx.Org.Organization.ID)
	if err != nil {
		ctx.ServerError("FindOrgTeams", err)
		return false
	}
	others := slices.DeleteFunc(teams, func(t *org_model.Team) bool {
		return slices.ContainsFunc(linked, func(l *org_model.Team) bool { return l.ID == t.ID })
	})
	ctx.Data["LinkedTeams"], ctx.Data["OtherTeams"] = linked, others
	return true
}

// RepoGroupTeamLink links a team to the project, which gives it every repository of the project.
func RepoGroupTeamLink(ctx *context.Context) {
	group := ctx.Data["RepoGroup"].(*repo_model.RepoGroup)
	err := repo_service.LinkTeamToRepoGroup(ctx, ctx.Doer, ctx.Org.Organization, ctx.FormInt64("team_id"), group.ID)
	switch {
	case errors.Is(err, util.ErrAlreadyExist):
		ctx.Flash.Error(ctx.Tr("repo_group.teams.already_linked"))
	case err != nil:
		repoGroupTeamError(ctx, "LinkTeamToRepoGroup", err)
		return
	default:
		ctx.Flash.Success(ctx.Tr("repo_group.teams.linked"))
	}
	ctx.Redirect(group.Link(ctx.Org.Organization.Name) + "/-/settings")
}

// RepoGroupTeamUnlink takes back what the link of a team to the project granted.
func RepoGroupTeamUnlink(ctx *context.Context) {
	group := ctx.Data["RepoGroup"].(*repo_model.RepoGroup)
	if err := repo_service.UnlinkTeamFromRepoGroup(ctx, ctx.Doer, ctx.Org.Organization, ctx.FormInt64("id"), group.ID); err != nil {
		repoGroupTeamError(ctx, "UnlinkTeamFromRepoGroup", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("repo_group.teams.unlinked"))
	ctx.JSONRedirect(group.Link(ctx.Org.Organization.Name) + "/-/settings")
}

// repoGroupTeamError answers 403 for an archived organization, like the archived-org check before the handler, and
// "not found" for a team or project the doer can't see.
func repoGroupTeamError(ctx *context.Context, name string, err error) {
	if org_model.IsErrOrgArchived(err) {
		ctx.Error(http.StatusForbidden)
		return
	}
	ctx.NotFoundOrServerError(name, func(err error) bool {
		return errors.Is(err, util.ErrNotExist) || errors.Is(err, util.ErrPermissionDenied)
	}, err)
}

// RepoGroupSettingsPost renames a project and changes its description.
func RepoGroupSettingsPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.RepoGroupForm)
	org := ctx.Org.Organization.AsUser()
	group := ctx.Data["RepoGroup"].(*repo_model.RepoGroup)
	if !prepareRepoGroupForm(ctx, "repo_group.settings") {
		return
	}
	ctx.Data["RepoGroupLink"] = group.Link(org.Name)
	if !prepareRepoGroupTeams(ctx, group) || !repo_setting.PrepareMergedBranches(ctx, repo_service.MergedBranchScope{Group: group}, group.Link(org.Name)+"/-/settings", false) {
		return
	}
	if ctx.HasError() {
		ctx.HTML(http.StatusOK, tplRepoGroupSettings)
		return
	}
	if form.Name != group.Name {
		if err := repo_service.RenameRepoGroup(ctx, org, group, form.Name); err != nil {
			renderRepoGroupError(ctx, err, tplRepoGroupSettings, form)
			return
		}
	}
	if form.Description != group.Description {
		group.Description = form.Description
		if err := repo_model.UpdateRepoGroupDescription(ctx, group); err != nil {
			ctx.ServerError("UpdateRepoGroupDescription", err)
			return
		}
	}
	ctx.Flash.Success(ctx.Tr("repo_group.settings.updated"))
	ctx.Redirect(group.Link(org.Name) + "/-/settings")
}

// RepoGroupDeletePost deletes an empty project once its full name is confirmed.
func RepoGroupDeletePost(ctx *context.Context) {
	org := ctx.Org.Organization.AsUser()
	group := ctx.Data["RepoGroup"].(*repo_model.RepoGroup)
	if ctx.FormString("confirm_name") != org.Name+"/"+group.Name {
		ctx.Flash.Error(ctx.Tr("repo_group.delete.confirm_mismatch"))
		ctx.Redirect(group.Link(org.Name) + "/-/settings")
		return
	}
	if err := repo_service.DeleteRepoGroup(ctx, org, group); errors.Is(err, repo_model.ErrRepoGroupNotEmpty) {
		ctx.Flash.Error(ctx.Tr("repo_group.delete.not_empty"))
		ctx.Redirect(group.Link(org.Name) + "/-/settings")
		return
	} else if err != nil {
		ctx.ServerError("DeleteRepoGroup", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("repo_group.delete.success", group.Name))
	ctx.Redirect(ctx.Org.OrgLink + "/groups")
}

// RepoGroupWebhooks lists the webhooks of a project, `/{org}/{project}/-/settings/hooks`.
func RepoGroupWebhooks(ctx *context.Context) {
	org := ctx.Org.Organization
	group := ctx.Data["RepoGroup"].(*repo_model.RepoGroup)
	if !prepareRepoGroupForm(ctx, "repo_group.hooks") {
		return
	}
	link := group.Link(org.Name) + "/-/settings/hooks"
	ctx.Data["RepoGroupLink"] = group.Link(org.Name)
	ctx.Data["BaseLink"] = link
	ctx.Data["BaseLinkNew"] = link
	ctx.Data["WebhookList"] = webhook_service.EnabledList(ctx)
	ctx.Data["DisabledWebhookTypes"] = webhook_service.DisabledTypes(ctx)
	ctx.Data["Description"] = ctx.Tr("repo_group.hooks_desc")

	ws, err := db.Find[webhook_model.Webhook](ctx, webhook_model.ListWebhookOptions{OwnerID: org.ID, GroupID: group.ID})
	if err != nil {
		ctx.ServerError("ListWebhooksByOpts", err)
		return
	}
	ctx.Data["Webhooks"] = ws
	ctx.HTML(http.StatusOK, tplRepoGroupHooks)
}

// RepoGroupDeleteWebhook deletes a webhook of the project.
func RepoGroupDeleteWebhook(ctx *context.Context) {
	org := ctx.Org.Organization
	group := ctx.Data["RepoGroup"].(*repo_model.RepoGroup)
	if err := webhook_model.DeleteWebhookByGroupID(ctx, org.ID, group.ID, ctx.FormInt64("id")); err != nil {
		ctx.Flash.Error("DeleteWebhookByGroupID: " + err.Error())
	} else {
		ctx.Flash.Success(ctx.Tr("repo.settings.webhook_deletion_success"))
	}
	ctx.JSONRedirect(group.Link(org.Name) + "/-/settings/hooks")
}
