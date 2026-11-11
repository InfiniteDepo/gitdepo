// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/web"
	repo_setting "forgejo.org/routers/web/repo/setting"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
	repo_service "forgejo.org/services/repository"
)

const tplSettingsBranchCleanup base.TplName = "org/settings/branch_cleanup"

// orgCleanupPageSize is how many repositories one page of the preview plans: each is one walk of its branches.
const orgCleanupPageSize = 20

// prepareCleanup sets the data of the cleanup section of the organization's branch workflow page.
func prepareCleanup(ctx *context.Context) bool {
	org := ctx.Org.Organization.AsUser()
	c, locked, err := branchworkflow.GetOrgCleanup(ctx, org)
	if err != nil {
		ctx.ServerError("GetOrgCleanup", err)
		return false
	}
	setOrgCleanupData(ctx, c)
	ctx.Data["CleanupEnforce"] = locked
	ctx.Data["CleanupLink"] = ctx.Org.OrgLink + "/settings/branch_workflow/cleanup"
	if c != nil && c.Days > 0 {
		n, err := repo_service.CountCleanupRepos(ctx, org, locked)
		if err != nil {
			ctx.ServerError("CountCleanupRepos", err)
			return false
		}
		ctx.Data["CleanupRepoCount"] = n
	}
	return true
}

// setOrgCleanupData sets the status of the organization's cleanup section. There is no one number in force for an
// organization: each repository has its own record, so the page names the days chosen and the earliest date a
// repository without a record starts at.
func setOrgCleanupData(ctx *context.Context, c *repo_model.BranchCleanup) {
	days := 0
	if c != nil {
		days = c.Days
	}
	repo_setting.SetCleanupData(ctx, days, days, 0, time.Time{})
	if days > 0 {
		first := branchworkflow.NextCleanupState(nil, days, timeutil.TimeStampNow().AsTime())
		ctx.Data["CleanupOrgFirst"] = timeutil.TimeStamp(first.PendingFrom)
	}
}

// BranchCleanupPost saves the organization's cleanup of merged branches.
func BranchCleanupPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.BranchCleanupForm)
	back := ctx.Org.OrgLink + "/settings/branch_workflow#cleanup"
	days, err := strconv.Atoi(strings.TrimSpace(form.Days))
	if err == nil {
		err = branchworkflow.SetOrgCleanup(ctx, ctx.Org.Organization.AsUser(), days, form.Enforce)
	}
	switch {
	case errors.Is(err, branchworkflow.ErrInvalidCleanupDays), errors.Is(err, strconv.ErrSyntax), errors.Is(err, strconv.ErrRange):
		ctx.Flash.Error(ctx.Tr("repo.settings.cleanup.invalid_days"))
	case err != nil:
		ctx.ServerError("SetOrgCleanup", err)
		return
	default:
		ctx.Flash.Success(ctx.Tr("org.settings.update_setting_success"))
	}
	ctx.Redirect(back)
}

// cleanupRepoRow is a repository of the organization's preview.
type cleanupRepoRow struct {
	Name    string
	Link    string
	Own     bool // it has a setting of its own, which the organization doesn't enforce
	Off     bool // that setting is off
	Days    int
	Skip    string
	Due     int
	Kept    int
	NotDue  int
	Planned bool
}

// BranchCleanup lists, for one page of the organization's repositories, what the cleanup would delete now. Each
// repository is planned on its own, so a large organization costs one page at a time. It deletes nothing.
func BranchCleanup(ctx *context.Context) {
	org := ctx.Org.Organization.AsUser()
	c, locked, err := branchworkflow.GetOrgCleanup(ctx, org)
	if err != nil {
		ctx.ServerError("GetOrgCleanup", err)
		return
	}
	now := timeutil.TimeStampNow().AsTime()
	days := repo_setting.PreviewDays(ctx, 0, c)
	if locked {
		days = c.Days
	}
	ctx.Data["Title"] = ctx.Tr("repo.settings.cleanup.preview_title")
	ctx.Data["PageIsOrgSettings"] = true
	ctx.Data["PageIsOrgSettingsBranchWorkflow"] = true
	ctx.Data["PreviewDays"] = days
	ctx.Data["CleanupLink"] = ctx.Org.OrgLink + "/settings/branch_workflow/cleanup"
	ctx.Data["BackLink"] = ctx.Org.OrgLink + "/settings/branch_workflow#cleanup"
	ctx.Data["CleanupEnforce"] = locked
	setOrgCleanupData(ctx, c)
	ctx.Data["MaxPerRun"] = repo_service.MaxCleanupPerRepo
	if ctx.Doer != nil && (ctx.Doer.IsAdmin || ctx.Doer.IsAuditor) {
		ctx.Data["AuditLink"] = setting.AppSubURL + "/-/admin/audit?action=repo.branches.cleanup_deleted"
	}
	if !locked && (c == nil || c.Days == 0) { // only while cleanup is off for the organization
		ctx.Data["CanTurnOn"] = true
		ctx.Data["TurnOnStart"] = timeutil.TimeStamp(branchworkflow.NextCleanupState(nil, days, now).PendingFrom)
	}

	page := max(ctx.FormInt("page"), 1)
	repos, total, err := repo_service.FindOrgCleanupRepos(ctx, org, page, orgCleanupPageSize)
	if err != nil {
		ctx.ServerError("FindOrgCleanupRepos", err)
		return
	}
	rows := make([]cleanupRepoRow, 0, len(repos))
	for _, r := range repos {
		e, err := branchworkflow.GetEffectiveCleanup(ctx, r)
		if err != nil {
			ctx.ServerError("GetEffectiveCleanup", err)
			return
		}
		row := cleanupRepoRow{Name: r.FullName(), Link: r.Link() + "/settings/branch_workflow/cleanup", Days: days}
		if e.Days > 0 { // the days in force (a change that waits is not counted), as on the repository's own page
			row.Days = e.Days
		}
		if e.Configured != nil && !e.Locked {
			row.Own, row.Off = true, e.Configured.Days == 0
		}
		if !row.Off {
			plan, err := repo_service.PlanBranchCleanup(ctx, r, row.Days, now)
			if err != nil {
				ctx.ServerError("PlanBranchCleanup", err)
				return
			}
			row.Skip, row.Planned = plan.Skip, plan.Skip == ""
			if row.Skip != "" {
				row.Skip = repo_setting.CleanupSkipText(ctx.Locale, row.Skip)
			}
			row.Due, row.Kept, row.NotDue = len(plan.Due), len(plan.Kept), len(plan.NotDue)
		}
		rows = append(rows, row)
	}
	ctx.Data["Repos"] = rows
	pager := context.NewPagination(int(total), orgCleanupPageSize, page, 5)
	pager.AddParamString("days", strconv.Itoa(days))
	ctx.Data["Page"] = pager
	ctx.HTML(http.StatusOK, tplSettingsBranchCleanup)
}
