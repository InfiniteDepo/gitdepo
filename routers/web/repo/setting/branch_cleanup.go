// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/translation"
	"forgejo.org/modules/web"
	"forgejo.org/routers/web/repo"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/context"
	"forgejo.org/services/cron"
	"forgejo.org/services/forms"
	repo_service "forgejo.org/services/repository"
)

const tplBranchCleanup base.TplName = "repo/settings/branch_cleanup"

// The most rows of each group the preview lists; the counts above them are exact.
const maxCleanupRows = 200

// defaultPreviewDays is what the preview assumes when nothing is set and no number is asked for.
const defaultPreviewDays = 30

// SetCleanupData sets what the cleanup section of the settings pages and the previews show: the days chosen, the days
// in force, and the change that waits with when it takes effect (zero when none). It also works out CleanupState,
// the one answer to "would a run delete anything now": "task_off" (the cron task is off), "paused" (read-only
// maintenance), "pending" (nothing is in force yet, the change waits) or "" (a run would act).
func SetCleanupData(ctx *context.Context, chosen, inForce, pendingDays int, pendingFrom time.Time) {
	ctx.Data["CleanupDays"] = chosen
	ctx.Data["CleanupInForce"] = inForce
	ctx.Data["CleanupTaskOff"] = !cleanupTaskOn()
	ctx.Data["CleanupPaused"] = setting.GetMaintenance(ctx).ReadOnly()
	switch {
	case !cleanupTaskOn():
		ctx.Data["CleanupState"] = "task_off"
	case setting.GetMaintenance(ctx).ReadOnly():
		ctx.Data["CleanupState"] = "paused"
	case inForce == 0 && !pendingFrom.IsZero():
		ctx.Data["CleanupState"] = "pending"
	}
	if !pendingFrom.IsZero() {
		ctx.Data["CleanupPending"] = true
		ctx.Data["CleanupPendingDays"] = pendingDays
		ctx.Data["CleanupStart"] = timeutil.TimeStamp(pendingFrom.Unix())
	}
}

func cleanupTaskOn() bool {
	t := cron.GetTask(repo_service.CleanupTaskName)
	return t != nil && t.IsEnabled()
}

// PreviewDays is the number of days a preview is made for: the one asked for in ?days= when it is valid, else the
// days in force, else the days that are set (while they wait), else defaultPreviewDays.
func PreviewDays(ctx *context.Context, inForce int, s *repo_model.BranchCleanup) int {
	if n, err := strconv.Atoi(ctx.FormString("days")); err == nil && n >= 1 && n <= branchworkflow.MaxCleanupDays {
		return n
	}
	if inForce > 0 {
		return inForce
	}
	if s != nil && s.Days > 0 {
		return s.Days
	}
	return defaultPreviewDays
}

// CleanupSkipText says why a repository is left alone by the cleanup; the reasons are a closed set.
func CleanupSkipText(locale translation.Locale, code string) string {
	switch code {
	case repo_service.CleanupSkipArchived:
		return locale.TrString("repo.settings.cleanup.skip.archived")
	case repo_service.CleanupSkipOrgArchived:
		return locale.TrString("repo.settings.cleanup.skip.org_archived")
	case repo_service.CleanupSkipTrashed:
		return locale.TrString("repo.settings.cleanup.skip.trashed")
	case repo_service.CleanupSkipMirror:
		return locale.TrString("repo.settings.cleanup.skip.mirror")
	case repo_service.CleanupSkipEmpty:
		return locale.TrString("repo.settings.cleanup.skip.empty")
	case repo_service.CleanupSkipNotReady:
		return locale.TrString("repo.settings.cleanup.skip.not_ready")
	case repo_service.CleanupSkipPullsOff:
		return locale.TrString("repo.settings.cleanup.skip.pulls_off")
	case repo_service.CleanupSkipDevMissing:
		return locale.TrString("repo.settings.cleanup.skip.dev_missing")
	}
	return locale.TrString("repo.settings.cleanup.skip.other")
}

// prepareCleanup sets the data of the cleanup section of the repository's branch workflow page.
func prepareCleanup(ctx *context.Context) bool {
	e, err := branchworkflow.GetEffectiveCleanup(ctx, ctx.Repo.Repository)
	if err != nil {
		ctx.ServerError("GetEffectiveCleanup", err)
		return false
	}
	SetCleanupData(ctx, e.Wanted, e.Days, e.PendingDays, e.PendingFrom)
	ctx.Data["RestoreText"] = repo.RestoreText(ctx)
	ctx.Data["CleanupInherit"] = e.Configured == nil
	ctx.Data["CleanupLocked"] = e.Locked
	ctx.Data["CleanupLink"] = ctx.Repo.RepoLink + "/settings/branch_workflow/cleanup"
	if e.Source == branchworkflow.SourceOrg {
		ctx.Data["CleanupSetBy"] = ctx.Locale.TrString("repo.settings.cleanup.set_by_org", e.SetBy)
	}
	if e.Locked && ctx.Doer != nil {
		isOwner, err := organization.OrgFromUser(ctx.Repo.Owner).IsActingOwner(ctx, ctx.Doer)
		if err != nil {
			ctx.ServerError("IsActingOwner", err)
			return false
		}
		if isOwner || ctx.Doer.IsAdmin {
			ctx.Data["CleanupSettingsLink"] = ctx.Repo.Owner.OrganisationLink() + "/settings/branch_workflow#cleanup"
		}
	}
	return true
}

// BranchCleanupPost saves the repository's own cleanup of merged branches.
func BranchCleanupPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.BranchCleanupForm)
	back := ctx.Repo.RepoLink + "/settings/branch_workflow#cleanup"
	var days *int
	if !form.Inherit || !ctx.Repo.Owner.IsOrganization() {
		n, err := strconv.Atoi(strings.TrimSpace(form.Days))
		if err != nil {
			ctx.Flash.Error(ctx.Tr("repo.settings.cleanup.invalid_days"))
			ctx.Redirect(back)
			return
		}
		days = &n
	}
	switch err := branchworkflow.SetRepoCleanup(ctx, ctx.Repo.Repository, days); {
	case errors.Is(err, branchworkflow.ErrLocked):
		ctx.Error(http.StatusForbidden, ctx.Locale.TrString("repo.settings.cleanup.locked"))
		return
	case errors.Is(err, branchworkflow.ErrNoPullRequests):
		ctx.Flash.Error(ctx.Tr("repo.settings.branch_workflow.pulls_disabled"))
	case errors.Is(err, branchworkflow.ErrInvalidCleanupDays):
		ctx.Flash.Error(ctx.Tr("repo.settings.cleanup.invalid_days"))
	case err != nil:
		ctx.ServerError("SetRepoCleanup", err)
		return
	default:
		ctx.Flash.Success(ctx.Tr("repo.settings.update_settings_success"))
		flashCleanupDue(ctx)
	}
	ctx.Redirect(back)
}

// flashCleanupDue tells, after a save that leaves cleanup on or waiting, how many branches it would delete now.
func flashCleanupDue(ctx *context.Context) {
	e, err := branchworkflow.GetEffectiveCleanup(ctx, ctx.Repo.Repository)
	if err != nil || e.Wanted == 0 {
		return
	}
	plan, err := repo_service.PlanBranchCleanup(ctx, ctx.Repo.Repository, e.Wanted, timeutil.TimeStampNow().AsTime())
	if err != nil || plan.Skip != "" {
		return
	}
	ctx.Flash.Info(ctx.Locale.TrPluralString(len(plan.Due), "repo.settings.cleanup.due_now", len(plan.Due)))
}

// cleanupRow is a branch of the preview.
type cleanupRow struct {
	Name   string
	Into   string
	At     timeutil.TimeStamp
	PR     int64 // 0 unless the viewer can read pull requests
	Age    int   // whole days since At
	FromPR bool
	Reason string
}

// BranchCleanupPreview shows what the cleanup of the repository would delete now, which merged branches are kept
// and why, and which are not due yet. It deletes nothing.
func BranchCleanupPreview(ctx *context.Context) {
	r := ctx.Repo.Repository
	e, err := branchworkflow.GetEffectiveCleanup(ctx, r)
	if err != nil {
		ctx.ServerError("GetEffectiveCleanup", err)
		return
	}
	now := timeutil.TimeStampNow().AsTime()
	days := PreviewDays(ctx, e.Days, e.Setting)
	if e.Locked { // what the organization enforces: in force, else the one that waits
		days = e.Days
		if days == 0 {
			days = e.Wanted
		}
	}
	ctx.Data["Title"] = ctx.Tr("repo.settings.cleanup.preview_title")
	ctx.Data["PageIsSettingsBranchWorkflow"] = true
	ctx.Data["CleanupLink"] = r.Link() + "/settings/branch_workflow/cleanup"
	ctx.Data["BackLink"] = r.Link() + "/settings/branch_workflow#cleanup"
	ctx.Data["PreviewDays"] = days
	ctx.Data["CleanupLocked"] = e.Locked
	ctx.Data["CleanupSetBy"] = ""
	if e.Source == branchworkflow.SourceOrg {
		ctx.Data["CleanupSetBy"] = ctx.Locale.TrString("repo.settings.cleanup.set_by_org", e.SetBy)
	}
	SetCleanupData(ctx, e.Wanted, e.Days, e.PendingDays, e.PendingFrom)
	ctx.Data["MaxPerRun"] = repo_service.MaxCleanupPerRepo
	ctx.Data["RestoreText"] = repo.RestoreText(ctx)
	if ctx.Doer != nil && (ctx.Doer.IsAdmin || ctx.Doer.IsAuditor) {
		ctx.Data["AuditLink"] = setting.AppSubURL + "/-/admin/audit?action=repo.branches.cleanup_deleted"
	}

	// "Turn on cleanup" for these days, with the date it would take effect; not offered when they already are the setting
	if ctx.Repo.IsAdmin() && !e.Locked && !(e.Setting != nil && e.Setting.Days == days) {
		ctx.Data["CanTurnOn"] = true
		if next := branchworkflow.NextCleanupState(e.State, days, now); next.PendingFrom != 0 && next.Days != days {
			ctx.Data["TurnOnStart"] = timeutil.TimeStamp(next.PendingFrom)
		}
	}

	plan, err := repo_service.PlanBranchCleanup(ctx, r, days, now)
	if err != nil {
		ctx.ServerError("PlanBranchCleanup", err)
		return
	}
	if plan.Skip != "" {
		ctx.Data["SkipText"] = CleanupSkipText(ctx.Locale, plan.Skip)
		ctx.HTML(http.StatusOK, tplBranchCleanup)
		return
	}
	ctx.Data["DueTotal"] = len(plan.Due)
	ctx.Data["DaysNeeded"] = (len(plan.Due) + repo_service.MaxCleanupPerRepo - 1) / repo_service.MaxCleanupPerRepo
	ctx.Data["NotDueTotal"] = len(plan.NotDue)
	// the reasons only for those who can delete the branches; the number of a pull request only for those who can read them
	canSeeKept := ctx.Repo.CanWrite(unit.TypeCode)
	ctx.Data["CanSeeKept"] = canSeeKept
	ctx.Data["KeptTotal"] = len(plan.Kept)
	due := plan.Due[:min(len(plan.Due), maxCleanupRows)]
	notDue := plan.NotDue[:min(len(plan.NotDue), maxCleanupRows)]
	var pulls map[string]int64
	if ctx.Repo.CanRead(unit.TypePullRequests) {
		var names []string
		for _, b := range append(append([]repo_service.CleanupBranch{}, due...), notDue...) {
			names = append(names, b.Name)
		}
		if pulls, err = repo_service.FindCleanupPulls(ctx, r, plan.Targets, names); err != nil {
			ctx.ServerError("FindCleanupPulls", err)
			return
		}
	}
	rows := func(list []repo_service.CleanupBranch) []cleanupRow {
		out := make([]cleanupRow, 0, len(list))
		for _, b := range list {
			out = append(out, cleanupRow{Name: b.Name, Into: b.Into, At: b.At, FromPR: b.FromPR, Age: int(now.Sub(b.At.AsTime()) / (24 * time.Hour)), PR: pulls[b.Name]})
		}
		return out
	}
	ctx.Data["Due"] = rows(due)
	ctx.Data["NotDue"] = rows(notDue)
	if canSeeKept {
		kept := plan.Kept[:min(len(plan.Kept), maxCleanupRows)]
		out := rows(kept)
		for i, b := range kept {
			out[i].Reason = repo.BranchReasonText(ctx.Locale, b.Reason)
		}
		ctx.Data["Kept"] = out
	}
	ctx.HTML(http.StatusOK, tplBranchCleanup)
}
