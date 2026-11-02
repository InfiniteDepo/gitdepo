// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"html/template"
	"net/http"

	"forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	"forgejo.org/services/context"
	"forgejo.org/services/user"
)

const tplSettingsNotifications base.TplName = "user/settings/notifications"

type notifyRow struct {
	Event   user_model.NotifyEvent
	Label   template.HTML
	Checked bool
}

type notifyGroup struct {
	Title template.HTML
	Rows  []*notifyRow
}

// watchedRepo returns the repo of ?repo= (or the posted repo), only when the doer can read it now and watches it.
// A watch row survives losing access, so it is not an access check. Everything else is a 404.
func watchedRepo(ctx *context.Context) (*repo_model.Repository, bool) {
	id := ctx.FormInt64("repo")
	if id == 0 {
		return nil, true
	}
	repo, err := repo_model.GetRepositoryByID(ctx, id)
	if err != nil {
		ctx.NotFound("GetRepositoryByID", err)
		return nil, false
	}
	perm, err := access.GetUserRepoPermission(ctx, repo, ctx.Doer)
	if err != nil {
		ctx.ServerError("GetUserRepoPermission", err)
		return nil, false
	}
	if !perm.HasAccess() || !repo_model.IsWatcher(ctx, ctx.Doer.ID, repo.ID) {
		ctx.NotFound("watchedRepo", nil)
		return nil, false
	}
	return repo, true
}

// Notifications renders the email notification preset and the per-event table, for the user or for one watched repo.
func Notifications(ctx *context.Context) {
	repo, ok := watchedRepo(ctx)
	if !ok {
		return
	}
	var repoID int64
	if repo != nil {
		repoID = repo.ID
	}
	all, err := user_model.LoadNotificationSettings(ctx, []int64{ctx.Doer.ID}, repoID)
	if err != nil {
		ctx.ServerError("LoadNotificationSettings", err)
		return
	}
	s := all[ctx.Doer.ID]
	row := func(e user_model.NotifyEvent, label template.HTML) *notifyRow {
		return &notifyRow{e, label, s.Enabled(e)}
	}
	ctx.Data["Groups"] = []*notifyGroup{
		{ctx.Tr("settings.notifications.group.pull_requests"), []*notifyRow{
			row(user_model.NotifyEventPRComment, ctx.Tr("settings.notifications.event.pr_comment")),
			row(user_model.NotifyEventPRApproved, ctx.Tr("settings.notifications.event.pr_approved")),
			row(user_model.NotifyEventPRChangesRequested, ctx.Tr("settings.notifications.event.pr_changes_requested")),
			row(user_model.NotifyEventPRMerged, ctx.Tr("settings.notifications.event.pr_merged")),
			row(user_model.NotifyEventPRClosed, ctx.Tr("settings.notifications.event.pr_closed")),
			row(user_model.NotifyEventPRNewCommits, ctx.Tr("settings.notifications.event.pr_new_commits")),
			row(user_model.NotifyEventReviewRequestedMe, ctx.Tr("settings.notifications.event.review_requested_me")),
		}},
		{ctx.Tr("settings.notifications.group.issues"), []*notifyRow{
			row(user_model.NotifyEventIssueAssigned, ctx.Tr("settings.notifications.event.issue_assigned")),
			row(user_model.NotifyEventIssueComment, ctx.Tr("settings.notifications.event.issue_comment")),
			row(user_model.NotifyEventIssueClosedReopened, ctx.Tr("settings.notifications.event.issue_closed_reopened")),
		}},
		{ctx.Tr("settings.notifications.group.mentions"), []*notifyRow{
			row(user_model.NotifyEventMention, ctx.Tr("settings.notifications.event.mention")),
		}},
		{ctx.Tr("settings.notifications.group.watching"), []*notifyRow{
			row(user_model.NotifyEventWatchNewIssue, ctx.Tr("settings.notifications.event.watch_new_issue")),
			row(user_model.NotifyEventWatchNewPR, ctx.Tr("settings.notifications.event.watch_new_pr")),
			row(user_model.NotifyEventWatchRelease, ctx.Tr("settings.notifications.event.watch_release")),
			row(user_model.NotifyEventWatchEveryComment, ctx.Tr("settings.notifications.event.watch_every_comment")),
		}},
		{ctx.Tr("settings.notifications.group.actions"), []*notifyRow{
			row(user_model.NotifyEventActionsFailed, ctx.Tr("settings.notifications.event.actions_failed")),
		}},
		{ctx.Tr("settings.notifications.group.credentials"), []*notifyRow{
			row(user_model.NotifyEventCredentialExpiry, ctx.Tr("settings.notifications.event.credential_expiry")),
		}},
		{ctx.Tr("settings.notifications.group.security"), []*notifyRow{
			row(user_model.NotifyEventSecretAlert, ctx.Tr("settings.notifications.event.secret_alert")),
		}},
		{ctx.Tr("settings.notifications.group.own"), []*notifyRow{
			row(user_model.NotifyEventOwnActions, ctx.Tr("settings.notifications.event.own_actions")),
		}},
	}
	ctx.Data["Title"] = ctx.Tr("settings.notifications")
	ctx.Data["PageIsSettingsNotifications"] = true
	ctx.Data["EmailNotificationsPreference"] = ctx.Doer.EmailNotificationsPreference
	ctx.Data["EnableNotifyMail"] = setting.Service.EnableNotifyMail
	if repo != nil {
		ctx.Data["NotificationRepo"] = repo
	}
	ctx.HTML(http.StatusOK, tplSettingsNotifications)
}

// NotificationsPost saves the preset and every event of the form (user level), or the override of one repo, or
// removes that override ("use my defaults").
func NotificationsPost(ctx *context.Context) {
	repo, ok := watchedRepo(ctx)
	if !ok {
		return
	}
	var repoID int64
	if repo != nil {
		repoID = repo.ID
	}
	back := setting.AppSubURL + "/user/settings/notifications"
	if repo != nil {
		back += "?repo=" + ctx.FormString("repo")
	}
	if ctx.FormBool("reset") && repo != nil {
		if err := user_model.DeleteRepoNotificationSettings(ctx, ctx.Doer.ID, repoID); err != nil {
			ctx.ServerError("DeleteRepoNotificationSettings", err)
			return
		}
		ctx.Flash.Success(ctx.Tr("settings.email_preference_set_success"))
		ctx.Redirect(back)
		return
	}

	// Rows come from the known events, never from the submitted keys; an unknown event_* key refuses the whole form.
	events := make(map[user_model.NotifyEvent]bool, len(user_model.AllNotifyEvents))
	for _, e := range user_model.AllNotifyEvents {
		events[e] = ctx.FormBool("event_" + string(e))
	}
	invalid := repo == nil && !user_model.IsValidEmailNotificationsPreference(ctx.FormString("preference"))
	for k := range ctx.Req.PostForm {
		if len(k) > 6 && k[:6] == "event_" && !user_model.NotifyEvent(k[6:]).IsValid() {
			invalid = true
		}
	}
	if invalid {
		ctx.Flash.Error(ctx.Tr("settings.notifications.invalid"))
		ctx.Redirect(back)
		return
	}
	if err := user_model.SaveNotificationSettings(ctx, ctx.Doer.ID, repoID, events); err != nil {
		ctx.ServerError("SaveNotificationSettings", err)
		return
	}
	if repo == nil {
		opts := &user.UpdateOptions{EmailNotificationsPreference: optional.Some(ctx.FormString("preference"))}
		if err := user.UpdateUser(ctx, ctx.Doer, opts); err != nil {
			ctx.ServerError("UpdateUser", err)
			return
		}
	}
	ctx.Flash.Success(ctx.Tr("settings.email_preference_set_success"))
	ctx.Redirect(back)
}
