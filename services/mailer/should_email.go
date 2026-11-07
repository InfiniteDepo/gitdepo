// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package mailer

import (
	"context"

	activities_model "forgejo.org/models/activities"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	"forgejo.org/modules/log"
)

// emailFilter decides whether a recipient wants a mail for an event. It only ever removes recipients from the list
// the call site built: IsActive, unwatch, access and GetMaileableUsersByIDs checks run independently of it, and Custom
// never sends more than andyourown would.
type emailFilter struct {
	settings map[int64]*user_model.NotificationSettings
}

// newEmailFilter loads the stored settings of all given users with one query.
func newEmailFilter(ctx context.Context, repoID int64, userIDs ...int64) (*emailFilter, error) {
	s, err := user_model.LoadNotificationSettings(ctx, userIDs, repoID)
	return &emailFilter{settings: s}, err
}

// ShouldEmail is the one-recipient form of emailFilter.ShouldEmail, for call sites that mail a single user.
func ShouldEmail(ctx context.Context, user *user_model.User, repo *repo_model.Repository, event user_model.NotifyEvent) bool {
	f, err := newEmailFilter(ctx, repo.ID, user.ID)
	if err != nil {
		log.Error("newEmailFilter: %v", err) // fall back to the preset and defaults
	}
	return f.ShouldEmail(user, event)
}

// ShouldEmail applies the preset, or the Custom settings when the user chose Custom or has an override for the repo.
// A disabled preset stays disabled.
func (f *emailFilter) ShouldEmail(user *user_model.User, event user_model.NotifyEvent) bool {
	pref := user.EmailNotificationsPreference
	if pref == user_model.EmailNotificationsDisabled {
		return false
	}
	s := f.settings[user.ID]
	if pref == user_model.EmailNotificationsCustom || s.HasRepoOverride() {
		return s.Enabled(event)
	}
	switch event {
	case user_model.NotifyEventMention, user_model.NotifyEventIssueAssigned, user_model.NotifyEventReviewRequestedMe, user_model.NotifyEventActionsFailed,
		user_model.NotifyEventCredentialExpiry, user_model.NotifyEventSecretAlert, user_model.NotifyEventDeployments:
		return true // these mails always went to everybody but disabled, onmention included
	}
	return pref == user_model.EmailNotificationsEnabled || pref == user_model.EmailNotificationsAndYourOwn
}

// sendsOwnActions reports whether the user wants mail about what they did themselves.
func (f *emailFilter) sendsOwnActions(user *user_model.User) bool {
	switch pref := user.EmailNotificationsPreference; pref {
	case user_model.EmailNotificationsAndYourOwn:
		return true
	case user_model.EmailNotificationsDisabled:
		return false
	}
	s := f.settings[user.ID]
	return (user.EmailNotificationsPreference == user_model.EmailNotificationsCustom || s.HasRepoOverride()) && s.Enabled(user_model.NotifyEventOwnActions)
}

// recipientRole is how a recipient relates to the thread, in precedence order (a mention beats all of them).
type recipientRole int

const (
	roleAuthor recipientRole = iota
	roleReviewer
	roleAssignee
	roleOther
)

// mailRecipients carries what mailIssueCommentBatch needs to pick the event of each recipient.
type mailRecipients struct {
	filter               *emailFilter
	assignees, reviewers container.Set[int64]
}

func (r *mailRecipients) roleOf(issue *issues_model.Issue, userID int64) recipientRole {
	switch {
	case userID == issue.PosterID:
		return roleAuthor
	case r.reviewers.Contains(userID):
		return roleReviewer
	case r.assignees.Contains(userID):
		return roleAssignee
	}
	return roleOther
}

// eventFor maps what happened and the recipient's role to the event the recipient ticks. Mentions are decided by the caller.
//
//	action               author               reviewer          assignee             other
//	comment              pr_comment/issue_comment  pr_comment   pr_comment/issue_comment  watch_every_comment
//	approve / reject     pr_approved / pr_changes_requested  pr_comment  pr_comment   watch_every_comment
//	merge, close, reopen pr_merged, pr_closed, issue_closed_reopened (author, reviewer, assignee)  watch_every_comment
//	new commits          pr_new_commits (author, reviewer, assignee)                     watch_every_comment
//	new issue / new PR   watch_new_issue / watch_new_pr (everyone)
func eventFor(ctx *mailCommentContext, role recipientRole) user_model.NotifyEvent {
	isPull := ctx.Issue.IsPull
	switch ctx.ActionType {
	case activities_model.ActionCreateIssue:
		return user_model.NotifyEventWatchNewIssue
	case activities_model.ActionCreatePullRequest, activities_model.ActionPullRequestReadyForReview:
		return user_model.NotifyEventWatchNewPR
	}
	if role == roleOther {
		return user_model.NotifyEventWatchEveryComment
	}
	switch ctx.ActionType {
	case activities_model.ActionMergePullRequest, activities_model.ActionAutoMergePullRequest:
		return user_model.NotifyEventPRMerged
	case activities_model.ActionClosePullRequest, activities_model.ActionReopenPullRequest:
		return user_model.NotifyEventPRClosed
	case activities_model.ActionCloseIssue, activities_model.ActionReopenIssue:
		if isPull {
			return user_model.NotifyEventPRClosed
		}
		return user_model.NotifyEventIssueClosedReopened
	}
	if ctx.Comment != nil && ctx.Comment.Type == issues_model.CommentTypePullRequestPush {
		return user_model.NotifyEventPRNewCommits
	}
	switch {
	case ctx.ReviewType == issues_model.ReviewTypeApprove && role == roleAuthor:
		return user_model.NotifyEventPRApproved
	case ctx.ReviewType == issues_model.ReviewTypeReject && role == roleAuthor:
		return user_model.NotifyEventPRChangesRequested
	case isPull:
		return user_model.NotifyEventPRComment
	}
	return user_model.NotifyEventIssueComment
}
