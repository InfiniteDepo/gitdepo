// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package mailer

import (
	"context"
	"strings"
	"testing"

	activities_model "forgejo.org/models/activities"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"code.forgejo.org/xorm/xorm/contexts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var presets = []string{
	user_model.EmailNotificationsEnabled, user_model.EmailNotificationsOnMention,
	user_model.EmailNotificationsAndYourOwn, user_model.EmailNotificationsDisabled,
}

// legacy copies the conditions the call sites had before ShouldEmail existed:
// comment batch (mail_issue.go), mention batch, assigned/review request (notify.go) and Actions (mail_actions.go).
// Credential expiry (mail_credential_expiry.go) and the secret digest (mail_secret_digest.go) are newer and go, like the
// Actions mail, to everybody but disabled.
func legacy(pref string, e user_model.NotifyEvent) bool {
	switch e {
	case user_model.NotifyEventMention:
		return pref == "enabled" || pref == "andyourown" || pref == "onmention"
	case user_model.NotifyEventIssueAssigned, user_model.NotifyEventReviewRequestedMe, user_model.NotifyEventActionsFailed,
		user_model.NotifyEventCredentialExpiry, user_model.NotifyEventSecretAlert:
		return pref != "disabled"
	}
	return pref == "enabled" || pref == "andyourown" // thread and release mails
}

func settingsOf(user, repo map[user_model.NotifyEvent]bool) *emailFilter {
	return &emailFilter{settings: map[int64]*user_model.NotificationSettings{1: {User: user, Repo: repo}}}
}

// AC1: the four presets give today's answer for every event, per call site; the doer rule is unchanged.
func TestShouldEmailLegacy(t *testing.T) {
	f := &emailFilter{}
	for _, p := range presets {
		u := &user_model.User{ID: 1, EmailNotificationsPreference: p}
		for _, e := range user_model.AllNotifyEvents {
			if e == user_model.NotifyEventOwnActions {
				continue
			}
			assert.Equal(t, legacy(p, e), f.ShouldEmail(u, e), "%s %s", p, e)
		}
		assert.Equal(t, p == "andyourown", f.sendsOwnActions(u), p)
	}
}

// AC2, AC4, AC12: Custom sends the ticked events, mentions are on by default, own actions follow own_actions.
func TestShouldEmailCustom(t *testing.T) {
	u := &user_model.User{ID: 1, EmailNotificationsPreference: user_model.EmailNotificationsCustom}
	f := settingsOf(map[user_model.NotifyEvent]bool{
		user_model.NotifyEventPRApproved: true, user_model.NotifyEventPRComment: false,
	}, nil)
	assert.True(t, f.ShouldEmail(u, user_model.NotifyEventPRApproved))
	assert.False(t, f.ShouldEmail(u, user_model.NotifyEventPRComment))
	assert.True(t, (&emailFilter{}).ShouldEmail(u, user_model.NotifyEventMention), "mention on by default")
	assert.False(t, f.sendsOwnActions(u))
	assert.True(t, settingsOf(map[user_model.NotifyEvent]bool{user_model.NotifyEventOwnActions: true}, nil).sendsOwnActions(u))
}

// AC8: a repo override acts as Custom for that repo, except for a disabled preset.
func TestShouldEmailRepoOverride(t *testing.T) {
	repo := map[user_model.NotifyEvent]bool{user_model.NotifyEventPRComment: false}
	for p, want := range map[string]bool{"enabled": false, "andyourown": false, "onmention": false, "custom": false, "disabled": false} {
		u := &user_model.User{ID: 1, EmailNotificationsPreference: p}
		assert.Equal(t, want, settingsOf(nil, repo).ShouldEmail(u, user_model.NotifyEventPRComment), p)
	}
	u := &user_model.User{ID: 1, EmailNotificationsPreference: "onmention"}
	assert.True(t, settingsOf(nil, repo).ShouldEmail(u, user_model.NotifyEventPRApproved), "override widens onmention to the custom defaults")
	u.EmailNotificationsPreference = "disabled"
	assert.False(t, settingsOf(nil, map[user_model.NotifyEvent]bool{user_model.NotifyEventPRApproved: true}).ShouldEmail(u, user_model.NotifyEventPRApproved), "override inert when disabled")
}

// Invariant: Custom never widens recipients beyond andyourown.
func TestCustomNeverWidens(t *testing.T) {
	all := map[user_model.NotifyEvent]bool{}
	for _, e := range user_model.AllNotifyEvents {
		all[e] = true
	}
	f := settingsOf(all, nil)
	custom := &user_model.User{ID: 1, EmailNotificationsPreference: "custom"}
	most := &user_model.User{ID: 1, EmailNotificationsPreference: "andyourown"}
	for _, e := range user_model.AllNotifyEvents {
		if e != user_model.NotifyEventOwnActions {
			assert.False(t, f.ShouldEmail(custom, e) && !(&emailFilter{}).ShouldEmail(most, e), e)
		}
	}
	assert.True(t, f.sendsOwnActions(custom))
}

// AC5: every event constant has a call site through eventFor (or the S4/S5/release sites).
func TestEventFor(t *testing.T) {
	E := user_model.NotifyEvent("")
	type c struct {
		action          activities_model.ActionType
		pull            bool
		review          issues_model.ReviewType
		push            bool
		author, rev     user_model.NotifyEvent
		assignee, other user_model.NotifyEvent
	}
	cases := []c{
		{activities_model.ActionCommentPull, true, 0, false, "pr_comment", "pr_comment", "pr_comment", "watch_every_comment"},
		{activities_model.ActionCommentIssue, false, 0, false, "issue_comment", E, "issue_comment", "watch_every_comment"},
		{activities_model.ActionCommentPull, true, issues_model.ReviewTypeApprove, false, "pr_approved", "pr_comment", "pr_comment", "watch_every_comment"},
		{activities_model.ActionCommentPull, true, issues_model.ReviewTypeReject, false, "pr_changes_requested", "pr_comment", "pr_comment", "watch_every_comment"},
		{activities_model.ActionMergePullRequest, true, 0, false, "pr_merged", "pr_merged", "pr_merged", "watch_every_comment"},
		{activities_model.ActionAutoMergePullRequest, true, 0, false, "pr_merged", "pr_merged", "pr_merged", "watch_every_comment"},
		{activities_model.ActionClosePullRequest, true, 0, false, "pr_closed", "pr_closed", "pr_closed", "watch_every_comment"},
		{activities_model.ActionReopenPullRequest, true, 0, false, "pr_closed", "pr_closed", "pr_closed", "watch_every_comment"},
		{activities_model.ActionCloseIssue, false, 0, false, "issue_closed_reopened", E, "issue_closed_reopened", "watch_every_comment"},
		{activities_model.ActionReopenIssue, false, 0, false, "issue_closed_reopened", E, "issue_closed_reopened", "watch_every_comment"},
		{activities_model.ActionCommentPull, true, 0, true, "pr_new_commits", "pr_new_commits", "pr_new_commits", "watch_every_comment"},
		{activities_model.ActionCreateIssue, false, 0, false, "watch_new_issue", E, "watch_new_issue", "watch_new_issue"},
		{activities_model.ActionCreatePullRequest, true, 0, false, "watch_new_pr", "watch_new_pr", "watch_new_pr", "watch_new_pr"},
	}
	for i, tc := range cases {
		ctx := &mailCommentContext{Issue: &issues_model.Issue{IsPull: tc.pull}, ActionType: tc.action, ReviewType: tc.review}
		if tc.push {
			ctx.Comment = &issues_model.Comment{Type: issues_model.CommentTypePullRequestPush}
		}
		assert.Equal(t, tc.author, eventFor(ctx, roleAuthor), "case %d author", i)
		if tc.rev != E {
			assert.Equal(t, tc.rev, eventFor(ctx, roleReviewer), "case %d reviewer", i)
		}
		assert.Equal(t, tc.assignee, eventFor(ctx, roleAssignee), "case %d assignee", i)
		assert.Equal(t, tc.other, eventFor(ctx, roleOther), "case %d other", i)
	}
}

type countHook struct{ n int }

func (h *countHook) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if strings.Contains(c.SQL, "user_notification_setting") {
		h.n++
	}
	return c.Ctx, nil
}

func (h *countHook) AfterProcess(*contexts.ContextHook) error { return nil }

// AC13: one settings load for the whole recipient list, none for an empty one, and ShouldEmail itself never queries.
func TestNewEmailFilterOneQuery(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	require.NoError(t, user_model.SaveNotificationSettings(db.DefaultContext, 2, 0, map[user_model.NotifyEvent]bool{user_model.NotifyEventPRComment: false}))
	h := &countHook{}
	x, err := db.GetMasterEngine(db.GetEngine(db.DefaultContext))
	require.NoError(t, err)
	x.AddHook(h)

	f, err := newEmailFilter(db.DefaultContext, 1, 2, 3, 4, 5)
	require.NoError(t, err)
	assert.Equal(t, 1, h.n)
	assert.Len(t, f.settings, 1)
	for _, e := range user_model.AllNotifyEvents {
		f.ShouldEmail(&user_model.User{ID: 2, EmailNotificationsPreference: "custom"}, e)
	}
	assert.Equal(t, 1, h.n)

	_, err = newEmailFilter(db.DefaultContext, 1)
	require.NoError(t, err)
	assert.Equal(t, 1, h.n)
}
