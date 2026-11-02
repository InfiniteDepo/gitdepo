// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/services/mailer"
	repo_service "forgejo.org/services/repository"
	user_service "forgejo.org/services/user"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// customOnly makes user a Custom user with exactly the given events ticked.
func customOnly(t *testing.T, user *user_model.User, repoID int64, events ...user_model.NotifyEvent) {
	t.Helper()
	m := map[user_model.NotifyEvent]bool{}
	for _, e := range user_model.AllNotifyEvents {
		m[e] = false
	}
	for _, e := range events {
		m[e] = true
	}
	user.EmailNotificationsPreference = user_model.EmailNotificationsCustom
	require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, user, "email_notifications_preference"))
	require.NoError(t, user_model.SaveNotificationSettings(db.DefaultContext, user.ID, repoID, m))
}

func captureMail(t *testing.T) (recipients func() []string, restore func()) {
	t.Helper()
	var to []string
	undo := test.MockVariableValue(&mailer.SendAsync, func(msgs ...*mailer.Message) {
		for _, m := range msgs {
			to = append(to, m.To)
		}
	})
	return func() []string { return to }, undo
}

func reviewPR3(t *testing.T, event api.ReviewStateType) {
	t.Helper()
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
	req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/reviews", &api.CreatePullReviewOptions{Body: "x", Event: event}).AddTokenAuth(token)
	MakeRequest(t, req, http.StatusOK)
}

func commentPR3(t *testing.T) {
	t.Helper()
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteIssue)
	req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/issues/3/comments", &api.CreateIssueCommentOption{Body: "plain"}).AddTokenAuth(token)
	MakeRequest(t, req, http.StatusCreated)
}

// AC3: with Custom "approved + changes requested" only, an approval mails the PR author and a plain comment does not.
func TestEmailCustomApprovedOnly(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	author := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	customOnly(t, author, 0, user_model.NotifyEventPRApproved, user_model.NotifyEventPRChangesRequested)

	got, undo := captureMail(t)
	defer undo()
	commentPR3(t)
	assert.NotContains(t, got(), author.Email, "plain comment")
	reviewPR3(t, api.ReviewStateApproved)
	assert.Contains(t, got(), author.Email, "approval")
}

// AC8: a per-repo override wins over the user's settings.
func TestEmailRepoOverrideWins(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	author := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	customOnly(t, author, 0, user_model.NotifyEventPRApproved)
	require.NoError(t, user_model.SaveNotificationSettings(db.DefaultContext, 1, 1, map[user_model.NotifyEvent]bool{user_model.NotifyEventPRApproved: false}))

	got, undo := captureMail(t)
	defer undo()
	reviewPR3(t, api.ReviewStateApproved)
	assert.NotContains(t, got(), author.Email)
}

// AC10: users keep their preset; the migration adds no rows and no preset changes recipients (presets are not Custom).
func TestEmailPresetUsersUnchanged(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	n, err := db.GetEngine(db.DefaultContext).Count(new(user_model.NotificationSetting))
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)
	author := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	assert.NotEqual(t, user_model.EmailNotificationsCustom, author.EmailNotificationsPreference)

	got, undo := captureMail(t)
	defer undo()
	commentPR3(t)
	assert.Contains(t, got(), author.Email, "enabled preset still gets plain comments")
}

// AC6: the page saves preset and events, a reload shows them, and picking a preset again keeps the events.
func TestEmailSettingsPage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")

	post := func(preset string, events ...string) {
		form := url.Values{"preference": {preset}}
		for _, e := range events {
			form.Set("event_"+e, "on")
		}
		req := NewRequestWithBody(t, "POST", "/user/settings/notifications", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		session.MakeRequest(t, req, http.StatusSeeOther)
	}
	post("custom", "pr_approved", "own_actions")
	body := session.MakeRequest(t, NewRequest(t, "GET", "/user/settings/notifications"), http.StatusOK).Body.String()
	assert.Regexp(t, `name="event_pr_approved"[^>]*checked`, body)
	assert.NotRegexp(t, `name="event_pr_comment"[^>]*checked`, body)
	assert.Regexp(t, `name="event_own_actions"[^>]*checked`, body)

	post("enabled", "pr_approved", "own_actions")
	u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	assert.Equal(t, "enabled", u.EmailNotificationsPreference)
	s, err := user_model.LoadNotificationSettings(db.DefaultContext, []int64{2}, 0)
	require.NoError(t, err)
	assert.True(t, s[2].Enabled(user_model.NotifyEventPRApproved))
	assert.False(t, s[2].Enabled(user_model.NotifyEventPRComment))

	// invalid preset, unknown event
	for _, form := range []url.Values{{"preference": {"x"}}, {"preference": {"custom"}, "event_nope": {"on"}}} {
		req := NewRequestWithBody(t, "POST", "/user/settings/notifications", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		session.MakeRequest(t, req, http.StatusSeeOther)
	}
	u = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	assert.Equal(t, "enabled", u.EmailNotificationsPreference, "invalid input changes nothing")
}

// AC7: the API returns and updates the preset and event map, rejects bad input with 422, and only touches the doer.
func TestAPIEmailSettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteUser)

	MakeRequest(t, NewRequest(t, "GET", "/api/v1/user/settings/notifications"), http.StatusUnauthorized)

	var got api.NotificationSettings
	DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/user/settings/notifications").AddTokenAuth(token), http.StatusOK), &got)
	assert.Equal(t, "enabled", got.Preset)
	assert.Len(t, got.Events, len(user_model.AllNotifyEvents))

	put := func(body api.NotificationSettings, status int) {
		MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/user/settings/notifications", body).AddTokenAuth(token), status)
	}
	put(api.NotificationSettings{Preset: "custom", Events: map[string]bool{"pr_approved": true, "pr_comment": false}}, http.StatusOK)
	DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/user/settings/notifications").AddTokenAuth(token), http.StatusOK), &got)
	assert.Equal(t, "custom", got.Preset)
	assert.True(t, got.Events["pr_approved"])
	assert.False(t, got.Events["pr_comment"])
	assert.True(t, got.Events["pr_merged"], "events missing from the body keep their value")

	put(api.NotificationSettings{Preset: "nope"}, http.StatusUnprocessableEntity)
	put(api.NotificationSettings{Preset: "custom", Events: map[string]bool{"nope": true}}, http.StatusUnprocessableEntity)

	// nobody else's settings are reachable
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/users/user1/settings/notifications").AddTokenAuth(token), http.StatusNotFound)
	s, err := user_model.LoadNotificationSettings(db.DefaultContext, []int64{1}, 0)
	require.NoError(t, err)
	assert.Empty(t, s)
}

// AC8: per-repo page needs current read access and an active watch; reset removes the rows; unwatch and repo delete remove them.
func TestEmailRepoOverridePage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	page := func(repoID int64, status int) { // user2 owns repo1 and repo2? only repo1 is used
		session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/user/settings/notifications?repo=%d", repoID)), status)
	}
	require.NoError(t, repo_model.WatchRepoExplicitly(db.DefaultContext, 2, 1, repo_model.WatchAllSelection))
	page(1, http.StatusOK)
	page(999999, http.StatusNotFound)
	page(2, http.StatusNotFound) // not watching

	form := url.Values{"repo": {"1"}, "event_pr_approved": {"on"}}
	req := NewRequestWithBody(t, "POST", "/user/settings/notifications", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	session.MakeRequest(t, req, http.StatusSeeOther)
	unittest.AssertExistsAndLoadBean(t, &user_model.NotificationSetting{UserID: 2, RepoID: 1, Event: "pr_approved"})

	// no read access any more: 404 even though the watch row survives
	require.NoError(t, repo_model.WatchRepoExplicitly(db.DefaultContext, 2, 6, repo_model.WatchAllSelection)) // repo6 is private and not accessible to user2
	page(6, http.StatusNotFound)
	req = NewRequestWithBody(t, "POST", "/user/settings/notifications", strings.NewReader(url.Values{"repo": {"6"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	session.MakeRequest(t, req, http.StatusNotFound)
	unittest.AssertNotExistsBean(t, &user_model.NotificationSetting{UserID: 2, RepoID: 6})

	// reset
	session.MakeRequest(t, NewRequest(t, "POST", "/user/settings/notifications?repo=1&reset=1"), http.StatusSeeOther) // as the watch menu posts it
	unittest.AssertNotExistsBean(t, &user_model.NotificationSetting{UserID: 2, RepoID: 1})

	// unwatch deletes the rows
	require.NoError(t, user_model.SaveNotificationSettings(db.DefaultContext, 2, 1, map[user_model.NotifyEvent]bool{user_model.NotifyEventPRComment: false}))
	require.NoError(t, repo_model.WatchRepoExplicitly(db.DefaultContext, 2, 1, repo_model.WatchNoneSelection))
	unittest.AssertNotExistsBean(t, &user_model.NotificationSetting{UserID: 2, RepoID: 1})
}

// AC9: org owners have no way to change a member's settings; the admin default for new users is honoured.
func TestEmailSettingsNotForcedByOrgOwner(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	// user2 owns org3; there is no org-scoped route, and the user routes only act on the doer.
	session := loginUser(t, "user2")
	req := NewRequestWithBody(t, "POST", "/org/org3/settings/notifications", strings.NewReader("preference=disabled"))
	session.MakeRequest(t, req, http.StatusNotFound)
	defer test.MockVariableValue(&setting.Admin.DefaultEmailNotification, "custom")()
	u := &user_model.User{Name: "newmailuser", Email: "newmailuser@example.com", Passwd: "password1234!@#", MustChangePassword: false}
	require.NoError(t, user_model.CreateUser(db.DefaultContext, u))
	assert.Equal(t, "custom", u.EmailNotificationsPreference)
}

// AC8: deleting the repo removes the overrides on it, deleting the user removes all their rows.
func TestEmailSettingsDeletedWithRepoAndUser(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := db.DefaultContext
	events := map[user_model.NotifyEvent]bool{user_model.NotifyEventPRComment: false}
	require.NoError(t, user_model.SaveNotificationSettings(ctx, 8, 0, events))
	require.NoError(t, user_model.SaveNotificationSettings(ctx, 8, 1, events))
	require.NoError(t, user_model.SaveNotificationSettings(ctx, 2, 0, events))

	require.NoError(t, repo_service.DeleteRepositoryDirectly(ctx, 1, repo_service.DeleteRepositoryOpts{}))
	unittest.AssertNotExistsBean(t, &user_model.NotificationSetting{RepoID: 1})
	unittest.AssertExistsAndLoadBean(t, &user_model.NotificationSetting{UserID: 8, RepoID: 0})

	require.NoError(t, user_service.DeleteUser(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8}), false))
	unittest.AssertNotExistsBean(t, &user_model.NotificationSetting{UserID: 8})
	unittest.AssertExistsAndLoadBean(t, &user_model.NotificationSetting{UserID: 2, RepoID: 0})
}
