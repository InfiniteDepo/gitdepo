// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	webhook_model "forgejo.org/models/webhook"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	webhook_module "forgejo.org/modules/webhook"
	webhook_service "forgejo.org/services/webhook"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setDisabledWebhookTypes(t *testing.T, types ...string) {
	t.Helper()
	require.NoError(t, webhook_service.SetDisabledTypes(db.DefaultContext, nil, types))
	bumpSettingsRevision(t)
}

// disableWebhookTypes disables the types and returns a function that enables every type again
func disableWebhookTypes(t *testing.T, types ...string) func() {
	t.Helper()
	setDisabledWebhookTypes(t, types...)
	return func() { setDisabledWebhookTypes(t) }
}

var webhookNewPrefixes = []string{
	"/user2/repo1/settings/hooks",
	"/org/org3/settings/hooks",
	"/user/settings/hooks",
	"/admin/system-hooks",
	"/admin/default-hooks",
}

// AC1, AC5: the admin page lists all 13 types on by default, and only site admins can read or change it
func TestWebhookTypesAdminPage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer disableWebhookTypes(t)()

	admin := loginUser(t, "user1")
	doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/webhook-types"), http.StatusOK).Body)
	assert.Equal(t, 13, doc.Find(`input[name^="enabled_"][checked]`).Length())

	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/webhook-types", map[string]string{"enabled_gitea": "on"}), http.StatusSeeOther)
	bumpSettingsRevision(t)
	assert.False(t, setting.Config().WebhookTypes.Value(db.DefaultContext).Enabled("slack"))
	assert.True(t, setting.Config().WebhookTypes.Value(db.DefaultContext).Enabled("gitea"))

	user2 := loginUser(t, "user2")
	user2.MakeRequest(t, NewRequest(t, "GET", "/admin/webhook-types"), http.StatusForbidden)
	user2.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/webhook-types", map[string]string{"enabled_slack": "on"}), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", "/admin/webhook-types"), http.StatusSeeOther)
}

// AC2: a disabled type is missing from the add menu and its new page is a 404
func TestWebhookTypesMenu(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer disableWebhookTypes(t, "slack", "forgejo")()

	admin := loginUser(t, "user1")
	for _, p := range webhookNewPrefixes {
		list := p
		if strings.HasPrefix(p, "/admin/") {
			list = "/admin/hooks"
		}
		resp := admin.MakeRequest(t, NewRequest(t, "GET", list), http.StatusOK)
		doc := NewHTMLParser(t, resp.Body)
		assert.Zero(t, doc.Find(`.menu a[href$="/slack/new"]`).Length(), p)
		assert.Zero(t, doc.Find(`.menu a[href$="/forgejo/new"]`).Length(), p)
		assert.NotZero(t, doc.Find(`.menu a[href$="/gitea/new"]`).Length(), p)
		assert.NotContains(t, resp.Body.String(), ">Forgejo<", p)

		admin.MakeRequest(t, NewRequest(t, "GET", p+"/slack/new"), http.StatusNotFound)
		admin.MakeRequest(t, NewRequest(t, "GET", p+"/gitea/new"), http.StatusOK)
	}
}

// AC3: creating a hook of a disabled type is refused on the web and in the API
func TestWebhookTypesCreateRefused(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer disableWebhookTypes(t, "slack")()
	before := unittest.GetCount(t, &webhook_model.Webhook{})

	admin := loginUser(t, "user1")
	for _, p := range webhookNewPrefixes {
		resp := admin.MakeRequest(t, NewRequestWithValues(t, "POST", p+"/slack/new", map[string]string{
			"payload_url": "http://example.com/", "events": "send_everything", "active": "1",
		}), http.StatusUnprocessableEntity)
		// the form page is shown again, with the localized error
		doc := NewHTMLParser(t, resp.Body)
		assert.Contains(t, doc.Find(".flash-error").Text(), "The site administrator has disabled the webhook type Slack.", p)
		assert.Equal(t, 1, doc.Find(`input[name="payload_url"]`).Length(), p)
	}
	unittest.AssertCount(t, &webhook_model.Webhook{}, before)

	token := getTokenForLoggedInUser(t, admin, auth_model.AccessTokenScopeAll)
	opt := api.CreateHookOption{Type: "slack", Config: api.CreateHookOptionConfig{"content_type": "json", "url": "http://example.com/"}}
	for _, p := range []string{"/api/v1/repos/user2/repo1/hooks", "/api/v1/orgs/org3/hooks", "/api/v1/user/hooks", "/api/v1/admin/hooks"} {
		resp := MakeRequest(t, NewRequestWithJSON(t, "POST", p, opt).AddTokenAuth(token), http.StatusUnprocessableEntity)
		assert.Contains(t, resp.Body.String(), "slack", p)
		opt.Type = "gitea"
		MakeRequest(t, NewRequestWithJSON(t, "POST", p, opt).AddTokenAuth(token), http.StatusCreated)
		opt.Type = "slack"
	}
}

// AC4: existing hooks of a disabled type are kept, listed with a badge and not delivered; re-enabling resumes delivery
func TestWebhookTypesExistingHooks(t *testing.T) {
	var requests atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	t.Cleanup(receiver.Close)
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Webhook.AllowedHostList, "*")()

	w := &webhook_model.Webhook{RepoID: 1, URL: receiver.URL, Type: webhook_module.GITEA, ContentType: webhook_model.ContentTypeJSON, IsActive: true, HookEvent: &webhook_module.HookEvent{SendEverything: true}}
	require.NoError(t, w.UpdateEvent())
	require.NoError(t, webhook_model.CreateWebhook(db.DefaultContext, w, ""))
	deliver := func() *webhook_model.HookTask {
		task, err := webhook_model.CreateHookTask(db.DefaultContext, &webhook_model.HookTask{HookID: w.ID, PayloadContent: `{"ref":"refs/heads/main"}`, EventType: webhook_module.HookEventPush, PayloadVersion: 2})
		require.NoError(t, err)
		require.NoError(t, webhook_service.Deliver(db.DefaultContext, task))
		task, err = webhook_model.GetHookTaskByID(db.DefaultContext, task.ID)
		require.NoError(t, err)
		return task
	}

	enable := disableWebhookTypes(t, "gitea")
	defer enable()
	task := deliver()
	skipped, err := webhook_model.GetWebhookByID(db.DefaultContext, w.ID)
	require.NoError(t, err)
	assert.Equal(t, w.LastStatus, skipped.LastStatus)
	assert.Zero(t, requests.Load())
	assert.True(t, task.IsDelivered)
	assert.False(t, task.IsSucceed)
	assert.Empty(t, task.RequestInfo.URL)
	assert.Empty(t, task.RequestInfo.Body)
	assert.Equal(t, "webhook type disabled", task.ResponseInfo.Body)

	session := loginUser(t, "user2")
	list := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/hooks"), http.StatusOK).Body)
	assert.Equal(t, 1, list.Find(`.item:contains("`+receiver.URL+`") .webhook-type-disabled`).Length())
	session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/hooks/"+strconv.FormatInt(w.ID, 10)), http.StatusOK)

	// the badge shows on the org, user and admin lists too
	admin := loginUser(t, "user1")
	for _, c := range []struct {
		name, list string
		hook       webhook_model.Webhook
	}{
		{"org", "/org/org3/settings/hooks", webhook_model.Webhook{OwnerID: 3}},
		{"user", "/user/settings/hooks", webhook_model.Webhook{OwnerID: 2}},
		{"system", "/admin/hooks", webhook_model.Webhook{IsSystemWebhook: true}},
		{"default", "/admin/hooks", webhook_model.Webhook{}},
	} {
		hook := c.hook
		list := c.list
		hook.URL, hook.Type, hook.ContentType = receiver.URL+"/"+c.name, webhook_module.GITEA, webhook_model.ContentTypeJSON
		hook.HookEvent = &webhook_module.HookEvent{SendEverything: true}
		require.NoError(t, hook.UpdateEvent())
		require.NoError(t, webhook_model.CreateWebhook(db.DefaultContext, &hook, ""))
		who := session
		if strings.HasPrefix(list, "/admin") || strings.HasPrefix(list, "/org") {
			who = admin
		}
		page := NewHTMLParser(t, who.MakeRequest(t, NewRequest(t, "GET", list), http.StatusOK).Body)
		assert.Equal(t, 1, page.Find(`.item:contains("`+hook.URL+`") .webhook-type-disabled`).Length(), list)
	}

	// the API still edits it
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	active := false
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/hooks/"+strconv.FormatInt(w.ID, 10), api.EditHookOption{Active: &active}).AddTokenAuth(token), http.StatusOK)
	active = true
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/hooks/"+strconv.FormatInt(w.ID, 10), api.EditHookOption{Active: &active}).AddTokenAuth(token), http.StatusOK)

	enable()
	deliver()
	assert.EqualValues(t, 1, requests.Load())

	setDisabledWebhookTypes(t, "gitea")
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/hooks/delete", map[string]string{"id": strconv.FormatInt(w.ID, 10)}), http.StatusOK)
	unittest.AssertNotExistsBean(t, &webhook_model.Webhook{ID: w.ID})
}

// AC6: a site admin can still change the setting in read-only maintenance mode, others can't
func TestWebhookTypesMaintenance(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer disableWebhookTypes(t)()
	defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()

	loginUser(t, "user1").MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/webhook-types", map[string]string{"enabled_gitea": "on"}), http.StatusSeeOther)
	bumpSettingsRevision(t)
	assert.False(t, setting.Config().WebhookTypes.Value(db.DefaultContext).Enabled("slack"))
	// a non-admin gets nothing done, whatever the response
	user2 := loginUser(t, "user2")
	user2.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/webhook-types", map[string]string{}), http.StatusSeeOther)
	assertMaintenanceFlash(t, user2)
	assert.True(t, setting.Config().WebhookTypes.Value(db.DefaultContext).Enabled("gitea"))
}
