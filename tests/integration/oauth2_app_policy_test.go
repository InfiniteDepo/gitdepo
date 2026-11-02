// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setOAuth2AppPolicy(t *testing.T, st setting.OAuth2AppPolicyState) {
	v, err := json.Marshal(st)
	require.NoError(t, err)
	require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{"oauth2.app_policy": string(v)}))
	bumpSettingsRevision(t)
}

func appForm(name string) map[string]string {
	return map[string]string{"application_name": name, "redirect_uris": "https://example.com/cb", "confidential_client": "true"}
}

// create + edit + regenerate on one owner's page (web), expecting `status` on every write.
// base is the applications page of the owner, app is an existing app of that owner.
func checkWebOAuth2Writes(t *testing.T, session *TestSession, base string, app *auth_model.OAuth2Application, allowed bool) {
	t.Helper()
	before := *app
	createStatus, writeStatus := http.StatusOK, http.StatusOK
	if !allowed {
		createStatus, writeStatus = http.StatusForbidden, http.StatusForbidden
	}
	session.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/oauth2", appForm("new-"+t.Name())), createStatus)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("%s/oauth2/%d/regenerate_secret", base, app.ID), nil), writeStatus)
	edit := appForm("renamed")
	edit["redirect_uris"] = "https://evil.example/cb"
	session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("%s/oauth2/%d", base, app.ID), edit), map[bool]int{true: http.StatusSeeOther, false: http.StatusForbidden}[allowed])
	after := unittest.AssertExistsAndLoadBean(t, &auth_model.OAuth2Application{ID: app.ID})
	if !allowed {
		assert.Equal(t, before.Name, after.Name)
		assert.Equal(t, before.RedirectURIs, after.RedirectURIs)
		assert.Equal(t, before.ClientSecret, after.ClientSecret) // 403 happens before any write
		unittest.AssertNotExistsBean(t, &auth_model.OAuth2Application{UID: app.UID, Name: "new-" + t.Name()})
	}
	// the page of a not-allowed owner has a note instead of the create form and keeps the list; view and delete stay open
	const note = "A site admin manages OAuth2 applications"
	list := session.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK).Body.String()
	assert.Equal(t, !allowed, strings.Contains(list, note))
	NewHTMLParser(t, bytes.NewBufferString(list)).AssertElement(t, "form[action$='/oauth2']", allowed)
	editPage := session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/oauth2/%d", base, app.ID)), http.StatusOK).Body.String()
	assert.Equal(t, !allowed, strings.Contains(editPage, note))
	NewHTMLParser(t, bytes.NewBufferString(editPage)).AssertElement(t, fmt.Sprintf("form[action$='/oauth2/%d']", app.ID), allowed)
}

func newOrgApp(t *testing.T, orgID int64, name string) *auth_model.OAuth2Application {
	app, err := auth_model.CreateOAuth2Application(db.DefaultContext, auth_model.CreateOAuth2ApplicationOptions{Name: name, UserID: orgID, RedirectURIs: []string{"https://example.com/cb"}, ConfidentialClient: true})
	require.NoError(t, err)
	return app
}

func checkAPIOAuth2Writes(t *testing.T, username string, app *auth_model.OAuth2Application, allowed bool) {
	t.Helper()
	token := getTokenForLoggedInUser(t, loginUser(t, username), auth_model.AccessTokenScopeWriteUser)
	body := api.CreateOAuth2ApplicationOptions{Name: "api-" + t.Name(), RedirectURIs: []string{"https://evil.example/cb"}, ConfidentialClient: true}
	create, patch := http.StatusCreated, http.StatusOK
	if !allowed {
		create, patch = http.StatusForbidden, http.StatusForbidden
	}
	before := *app
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/applications/oauth2", &body).AddTokenAuth(token), create)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/user/applications/oauth2/%d", app.ID), &body).AddTokenAuth(token), patch)
	if !allowed {
		after := unittest.AssertExistsAndLoadBean(t, &auth_model.OAuth2Application{ID: app.ID})
		assert.Equal(t, before.Name, after.Name)
		assert.Equal(t, before.RedirectURIs, after.RedirectURIs)
		assert.Equal(t, before.ClientSecret, after.ClientSecret)
		unittest.AssertNotExistsBean(t, &auth_model.OAuth2Application{Name: body.Name})
	}
}

// AC2 + AC5 + AC6: default (no stored setting, apps exist) is "site admins only" on every route.
func TestOAuth2AppPolicyDefaultAdminsOnly(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	bumpSettingsRevision(t) // the previous test's cached policy must not outlive the fixtures
	// existing apps keep authorizing, exchanging and refreshing without any stored setting (before any edit below)
	loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", "/login/oauth/authorize?client_id=da7da3ba-9a13-4167-856f-3899de0b0138&redirect_uri=a&response_type=code&state=s"), http.StatusOK)
	resp := MakeRequest(t, NewRequestWithValues(t, "POST", "/login/oauth/access_token", map[string]string{
		"grant_type": "authorization_code", "client_id": "da7da3ba-9a13-4167-856f-3899de0b0138",
		"client_secret": "4MK8Na6R55smdCY0WuCCumZ6hjRPnGY5saWVRHHjJiA=", "redirect_uri": "a", "code": "authcode",
		"code_verifier": "N1Zo9-8Rfwhkt68r1r29ty8YwIraXR8eh_1Qwxg7yQXsonBt",
	}), http.StatusOK)
	var tok struct {
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &tok))
	MakeRequest(t, NewRequestWithValues(t, "POST", "/login/oauth/access_token", map[string]string{
		"grant_type": "refresh_token", "client_id": "da7da3ba-9a13-4167-856f-3899de0b0138",
		"client_secret": "4MK8Na6R55smdCY0WuCCumZ6hjRPnGY5saWVRHHjJiA=", "redirect_uri": "a", "refresh_token": tok.RefreshToken,
	}), http.StatusOK)

	user2App := unittest.AssertExistsAndLoadBean(t, &auth_model.OAuth2Application{ID: 2}) // user 2, existing
	orgApp := newOrgApp(t, 3, "org3-existing")                                            // org3 is owned by user 2

	checkWebOAuth2Writes(t, loginUser(t, "user2"), "/user/settings/applications", user2App, false)
	checkWebOAuth2Writes(t, loginUser(t, "user2"), "/org/org3/settings/applications", orgApp, false)
	checkAPIOAuth2Writes(t, "user2", user2App, false)
	checkAPIOAuth2Writes(t, "user4", user2App, false) // user 4 creates nothing, 404/403 before any change

	// site admin is still allowed on its own page and the instance-wide page
	admin := loginUser(t, "user1")
	adminApp := newOrgApp(t, 1, "admin-own")
	checkWebOAuth2Writes(t, admin, "/user/settings/applications", adminApp, true)
	checkAPIOAuth2Writes(t, "user1", adminApp, true)
}

// AC4/AC5: selected organizations. org3 (owner user2) selected, org6 (owner user5) not.
func TestOAuth2AppPolicySelectedOrgs(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	setOAuth2AppPolicy(t, setting.OAuth2AppPolicyState{Mode: setting.OAuth2AppPolicyOrgs, OrgIDs: []int64{3}})
	selected, other := newOrgApp(t, 3, "selected"), newOrgApp(t, 6, "other")
	user2App := unittest.AssertExistsAndLoadBean(t, &auth_model.OAuth2Application{ID: 2})

	checkWebOAuth2Writes(t, loginUser(t, "user2"), "/org/org3/settings/applications", selected, true)
	checkWebOAuth2Writes(t, loginUser(t, "user5"), "/org/org6/settings/applications", other, false)
	checkWebOAuth2Writes(t, loginUser(t, "user2"), "/user/settings/applications", user2App, false) // no personal apps
	checkAPIOAuth2Writes(t, "user2", user2App, false)
}

// AC4/AC5: everyone is today's behaviour.
func TestOAuth2AppPolicyEveryone(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	setOAuth2AppPolicy(t, setting.OAuth2AppPolicyState{Mode: setting.OAuth2AppPolicyEveryone})
	user2App := unittest.AssertExistsAndLoadBean(t, &auth_model.OAuth2Application{ID: 2})
	checkWebOAuth2Writes(t, loginUser(t, "user2"), "/user/settings/applications", user2App, true)
	checkWebOAuth2Writes(t, loginUser(t, "user2"), "/org/org3/settings/applications", newOrgApp(t, 3, "org3-app"), true)
	checkAPIOAuth2Writes(t, "user2", user2App, true)

	// inactive and login-prohibited users never pass, even in this mode
	u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteUser)
	u.ProhibitLogin = true
	require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, u, "prohibit_login"))
	body := api.CreateOAuth2ApplicationOptions{Name: "prohibited", RedirectURIs: []string{"https://example.com"}}
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/applications/oauth2", &body).AddTokenAuth(token), http.StatusForbidden)
	unittest.AssertNotExistsBean(t, &auth_model.OAuth2Application{Name: "prohibited"})
}

// AC1 + AC3: only site admins read/change the setting; saving validates; the choice sticks.
func TestOAuth2AppPolicyAdminSetting(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	bumpSettingsRevision(t) // the previous test's cached policy must not outlive the fixtures
	for _, name := range []string{"user2", "user4"} {
		s := loginUser(t, name)
		s.MakeRequest(t, NewRequest(t, "GET", "/admin/applications"), http.StatusForbidden)
		s.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/applications/policy", map[string]string{"mode": "everyone"}), http.StatusForbidden)
	}
	admin := loginUser(t, "user1")
	assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/applications"), http.StatusOK).Body.String(), "restricted to site admins by default")
	post := func(mode, orgs string, status int) {
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/applications/policy", map[string]string{"mode": mode, "org_names": orgs}), status)
	}
	post("bogus", "", http.StatusBadRequest)
	post("orgs", "user2", http.StatusBadRequest) // a user, not an organization
	post("orgs", "nosuchorg", http.StatusBadRequest)
	assert.Empty(t, setting.Config().OAuth2AppPolicy.Value(db.DefaultContext).Mode) // rejected saves stored nothing
	post("orgs", "org3", http.StatusSeeOther)
	bumpSettingsRevision(t)
	st := setting.Config().OAuth2AppPolicy.Value(db.DefaultContext)
	assert.Equal(t, setting.OAuth2AppPolicyOrgs, st.Mode)
	assert.Equal(t, []int64{3}, st.OrgIDs)
	assert.Equal(t, int64(1), st.UpdatedBy)
	doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/applications"), http.StatusOK).Body)
	assert.Contains(t, doc.doc.Find("textarea[name=org_names]").Text(), "org3")
}

// AC7: review list shows every app with owner, date and "owner no longer allowed"; orphaned apps don't 500.
func TestOAuth2AppPolicyAdminReviewList(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	orphan := newOrgApp(t, 99999, "orphaned-app") // owner (org) was deleted
	admin := loginUser(t, "user1")
	body := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/applications"), http.StatusOK).Body.String()
	for _, want := range []string{"Test native app", "user2", "orphaned-app"} {
		assert.Contains(t, body, want)
	}
	assert.Contains(t, body, "owner-not-allowed") // marker class on rows whose owner may no longer create
	assert.Contains(t, body, "owner-deleted")
	// a site admin can delete any app, including user-owned and orphaned ones
	admin.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/admin/applications/oauth2/%d/delete", orphan.ID)), http.StatusOK)
	unittest.AssertNotExistsBean(t, &auth_model.OAuth2Application{ID: orphan.ID})
	admin.MakeRequest(t, NewRequest(t, "POST", "/admin/applications/oauth2/2/delete"), http.StatusOK)
	unittest.AssertNotExistsBean(t, &auth_model.OAuth2Application{ID: 2})
	// the owner can delete their own app even when not allowed
	app := newOrgApp(t, 3, "org3-del")
	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/org/org3/settings/applications/oauth2/%d/delete", app.ID)), http.StatusOK)
	unittest.AssertNotExistsBean(t, &auth_model.OAuth2Application{ID: app.ID})
}

// AC8: consent screen shows the owner and a mark for site-admin apps, outside the editable name.
func TestOAuth2AppPolicyConsent(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	authorize := func(app *auth_model.OAuth2Application) string {
		return loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", "/login/oauth/authorize?client_id="+app.ClientID+"&redirect_uri=https://example.com/cb&response_type=code&state=s"), http.StatusOK).Body.String()
	}
	instance := newOrgApp(t, 0, "instance-app") // instance-wide, registered on the admin page
	adminOwned := newOrgApp(t, 1, "admin-owned")
	normal := newOrgApp(t, 2, "Registered by a site admin") // a name that imitates the mark
	org := newOrgApp(t, 3, "org-app")

	assert.Contains(t, authorize(instance), "registered by a site admin")
	assert.Contains(t, authorize(adminOwned), "registered by a site admin")
	assert.Contains(t, authorize(adminOwned), "@user1")
	body := authorize(normal)
	assert.Contains(t, body, "@user2")
	assert.NotContains(t, body, `class="oauth2-admin-mark"`)
	body = authorize(org)
	assert.Contains(t, body, "org3")
	assert.NotContains(t, body, `class="oauth2-admin-mark"`)
}
