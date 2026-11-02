// Copyright 2026 The spoved contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"testing"

	"forgejo.org/models/auth"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
)

func assertNoBrandMentions(t *testing.T, session *TestSession, url string) {
	t.Helper()
	req := NewRequest(t, "GET", url)
	var body string
	if session == nil {
		body = MakeRequest(t, req, http.StatusOK).Body.String()
	} else {
		body = session.MakeRequest(t, req, http.StatusOK).Body.String()
	}
	assert.Empty(t, test.BrandMentions(body), url)
}

func TestBranding(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	t.Run("Signed out", func(t *testing.T) {
		for _, url := range []string{"/", "/user/login"} {
			assertNoBrandMentions(t, nil, url)
		}

		page := NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", "/"), http.StatusOK).Body)
		assert.Contains(t, page.Find("title").Text(), "gitdepo")
		assert.Contains(t, page.Find("footer").Text(), "Powered by gitdepo")
		page.AssertElement(t, `footer a.codehat-credit[href="https://forgejo.org"]`, true)
		og, _ := page.Find(`meta[property="og:description"]`).Attr("content")
		assert.Contains(t, og, "gitdepo")
	})

	t.Run("Site admin", func(t *testing.T) {
		source := addAuthSource(t, map[string]string{
			"type":            fmt.Sprintf("%d", auth.OAuth2),
			"name":            "branding",
			"is_active":       "on",
			"oauth2_provider": "gitlab",
		})
		session := loginUser(t, "user1")
		for _, url := range []string{"/admin", "/admin/webhook-types", "/admin/auths/new", fmt.Sprintf("/admin/auths/%d", source.ID), "/user/settings/keys"} {
			assertNoBrandMentions(t, session, url)
		}
	})

	t.Run("Repo admin", func(t *testing.T) {
		session := loginUser(t, "user2")
		for _, url := range []string{
			"/user2/repo1/settings",
			"/user2/repo1/settings/branches",
			"/user2/repo1/settings/hooks",
			"/user2/repo1/settings/hooks/forgejo/new",
			"/user2/repo1/settings/hooks/slack/new",
			"/user2/repo1/settings/hooks/discord/new",
			"/user2/repo1/settings/hooks/packagist/new",
		} {
			assertNoBrandMentions(t, session, url)
		}
	})

	t.Run("Projects", func(t *testing.T) {
		prepareRepoGroupWeb(t)
		session := loginUser(t, "user2")
		for _, url := range []string{"/org/org3/groups", "/org/org3/groups/new", "/org3/proj", "/org3/proj/-/settings", "/explore/groups"} {
			assertNoBrandMentions(t, session, url)
		}
		for _, url := range []string{"/org/org3/groups", "/org3/proj", "/explore/groups"} {
			assertNoBrandMentions(t, nil, url)
		}
	})

	t.Run("Runner setup pages", func(t *testing.T) {
		session := loginUser(t, "user1")
		for _, base := range []string{"/user2/repo1/settings/actions/runners", "/org/org3/settings/actions/runners", "/admin/actions/runners"} {
			req := NewRequestWithValues(t, "POST", base+"/new", map[string]string{"runner_name": "branding"})
			resp := session.MakeRequest(t, req, http.StatusOK)
			assert.Empty(t, test.BrandMentions(resp.Body.String()), base)
			page := NewHTMLParser(t, resp.Body)
			setup := page.Find(".runner-container").Text()
			assert.Contains(t, setup, "gitdepo runner", base)
			assert.Contains(t, setup, "gitdepo:", base)
			assert.Contains(t, setup, "forgejo-runner daemon", base)
		}
	})

	t.Run("API versions unchanged", func(t *testing.T) {
		var version structs.ServerVersion
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/version"), http.StatusOK), &version)
		assert.Equal(t, setting.AppVer, version.Version)

		resp := MakeRequest(t, NewRequest(t, "GET", "/api/forgejo/v1/version"), http.StatusOK)
		assert.JSONEq(t, `{"version":"1.0.0"}`, resp.Body.String())
	})
}
