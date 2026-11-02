// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Create and regenerate check the secret expiry against the default policy (#461) on every owner's page and the API.
func TestOAuth2AppSecretExpiryPolicy(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.OAuth2AppSecretExpiry, setting.DefaultCredentialExpiry)()
	day := func(days int) string {
		return time.Now().In(setting.DefaultUILocation).AddDate(0, 0, days).Format("2006-01-02")
	}
	admin := loginUser(t, "user1")

	for _, tc := range []struct{ name, base string }{
		{"user", "/user/settings/applications"},
		{"org", "/org/org3/settings/applications"},
		{"admin", "/admin/applications"},
	} {
		t.Run("web "+tc.name, func(t *testing.T) {
			page := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", tc.base), http.StatusOK).Body)
			input := page.Find("form[action$='/oauth2'] input#expires-at")
			assert.Equal(t, day(30), input.AttrOr("value", ""))
			assert.Equal(t, day(365), input.AttrOr("max", ""))
			assert.True(t, input.Is("[required]"))

			for suffix, expires := range map[string]string{"missing": "", "too late": day(366)} {
				name := tc.name + " " + suffix
				values := appForm(name)
				values["expires_at"] = expires
				admin.MakeRequest(t, NewRequestWithValues(t, "POST", tc.base+"/oauth2", values), http.StatusSeeOther)
				assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", tc.base), http.StatusOK).Body.String(), "at most 365 days from today.", suffix)
				unittest.AssertNotExistsBean(t, &auth_model.OAuth2Application{Name: name})
			}

			values := appForm(tc.name + " ok")
			values["expires_at"] = day(365)
			admin.MakeRequest(t, NewRequestWithValues(t, "POST", tc.base+"/oauth2", values), http.StatusOK)
			app := unittest.AssertExistsAndLoadBean(t, &auth_model.OAuth2Application{Name: tc.name + " ok"})
			assert.Equal(t, day(365), app.ClientSecretExpiresUnix.AsTimeInLocation(setting.DefaultUILocation).Format("2006-01-02"))

			regenerate := fmt.Sprintf("%s/oauth2/%d/regenerate_secret", tc.base, app.ID)
			edit := fmt.Sprintf("%s/oauth2/%d", tc.base, app.ID)
			editPage := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", edit), http.StatusOK).Body)
			assert.Equal(t, day(30), editPage.Find("form[action$='/regenerate_secret'] input#expires-at").AttrOr("value", ""))
			assert.Contains(t, editPage.Find("label[for='client-secret']").Text(), "Expires ")

			admin.MakeRequest(t, NewRequestWithValues(t, "POST", regenerate, map[string]string{"expires_at": day(366)}), http.StatusSeeOther)
			assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", edit), http.StatusOK).Body.String(), "The expiry date can be at most 365 days from today.")
			// a missing field is "required", never "no expiry"
			admin.MakeRequest(t, NewRequestWithValues(t, "POST", regenerate, nil), http.StatusSeeOther)
			assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", edit), http.StatusOK).Body.String(), "An expiry date is required, at most 365 days from today.")
			after := unittest.AssertExistsAndLoadBean(t, &auth_model.OAuth2Application{ID: app.ID})
			assert.Equal(t, app.ClientSecret, after.ClientSecret, "a refused regenerate keeps the secret")
			assert.Equal(t, app.ClientSecretExpiresUnix, after.ClientSecretExpiresUnix)

			admin.MakeRequest(t, NewRequestWithValues(t, "POST", regenerate, map[string]string{"expires_at": day(10)}), http.StatusOK)
			after = unittest.AssertExistsAndLoadBean(t, &auth_model.OAuth2Application{ID: app.ID})
			assert.NotEqual(t, app.ClientSecret, after.ClientSecret)
			assert.Equal(t, day(10), after.ClientSecretExpiresUnix.AsTimeInLocation(setting.DefaultUILocation).Format("2006-01-02"))
		})
	}

	t.Run("API", func(t *testing.T) {
		token := getTokenForLoggedInUser(t, admin, auth_model.AccessTokenScopeWriteUser)
		send := func(method, url string, expires *time.Time, status int) *api.OAuth2Application {
			t.Helper()
			name := "api"
			if status >= 300 {
				name = "refused"
			}
			body := api.CreateOAuth2ApplicationOptions{Name: name, RedirectURIs: []string{"https://example.com/cb"}, ConfidentialClient: true, ClientSecretExpiresAt: expires}
			resp := MakeRequest(t, NewRequestWithJSON(t, method, url, body).AddTokenAuth(token), status)
			app := new(api.OAuth2Application)
			if status < 300 {
				DecodeJSON(t, resp, app)
			}
			return app
		}
		tooLate := time.Now().AddDate(0, 0, 366)
		inPolicy := time.Now().AddDate(0, 0, 365).Truncate(time.Second)

		send("POST", "/api/v1/user/applications/oauth2", nil, http.StatusUnprocessableEntity)
		send("POST", "/api/v1/user/applications/oauth2", &tooLate, http.StatusUnprocessableEntity)
		unittest.AssertNotExistsBean(t, &auth_model.OAuth2Application{UID: 1, Name: "refused"})
		created := send("POST", "/api/v1/user/applications/oauth2", &inPolicy, http.StatusCreated)
		require.NotNil(t, created.ClientSecretExpiresAt)
		assert.True(t, inPolicy.Equal(*created.ClientSecretExpiresAt))

		url := fmt.Sprintf("/api/v1/user/applications/oauth2/%d", created.ID)
		send("PATCH", url, nil, http.StatusUnprocessableEntity)
		send("PATCH", url, &tooLate, http.StatusUnprocessableEntity)
		stored := unittest.AssertExistsAndLoadBean(t, &auth_model.OAuth2Application{ID: created.ID})
		assert.True(t, stored.ValidateClientSecret([]byte(created.ClientSecret)), "a refused PATCH keeps the secret")
		assert.Equal(t, "api", stored.Name, "a refused PATCH changes nothing")
		soon := time.Now().AddDate(0, 0, 10).Truncate(time.Second)
		patched := send("PATCH", url, &soon, http.StatusOK)
		assert.True(t, soon.Equal(*patched.ClientSecretExpiresAt))

		var got api.OAuth2Application
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", url).AddTokenAuth(token), http.StatusOK), &got)
		assert.True(t, soon.Equal(*got.ClientSecretExpiresAt))
		var never api.OAuth2Application
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/user/applications/oauth2/1").AddTokenAuth(token), http.StatusOK), &never)
		assert.Nil(t, never.ClientSecretExpiresAt, "a secret without expiry")
	})
}

// An expired client secret is refused wherever the secret is checked; a public client doesn't use it (#461).
func TestOAuth2AppSecretExpiredRefused(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	const (
		clientID = "da7da3ba-9a13-4167-856f-3899de0b0138"
		secret   = "4MK8Na6R55smdCY0WuCCumZ6hjRPnGY5saWVRHHjJiA="
		verifier = "N1Zo9-8Rfwhkt68r1r29ty8YwIraXR8eh_1Qwxg7yQXsonBt"
	)
	setExpiry := func(appID int64, expires timeutil.TimeStamp) {
		t.Helper()
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE oauth2_application SET client_secret_expires_unix = ? WHERE id = ?", expires, appID)
		require.NoError(t, err)
	}
	tokenRequest := func(values map[string]string, status int) map[string]any {
		t.Helper()
		resp := MakeRequest(t, NewRequestWithValues(t, "POST", "/login/oauth/access_token", values), status)
		parsed := map[string]any{}
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &parsed))
		return parsed
	}
	introspect := func(clientSecret string, status int) {
		t.Helper()
		req := NewRequestWithValues(t, "POST", "/login/oauth/introspect", map[string]string{"token": "x"})
		req.SetBasicAuth(clientID, clientSecret)
		MakeRequest(t, req, status)
	}

	// valid: a secret that expires later is accepted
	setExpiry(1, timeutil.TimeStampNow().Add(3600))
	tok := tokenRequest(map[string]string{
		"grant_type": "authorization_code", "client_id": clientID, "client_secret": secret,
		"redirect_uri": "a", "code": "authcode", "code_verifier": verifier,
	}, http.StatusOK)
	introspect(secret, http.StatusOK)

	setExpiry(1, timeutil.TimeStampNow().Add(-1))
	expired := map[string]any{"error": "invalid_client", "error_description": "client secret expired"}

	t.Run("refresh_token", func(t *testing.T) {
		refresh := map[string]string{"grant_type": "refresh_token", "client_id": clientID, "client_secret": secret, "refresh_token": tok["refresh_token"].(string)}
		assert.Equal(t, expired, tokenRequest(refresh, http.StatusBadRequest))
		refresh["client_secret"] = "wrong"
		assert.Equal(t, map[string]any{"error": "invalid_client", "error_description": "invalid client secret"}, tokenRequest(refresh, http.StatusBadRequest), "a wrong secret keeps today's answer")
	})

	t.Run("authorization_code", func(t *testing.T) {
		grant := unittest.AssertExistsAndLoadBean(t, &auth_model.OAuth2Grant{ID: 1})
		code, err := grant.GenerateNewAuthorizationCode(db.DefaultContext, "a", "CjvyTLSdR47G5zYenDA-eDWW4lRrO8yvjcWwbD_deOg", "S256")
		require.NoError(t, err)
		exchange := map[string]string{
			"grant_type": "authorization_code", "client_id": clientID, "client_secret": secret,
			"redirect_uri": "a", "code": code.Code, "code_verifier": verifier,
		}
		assert.Equal(t, expired, tokenRequest(exchange, http.StatusBadRequest))
		exchange["client_secret"] = "wrong"
		assert.Equal(t, map[string]any{"error": "unauthorized_client", "error_description": "invalid client secret"}, tokenRequest(exchange, http.StatusBadRequest), "a wrong secret keeps today's answer")
	})

	t.Run("introspect", func(t *testing.T) {
		introspect(secret, http.StatusUnauthorized)
	})

	t.Run("public client with PKCE", func(t *testing.T) {
		setExpiry(2, timeutil.TimeStampNow().Add(-1))
		tokenRequest(map[string]string{
			"grant_type": "authorization_code", "client_id": "ce5a1322-42a7-11ed-b878-0242ac120002",
			"redirect_uri": "http://127.0.0.1/", "code": "authcodepublic", "code_verifier": verifier,
		}, http.StatusOK)
	})
}
