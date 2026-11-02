// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"fmt"
	"maps"
	"net/http"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	"forgejo.org/services/authz"
	"forgejo.org/tests"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizedIntegrationExpiryVerify(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	t.Run("expired", func(t *testing.T) {
		ait := newAITester(t, func(ai *auth_model.AuthorizedIntegration) {
			ai.ExpiresUnix = timeutil.TimeStampNow() - 1
		})
		defer ait.close()
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(ait.signedJWT()), http.StatusUnauthorized)
		assert.NotContains(t, resp.Body.String(), ait.authorizedIntegration.ExpiresUnix.FormatDate(), "no stored date in the answer")
	})

	t.Run("unexpired caps derived package tokens", func(t *testing.T) {
		expires := timeutil.TimeStampNow() + 3600
		ait := newAITester(t, func(ai *auth_model.AuthorizedIntegration) {
			ai.ExpiresUnix = expires
		})
		defer ait.close()
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(ait.signedJWT()), http.StatusOK)

		resp := MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%sv2/token", setting.AppURL)).AddTokenAuth(ait.signedJWT()), http.StatusOK)
		var tokenResponse struct {
			Token string `json:"token"`
		}
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &tokenResponse))
		claims := jwt.MapClaims{}
		_, _, err := jwt.NewParser().ParseUnverified(tokenResponse.Token, claims)
		require.NoError(t, err)
		exp, err := claims.GetExpirationTime()
		require.NoError(t, err)
		assert.LessOrEqual(t, exp.Unix(), int64(expires), "a 24 h container token is cut to the integration's expiry")
	})
}

func TestAuthorizedIntegrationExpiryWeb(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	// the generic UI checks the issuer's OpenID configuration: use the tester's server
	ait := newAITester(t)
	defer ait.close()
	defer test.MockVariableValue(&setting.AuthorizedIntegrationExpiry, setting.DefaultCredentialExpiry)()
	session := loginUser(t, "user2")

	day := func(days int) string {
		return time.Now().In(setting.DefaultUILocation).AddDate(0, 0, days).Format("2006-01-02")
	}
	expiryInput := func(t *testing.T, body string) string {
		t.Helper()
		v, _ := NewHTMLParser(t, bytes.NewBufferString(body)).Find("input#expires-at").Attr("value")
		return v
	}

	for ui, fields := range map[string]map[string]string{
		"generic":               {"issuer": ait.authorizedIntegration.Issuer, "claim_rules": `{"rules":[]}`},
		"forgejo-actions-local": {"source_repo": "user2/repo1"},
	} {
		t.Run(ui, func(t *testing.T) {
			base := "/user/settings/authorized-integrations/" + ui
			post := func(t *testing.T, link, name, expires string, status int) string {
				t.Helper()
				values := map[string]string{"name": name, "resource": "all", "scope": "read:user", "expires_at": expires}
				maps.Copy(values, fields)
				return session.MakeRequest(t, NewRequestWithValues(t, "POST", link, values), status).Body.String()
			}

			body := session.MakeRequest(t, NewRequest(t, "GET", base+"/new"), http.StatusOK).Body.String()
			assert.Equal(t, authz.DefaultExpiryDate(setting.AuthorizedIntegrationExpiry), expiryInput(t, body), "prefilled")

			name := "expiry-" + ui
			body = post(t, base+"/new", name, "", http.StatusOK)
			assert.Contains(t, body, "An expiry date is required, at most 365 days from today.")
			body = post(t, base+"/new", name, day(366), http.StatusOK)
			assert.Contains(t, body, "The expiry date can be at most 365 days from today.")
			assert.Equal(t, day(366), expiryInput(t, body), "the date survives a refusal")
			unittest.AssertNotExistsBean(t, &auth_model.AuthorizedIntegration{UserID: 2, Name: name})

			post(t, base+"/new", name, day(10), http.StatusSeeOther)
			ai := unittest.AssertExistsAndLoadBean(t, &auth_model.AuthorizedIntegration{UserID: 2, Name: name})
			assert.Equal(t, day(10), ai.ExpiresUnix.FormatDate())

			link := fmt.Sprintf("%s/%d", base, ai.ID)
			body = session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body.String()
			assert.Equal(t, day(10), expiryInput(t, body), "the stored date is shown")

			body = post(t, link, name+"-renamed", day(-1), http.StatusOK)
			assert.Contains(t, body, "The expiry date must be in the future.")
			fromDB := unittest.AssertExistsAndLoadBean(t, &auth_model.AuthorizedIntegration{ID: ai.ID})
			assert.Equal(t, name, fromDB.Name, "a refused edit changes nothing")
			assert.Equal(t, ai.ExpiresUnix, fromDB.ExpiresUnix)

			post(t, link, name, day(20), http.StatusSeeOther)
			assert.Equal(t, day(20), unittest.AssertExistsAndLoadBean(t, &auth_model.AuthorizedIntegration{ID: ai.ID}).ExpiresUnix.FormatDate())

			// the list labels it, then it expires
			assertExpiryLabel(t, session, "/user/settings/authorized-integrations", &auth_model.AuthorizedIntegration{}, ai.ID, name)

			// an expired integration is saved again only with a new date
			body = post(t, link, name, day(-1), http.StatusOK)
			assert.Contains(t, body, "This integration has expired. Set a new expiry date to save it.")
			post(t, link, name, day(5), http.StatusSeeOther)
			assert.False(t, unittest.AssertExistsAndLoadBean(t, &auth_model.AuthorizedIntegration{ID: ai.ID}).IsExpired())
		})
	}
}
