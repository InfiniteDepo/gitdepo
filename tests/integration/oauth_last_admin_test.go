// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An OAuth2 login whose group claim drops the admin group keeps the admin flag of the last usable admin.
func TestOAuth2LoginKeepsLastAdmin(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.OAuth2Client.EnableAutoRegistration, true)()

	const sourceName = "gitlab"
	payload := authSourcePayloadGitLabCustom(sourceName)
	payload["oauth2_group_claim_name"] = "groups"
	payload["oauth2_admin_group"] = "admins-claim"
	payload["oauth2_restricted_group"] = "restricted-claim"
	addAuthSource(t, payload)

	signIn := func(groups ...string) *TestSession {
		t.Helper()
		defer mockCompleteUserAuth(func(http.ResponseWriter, *http.Request) (goth.User, error) {
			return goth.User{
				Provider: sourceName,
				UserID:   "4242",
				NickName: "sso-admin",
				Email:    "sso-admin@example.com",
				RawData:  map[string]any{"groups": groups},
			}, nil
		})()
		session := emptyTestSession(t)
		session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/user/oauth2/%s/callback?code=XYZ&state=XYZ", sourceName)), http.StatusSeeOther)
		return session
	}
	setAdmin := func(id int64, admin bool) {
		t.Helper()
		u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: id})
		u.IsAdmin = admin
		require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, u, "is_admin"))
	}

	// sign up as admin, then user 1 (the fixture admin) stops being one
	signIn("admins-claim")
	ssoAdmin := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "sso-admin", IsAdmin: true})
	setAdmin(1, false)

	t.Run("last usable admin keeps the flag", func(t *testing.T) {
		logChecker, cleanup := test.NewLogChecker(log.DEFAULT, log.WARN)
		defer cleanup()
		logChecker.Filter(fmt.Sprintf(`login source %q would remove the admin flag of sso-admin (id %d)`, sourceName, ssoAdmin.ID), "restricted-claim").StopMark("flag kept")

		session := signIn("restricted-claim")
		unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: ssoAdmin.ID, IsAdmin: true, IsRestricted: true})
		// signed in, and admin and restricted together still reach the admin pages
		session.MakeRequest(t, NewRequest(t, "GET", "/admin"), http.StatusOK)

		filtered, stopped := logChecker.Check(5 * time.Second)
		assert.True(t, stopped)
		assert.Equal(t, []bool{true, false}, filtered, "warning names user and source, not the claims")
	})

	t.Run("with another usable admin the flag is removed", func(t *testing.T) {
		setAdmin(1, true)
		session := signIn()
		unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: ssoAdmin.ID, IsAdmin: false, IsRestricted: false})
		session.MakeRequest(t, NewRequest(t, "GET", "/admin"), http.StatusForbidden)
	})
}
