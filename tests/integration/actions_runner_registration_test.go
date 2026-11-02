// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/routers/api/v1/shared"

	runnerv1 "code.forgejo.org/forgejo/actions-proto/runner/v1"
	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionsRunnerRegistrationRestriction(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockProtect(&setting.Actions.RunnerRegistration)()

		// user2 is a repo admin of user2/repo1 and an owner of org3; user1 is a site admin.
		userSess := loginUser(t, "user2")
		userToken := getTokenForLoggedInUser(t, userSess, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteUser)
		adminSess := loginUser(t, "user1")
		adminToken := getTokenForLoggedInUser(t, adminSess, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteAdmin)

		const (
			repoAPI = "/api/v1/repos/user2/repo1/actions/runners"
			orgAPI  = "/api/v1/orgs/org3/actions/runners"
			userAPI = "/api/v1/user/actions/runners"
			repoWeb = "/user2/repo1/settings/actions/runners"
		)
		getToken := func(t *testing.T, url, token string, status int) string {
			t.Helper()
			resp := MakeRequest(t, NewRequest(t, "GET", url+"/registration-token").AddTokenAuth(token), status)
			var registrationToken shared.RegistrationToken
			if status == http.StatusOK {
				DecodeJSON(t, resp, &registrationToken)
			}
			return registrationToken.Token
		}
		createRunner := func(t *testing.T, url, token string, status int) int64 {
			t.Helper()
			resp := MakeRequest(t, NewRequestWithJSON(t, "POST", url, &api.RegisterRunnerOptions{Name: "restricted"}).AddTokenAuth(token), status)
			var runner api.RegisterRunnerResponse
			if status == http.StatusCreated {
				DecodeJSON(t, resp, &runner)
			}
			return runner.ID
		}
		register := func(token string) error {
			_, err := newMockRunner().client.runnerServiceClient.Register(t.Context(), connect.NewRequest(&runnerv1.RegisterRequest{
				Name:  "restricted",
				Token: token,
			}))
			return err
		}

		t.Run("everyone", func(t *testing.T) {
			setting.Actions.RunnerRegistration = setting.RunnerRegistrationEveryone
			getToken(t, repoAPI, userToken, http.StatusOK)
			getToken(t, orgAPI, userToken, http.StatusOK)
			getToken(t, userAPI, userToken, http.StatusOK)
		})

		t.Run("admin_and_org_owners", func(t *testing.T) {
			setting.Actions.RunnerRegistration = setting.RunnerRegistrationAdminAndOrgOwners
			getToken(t, repoAPI, userToken, http.StatusForbidden)
			getToken(t, userAPI, userToken, http.StatusForbidden)
			createRunner(t, repoAPI, userToken, http.StatusForbidden)
			createRunner(t, userAPI, userToken, http.StatusForbidden)
			orgToken := getToken(t, orgAPI, userToken, http.StatusOK)
			createRunner(t, orgAPI, userToken, http.StatusCreated)
			require.NoError(t, register(orgToken))
		})

		var repoRunnerID int64
		t.Run("admin", func(t *testing.T) {
			setting.Actions.RunnerRegistration = setting.RunnerRegistrationAdmin
			getToken(t, repoAPI, userToken, http.StatusForbidden)
			getToken(t, orgAPI, userToken, http.StatusForbidden)
			getToken(t, userAPI, userToken, http.StatusForbidden)
			createRunner(t, repoAPI, userToken, http.StatusForbidden)
			createRunner(t, orgAPI, userToken, http.StatusForbidden)
			createRunner(t, userAPI, userToken, http.StatusForbidden)

			// Site admins create scoped runners directly, but get no scoped registration tokens.
			getToken(t, repoAPI, adminToken, http.StatusForbidden)
			repoRunnerID = createRunner(t, repoAPI, adminToken, http.StatusCreated)
			globalToken := getToken(t, "/api/v1/admin/actions/runners", adminToken, http.StatusOK)
			require.NoError(t, register(globalToken))
		})

		t.Run("token issued before restriction", func(t *testing.T) {
			setting.Actions.RunnerRegistration = setting.RunnerRegistrationEveryone
			repoToken := getToken(t, repoAPI, userToken, http.StatusOK)
			setting.Actions.RunnerRegistration = setting.RunnerRegistrationAdmin
			err := register(repoToken)
			require.Error(t, err)
			assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
		})

		t.Run("web", func(t *testing.T) {
			setting.Actions.RunnerRegistration = setting.RunnerRegistrationAdmin

			htmlDoc := NewHTMLParser(t, userSess.MakeRequest(t, NewRequest(t, "GET", repoWeb), http.StatusOK).Body)
			htmlDoc.AssertElement(t, "a[href$='/reset_registration_token']", false)
			htmlDoc.AssertElement(t, "a[href$='/runners/new']", false)
			assert.Contains(t, htmlDoc.Find(".runner-container .info.message").Text(), "restricted by the site administrator")

			userSess.MakeRequest(t, NewRequest(t, "GET", repoWeb+"/reset_registration_token"), http.StatusForbidden)
			userSess.MakeRequest(t, NewRequest(t, "GET", repoWeb+"/new"), http.StatusForbidden)
			userSess.MakeRequest(t, NewRequestWithValues(t, "POST", repoWeb+"/new", map[string]string{"runner_name": "restricted"}), http.StatusForbidden)
			adminSess.MakeRequest(t, NewRequestWithValues(t, "POST", repoWeb+"/new", map[string]string{"runner_name": "restricted"}), http.StatusOK)

			// Renaming an existing runner still works; regenerating its secret doesn't.
			editURL := fmt.Sprintf("%s/%d/edit", repoWeb, repoRunnerID)
			userSess.MakeRequest(t, NewRequestWithValues(t, "POST", editURL, map[string]string{"runner_name": "renamed"}), http.StatusSeeOther)
			userSess.MakeRequest(t, NewRequestWithValues(t, "POST", editURL, map[string]string{"runner_name": "renamed", "regenerate_token": "on"}), http.StatusForbidden)

			// The admin list flags the repo runners created above, but not global ones.
			htmlDoc = NewHTMLParser(t, adminSess.MakeRequest(t, NewRequest(t, "GET", "/admin/actions/runners"), http.StatusOK).Body)
			assert.Contains(t, htmlDoc.Find(".runner-container .info.message").Text(), "admin")
			assert.Positive(t, htmlDoc.Find(".runner-list .ui.red.label").Length())
			htmlDoc.AssertElement(t, "a[href$='/reset_registration_token']", true)
		})
	})
}
