// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	perm_model "forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The dependency endpoints answer exactly what the other repository endpoints answer for the same credential:
// org3/repo3 is private, user4 reads it through team1.
func TestDependencyGraphPolicies(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		enableDependencyGraph(t)
		repo3 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
		storeScan(t, repo3, &repo_model.Dependency{Ecosystem: "Go", Name: "example.com/x", Version: "v1", Direct: true})
		const api, web = "/api/v1/repos/org3/repo3", "/org3/repo3/activity/dependencies"
		status := func(method, path, token string) int {
			req := NewRequest(t, method, path)
			if token != "" {
				req.AddTokenAuth(token)
			}
			return MakeRequest(t, req, NoExpectedStatus).Code
		}
		member := loginUser(t, "user4")
		token := getTokenForLoggedInUser(t, member, auth_model.AccessTokenScopeReadRepository)
		webStatus := func(path string) int {
			return member.MakeRequest(t, NewRequest(t, "GET", path), NoExpectedStatus).Code
		}
		assert.Equal(t, http.StatusOK, status("GET", api+"/dependencies", token))
		assert.Equal(t, http.StatusOK, webStatus(web))

		t.Run("org that requires 2FA, member without it", func(t *testing.T) {
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
			require.NoError(t, err)
			t.Cleanup(func() {
				_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = 3", false)
				require.NoError(t, err)
			})
			for _, tail := range []string{"/dependencies", "/sbom"} {
				assert.Equal(t, http.StatusNotFound, status("GET", api+tail, token), tail)
			}
			assert.Equal(t, http.StatusForbidden, webStatus(web))
			assert.Equal(t, http.StatusForbidden, webStatus(web+"/sbom"))
		})

		t.Run("organization with Code off", func(t *testing.T) {
			require.NoError(t, db.Insert(db.DefaultContext, &repo_model.OrgUnit{OrgID: 3, Type: unit_model.TypeCode, Disabled: true}))
			t.Cleanup(func() {
				_, err := db.GetEngine(db.DefaultContext).Where("org_id = ? AND type = ?", 3, unit_model.TypeCode).Delete(&repo_model.OrgUnit{})
				require.NoError(t, err)
			})
			assert.Equal(t, http.StatusNotFound, status("GET", api+"/dependencies", token))
			assert.Equal(t, http.StatusNotFound, status("GET", api+"/sbom", token))
			assert.Equal(t, http.StatusNotFound, webStatus(web))
		})

		t.Run("site policy", func(t *testing.T) {
			// Code can't be hidden by the policy, and hiding the other units doesn't take the reader's access away
			defer resetRepoUnitPolicy(t)
			defer denyRepoUnits(t, nil, unit_model.TypeIssues, unit_model.TypePullRequests, unit_model.TypeReleases)()
			assert.Equal(t, http.StatusOK, status("GET", api+"/dependencies", token))
			assert.Equal(t, http.StatusOK, status("GET", api+"/sbom", token))
			assert.Equal(t, http.StatusOK, webStatus(web))
		})

		t.Run("OAuth2 grant", func(t *testing.T) {
			read := createOAuth2Token(t, member, []auth_model.AccessTokenScope{auth_model.AccessTokenScopeReadRepository})
			issues := createOAuth2Token(t, loginUser(t, "user2"), []auth_model.AccessTokenScope{auth_model.AccessTokenScopeReadIssue})
			assert.Equal(t, http.StatusOK, status("GET", api+"/dependencies", read))
			assert.Equal(t, http.StatusOK, status("GET", api+"/sbom", read))
			assert.Equal(t, http.StatusForbidden, status("GET", api+"/dependencies", issues))
			assert.Equal(t, http.StatusForbidden, status("GET", api+"/sbom", issues))
		})

		t.Run("authorized integration", func(t *testing.T) {
			for scope, want := range map[auth_model.AccessTokenScope]int{
				auth_model.AccessTokenScopeReadRepository: http.StatusOK,
				auth_model.AccessTokenScopeReadIssue:      http.StatusForbidden,
			} {
				ait := newAITester(t, func(ai *auth_model.AuthorizedIntegration) { ai.UserID, ai.Scope = 4, scope })
				assert.Equal(t, want, status("GET", api+"/dependencies", ait.signedJWT()), scope)
				assert.Equal(t, want, status("GET", api+"/sbom", ait.signedJWT()), scope)
				ait.close()
			}
		})

		t.Run("owned token", func(t *testing.T) {
			tok := newOwnedAccessToken(t, auth_model.AccessTokenOwnerOrg, 3, 0, perm_model.AccessModeRead, auth_model.AccessTokenScopeReadRepository)
			assert.Equal(t, http.StatusOK, status("GET", api+"/dependencies", tok.Token))
			assert.Equal(t, http.StatusOK, status("GET", api+"/sbom", tok.Token))
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE access_token SET expires_unix = ? WHERE id = ?", timeutil.TimeStampNow().AddDuration(-time.Hour), tok.ID)
			require.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, status("GET", api+"/dependencies", tok.Token))
			assert.Equal(t, http.StatusUnauthorized, status("GET", api+"/sbom", tok.Token))
		})
	})
}
