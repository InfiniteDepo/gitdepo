// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	asymkey_model "forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/perm"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The test configs turn the expiry policies off; this test runs every create path with the default policy, the one an
// instance gets without any [security] expiry keys (pinned by TestLoadCredentialExpiryPolicyDefault).
func TestCredentialExpiryDefault(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	user2 := loginUser(t, "user2")
	user1 := loginUser(t, "user1")
	// created while the policy is off, like credentials that exist before an instance changes it
	userToken := getTokenForLoggedInUser(t, user2, auth_model.AccessTokenScopeWriteUser, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
	adminToken := getTokenForLoggedInUser(t, user1, auth_model.AccessTokenScopeWriteAdmin)
	pay := createProjectForKeys(t, 3, "pay")
	task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
	task.GenerateToken()
	require.NoError(t, actions_model.UpdateTask(t.Context(), task))

	defer test.MockVariableValue(&setting.SSHKeyExpiry, setting.DefaultCredentialExpiry)()
	defer test.MockVariableValue(&setting.DeployKeyExpiry, setting.DefaultCredentialExpiry)()
	defer test.MockVariableValue(&setting.AccessTokenExpiry, setting.DefaultCredentialExpiry)()

	day := func(days int) string {
		return time.Now().In(setting.DefaultUILocation).AddDate(0, 0, days).Format("2006-01-02")
	}
	projectKeys := fmt.Sprintf("/org/org3/groups/%d/settings/keys", pay.ID)

	t.Run("web", func(t *testing.T) {
		for _, tc := range []struct {
			name, page, post string
			session          *TestSession
			values           func(name string) map[string]string
			bean             func(name string) any
		}{
			{
				"access token", "/user/settings/keys/tokens/new", "/user/settings/keys/tokens/new", user2,
				func(name string) map[string]string {
					return map[string]string{"name": name, "resource": "all", "scope": "read:user"}
				},
				func(name string) any { return &auth_model.AccessToken{UID: 2, Name: name} },
			},
			{
				"SSH key", "/user/settings/keys", "/user/settings/keys", user2,
				func(name string) map[string]string {
					content, _ := newTestSSHKey(t)
					return map[string]string{"type": "ssh", "title": name, "content": content}
				},
				func(name string) any { return &asymkey_model.PublicKey{OwnerID: 2, Name: name} },
			},
			{
				"repo deploy key", "/user2/repo1/settings/keys", "/user2/repo1/settings/keys", user2,
				func(name string) map[string]string {
					return map[string]string{"title": name, "content": newOrgDeployKeyContent(t)}
				},
				func(name string) any { return &asymkey_model.DeployKey{RepoID: 1, Name: name} },
			},
			{
				"org deploy key", "/org/org3/settings/keys", "/org/org3/settings/keys", user2,
				func(name string) map[string]string {
					return map[string]string{"title": name, "content": newOrgDeployKeyContent(t), "scope": "all"}
				},
				func(name string) any { return &asymkey_model.OrgDeployKey{OrgID: 3, GroupID: 0, Name: name} },
			},
			{
				"project deploy key", projectKeys, projectKeys, user2,
				func(name string) map[string]string {
					return map[string]string{"title": name, "content": newOrgDeployKeyContent(t), "scope": "all"}
				},
				func(name string) any { return &asymkey_model.OrgDeployKey{OrgID: 3, GroupID: pay.ID, Name: name} },
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				page := NewHTMLParser(t, tc.session.MakeRequest(t, NewRequest(t, "GET", tc.page), http.StatusOK).Body)
				input := page.Find("input#expires-at")
				assert.Equal(t, day(30), input.AttrOr("value", ""))
				assert.Equal(t, day(365), input.AttrOr("max", ""))
				assert.True(t, input.Is("[required]"))
				assert.Contains(t, page.Find(".field:has(#expires-at) .help").Text(), "At most 365 days from today.")

				for suffix, expires := range map[string]string{"missing": "", "too late": day(366)} {
					values := tc.values(tc.name + " " + suffix)
					if expires != "" {
						values["expires_at"] = expires
					}
					resp := tc.session.MakeRequest(t, NewRequestWithValues(t, "POST", tc.post, values), http.StatusOK)
					assert.Contains(t, resp.Body.String(), "at most 365 days from today.", suffix)
					unittest.AssertNotExistsBean(t, tc.bean(tc.name+" "+suffix))
				}

				values := tc.values(tc.name + " ok")
				values["expires_at"] = day(365)
				tc.session.MakeRequest(t, NewRequestWithValues(t, "POST", tc.post, values), http.StatusSeeOther)
				unittest.AssertExistsAndLoadBean(t, tc.bean(tc.name+" ok"))
			})
		}
	})

	t.Run("API", func(t *testing.T) {
		for _, tc := range []struct {
			name, url, token string
			body             func(expires *time.Time) map[string]any
		}{
			{"access token", "/api/v1/users/user2/tokens", "", func(expires *time.Time) map[string]any {
				return map[string]any{"name": fmt.Sprintf("api-%d", tokenCounter.Add(1)), "scopes": []string{"read:user"}, "expires_at": expires}
			}},
			{"admin: access token for another user", "/api/v1/admin/users/user2/tokens", adminToken, func(expires *time.Time) map[string]any {
				return map[string]any{"name": fmt.Sprintf("admin-%d", tokenCounter.Add(1)), "scopes": []string{"read:user"}, "expires_at": expires}
			}},
			{"SSH key", "/api/v1/user/keys", userToken, func(expires *time.Time) map[string]any {
				content, _ := newTestSSHKey(t)
				return map[string]any{"title": fmt.Sprintf("api-%d", tokenCounter.Add(1)), "key": content, "expires_at": expires}
			}},
			{"admin: SSH key for another user", "/api/v1/admin/users/user2/keys", adminToken, func(expires *time.Time) map[string]any {
				content, _ := newTestSSHKey(t)
				return map[string]any{"title": fmt.Sprintf("admin-%d", tokenCounter.Add(1)), "key": content, "expires_at": expires}
			}},
			{"repo deploy key", "/api/v1/repos/user2/repo1/keys", userToken, func(expires *time.Time) map[string]any {
				return map[string]any{"title": fmt.Sprintf("api-%d", tokenCounter.Add(1)), "key": newOrgDeployKeyContent(t), "expires_at": expires}
			}},
			{"org deploy key", "/api/v1/orgs/org3/keys", userToken, func(expires *time.Time) map[string]any {
				return map[string]any{"title": fmt.Sprintf("api-%d", tokenCounter.Add(1)), "key": newOrgDeployKeyContent(t), "all_repositories": true, "expires_at": expires}
			}},
			{"project deploy key", fmt.Sprintf("/api/v1/orgs/org3/projects/%d/keys", pay.ID), userToken, func(expires *time.Time) map[string]any {
				return map[string]any{"title": fmt.Sprintf("api-%d", tokenCounter.Add(1)), "key": newOrgDeployKeyContent(t), "expires_at": expires}
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				send := func(expires *time.Time, status int) string {
					t.Helper()
					req := NewRequestWithJSON(t, "POST", tc.url, tc.body(expires))
					if tc.token == "" {
						req.AddBasicAuth("user2")
					} else {
						req.AddTokenAuth(tc.token)
					}
					return MakeRequest(t, req, status).Body.String()
				}
				tooLate := time.Now().AddDate(0, 0, 366)
				inPolicy := time.Now().AddDate(0, 0, 365)
				assert.Contains(t, send(nil, http.StatusUnprocessableEntity), "expiry date: required: the maximum lifetime is 365 days")
				assert.Contains(t, send(&tooLate, http.StatusUnprocessableEntity), "the maximum lifetime is 365 days")
				send(&inPolicy, http.StatusCreated)
			})
		}
	})

	t.Run("existing credentials and automatic tokens keep working", func(t *testing.T) {
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(userToken), http.StatusOK)

		// a row stored without an expiry, as by an import or an older policy
		row := &auth_model.AccessToken{UID: 2, Name: "stored without expiry", Scope: auth_model.AccessTokenScopeReadUser, ResourceAllRepos: true}
		require.NoError(t, auth_model.NewAccessToken(audit_model.WithSystem(t.Context(), "test"), row, nil))
		require.Zero(t, row.ExpiresUnix)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(row.Token), http.StatusOK)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user5/repo4").AddTokenAuth(task.Token), http.StatusOK)

		req := NewRequest(t, "GET", setting.AppURL+"v2/token")
		req.SetBasicAuth("user2", userToken)
		var tokenResponse struct{ Token string }
		DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &tokenResponse)
		req = NewRequest(t, "GET", setting.AppURL+"v2/")
		req.Header.Set("Authorization", "Bearer "+tokenResponse.Token)
		MakeRequest(t, req, http.StatusOK)
	})
}

// SSH keys stored without an expiry (the fixture key, and a deploy key) still pass serv, which every SSH path and the
// LFS token go through; the LFS token then gets its usual lifetime (lfsTokenExpiry, cmd/serv_test.go).
func TestCredentialExpiryDefaultServ(t *testing.T) {
	onApplicationRun(t, func(*testing.T, *url.URL) {
		defer test.MockVariableValue(&setting.SSHKeyExpiry, setting.DefaultCredentialExpiry)()
		defer test.MockVariableValue(&setting.DeployKeyExpiry, setting.DefaultCredentialExpiry)()
		ctx := t.Context()

		fixture := unittest.AssertExistsAndLoadBean(t, &asymkey_model.PublicKey{ID: 1, OwnerID: 2})
		require.Zero(t, fixture.ExpiresUnix)
		results, extra := private.ServCommand(ctx, fixture.ID, "user2", "repo1", perm.AccessModeWrite, "", "git-receive-pack", "")
		require.NoError(t, extra.Error)
		assert.Zero(t, results.ExpiresUnix)

		content, _ := newTestSSHKey(t)
		deployKey, err := asymkey_model.AddDeployKey(ctx, 1, "stored without expiry", content, true, 0)
		require.NoError(t, err)
		results, extra = private.ServCommand(ctx, deployKey.KeyID, "user2", "repo1", perm.AccessModeRead, "", "git-upload-pack", "")
		require.NoError(t, extra.Error)
		assert.Zero(t, results.ExpiresUnix)
	})
}

func TestCredentialExpiryDefaultCLI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	// The CLI runs in another process: give it the test config without the expiry keys, so it gets the default.
	conf, err := os.ReadFile(setting.CustomConf)
	require.NoError(t, err)
	conf = regexp.MustCompile(`(?m)^(SSH_KEY|DEPLOY_KEY|ACCESS_TOKEN|OAUTH2_APP_SECRET|AUTHORIZED_INTEGRATION)_(EXPIRY_REQUIRED|MAX_LIFETIME_DAYS)\s*=.*$`).ReplaceAll(conf, nil)
	require.NotContains(t, string(conf), "_MAX_LIFETIME_DAYS")
	confPath := filepath.Join(t.TempDir(), "app.ini")
	require.NoError(t, os.WriteFile(confPath, conf, 0o600))
	defer test.MockVariableValue(&setting.CustomConf, confPath)()

	day := func(days int) string {
		return time.Now().In(setting.DefaultUILocation).AddDate(0, 0, days).Format("2006-01-02")
	}
	refused := func(t *testing.T, err error) {
		t.Helper()
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr)
		assert.Contains(t, string(exitErr.Stderr), "the maximum lifetime is 365 days")
	}
	generate := func(name string, args ...string) error {
		_, err := runMainApp("admin", append([]string{"user", "generate-access-token", "--username", "user2", "--token-name", name, "--scopes", "read:user"}, args...)...)
		return err
	}

	t.Run("generate-access-token", func(t *testing.T) {
		require.NoError(t, generate("cli-default"))
		token := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 2, Name: "cli-default"})
		assert.Equal(t, day(365), token.ExpiresUnix.FormatDate())

		require.NoError(t, generate("cli-10-days", "--expires-at", day(10)))
		token = unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 2, Name: "cli-10-days"})
		assert.Equal(t, day(10), token.ExpiresUnix.FormatDate())

		refused(t, generate("cli-too-late", "--expires-at", day(366)))
		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{UID: 2, Name: "cli-too-late"})
	})

	t.Run("create-authorized-integration", func(t *testing.T) {
		create := func(name string, args ...string) error {
			args = append([]string{
				"user", "create-authorized-integration", "--username", "user2", "--name", name,
				"--issuer", "urn:forgejo:authorized-integrations:actions", "--scope", "read:user",
			}, args...)
			_, err := runMainApp("admin", args...)
			return err
		}
		require.NoError(t, create("cli-ai-default"))
		ai := unittest.AssertExistsAndLoadBean(t, &auth_model.AuthorizedIntegration{UserID: 2, Name: "cli-ai-default"})
		assert.Equal(t, day(365), ai.ExpiresUnix.FormatDate())

		require.NoError(t, create("cli-ai-10-days", "--expires-at", day(10)))
		ai = unittest.AssertExistsAndLoadBean(t, &auth_model.AuthorizedIntegration{UserID: 2, Name: "cli-ai-10-days"})
		assert.Equal(t, day(10), ai.ExpiresUnix.FormatDate())

		refused(t, create("cli-ai-too-late", "--expires-at", day(366)))
		unittest.AssertNotExistsBean(t, &auth_model.AuthorizedIntegration{UserID: 2, Name: "cli-ai-too-late"})

		var exitErr *exec.ExitError
		require.ErrorAs(t, create("cli-ai-past", "--expires-at", day(-1)), &exitErr)
		assert.Contains(t, string(exitErr.Stderr), "must be in the future")
		unittest.AssertNotExistsBean(t, &auth_model.AuthorizedIntegration{UserID: 2, Name: "cli-ai-past"})
	})

	t.Run("user create --access-token", func(t *testing.T) {
		create := func(name string, args ...string) error {
			_, err := runMainApp("admin", append([]string{"user", "create", "--username", name, "--email", name + "@example.com", "--random-password", "--access-token", "--access-token-scopes", "read:user"}, args...)...)
			return err
		}
		require.NoError(t, create("cli-expiry-default"))
		u := unittest.AssertExistsAndLoadBean(t, &user_model.User{LowerName: "cli-expiry-default"})
		token := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: u.ID})
		assert.Equal(t, day(365), token.ExpiresUnix.FormatDate())

		require.NoError(t, create("cli-expiry-10", "--access-token-expires-at", day(10)))
		u = unittest.AssertExistsAndLoadBean(t, &user_model.User{LowerName: "cli-expiry-10"})
		token = unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: u.ID})
		assert.Equal(t, day(10), token.ExpiresUnix.FormatDate())

		// refused before the user is created
		refused(t, create("cli-expiry-late", "--access-token-expires-at", day(366)))
		unittest.AssertNotExistsBean(t, &user_model.User{LowerName: "cli-expiry-late"})
	})

	t.Run("required without a maximum", func(t *testing.T) {
		withRequired := append(append([]byte{}, conf...), "\n[security]\nACCESS_TOKEN_EXPIRY_REQUIRED = true\nACCESS_TOKEN_MAX_LIFETIME_DAYS = 0\n"...)
		requiredPath := filepath.Join(t.TempDir(), "app.ini")
		require.NoError(t, os.WriteFile(requiredPath, withRequired, 0o600))
		defer test.MockVariableValue(&setting.CustomConf, requiredPath)()
		required := func(t *testing.T, err error) {
			t.Helper()
			var exitErr *exec.ExitError
			require.ErrorAs(t, err, &exitErr)
			assert.Contains(t, string(exitErr.Stderr), "expiry date: required")
		}

		// no maximum to default to: refused, never a token without expiry
		required(t, generate("cli-required"))
		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{UID: 2, Name: "cli-required"})
		_, err := runMainApp("admin", "user", "create", "--username", "cli-required", "--email", "cli-required@example.com", "--random-password", "--access-token")
		required(t, err)
		unittest.AssertNotExistsBean(t, &user_model.User{LowerName: "cli-required"})

		require.NoError(t, generate("cli-required-dated", "--expires-at", day(400)))
		token := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 2, Name: "cli-required-dated"})
		assert.Equal(t, day(400), token.ExpiresUnix.FormatDate())
		_, err = runMainApp("admin", "user", "create", "--username", "cli-required-dated", "--email", "cli-required-dated@example.com", "--random-password", "--access-token", "--access-token-expires-at", day(400))
		require.NoError(t, err)
		u := unittest.AssertExistsAndLoadBean(t, &user_model.User{LowerName: "cli-required-dated"})
		token = unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: u.ID})
		assert.Equal(t, day(400), token.ExpiresUnix.FormatDate())
	})
}
