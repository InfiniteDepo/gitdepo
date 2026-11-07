// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	asymkey_model "forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	"forgejo.org/services/authz"
	"forgejo.org/tests"

	"github.com/42wim/httpsig"
	"github.com/PuerkitoBio/goquery"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func newTestSSHKey(t *testing.T) (string, ssh.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), signer
}

func setExpiresUnix(t *testing.T, bean any, id int64, expires timeutil.TimeStamp) {
	t.Helper()
	_, err := db.GetEngine(t.Context()).Table(bean).ID(id).Cols("expires_unix").Update(map[string]any{"expires_unix": expires})
	require.NoError(t, err)
}

// SSH is covered through the private serv API, which every SSH path (OpenSSH and the built-in server) goes through.
func TestCredentialExpiryServ(t *testing.T) {
	onApplicationRun(t, func(*testing.T, *url.URL) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		past := timeutil.TimeStampNow().Add(-60)
		future := timeutil.TimeStampNow().Add(3600)

		t.Run("expired user key", func(t *testing.T) {
			content, _ := newTestSSHKey(t)
			key, err := asymkey_model.AddPublicKey(audit_model.WithSystem(ctx, "test"), 2, "expired-laptop", content, 0, past)
			require.NoError(t, err)

			_, _, err = private.ServNoCommand(ctx, key.ID)
			require.Error(t, err)

			// Refused even for a read of a public repository.
			_, extra := private.ServCommand(ctx, key.ID, "user2", "repo1", perm.AccessModeRead, "", "git-upload-pack", "")
			require.Error(t, extra.Error)
			assert.Equal(t, fmt.Sprintf(`SSH key "expired-laptop" expired on %s. Add a new key in your settings.`, past.FormatDate()), extra.UserMsg)

			_, extra = private.ServCommand(ctx, key.ID, "user2", "repo1", perm.AccessModeWrite, "", "git-receive-pack", "")
			require.Error(t, extra.Error)
			assert.Contains(t, extra.UserMsg, "expired on")
		})

		t.Run("user key not yet expired", func(t *testing.T) {
			content, _ := newTestSSHKey(t)
			key, err := asymkey_model.AddPublicKey(audit_model.WithSystem(ctx, "test"), 2, "valid-laptop", content, 0, future)
			require.NoError(t, err)

			_, _, err = private.ServNoCommand(ctx, key.ID)
			require.NoError(t, err)

			results, extra := private.ServCommand(ctx, key.ID, "user2", "repo1", perm.AccessModeWrite, "", "git-receive-pack", "")
			require.NoError(t, extra.Error)
			assert.Equal(t, future, results.ExpiresUnix)
		})

		t.Run("deploy key expiry is per repository", func(t *testing.T) {
			content, _ := newTestSSHKey(t)
			expired, err := asymkey_model.AddDeployKey(ctx, 1, "expired-ci", content, true, past)
			require.NoError(t, err)
			valid, err := asymkey_model.AddDeployKey(ctx, 2, "valid-ci", content, true, future)
			require.NoError(t, err)
			require.Equal(t, expired.KeyID, valid.KeyID)

			// The shared public key row has no expiry of its own.
			pkey := unittest.AssertExistsAndLoadBean(t, &asymkey_model.PublicKey{ID: expired.KeyID})
			assert.Zero(t, pkey.ExpiresUnix)

			_, extra := private.ServCommand(ctx, expired.KeyID, "user2", "repo1", perm.AccessModeRead, "", "git-upload-pack", "")
			require.Error(t, extra.Error)
			assert.Equal(t, fmt.Sprintf(`Deploy key "expired-ci" expired on %s.`, past.FormatDate()), extra.UserMsg)

			results, extra := private.ServCommand(ctx, valid.KeyID, "user2", "repo2", perm.AccessModeRead, "", "git-upload-pack", "")
			require.NoError(t, extra.Error)
			assert.Equal(t, valid.KeyID, results.DeployKeyKeyID)
			assert.Equal(t, future, results.ExpiresUnix)
		})
	})
}

func TestCredentialExpiryHTTPSig(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	content, signer := newTestSSHKey(t)
	key, err := asymkey_model.AddPublicKey(audit_model.WithSystem(t.Context(), "test"), 2, "httpsig", content, 0, timeutil.TimeStampNow().Add(3600))
	require.NoError(t, err)

	signedRequest := func() *RequestWrapper {
		req := NewRequest(t, "GET", "/api/v1/user")
		sigSigner, _, err := httpsig.NewSSHSigner(signer, httpsig.DigestSha512, []string{httpsig.RequestTarget, "(created)", "(expires)"}, httpsig.Signature, 10)
		require.NoError(t, err)
		require.NoError(t, sigSigner.SignRequest(ssh.FingerprintSHA256(signer.PublicKey()), req.Request, nil))
		return req
	}

	resp := MakeRequest(t, signedRequest(), http.StatusOK)
	var u api.User
	DecodeJSON(t, resp, &u)
	assert.Equal(t, "user2", u.UserName)

	setExpiresUnix(t, &asymkey_model.PublicKey{}, key.ID, timeutil.TimeStampNow().Add(-1))
	MakeRequest(t, signedRequest(), http.StatusUnauthorized)
}

func TestCredentialExpiryAccessToken(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	readToken := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteUser)

	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
	req := NewRequestWithJSON(t, "POST", "/api/v1/users/user2/tokens", api.CreateAccessTokenOption{
		Name:      "expiring",
		Scopes:    []string{"all"},
		ExpiresAt: &expiresAt,
	}).AddBasicAuth("user2")
	var created api.AccessToken
	DecodeJSON(t, MakeRequest(t, req, http.StatusCreated), &created)
	require.NotNil(t, created.Expires)
	assert.Equal(t, expiresAt.Unix(), created.Expires.Unix())

	req = NewRequest(t, "GET", "/api/v1/users/user2/tokens").AddTokenAuth(readToken)
	var listed []*api.AccessToken
	DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &listed)
	for _, tok := range listed {
		if tok.ID == created.ID {
			require.NotNil(t, tok.Expires)
			assert.Equal(t, expiresAt.Unix(), tok.Expires.Unix())
		} else {
			assert.Nil(t, tok.Expires)
		}
	}

	req = NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(created.Token)
	MakeRequest(t, req, http.StatusOK)

	t.Run("container token is capped at the token expiry", func(t *testing.T) {
		req := NewRequest(t, "GET", fmt.Sprintf("%sv2/token", setting.AppURL))
		req.SetBasicAuth("user2", created.Token)
		resp := MakeRequest(t, req, http.StatusOK)
		var tokenResponse struct{ Token string }
		DecodeJSON(t, resp, &tokenResponse)

		claims := jwt.MapClaims{}
		_, _, err := jwt.NewParser().ParseUnverified(tokenResponse.Token, claims)
		require.NoError(t, err)
		exp, err := claims.GetExpirationTime()
		require.NoError(t, err)
		assert.LessOrEqual(t, exp.Unix(), expiresAt.Unix())
	})

	setExpiresUnix(t, &auth_model.AccessToken{}, created.ID, timeutil.TimeStampNow().Add(-1))

	t.Run("API", func(t *testing.T) {
		req := NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(created.Token)
		resp := MakeRequest(t, req, http.StatusUnauthorized)
		assert.Contains(t, resp.Body.String(), `access token \"expiring\" expired on`)
	})

	t.Run("git HTTP", func(t *testing.T) {
		req := NewRequest(t, "GET", "/user2/repo2.git/info/refs?service=git-upload-pack")
		req.SetBasicAuth("user2", created.Token)
		MakeRequest(t, req, http.StatusUnauthorized)
	})

	t.Run("nuget", func(t *testing.T) {
		req := NewRequest(t, "GET", "/api/packages/user2/nuget/index.json").
			SetHeader("X-NuGet-ApiKey", created.Token)
		MakeRequest(t, req, http.StatusUnauthorized)
	})
}

func TestCredentialExpiryPolicyAPI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteUser, auth_model.AccessTokenScopeWriteRepository)

	defer test.MockVariableValue(&setting.AccessTokenExpiry, setting.CredentialExpiryPolicy{MaxLifetimeDays: 30})()
	defer test.MockVariableValue(&setting.SSHKeyExpiry, setting.CredentialExpiryPolicy{Required: true})()
	defer test.MockVariableValue(&setting.DeployKeyExpiry, setting.CredentialExpiryPolicy{MaxLifetimeDays: 7})()
	now := time.Now()
	ptr := func(t time.Time) *time.Time { return &t }

	t.Run("access token", func(t *testing.T) {
		for _, tc := range []struct {
			expires *time.Time
			status  int
			msg     string
		}{
			{nil, http.StatusUnprocessableEntity, "expiry date: required"},
			{ptr(now.Add(-time.Hour)), http.StatusUnprocessableEntity, "expiry date: must be in the future"},
			{ptr(now.AddDate(0, 0, 40)), http.StatusUnprocessableEntity, "the maximum lifetime is 30 days"},
			{ptr(now.AddDate(0, 0, 1)), http.StatusCreated, ""},
		} {
			req := NewRequestWithJSON(t, "POST", "/api/v1/users/user2/tokens", api.CreateAccessTokenOption{
				Name:      fmt.Sprintf("policy-%d", tokenCounter.Add(1)),
				Scopes:    []string{"read:user"},
				ExpiresAt: tc.expires,
			}).AddBasicAuth("user2")
			resp := MakeRequest(t, req, tc.status)
			assert.Contains(t, resp.Body.String(), tc.msg)
		}
	})

	t.Run("user key", func(t *testing.T) {
		content, _ := newTestSSHKey(t)
		req := NewRequestWithJSON(t, "POST", "/api/v1/user/keys", api.CreateKeyOption{Title: "no-expiry", Key: content}).AddTokenAuth(token)
		MakeRequest(t, req, http.StatusUnprocessableEntity)

		expiresAt := now.AddDate(1, 0, 0).Truncate(time.Second)
		req = NewRequestWithJSON(t, "POST", "/api/v1/user/keys", api.CreateKeyOption{Title: "expiring", Key: content, ExpiresAt: &expiresAt}).AddTokenAuth(token)
		var created api.PublicKey
		DecodeJSON(t, MakeRequest(t, req, http.StatusCreated), &created)

		req = NewRequest(t, "GET", fmt.Sprintf("/api/v1/user/keys/%d", created.ID)).AddTokenAuth(token)
		var key api.PublicKey
		DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &key)
		require.NotNil(t, key.Expires)
		assert.Equal(t, expiresAt.Unix(), key.Expires.Unix())
	})

	t.Run("deploy key", func(t *testing.T) {
		content, _ := newTestSSHKey(t)
		req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/keys", api.CreateKeyOption{Title: "too-late", Key: content, ExpiresAt: ptr(now.AddDate(0, 0, 30))}).AddTokenAuth(token)
		MakeRequest(t, req, http.StatusUnprocessableEntity)

		expiresAt := now.AddDate(0, 0, 1).Truncate(time.Second)
		req = NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/keys", api.CreateKeyOption{Title: "expiring", Key: content, ExpiresAt: &expiresAt}).AddTokenAuth(token)
		var created api.DeployKey
		DecodeJSON(t, MakeRequest(t, req, http.StatusCreated), &created)
		require.NotNil(t, created.Expires)
		assert.Equal(t, expiresAt.Unix(), created.Expires.Unix())
		unittest.AssertExistsAndLoadBean(t, &asymkey_model.DeployKey{ID: created.ID, ExpiresUnix: timeutil.TimeStamp(expiresAt.Unix())})
	})
}

func TestCredentialExpiryWeb(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	date := time.Now().AddDate(0, 0, 10).Format("2006-01-02")
	expires, err := authz.ParseExpiryDate(date)
	require.NoError(t, err)

	t.Run("SSH key", func(t *testing.T) {
		content, _ := newTestSSHKey(t)
		req := NewRequestWithValues(t, "POST", "/user/settings/keys", map[string]string{
			"type": "ssh", "title": "web-expiring", "content": content, "expires_at": date,
		})
		session.MakeRequest(t, req, http.StatusSeeOther)
		key := unittest.AssertExistsAndLoadBean(t, &asymkey_model.PublicKey{OwnerID: 2, Name: "web-expiring", ExpiresUnix: expires})
		assertExpiryLabel(t, session, "/user/settings/keys", &asymkey_model.PublicKey{}, key.ID, "")

		defer test.MockVariableValue(&setting.SSHKeyExpiry, setting.CredentialExpiryPolicy{Required: true})()
		content, _ = newTestSSHKey(t)
		req = NewRequestWithValues(t, "POST", "/user/settings/keys", map[string]string{
			"type": "ssh", "title": "web-no-expiry", "content": content,
		})
		resp := session.MakeRequest(t, req, http.StatusOK)
		assert.Contains(t, resp.Body.String(), "An expiry date is required.")
		unittest.AssertNotExistsBean(t, &asymkey_model.PublicKey{OwnerID: 2, Name: "web-no-expiry"})
	})

	t.Run("deploy key", func(t *testing.T) {
		content, _ := newTestSSHKey(t)
		req := NewRequestWithValues(t, "POST", "/user2/repo1/settings/keys", map[string]string{
			"title": "web-deploy", "content": content, "expires_at": date,
		})
		session.MakeRequest(t, req, http.StatusSeeOther)
		key := unittest.AssertExistsAndLoadBean(t, &asymkey_model.DeployKey{RepoID: 1, Name: "web-deploy", ExpiresUnix: expires})
		assertExpiryLabel(t, session, "/user2/repo1/settings/keys", &asymkey_model.DeployKey{}, key.ID, "")

		defer test.MockVariableValue(&setting.DeployKeyExpiry, setting.CredentialExpiryPolicy{MaxLifetimeDays: 5})()
		content, _ = newTestSSHKey(t)
		req = NewRequestWithValues(t, "POST", "/user2/repo1/settings/keys", map[string]string{
			"title": "web-deploy-too-late", "content": content, "expires_at": date,
		})
		resp := session.MakeRequest(t, req, http.StatusOK)
		assert.Contains(t, resp.Body.String(), "The expiry date can be at most 5 days from today.")
	})

	t.Run("access token", func(t *testing.T) {
		req := NewRequestWithValues(t, "POST", "/user/settings/keys/tokens/new", map[string]string{
			"name": "web-token-expiring", "resource": "all", "scope": "read:user", "expires_at": date,
		})
		session.MakeRequest(t, req, http.StatusSeeOther)
		token := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{UID: 2, Name: "web-token-expiring", ExpiresUnix: expires})
		assertExpiryLabel(t, session, "/user/settings/keys", &auth_model.AccessToken{}, token.ID, "web-token-expiring")

		req = NewRequestWithValues(t, "POST", "/user/settings/keys/tokens/new", map[string]string{
			"name": "web-past", "resource": "all", "scope": "read:user", "expires_at": "2020-01-01",
		})
		resp := session.MakeRequest(t, req, http.StatusOK)
		assert.Contains(t, resp.Body.String(), "The expiry date must be in the future.")
	})
}

// assertExpiryLabel checks that the list on page shows "Expires", then "Expired" once the credential has expired.
// A non-empty name limits the check to the list items showing it (the keys page lists several credential types).
func assertExpiryLabel(t *testing.T, session *TestSession, page string, bean any, id int64, name string) {
	t.Helper()
	text := func() string {
		body := session.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body
		if name == "" {
			return body.String()
		}
		return NewHTMLParser(t, body).doc.Find(".flex-item").FilterFunction(func(_ int, s *goquery.Selection) bool {
			return strings.Contains(s.Text(), name)
		}).Text()
	}
	assert.Contains(t, text(), "Expires ")
	assert.NotContains(t, text(), "Expired ")

	setExpiresUnix(t, bean, id, timeutil.TimeStampNow().Add(-1))
	assert.Contains(t, text(), "Expired ")
}

func TestCredentialExpiryUserKeysFile(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	content, _ := newTestSSHKey(t)
	key, err := asymkey_model.AddPublicKey(audit_model.WithSystem(t.Context(), "test"), user.ID, "soon-expired", content, 0, timeutil.TimeStampNow().Add(3600))
	require.NoError(t, err)

	resp := MakeRequest(t, NewRequest(t, "GET", "/user2.keys"), http.StatusOK)
	assert.Contains(t, resp.Body.String(), content)

	setExpiresUnix(t, &asymkey_model.PublicKey{}, key.ID, timeutil.TimeStampNow().Add(-1))
	resp = MakeRequest(t, NewRequest(t, "GET", "/user2.keys"), http.StatusOK)
	assert.NotContains(t, resp.Body.String(), content)
}
