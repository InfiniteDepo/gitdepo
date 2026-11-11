// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	asymkey_model "forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/keying"
	"forgejo.org/modules/ratelimit"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/translation"
	"forgejo.org/routers"
	"forgejo.org/tests"

	"github.com/markbates/goth"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditActions returns the entries of action written after since, oldest first.
func auditActions(t *testing.T, since int64, action string) []*audit_model.Entry {
	t.Helper()
	var entries []*audit_model.Entry
	require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND action = ?", since, action).OrderBy("id").Find(&entries))
	return entries
}

// auditFresh starts a test with no remembered credential uses and no pending aggregates from earlier tests.
func auditFresh(t *testing.T) {
	t.Helper()
	audit_model.ResetActivity()
	t.Cleanup(audit_model.ResetActivity)
}

func assertSignIn(t *testing.T, e *audit_model.Entry, uid int64, ip, method string) {
	t.Helper()
	assert.Equal(t, audit_model.CategoryAuth, e.Category)
	assert.Equal(t, audit_model.ActorUser, e.ActorType)
	assert.Equal(t, uid, e.ActorID)
	assert.Equal(t, uid, e.SubjectUserID)
	assert.Equal(t, audit_model.CredentialSession, e.CredentialType)
	if ip != "" {
		assert.Equal(t, ip, e.IP)
	}
	assert.Equal(t, method, auditData(t, e)["method"])
}

// sessionData returns the raw stored session of s (the tests use the file session provider).
func sessionData(t *testing.T, s *TestSession) string {
	t.Helper()
	var conf struct{ ProviderConfig string }
	require.NoError(t, json.Unmarshal([]byte(setting.SessionConfig.ProviderConfig), &conf))
	sid := s.GetCookie(setting.SessionConfig.CookieName).Value
	data, err := os.ReadFile(filepath.Join(conf.ProviderConfig, sid[0:1], sid[1:2], sid))
	require.NoError(t, err)
	return string(data)
}

func totpPasscode(t *testing.T, u *user_model.User) string {
	t.Helper()
	twoFactor, err := auth_model.GetTwoFactorByUID(db.DefaultContext, u.ID)
	require.NoError(t, err)
	secret, err := keying.TOTP.Decrypt(twoFactor.Secret, keying.ColumnAndID("secret", twoFactor.ID))
	require.NoError(t, err)
	passcode, err := totp.GenerateCode(string(secret), time.Now())
	require.NoError(t, err)
	return passcode
}

func TestAuditSignInPassword(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	signIn := func(ip, name, password string, status int) {
		t.Helper()
		MakeRequest(t, from(ip, NewRequestWithValues(t, "POST", "/user/login", map[string]string{"user_name": name, "password": password})), status)
	}

	since := auditMaxID(t)
	signIn("203.0.113.20", "user2", userPassword, http.StatusSeeOther)
	entries := auditActions(t, since, "auth.signin.success")
	require.Len(t, entries, 1)
	assertSignIn(t, entries[0], 2, "203.0.113.20", "password")
	assert.Equal(t, "user2", entries[0].TargetName)

	since = auditMaxID(t)
	signIn("203.0.113.21", "user2", "wrong", http.StatusOK)
	signIn("203.0.113.21", "user2", "wrong", http.StatusOK)
	signIn("203.0.113.21", "no-such-user@example.com", "wrong", http.StatusOK)
	failed := auditActions(t, since, "auth.signin.failed")
	require.Len(t, failed, 2, "the second bad password of the same user and IP is aggregated")
	assert.EqualValues(t, 2, failed[0].SubjectUserID)
	assert.Equal(t, audit_model.ResultFailure, failed[0].Result)
	assert.Equal(t, audit_model.ActorAnonymous, failed[0].ActorType)
	assert.Equal(t, "203.0.113.21", failed[0].IP)
	assert.Equal(t, "bad_password", auditData(t, failed[0])["reason"])
	assert.Zero(t, failed[1].SubjectUserID)
	assert.Equal(t, "unknown_user", auditData(t, failed[1])["reason"])
	assert.NotContains(t, failed[1].Data+failed[1].TargetName, "no-such-user", "a typed name is never stored")

	audit_model.FlushAggregated(t.Context(), true)
	agg := auditActions(t, since, "auth.signin.failed.aggregated")
	require.Len(t, agg, 1)
	assert.EqualValues(t, 2, agg[0].SubjectUserID)
	assert.EqualValues(t, 1, auditData(t, agg[0])["count"])

	since = auditMaxID(t)
	signIn("203.0.113.22", "user37", userPassword, http.StatusOK) // login prohibited
	failed = auditActions(t, since, "auth.signin.failed")
	require.Len(t, failed, 1)
	assert.EqualValues(t, 37, failed[0].SubjectUserID)
	assert.Equal(t, "prohibited", auditData(t, failed[0])["reason"])
}

func TestAuditSignInSecondFactor(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)

	t.Run("totp", func(t *testing.T) {
		session := loginUser(t, "user2")
		session.EnrollTOTP(t)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

		// the method is set by the server and dropped after the sign-in; a request value can't set it
		since := auditMaxID(t)
		session = loginUser(t, "user2") // stops at the 2FA page
		assert.Empty(t, auditActions(t, since, "auth.signin.success"), "the password step alone is no sign-in")
		assert.Contains(t, sessionData(t, session), "twofaMethod")
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/two_factor?twofaMethod=evil", map[string]string{
			"passcode": totpPasscode(t, user2), "twofaMethod": "evil", "method": "evil",
		}), http.StatusSeeOther)
		entries := auditActions(t, since, "auth.signin.success")
		require.Len(t, entries, 1)
		assertSignIn(t, entries[0], 2, "", "password+totp")
		assert.NotContains(t, sessionData(t, session), "twofaMethod")

		since = auditMaxID(t)
		session = loginUser(t, "user2") // stops at the 2FA page
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/two_factor", map[string]string{"passcode": "000000"}), http.StatusOK)
		failed := auditActions(t, since, "auth.signin.failed")
		require.Len(t, failed, 1)
		assert.EqualValues(t, 2, failed[0].SubjectUserID)
		assert.Equal(t, "bad_totp", auditData(t, failed[0])["reason"])
	})

	t.Run("scratch", func(t *testing.T) {
		twoFactor := &auth_model.TwoFactor{UID: 5}
		token := twoFactor.GenerateScratchToken()
		require.NoError(t, auth_model.NewTwoFactor(t.Context(), twoFactor, token))

		session := loginUser(t, "user5")
		since := auditMaxID(t)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/two_factor/scratch", map[string]string{"token": "wrong"}), http.StatusOK)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/two_factor/scratch", map[string]string{"token": token}), http.StatusSeeOther)
		failed := auditActions(t, since, "auth.signin.failed")
		require.Len(t, failed, 1)
		assert.Equal(t, "bad_scratch", auditData(t, failed[0])["reason"])
		entries := auditActions(t, since, "auth.signin.success")
		require.Len(t, entries, 1)
		assertSignIn(t, entries[0], 5, "", "password+scratch")
	})

	t.Run("webauthn failure", func(t *testing.T) {
		// there is no virtual authenticator, so only a refused assertion is tested
		unittest.AssertSuccessfulInsert(t, &auth_model.WebAuthnCredential{UserID: 4, Name: "k", LowerName: "k", CredentialID: []byte{1}})
		session := loginUser(t, "user4")
		session.MakeRequest(t, NewRequest(t, "GET", "/user/webauthn/assertion"), http.StatusOK)
		since := auditMaxID(t)
		session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/user/webauthn/assertion", map[string]any{}), http.StatusForbidden)
		failed := auditActions(t, since, "auth.signin.failed")
		require.Len(t, failed, 1)
		assert.EqualValues(t, 4, failed[0].SubjectUserID)
		assert.Equal(t, "bad_webauthn", auditData(t, failed[0])["reason"])
	})
}

func TestAuditSignInOAuth2(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	gitlab := addAuthSource(t, authSourcePayloadGitLabCustom("gitlab"))
	userGitLab := &user_model.User{
		Name: "gitlabuser", Email: "gitlabuser@example.com", Passwd: "gitlabuserpassword",
		Type: user_model.UserTypeIndividual, LoginType: auth_model.OAuth2, LoginSource: gitlab.ID, LoginName: "5678",
	}
	defer createUser(t.Context(), t, userGitLab)()
	defer mockCompleteUserAuth(func(res http.ResponseWriter, req *http.Request) (goth.User, error) {
		return goth.User{Provider: "gitlab", UserID: "5678", Email: userGitLab.Email}, nil
	})()

	since := auditMaxID(t)
	MakeRequest(t, from("203.0.113.30", NewRequest(t, "GET", "/user/oauth2/gitlab/callback?code=XYZ&state=XYZ")), http.StatusSeeOther)
	entries := auditActions(t, since, "auth.signin.success")
	require.Len(t, entries, 1)
	assertSignIn(t, entries[0], userGitLab.ID, "203.0.113.30", fmt.Sprintf("oauth2:%d", gitlab.ID))

	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "GET", "/user/oauth2/gitlab/callback?code=XYZ&state=XYZ&error=access_denied"), http.StatusSeeOther)
	failed := auditActions(t, since, "auth.signin.failed")
	require.Len(t, failed, 1)
	assert.Equal(t, "oauth2_failed", auditData(t, failed[0])["reason"])
}

func TestAuditSignInRememberMe(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	sess := emptyTestSession(t)
	sess.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/login", map[string]string{
		"user_name": "user2", "password": userPassword, "remember": "true",
	}), http.StatusSeeOther)

	since := auditMaxID(t)
	session := GetSessionForLTACookie(t, sess.GetCookie(setting.CookieRememberName))
	session.MakeRequest(t, NewRequest(t, "GET", "/user/login"), http.StatusSeeOther)
	session.MakeRequest(t, NewRequest(t, "GET", "/"), http.StatusOK)
	entries := auditActions(t, since, "auth.signin.success")
	require.Len(t, entries, 1)
	assertSignIn(t, entries[0], 2, "", "remember_me")
}

func TestAuditSignInReverseProxy(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	defer test.MockVariableValue(&setting.Service.EnableReverseProxyAuth, true)()
	defer test.MockVariableValue(&testWebRoutes, routers.NormalRoutes())()

	since := auditMaxID(t)
	session := emptyTestSession(t)
	for range 2 {
		session.MakeRequest(t, NewRequest(t, "GET", "/user/settings").SetHeader(setting.ReverseProxyAuthUser, "user2"), http.StatusOK)
	}
	entries := auditActions(t, since, "auth.signin.success")
	require.Len(t, entries, 1, "only the request that created the session signs in")
	assertSignIn(t, entries[0], 2, "", "reverse_proxy")
}

// Package and container routes verify credentials themselves, with the request actor stored first as on web and API:
// a reverse proxy user created there (the first one is an admin) is created by the anonymous request actor.
func TestAuditReverseProxyContainerRegistration(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	defer test.MockVariableValue(&setting.Service.EnableReverseProxyAuth, true)()
	defer test.MockVariableValue(&setting.Service.EnableReverseProxyAutoRegister, true)()
	defer test.MockVariableValue(&testWebRoutes, routers.NormalRoutes())()

	since := auditMaxID(t)
	MakeRequest(t, NewRequest(t, "GET", "/v2/").SetHeader(setting.ReverseProxyAuthUser, "rp-container"), http.StatusOK)
	u := unittest.AssertExistsAndLoadBean(t, &user_model.User{LowerName: "rp-container"})
	entries := auditActions(t, since, "account.user.created")
	require.Len(t, entries, 1)
	assert.Equal(t, u.ID, entries[0].TargetID)
	assert.Equal(t, audit_model.ActorAnonymous, entries[0].ActorType, "the request actor, not an unknown one")
	assert.NotEmpty(t, entries[0].RequestID)
}

func TestAuditSignInResetAndActivation(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)

	t.Run("password reset", func(t *testing.T) {
		// user4: another user than the other reset tests, whose mail resend limit (cached for 180 s) this would hit
		user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
		cleanup, code, _ := parseMailHelper(t, user4.EmailTo(), translation.NewLocale("en-US").TrString("mail.reset_password"))
		defer cleanup()
		session := emptyTestSession(t)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/forgot_password", map[string]string{"email": user4.Email}), http.StatusOK)

		since := auditMaxID(t)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/recover_account", map[string]string{"code": *code, "password": "new_password1!"}), http.StatusSeeOther)
		entries := auditActions(t, since, "auth.signin.success")
		require.Len(t, entries, 1)
		assertSignIn(t, entries[0], 4, "", "password_reset")
		assert.Equal(t, "reset_code", auditData(t, entries[0])["reason"])
	})

	t.Run("activation", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Service.RegisterEmailConfirm, true)()
		cleanup, code, _ := parseMailHelper(t, `"auditactivate" <auditactivate@example.com>`, translation.NewLocale("en-US").TrString("mail.activate_account"))
		defer cleanup()
		session := emptyTestSession(t)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/sign_up", map[string]string{
			"user_name": "auditactivate", "email": "auditactivate@example.com", "password": "examplePassword!1", "retype": "examplePassword!1",
		}), http.StatusOK)
		u := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "auditactivate"})

		since := auditMaxID(t)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/activate?code="+url.QueryEscape(*code), map[string]string{"password": "wrong"}), http.StatusOK)
		failed := auditActions(t, since, "auth.signin.failed")
		require.Len(t, failed, 1)
		assert.Equal(t, u.ID, failed[0].SubjectUserID)
		assert.Equal(t, "bad_activation_password", auditData(t, failed[0])["reason"])

		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/activate?code="+url.QueryEscape(*code), map[string]string{"password": "examplePassword!1"}), http.StatusSeeOther)
		entries := auditActions(t, since, "auth.signin.success")
		require.Len(t, entries, 1)
		assertSignIn(t, entries[0], u.ID, "", "activation")
		assert.Equal(t, "activation_code", auditData(t, entries[0])["reason"])
	})
}

// servCommandTo calls the private serv API for a git command on owner/repo (or owner/project/repo) from ip.
func servCommandTo(t *testing.T, keyID int64, path, ip string) (int, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	routers.InternalRoutes().ServeHTTP(recorder, NewRequest(t, "GET", fmt.Sprintf("/api/internal/serv/command/%d/%s?mode=1&verb=git-upload-pack&ip=%s", keyID, path, url.QueryEscape(ip))).Request)
	return recorder.Code, recorder.Body.String()
}

func TestAuditCredentialUsed(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadUser, auth_model.AccessTokenScopeReadRepository)
	tok, err := auth_model.GetAccessTokenBySHA(t.Context(), token)
	require.NoError(t, err)

	used := func(t *testing.T, since int64) []*audit_model.Entry {
		t.Helper()
		return auditActions(t, since, "auth.credential.used")
	}
	api := func(ip string) *RequestWrapper {
		return from(ip, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(token))
	}

	t.Run("token per IP", func(t *testing.T) {
		since := auditMaxID(t)
		MakeRequest(t, api("203.0.113.40"), http.StatusOK)
		entries := used(t, since)
		require.Len(t, entries, 1)
		e := entries[0]
		assert.Equal(t, audit_model.CredentialAccessToken, e.CredentialType)
		assert.Equal(t, tok.ID, e.CredentialID)
		assert.EqualValues(t, 2, e.ActorID)
		assert.EqualValues(t, 2, e.SubjectUserID)
		assert.Equal(t, "203.0.113.40", e.IP)
		assert.Equal(t, "api", auditData(t, e)["method"])

		since = auditMaxID(t)
		MakeRequest(t, api("203.0.113.40"), http.StatusOK)
		assert.Empty(t, used(t, since), "the same IP again")
		MakeRequest(t, api("203.0.113.41"), http.StatusOK)
		assert.Len(t, used(t, since), 1, "a new IP")

		since = auditMaxID(t)
		MakeRequest(t, api("2001:db8:40::1"), http.StatusOK)
		MakeRequest(t, api("2001:db8:40::2"), http.StatusOK)
		assert.Len(t, used(t, since), 1, "one /64")
	})

	t.Run("ambiguous IP", func(t *testing.T) {
		since := auditMaxID(t)
		for _, realIP := range []string{"198.51.100.40", "198.51.100.41"} {
			req := NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(token)
			req.RemoteAddr = "127.0.0.1:1234"
			req.SetHeader("X-Forwarded-For", "203.0.113.42")
			req.SetHeader("X-Real-IP", realIP)
			MakeRequest(t, req, http.StatusOK)
		}
		entries := used(t, since)
		require.Len(t, entries, 2, "conflicting headers are not folded into one key")
		assert.Equal(t, true, auditData(t, entries[0])["ip_ambiguous"])
	})

	t.Run("basic auth and git", func(t *testing.T) {
		since := auditMaxID(t)
		MakeRequest(t, from("203.0.113.43", NewRequest(t, "GET", "/api/v1/user").AddBasicAuth("user2")), http.StatusOK)
		MakeRequest(t, from("203.0.113.44", NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack").AddTokenAuth(token)), http.StatusOK)
		entries := used(t, since)
		require.Len(t, entries, 2)
		assert.Equal(t, audit_model.CredentialPassword, entries[0].CredentialType)
		assert.EqualValues(t, 2, entries[0].SubjectUserID)
		assert.Equal(t, audit_model.CredentialAccessToken, entries[1].CredentialType)
		assert.Equal(t, "git", auditData(t, entries[1])["method"])
	})

	t.Run("ssh", func(t *testing.T) {
		since := auditMaxID(t)
		for _, ip := range []string{"203.0.113.45", "203.0.113.45", "203.0.113.46"} {
			status, body := servCommandTo(t, 1, "user2/repo1", ip)
			require.Equal(t, http.StatusOK, status, body)
		}
		entries := used(t, since)
		require.Len(t, entries, 2)
		assert.Equal(t, audit_model.CredentialSSHKey, entries[0].CredentialType)
		assert.EqualValues(t, 1, entries[0].CredentialID)
		assert.EqualValues(t, 2, entries[0].ActorID)
		assert.Equal(t, "203.0.113.45", entries[0].IP)
		assert.Equal(t, "ssh", auditData(t, entries[0])["method"])
	})

	t.Run("rate limited", func(t *testing.T) {
		mockRateLimit(t, map[string]setting.RateLimitClass{ratelimit.API: {AuthenticatedRate: slow, AuthenticatedBurst: 1}}, "")
		since := auditMaxID(t)
		MakeRequest(t, api("203.0.113.47"), http.StatusOK)
		MakeRequest(t, api("203.0.113.48"), http.StatusTooManyRequests)
		MakeRequest(t, api("203.0.113.48"), http.StatusTooManyRequests)
		entries := used(t, since)
		require.Len(t, entries, 1, "a refused request records no credential use")
		assert.Equal(t, "203.0.113.47", entries[0].IP)
		refused := auditActions(t, since, "auth.refused")
		require.Len(t, refused, 1)
		assert.Equal(t, "rate_limit", auditData(t, refused[0])["reason"])
		assert.Equal(t, ratelimit.API, auditData(t, refused[0])["class"])

		audit_model.FlushAggregated(t.Context(), true)
		agg := auditActions(t, since, "auth.refused.aggregated")
		require.Len(t, agg, 1)
		assert.EqualValues(t, 1, auditData(t, agg[0])["count"])
	})

	t.Run("write failure", func(t *testing.T) {
		defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error { return errors.New("boom") })()
		before := audit_model.WriteErrors.Load()
		MakeRequest(t, api("203.0.113.49"), http.StatusOK)
		assert.Equal(t, before+1, audit_model.WriteErrors.Load(), "the request still succeeds")
		emptyTestSession(t).MakeRequest(t, NewRequestWithValues(t, "POST", "/user/login", map[string]string{"user_name": "user2", "password": userPassword}), http.StatusSeeOther)
		assert.Equal(t, before+2, audit_model.WriteErrors.Load(), "a sign-in still succeeds")
	})
}

func TestAuditBadCredential(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)

	since := auditMaxID(t)
	hugeUA := strings.Repeat("u", 1<<20)
	for range 2 {
		MakeRequest(t, from("203.0.113.50", NewRequest(t, "GET", "/api/v1/user").AddTokenAuth("0123456789abcdef0123456789abcdef01234567").SetHeader("User-Agent", hugeUA)), http.StatusUnauthorized)
	}
	failed := auditActions(t, since, "auth.signin.failed")
	require.Len(t, failed, 1)
	assert.Len(t, failed[0].UserAgent, audit_model.MaxUserAgent)
	audit_model.FlushAggregated(t.Context(), true)
	agg := auditActions(t, since, "auth.signin.failed.aggregated")
	require.Len(t, agg, 1)
	assert.Len(t, agg[0].UserAgent, audit_model.MaxUserAgent, "the aggregate keeps the capped actor")
	assert.Equal(t, audit_model.ActorAnonymous, failed[0].ActorType)
	assert.Equal(t, "203.0.113.50", failed[0].IP)
	assert.Zero(t, failed[0].SubjectUserID)
	assert.Equal(t, "bad_credential", auditData(t, failed[0])["reason"])
	assert.NotContains(t, failed[0].Data, "0123456789abcdef")

	t.Run("rate limited", func(t *testing.T) {
		mockRateLimit(t, map[string]setting.RateLimitClass{ratelimit.Auth: {AuthenticatedRate: slow, AuthenticatedBurst: 1}}, "")
		basic := func(status int) {
			req := from("203.0.113.51", NewRequest(t, "GET", "/api/v1/user"))
			req.Request.SetBasicAuth("user2", "wrong")
			MakeRequest(t, req, status)
		}
		since := auditMaxID(t)
		basic(http.StatusUnauthorized)
		basic(http.StatusTooManyRequests)
		basic(http.StatusTooManyRequests)
		failed := auditActions(t, since, "auth.signin.failed")
		require.Len(t, failed, 1, "the refused attempt is only a rate limit refusal")
		assert.EqualValues(t, 2, failed[0].SubjectUserID)
		refused := auditActions(t, since, "auth.refused")
		require.Len(t, refused, 1)
		assert.Equal(t, "rate_limit", auditData(t, refused[0])["reason"])
		assert.Equal(t, ratelimit.Auth, auditData(t, refused[0])["class"])

		audit_model.FlushAggregated(t.Context(), true)
		agg := auditActions(t, since, "auth.refused.aggregated")
		require.Len(t, agg, 1)
		assert.Equal(t, "rate_limit", auditData(t, agg[0])["reason"])
		assert.EqualValues(t, 1, auditData(t, agg[0])["count"])
	})
}

func TestAuditRefusals(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadUser)

	t.Run("ip allowlist", func(t *testing.T) {
		defer setIPAllowlist(t, nil)()
		since := auditMaxID(t)
		for range 3 {
			MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(token)), http.StatusForbidden)
		}
		refused := auditActions(t, since, "auth.refused")
		require.Len(t, refused, 1)
		assert.Equal(t, "ip_allowlist", auditData(t, refused[0])["reason"])
		assert.Equal(t, ipBlocked, refused[0].IP)
		assert.EqualValues(t, 2, refused[0].SubjectUserID)
		assert.Empty(t, auditActions(t, since, "auth.credential.used"), "a refused request records no credential use")

		audit_model.FlushAggregated(t.Context(), true)
		agg := auditActions(t, since, "auth.refused.aggregated")
		require.Len(t, agg, 1)
		assert.EqualValues(t, 2, auditData(t, agg[0])["count"])

		since = auditMaxID(t)
		for _, ip := range []string{"2001:db8:77::1", "2001:db8:77:1::1", "2001:db8:78::1"} {
			MakeRequest(t, from(ip, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(token)), http.StatusForbidden)
		}
		assert.Len(t, auditActions(t, since, "auth.refused"), 2, "one per IPv6 /48")
	})

	t.Run("org two-factor requirement", func(t *testing.T) {
		member := loginUser(t, "user4")
		flagOrg3(t)
		since := auditMaxID(t)
		member.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3"), http.StatusForbidden)
		member.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3"), http.StatusForbidden)
		refused := auditActions(t, since, "auth.refused")
		require.Len(t, refused, 1, "once per user, organization and day")
		assert.Equal(t, "org_two_factor", auditData(t, refused[0])["reason"])
		assert.EqualValues(t, 3, refused[0].OwnerID)
		assert.EqualValues(t, 4, refused[0].SubjectUserID)
	})

	t.Run("expired access token", func(t *testing.T) {
		tok, err := auth_model.GetAccessTokenBySHA(t.Context(), token)
		require.NoError(t, err)
		setExpiresUnix(t, &auth_model.AccessToken{}, tok.ID, timeutil.TimeStampNow().Add(-1))
		since := auditMaxID(t)
		for range 2 {
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(token), http.StatusUnauthorized)
		}
		expired := auditActions(t, since, "credential.access_token.expired")
		require.Len(t, expired, 1)
		assert.Equal(t, tok.ID, expired[0].TargetID)
		assert.EqualValues(t, 2, expired[0].SubjectUserID)
		assert.Equal(t, audit_model.ResultRefused, expired[0].Result)
		refused := auditActions(t, since, "auth.refused")
		require.Len(t, refused, 1)
		assert.Equal(t, "expired", auditData(t, refused[0])["reason"])
		assert.Empty(t, auditActions(t, since, "auth.signin.failed"))

		audit_model.FlushAggregated(t.Context(), true) // earlier subtests' buckets
		since = auditMaxID(t)
		for range 2 {
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(token), http.StatusUnauthorized)
		}
		audit_model.FlushAggregated(t.Context(), true)
		agg := auditActions(t, since, "auth.refused.aggregated")
		require.Len(t, agg, 1)
		assert.Equal(t, "expired", auditData(t, agg[0])["reason"])
		assert.EqualValues(t, 1, auditData(t, agg[0])["count"])

		audit_model.ResetActivity() // another pod: the existing entry still counts
		since = auditMaxID(t)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(token), http.StatusUnauthorized)
		assert.Empty(t, auditActions(t, since, "credential.access_token.expired"))
		assert.Len(t, auditActions(t, since, "auth.refused"), 1)
	})

	t.Run("expired keys", func(t *testing.T) {
		past := timeutil.TimeStampNow().Add(-60)
		content, _ := newTestSSHKey(t)
		key, err := asymkey_model.AddPublicKey(audit_model.WithSystem(t.Context(), "test"), 2, "audit-expired", content, 0, past)
		require.NoError(t, err)
		since := auditMaxID(t)
		status, _ := servCommandTo(t, key.ID, "user2/repo1", "203.0.113.60")
		assert.Equal(t, http.StatusUnauthorized, status)
		expired := auditActions(t, since, "credential.ssh_key.expired")
		require.Len(t, expired, 1)
		assert.Equal(t, key.ID, expired[0].TargetID)
		assert.Equal(t, "203.0.113.60", expired[0].IP)

		content, _ = newTestSSHKey(t)
		deployKey, err := asymkey_model.AddDeployKey(t.Context(), 1, "audit-expired-ci", content, true, past)
		require.NoError(t, err)
		servCommandTo(t, deployKey.KeyID, "user2/repo1", "203.0.113.61")
		expired = auditActions(t, since, "credential.deploy_key.expired")
		require.Len(t, expired, 1)
		assert.Equal(t, deployKey.ID, expired[0].TargetID)

		orgKey, err := asymkey_model.AddOrgDeployKey(t.Context(), 3, 0, "audit-expired-org", newOrgDeployKeyContent(t), true, true, nil, past)
		require.NoError(t, err)
		servCommandTo(t, orgKey.KeyID, "org3/repo3", "203.0.113.62")
		expired = auditActions(t, since, "credential.org_deploy_key.expired")
		require.Len(t, expired, 1)
		assert.Equal(t, orgKey.ID, expired[0].TargetID)
		assert.EqualValues(t, 3, expired[0].SubjectUserID)

		group := createProjectForKeys(t, 3, "auditproj")
		moveRepoForKeys(t, 3, group.ID)
		projectKey := addProjectDeployKey(t, 3, group.ID, "audit-expired-project", true, past)
		servCommandTo(t, projectKey.KeyID, "org3/auditproj/repo3", "203.0.113.63")
		expired = auditActions(t, since, "credential.project_deploy_key.expired")
		require.Len(t, expired, 1)
		assert.Equal(t, projectKey.ID, expired[0].TargetID)
	})

	t.Run("expired OAuth2 client secret", func(t *testing.T) {
		_, err := db.GetEngine(t.Context()).Exec("UPDATE oauth2_application SET client_secret_expires_unix = ? WHERE id = 1", timeutil.TimeStampNow().Add(-1))
		require.NoError(t, err)
		since := auditMaxID(t)
		MakeRequest(t, NewRequestWithValues(t, "POST", "/login/oauth/access_token", map[string]string{
			"grant_type": "refresh_token", "client_id": "da7da3ba-9a13-4167-856f-3899de0b0138",
			"client_secret": "4MK8Na6R55smdCY0WuCCumZ6hjRPnGY5saWVRHHjJiA=", "refresh_token": "x",
		}), http.StatusBadRequest)
		expired := auditActions(t, since, "credential.oauth2_app.expired")
		require.Len(t, expired, 1)
		assert.EqualValues(t, 1, expired[0].TargetID)
	})
}

// A member of an organization that requires two-factor and has none is refused on the API and on git too, and
// each refusal is recorded once per user, organization and day, with the same answers as before.
func TestAuditTwoFactorBlockedAPIAndGit(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	flagOrg3(t)
	content, _ := newTestSSHKey(t)
	key, err := asymkey_model.AddPublicKey(audit_model.WithSystem(t.Context(), "test"), 4, "audit-2fa", content, 0, 0)
	require.NoError(t, err)
	tokenOf := func(name string) string {
		return getTokenForLoggedInUser(t, loginUser(t, name), auth_model.AccessTokenScopeReadRepository)
	}
	member, stranger := tokenOf("user4"), tokenOf("user5")

	for name, tc := range map[string]struct {
		token    string
		do       func(token string) int
		uid      int64
		recorded bool
		status   int
	}{
		"api hidden":     {member, func(tok string) int { return apiStatus(t, "/api/v1/repos/org3/repo3", tok) }, 4, true, 0},
		"api missing":    {member, func(tok string) int { return apiStatus(t, "/api/v1/repos/org3/nope", tok) }, 4, true, 0},
		"git hidden":     {member, func(tok string) int { return apiStatus(t, "/org3/repo3.git/info/refs?service=git-upload-pack", tok) }, 4, true, 0},
		"git missing":    {member, func(tok string) int { return apiStatus(t, "/org3/nope.git/info/refs?service=git-upload-pack", tok) }, 4, true, 0},
		"ssh hidden":     {"", func(string) int { s, _ := servCommandTo(t, key.ID, "org3/repo3", "203.0.113.70"); return s }, 4, true, http.StatusUnauthorized},
		"ssh missing":    {"", func(string) int { s, _ := servCommandTo(t, key.ID, "org3/nope", "203.0.113.70"); return s }, 4, true, 0},
		"api non-member": {stranger, func(tok string) int { return apiStatus(t, "/api/v1/repos/org3/repo3", tok) }, 5, false, 0},
		"git non-member": {stranger, func(tok string) int { return apiStatus(t, "/org3/repo3.git/info/refs?service=git-upload-pack", tok) }, 5, false, 0},
	} {
		t.Run(name, func(t *testing.T) {
			audit_model.ResetActivity()
			since := auditMaxID(t)
			first := tc.do(tc.token)
			want := cmp.Or(tc.status, http.StatusNotFound)
			assert.Equal(t, want, first, "the answer is unchanged")
			assert.Equal(t, first, tc.do(tc.token))
			refused := auditActions(t, since, "auth.refused")
			if !tc.recorded {
				assert.Empty(t, refused)
				return
			}
			require.Len(t, refused, 1, "once per user, organization and day")
			assert.Equal(t, "org_two_factor", auditData(t, refused[0])["reason"])
			assert.EqualValues(t, 3, refused[0].OwnerID)
			assert.Equal(t, tc.uid, refused[0].SubjectUserID)
			assert.NotEqual(t, audit_model.ActorUnknown, refused[0].ActorType, "the request's actor is known")
		})
	}
}

func apiStatus(t *testing.T, path, token string) int {
	t.Helper()
	req := NewRequest(t, "GET", path)
	if token != "" {
		req = req.AddTokenAuth(token)
	}
	return MakeRequest(t, req, NoExpectedStatus).Code
}
