// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	asymkey_model "forgejo.org/models/asymkey"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/hostmatcher"
	"forgejo.org/modules/ratelimit"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/routers"
	"forgejo.org/tests"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// slow is a refill rate that never refills during a test
const slow = 0.0001

func mockRateLimit(t *testing.T, classes map[string]setting.RateLimitClass, exempt string) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.RateLimit.Enabled, true))
	t.Cleanup(test.MockVariableValue(&setting.RateLimit.Classes, classes))
	t.Cleanup(test.MockVariableValue(&setting.RateLimit.ExemptCIDRs, hostmatcher.ParseHostMatchList("", exempt)))
	ratelimit.ResetForTest()
	t.Cleanup(ratelimit.ResetForTest)
}

func fromIP(rw *RequestWrapper, ip string) *RequestWrapper {
	rw.Request.RemoteAddr = ip + ":1234"
	return rw
}

func TestRateLimitDisabled(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ratelimit.ResetForTest()

	for range 3 {
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/version"), http.StatusOK)
		assert.Empty(t, resp.Header().Get("X-RateLimit-Limit"))
	}
}

func TestRateLimitAPI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeAll)
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.API:      {AuthenticatedRate: slow, AuthenticatedBurst: 3, AnonymousRate: slow, AnonymousBurst: 2},
		ratelimit.APIWrite: {AuthenticatedRate: slow, AuthenticatedBurst: 1},
	}, "")

	t.Run("anonymous per IP", func(t *testing.T) {
		for _, remaining := range []string{"1", "0"} {
			resp := MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/version"), "192.0.2.1"), http.StatusOK)
			assert.Equal(t, "2", resp.Header().Get("X-RateLimit-Limit"))
			assert.Equal(t, remaining, resp.Header().Get("X-RateLimit-Remaining"))
			assert.NotEmpty(t, resp.Header().Get("X-RateLimit-Reset"))
			assert.Contains(t, resp.Header().Get("Access-Control-Expose-Headers"), "X-RateLimit-Remaining")
		}
		resp := MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/version"), "192.0.2.1"), http.StatusTooManyRequests)
		assert.NotEmpty(t, resp.Header().Get("Retry-After"))
		assert.Equal(t, "0", resp.Header().Get("X-RateLimit-Remaining"))
		assert.Contains(t, resp.Body.String(), "rate limit exceeded, retry in")

		// the other API mount shares the class
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/forgejo/v1/version"), "192.0.2.1"), http.StatusTooManyRequests)
		// other IPs have their own bucket
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/version"), "192.0.2.2"), http.StatusOK)
	})

	t.Run("forwarded headers only from trusted proxies", func(t *testing.T) {
		// 192.0.2.1 is not a trusted proxy, so its X-Forwarded-For is ignored
		req := fromIP(NewRequest(t, "GET", "/api/v1/version"), "192.0.2.1").SetHeader("X-Forwarded-For", "198.51.100.1")
		MakeRequest(t, req, http.StatusTooManyRequests)
		req = fromIP(NewRequest(t, "GET", "/api/v1/version"), "192.0.2.1").SetHeader("X-Real-IP", "198.51.100.1")
		MakeRequest(t, req, http.StatusTooManyRequests)
		// loopback is trusted by default
		req = fromIP(NewRequest(t, "GET", "/api/v1/version"), "127.0.0.1").SetHeader("X-Forwarded-For", "192.0.2.1")
		MakeRequest(t, req, http.StatusTooManyRequests)
		req = fromIP(NewRequest(t, "GET", "/api/v1/version"), "127.0.0.1").SetHeader("X-Forwarded-For", "198.51.100.1")
		MakeRequest(t, req, http.StatusOK)
	})

	t.Run("authenticated per user, writes separately", func(t *testing.T) {
		// the IP is exhausted, the user isn't
		resp := MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/user"), "192.0.2.1").AddTokenAuth(token), http.StatusOK)
		assert.Equal(t, "3", resp.Header().Get("X-RateLimit-Limit"))

		req := NewRequestWithJSON(t, "POST", "/api/v1/markdown", map[string]string{"Text": "hi"})
		MakeRequest(t, fromIP(req.AddTokenAuth(token), "192.0.2.3"), http.StatusOK)
		req = NewRequestWithJSON(t, "POST", "/api/v1/markdown", map[string]string{"Text": "hi"})
		MakeRequest(t, fromIP(req.AddTokenAuth(token), "192.0.2.4"), http.StatusTooManyRequests)

		// reads have their own bucket: 3 in all
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/user"), "192.0.2.4").AddTokenAuth(token), http.StatusOK)
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/user"), "192.0.2.4").AddTokenAuth(token), http.StatusOK)
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/user"), "192.0.2.4").AddTokenAuth(token), http.StatusTooManyRequests)
	})
}

func TestRateLimitExempt(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.API:  {AuthenticatedRate: slow, AuthenticatedBurst: 1, AnonymousRate: slow, AnonymousBurst: 1},
		ratelimit.Auth: {AuthenticatedRate: slow, AuthenticatedBurst: 1},
	}, "192.0.2.0/24")

	for range 3 {
		resp := MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/version"), "192.0.2.9"), http.StatusOK)
		assert.Empty(t, resp.Header().Get("X-RateLimit-Limit"))
		req := NewRequestWithValues(t, "POST", "/user/login", map[string]string{"user_name": "user2", "password": "wrong"})
		MakeRequest(t, fromIP(req, "192.0.2.9"), http.StatusOK)
	}
	MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/version"), "198.51.100.9"), http.StatusOK)
	MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/version"), "198.51.100.9"), http.StatusTooManyRequests)
}

func TestRateLimitNeverLimited(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	tiny := setting.RateLimitClass{AuthenticatedRate: slow, AuthenticatedBurst: 1, AnonymousRate: slow, AnonymousBurst: 1}
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.API: tiny, ratelimit.APIWrite: tiny, ratelimit.Git: tiny, ratelimit.Web: tiny, ratelimit.Auth: tiny,
	}, "")
	internalRoutes := routers.InternalRoutes()

	for range 3 {
		resp := MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/healthz"), "192.0.2.1"), http.StatusOK)
		assert.Empty(t, resp.Header().Get("X-RateLimit-Limit"))

		// the Actions runner API
		req := NewRequestWithBody(t, "POST", "/api/actions/ping.v1.PingService/Ping", strings.NewReader(`{"data":"x"}`)).
			SetHeader("Content-Type", "application/json")
		resp = MakeRequest(t, fromIP(req, "192.0.2.1"), http.StatusOK)
		assert.Empty(t, resp.Header().Get("X-RateLimit-Limit"))

		MakeRequest(t, fromIP(NewRequest(t, "GET", "/assets/img/logo.svg"), "192.0.2.1"), http.StatusOK)

		// the internal API is a separate router without the rate limit middleware
		req = fromIP(NewRequest(t, "GET", "/api/internal/serv/none/1"), "192.0.2.1")
		recorder := NewNilResponseRecorder()
		internalRoutes.ServeHTTP(recorder, req.Request)
		assert.NotEqual(t, http.StatusTooManyRequests, recorder.Code)
		assert.Empty(t, recorder.Header().Get("X-RateLimit-Limit"))
	}
}

func TestRateLimitWebAndGit(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.Web: {AuthenticatedRate: slow, AuthenticatedBurst: 1, AnonymousRate: slow, AnonymousBurst: 1},
		ratelimit.Git: {AuthenticatedRate: slow, AuthenticatedBurst: 1, AnonymousRate: slow, AnonymousBurst: 1},
	}, "")

	MakeRequest(t, fromIP(NewRequest(t, "GET", "/explore/repos"), "192.0.2.1"), http.StatusOK)
	resp := MakeRequest(t, fromIP(NewRequest(t, "GET", "/explore/repos"), "192.0.2.1"), http.StatusTooManyRequests)
	assert.Contains(t, resp.Body.String(), "You have sent too many requests")
	assert.NotEmpty(t, resp.Header().Get("Retry-After"))
	// the 404 page is limited too
	MakeRequest(t, fromIP(NewRequest(t, "GET", "/no/such/page/at/all"), "192.0.2.1"), http.StatusTooManyRequests)

	// git has its own bucket
	MakeRequest(t, fromIP(NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack"), "192.0.2.1"), http.StatusOK)
	resp = MakeRequest(t, fromIP(NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack"), "192.0.2.1"), http.StatusTooManyRequests)
	assert.Contains(t, resp.Header().Get("Content-Type"), "text/plain")
	assert.Contains(t, resp.Body.String(), "rate limit exceeded, retry in")

	// a signed in user has their own bucket
	session.MakeRequest(t, fromIP(NewRequest(t, "GET", "/explore/repos"), "192.0.2.1"), http.StatusOK)
	session.MakeRequest(t, fromIP(NewRequest(t, "GET", "/explore/repos"), "192.0.2.1"), http.StatusTooManyRequests)
}

func TestRateLimitExemptAdmins(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeAll)
	userToken := getUserToken(t, "user2", auth_model.AccessTokenScopeAll)
	adminSession := loginUser(t, "user1")
	one := setting.RateLimitClass{AuthenticatedRate: slow, AuthenticatedBurst: 1, AnonymousRate: slow, AnonymousBurst: 1}
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.API: one, ratelimit.APIWrite: one, ratelimit.Git: one, ratelimit.Web: one,
		ratelimit.Auth: {AuthenticatedRate: slow, AuthenticatedBurst: 2},
	}, "")
	get := func(rw *RequestWrapper, status int) *httptest.ResponseRecorder {
		return MakeRequest(t, fromIP(rw, "192.0.2.1"), status)
	}
	gitRefs := func(status int) {
		req := NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack")
		req.Request.SetBasicAuth("user1", userPassword)
		get(req, status)
	}

	t.Run("off by default", func(t *testing.T) {
		get(NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(adminToken), http.StatusOK)
		get(NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(adminToken), http.StatusTooManyRequests)
	})

	t.Run("on", func(t *testing.T) {
		defer test.MockVariableValue(&setting.RateLimit.ExemptAdmins, true)()
		ratelimit.ResetForTest()
		for range 3 {
			resp := get(NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(adminToken), http.StatusOK)
			assert.Empty(t, resp.Header().Get("X-RateLimit-Limit"))
			req := NewRequestWithJSON(t, "POST", "/api/v1/markdown", map[string]string{"Text": "hi"})
			get(req.AddTokenAuth(adminToken), http.StatusOK)
			adminSession.MakeRequest(t, fromIP(NewRequest(t, "GET", "/explore/repos"), "192.0.2.1"), http.StatusOK)
			gitRefs(http.StatusOK)
		}

		// everyone else is still limited
		get(NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(userToken), http.StatusOK)
		get(NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(userToken), http.StatusTooManyRequests)
		get(NewRequest(t, "GET", "/api/v1/version"), http.StatusOK)
		get(NewRequest(t, "GET", "/api/v1/version"), http.StatusTooManyRequests)

		// the auth class still applies to the admin account
		signIn := func(ip, password string, status int) {
			req := NewRequestWithValues(t, "POST", "/user/login", map[string]string{"user_name": "user1", "password": password})
			MakeRequest(t, fromIP(req, ip), status)
		}
		signIn("192.0.2.2", "wrong", http.StatusOK)
		signIn("192.0.2.3", "wrong", http.StatusOK)
		signIn("192.0.2.4", userPassword, http.StatusTooManyRequests)
	})

	t.Run("prohibit login admin is limited", func(t *testing.T) {
		defer test.MockVariableValue(&setting.RateLimit.ExemptAdmins, true)()
		ratelimit.ResetForTest()
		_, err := db.GetEngine(t.Context()).ID(1).Cols("prohibit_login").Update(&user_model.User{ProhibitLogin: true})
		require.NoError(t, err)
		resp := get(NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(adminToken), NoExpectedStatus)
		assert.NotEmpty(t, resp.Header().Get("X-RateLimit-Limit"))
		get(NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(adminToken), http.StatusTooManyRequests)
	})
}

func TestRateLimitGitClone(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		mockRateLimit(t, map[string]setting.RateLimitClass{
			ratelimit.Git: {AuthenticatedRate: slow, AuthenticatedBurst: 1, AnonymousRate: slow, AnonymousBurst: 1},
		}, "")
		u.Path = "/user2/repo1.git"

		// use up the only token of this client
		resp, err := http.Get(u.String() + "/info/refs?service=git-upload-pack")
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		err = git.CloneWithArgs(t.Context(), nil, u.String(), filepath.Join(t.TempDir(), "repo1"), git.CloneRepoOptions{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "remote: rate limit exceeded, retry in")
	})
}

func TestRateLimitSignIn(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.Auth: {AuthenticatedRate: slow, AuthenticatedBurst: 2},
	}, "")
	signIn := func(ip, user, password string, status int) {
		t.Helper()
		req := NewRequestWithValues(t, "POST", "/user/login", map[string]string{"user_name": user, "password": password})
		MakeRequest(t, fromIP(req, ip), status)
	}

	t.Run("successful sign-ins never consume", func(t *testing.T) {
		for range 5 {
			signIn("192.0.2.1", "user2", userPassword, http.StatusSeeOther)
		}
	})

	t.Run("failures per username and per IP", func(t *testing.T) {
		signIn("192.0.2.1", "user2", "wrong", http.StatusOK)
		signIn("192.0.2.1", "user2", "wrong", http.StatusOK)
		// the user name is exhausted, from any IP and in any case, even with the right password
		signIn("192.0.2.2", "User2", userPassword, http.StatusTooManyRequests)
		// the IP is exhausted for every user name
		signIn("192.0.2.1", "user4", userPassword, http.StatusTooManyRequests)
		signIn("192.0.2.3", "user4", userPassword, http.StatusSeeOther)
	})

	t.Run("basic auth", func(t *testing.T) {
		basic := func(ip, path, user, password string, status int) *http.Response {
			t.Helper()
			req := fromIP(NewRequest(t, "GET", path), ip)
			req.Request.SetBasicAuth(user, password)
			return MakeRequest(t, req, status).Result()
		}
		for range 5 {
			basic("192.0.2.10", "/api/v1/user", "user4", userPassword, http.StatusOK)
		}
		basic("192.0.2.10", "/api/v1/user", "user4", "wrong", http.StatusUnauthorized)
		basic("192.0.2.11", "/api/v1/user", "user4", "wrong", http.StatusUnauthorized)
		// 429 rather than 401, so that git credential helpers keep the stored password
		resp := basic("192.0.2.12", "/api/v1/user", "user4", userPassword, http.StatusTooManyRequests)
		assert.NotEmpty(t, resp.Header.Get("Retry-After"))
		resp = basic("192.0.2.12", "/user2/repo1.git/info/refs?service=git-upload-pack", "user4", userPassword, http.StatusTooManyRequests)
		assert.Contains(t, resp.Header.Get("Content-Type"), "text/plain")
		basic("192.0.2.12", "/api/packages/user2/generic/pkg/1.0/file.txt", "user4", userPassword, http.StatusTooManyRequests)

		// unknown email-style names count too, so guesses aren't free and unknown addresses look like known ones
		// (an unknown email address currently answers 500 rather than 401, independently of rate limiting)
		for _, ip := range []string{"192.0.2.20", "192.0.2.21"} {
			assert.NotEqual(t, http.StatusTooManyRequests, basic(ip, "/api/v1/user", "nobody@example.com", "wrong", NoExpectedStatus).StatusCode)
		}
		basic("192.0.2.22", "/api/v1/user", "nobody@example.com", "wrong", http.StatusTooManyRequests)

		// another user name from an exhausted IP
		basic("192.0.2.10", "/api/v1/user", "user8", "wrong", http.StatusUnauthorized)
		basic("192.0.2.10", "/api/v1/user", "user8", userPassword, http.StatusTooManyRequests)
	})
}

func TestRateLimitTwoFactor(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	session.EnrollTOTP(t)
	session.MakeRequest(t, NewRequest(t, "POST", "/user/logout"), http.StatusSeeOther)

	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.Auth: {AuthenticatedRate: slow, AuthenticatedBurst: 2},
	}, "")
	// successful 2FA sign-ins never consume
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "user2"})
	loginUserWithTOTP(t, user2)

	session = loginUser(t, "user2") // stops at the 2FA page
	twoFactor := func(ip string, status int) {
		t.Helper()
		req := NewRequestWithValues(t, "POST", "/user/two_factor", map[string]string{"passcode": "000000"})
		session.MakeRequest(t, fromIP(req, ip), status)
		req = NewRequestWithValues(t, "POST", "/user/two_factor/scratch", map[string]string{"token": "wrongtoken"})
		session.MakeRequest(t, fromIP(req, ip), status)
	}
	twoFactor("192.0.2.1", http.StatusOK)
	// the same 2FA session from another IP shares the per-user bucket
	twoFactor("192.0.2.2", http.StatusTooManyRequests)
}

func TestRateLimitLinkAccount(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	gitlabName := "gitlab"
	addAuthSource(t, authSourcePayloadGitLabCustom(gitlabName))
	defer mockCompleteUserAuth(func(res http.ResponseWriter, req *http.Request) (goth.User, error) {
		return goth.User{Provider: gitlabName, UserID: "5678"}, nil
	})()
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.Auth: {AuthenticatedRate: slow, AuthenticatedBurst: 2},
	}, "")

	session := emptyTestSession(t)
	req := NewRequest(t, "GET", fmt.Sprintf("/user/oauth2/%s/callback?code=XYZ&state=XYZ", gitlabName))
	session.MakeRequest(t, req, http.StatusSeeOther)
	linkSignIn := func(ip, password string, status int) {
		t.Helper()
		req := NewRequestWithValues(t, "POST", "/user/link_account_signin", map[string]string{"user_name": "user2", "password": password})
		session.MakeRequest(t, fromIP(req, ip), status)
	}
	linkSignIn("192.0.2.1", "wrong", http.StatusOK)
	linkSignIn("192.0.2.2", "wrong", http.StatusOK)
	linkSignIn("192.0.2.3", userPassword, http.StatusTooManyRequests)
	// the web sign-in form shares the per-username bucket
	req = NewRequestWithValues(t, "POST", "/user/login", map[string]string{"user_name": "user2", "password": userPassword})
	MakeRequest(t, fromIP(req, "192.0.2.4"), http.StatusTooManyRequests)
}

func TestRateLimitAuthIPEndpoints(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.Auth: {AuthenticatedRate: slow, AuthenticatedBurst: 2},
	}, "")

	// every request counts, successful or not; an unknown address, so that no MailResendLimit_<user> cache entry
	// is left behind for later tests
	for range 2 {
		req := NewRequestWithValues(t, "POST", "/user/forgot_password", map[string]string{"email": "nobody@example.com"})
		MakeRequest(t, fromIP(req, "192.0.2.1"), http.StatusOK)
	}
	for _, path := range []string{"/user/forgot_password", "/user/sign_up", "/user/activate", "/user/recover_account"} {
		MakeRequest(t, fromIP(NewRequest(t, "POST", path), "192.0.2.1"), http.StatusTooManyRequests)
	}
}

func TestRateLimitOAuthToken(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.Auth: {AuthenticatedRate: slow, AuthenticatedBurst: 1},
	}, "")
	tokenRequest := func(values map[string]string, status int) map[string]any {
		t.Helper()
		values["client_id"] = "da7da3ba-9a13-4167-856f-3899de0b0138"
		values["client_secret"] = "4MK8Na6R55smdCY0WuCCumZ6hjRPnGY5saWVRHHjJiA="
		resp := MakeRequest(t, fromIP(NewRequestWithValues(t, "POST", "/login/oauth/access_token", values), "192.0.2.1"), status)
		var parsed map[string]any
		DecodeJSON(t, resp, &parsed)
		return parsed
	}

	// successful exchanges never consume the only token
	parsed := tokenRequest(map[string]string{
		"grant_type":    "authorization_code",
		"redirect_uri":  "a",
		"code":          "authcode",
		"code_verifier": "N1Zo9-8Rfwhkt68r1r29ty8YwIraXR8eh_1Qwxg7yQXsonBt",
	}, http.StatusOK)
	for range 2 {
		parsed = tokenRequest(map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": parsed["refresh_token"].(string),
		}, http.StatusOK)
	}

	// failures do
	tokenRequest(map[string]string{"grant_type": "authorization_code", "redirect_uri": "a", "code": "wrong"}, http.StatusBadRequest)
	parsed = tokenRequest(map[string]string{"grant_type": "authorization_code", "redirect_uri": "a", "code": "wrong"}, http.StatusTooManyRequests)
	assert.Contains(t, parsed["message"], "rate limit exceeded")
}

func TestRateLimitSignInAliasing(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	const burst = 3
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.Auth: {AuthenticatedRate: slow, AuthenticatedBurst: burst},
	}, "")
	// every attempt comes from its own IP, so that only the per-name budget limits
	n := 0
	signIn := func(name string) *httptest.ResponseRecorder {
		n++
		req := NewRequestWithValues(t, "POST", "/user/login", map[string]string{"user_name": name, "password": "wrong"})
		return MakeRequest(t, fromIP(req, fmt.Sprintf("198.51.100.%d", n)), NoExpectedStatus)
	}
	// failures until the first 429, at most 2*burst+2
	limitedAfter := func(names ...string) (int, *httptest.ResponseRecorder) {
		for i := range 2*burst + 2 {
			if r := signIn(names[i%len(names)]); r.Code == http.StatusTooManyRequests {
				return i, r
			}
		}
		return -1, nil
	}

	t.Run("email and username share one budget", func(t *testing.T) {
		single, _ := limitedAfter("user2")
		assert.Equal(t, burst, single)
		ratelimit.ResetForTest()
		alternating, _ := limitedAfter("user2", "user2@example.com")
		assert.Equal(t, single, alternating)
	})

	t.Run("unknown and known names get the same budget and 429 page", func(t *testing.T) {
		ratelimit.ResetForTest()
		known, knownResp := limitedAfter("user4")
		ratelimit.ResetForTest()
		unknown, unknownResp := limitedAfter("nobody")
		assert.Equal(t, burst, known)
		assert.Equal(t, burst, unknown)
		assert.Equal(t, knownResp.Code, unknownResp.Code)
		assert.Contains(t, knownResp.Body.String(), "You have sent too many requests")
		assert.Contains(t, unknownResp.Body.String(), "You have sent too many requests")
		// unknown names don't alias: an unknown email and username are limited separately
		ratelimit.ResetForTest()
		alternating, _ := limitedAfter("nobody", "nobody@example.com")
		assert.Equal(t, 2*burst, alternating)
	})

	t.Run("an unactivated email address doesn't share the budget of its owner", func(t *testing.T) {
		ratelimit.ResetForTest()
		alternating, _ := limitedAfter("user11", "user11@example.com")
		assert.Equal(t, 2*burst, alternating)
	})

	t.Run("a disabled account doesn't alias", func(t *testing.T) {
		_, err := db.GetEngine(t.Context()).ID(2).Cols("prohibit_login").Update(&user_model.User{ProhibitLogin: true})
		require.NoError(t, err)
		ratelimit.ResetForTest()
		alternating, _ := limitedAfter("user2", "user2@example.com")
		assert.Equal(t, 2*burst, alternating)
	})
}

func TestRateLimitSignInIPv6Aggregate(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.Auth: {AuthenticatedRate: slow, AuthenticatedBurst: 2},
	}, "")
	signIn := func(ip, name string, status int) {
		t.Helper()
		req := NewRequestWithValues(t, "POST", "/user/login", map[string]string{"user_name": name, "password": "wrong"})
		req.Request.RemoteAddr = "[" + ip + "]:1234"
		MakeRequest(t, req, status)
	}
	for i := range 20 { // 10x the burst, from different /64s and names
		signIn(fmt.Sprintf("2001:db8:1:%x::1", i), fmt.Sprint("name", i), http.StatusOK)
	}
	signIn("2001:db8:1:ff::1", "other", http.StatusTooManyRequests)
	signIn("2001:db8:2::1", "other", http.StatusOK)
}

// A trusted proxy that sends disagreeing X-Real-IP and X-Forwarded-For makes the client IP ambiguous: such requests
// share one bucket, whatever X-Real-IP the client chose, and are never exempt.
func TestRateLimitAmbiguousClientIP(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.Auth: {AuthenticatedRate: slow, AuthenticatedBurst: 2},
	}, "203.0.113.0/24")
	ambiguous := func(req *RequestWrapper, i int) *RequestWrapper {
		return fromIP(req, "127.0.0.1").
			SetHeader("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i)).
			SetHeader("X-Real-IP", fmt.Sprintf("203.0.113.%d", i))
	}
	for i := range 2 {
		req := NewRequestWithValues(t, "POST", "/user/login", map[string]string{"user_name": fmt.Sprint("name", i), "password": "wrong"})
		MakeRequest(t, ambiguous(req, i), http.StatusOK)
	}
	req := NewRequestWithValues(t, "POST", "/user/login", map[string]string{"user_name": "other", "password": "wrong"})
	MakeRequest(t, ambiguous(req, 9), http.StatusTooManyRequests)
	MakeRequest(t, ambiguous(NewRequest(t, "GET", "/api/v1/user").AddBasicAuth("user2"), 10), http.StatusTooManyRequests)
}

// Every request to a mail or account endpoint counts, from many /64s of one /48 as well: they share 10x the budget.
func TestRateLimitAuthIPEndpointsIPv6Aggregate(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.Auth: {AuthenticatedRate: slow, AuthenticatedBurst: 2},
	}, "2001:db8:1:ff::/64")
	post := func(path, ip string) *httptest.ResponseRecorder {
		t.Helper()
		// an unknown address, so that no MailResendLimit_<user> cache entry is left behind for later tests
		req := NewRequestWithValues(t, "POST", path, map[string]string{"email": "nobody@example.com"})
		req.Request.RemoteAddr = "[" + ip + "]:1234"
		return MakeRequest(t, req, NoExpectedStatus)
	}
	for _, path := range []string{"/user/sign_up", "/user/forgot_password", "/user/activate"} {
		t.Run(path, func(t *testing.T) {
			ratelimit.ResetForTest()
			for i := range 20 { // 10x the burst, each from its own /64
				assert.NotEqual(t, http.StatusTooManyRequests, post(path, fmt.Sprintf("2001:db8:1:%x::1", i)).Code)
			}
			resp := post(path, "2001:db8:1:ff::2") // exempt
			assert.NotEqual(t, http.StatusTooManyRequests, resp.Code)
			resp = post(path, "2001:db8:1:fe::1")
			assert.Equal(t, http.StatusTooManyRequests, resp.Code)
			assert.NotEmpty(t, resp.Header().Get("Retry-After"))
			assert.NotEqual(t, http.StatusTooManyRequests, post(path, "2001:db8:2::1").Code) // another /48
			// a single /64 still limits at the burst
			post(path, "2001:db8:3::1")
			post(path, "2001:db8:3::2")
			assert.Equal(t, http.StatusTooManyRequests, post(path, "2001:db8:3::3").Code)
		})
	}
}

func servCommand(t *testing.T, keyID int64, ip, verb string, mode int) (int, string) {
	t.Helper()
	path := fmt.Sprintf("/api/internal/serv/command/%d/user2/repo1?mode=%d&verb=%s&ip=%s", keyID, mode, verb, url.QueryEscape(ip))
	recorder := httptest.NewRecorder()
	routers.InternalRoutes().ServeHTTP(recorder, NewRequest(t, "GET", path).Request)
	return recorder.Code, recorder.Body.String()
}

// addUserKey adds a second key to user2, whose fixture key is the only usable one
func addUserKey(t *testing.T) {
	t.Helper()
	require.NoError(t, db.Insert(db.DefaultContext, &asymkey_model.PublicKey{
		ID: 901, OwnerID: 2, Name: "second", Fingerprint: "SHA256:second901", Content: "ssh-ed25519 AAAAsecond901",
		Mode: perm.AccessModeWrite, Type: asymkey_model.KeyTypeUser,
	}))
}

func sshClass(keyBurst, ipBurst int) map[string]setting.RateLimitClass {
	return map[string]setting.RateLimitClass{
		ratelimit.SSH: {AuthenticatedRate: slow, AuthenticatedBurst: keyBurst, AnonymousRate: slow, AnonymousBurst: ipBurst},
	}
}

// AC2, AC3: every verb that reaches serv is limited per key, other keys and IPs are not affected
func TestRateLimitServ(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	addUserKey(t)
	mockRateLimit(t, sshClass(2, 3), "192.0.2.0/24")

	verbs := map[string]int{"git-upload-pack": 1, "git-receive-pack": 2, "git-upload-archive": 1, "git-lfs-authenticate": 1, "git-lfs-transfer": 1}
	for verb, mode := range verbs {
		ratelimit.ResetForTest()
		for i := range 2 {
			code, _ := servCommand(t, 1, fmt.Sprintf("198.51.100.%d", i), verb, mode)
			assert.Equal(t, http.StatusOK, code, verb)
		}
		code, body := servCommand(t, 1, "198.51.100.9", verb, mode)
		assert.Equal(t, http.StatusTooManyRequests, code, verb)
		assert.Contains(t, body, "rate limit exceeded, retry in", verb)
	}

	ratelimit.ResetForTest()
	servCommand(t, 1, "198.51.100.1", "git-upload-pack", 1)
	servCommand(t, 1, "198.51.100.1", "git-upload-pack", 1)
	// another key from the same IP, and the same key limited from any IP
	code, _ := servCommand(t, 901, "198.51.100.1", "git-upload-pack", 1)
	assert.Equal(t, http.StatusOK, code)
	code, _ = servCommand(t, 1, "198.51.100.1", "git-upload-pack", 1)
	assert.Equal(t, http.StatusTooManyRequests, code)
	// the IP budget (3) is spent now, for keys that still have tokens, and other IPs are fine
	code, _ = servCommand(t, 901, "198.51.100.1", "git-upload-pack", 1)
	assert.Equal(t, http.StatusTooManyRequests, code)
	code, _ = servCommand(t, 901, "198.51.100.2", "git-upload-pack", 1)
	assert.Equal(t, http.StatusOK, code)

	// IPv6 addresses of one /64 share a bucket
	for i, ip := range []string{"2001:db8:1:1::1", "2001:db8:1:1::2", "2001:db8:1:1::3"} {
		code, _ = servCommand(t, int64(100+i), ip, "git-upload-pack", 1) // unknown keys are not found, but counted
		assert.NotEqual(t, http.StatusTooManyRequests, code)
	}
	code, _ = servCommand(t, 200, "2001:db8:1:1::4", "git-upload-pack", 1)
	assert.Equal(t, http.StatusTooManyRequests, code)

	// an IPv4-mapped address is the IPv4 address
	ratelimit.ResetForTest()
	for i, ip := range []string{"198.51.100.7", "::ffff:198.51.100.7", "198.51.100.7"} {
		code, _ = servCommand(t, int64(300+i), ip, "git-upload-pack", 1)
		assert.NotEqual(t, http.StatusTooManyRequests, code)
	}
	code, _ = servCommand(t, 303, "::ffff:198.51.100.7", "git-upload-pack", 1)
	assert.Equal(t, http.StatusTooManyRequests, code)

	// a zoned IPv6 address is the address without the zone, not an invalid one
	ratelimit.ResetForTest()
	for i, ip := range []string{"2001:db8:9::1%25eth0", "2001:db8:9::2", "2001:db8:9::3"} {
		code, _ = servCommand(t, int64(400+i), ip, "git-upload-pack", 1)
		assert.NotEqual(t, http.StatusTooManyRequests, code)
	}
	code, _ = servCommand(t, 403, "2001:db8:9::4%25eth1", "git-upload-pack", 1)
	assert.Equal(t, http.StatusTooManyRequests, code)

	// exempt IPs are never limited
	for range 6 {
		code, _ = servCommand(t, 1, "192.0.2.5", "git-upload-pack", 1)
		assert.Equal(t, http.StatusOK, code)
	}
}

// AC2: a missing or unparsable IP skips the IP budget (the IP allowlist refuses it when SSH is enforced), the key
// budget still applies
func TestRateLimitServNoIP(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	addUserKey(t)
	mockRateLimit(t, sshClass(2, 1), "")

	for _, ip := range []string{"", "garbage"} {
		ratelimit.ResetForTest()
		for range 2 {
			code, _ := servCommand(t, 1, ip, "git-upload-pack", 1)
			assert.Equal(t, http.StatusOK, code)
		}
		code, _ := servCommand(t, 1, ip, "git-upload-pack", 1)
		assert.Equal(t, http.StatusTooManyRequests, code)
		// the IP bucket (burst 1) was never touched
		code, _ = servCommand(t, 901, "198.51.100.1", "git-upload-pack", 1)
		assert.Equal(t, http.StatusOK, code)
	}
}

// AC4: a deploy key is limited by its own key, never as the repository owner; admins are exempt, deploy keys not
func TestRateLimitServDeployKeyAndAdmin(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	require.NoError(t, db.Insert(db.DefaultContext, &asymkey_model.PublicKey{
		ID: 900, Name: "dk", Fingerprint: "SHA256:deploykey900", Content: "ssh-ed25519 AAAAdeploy900",
		Mode: perm.AccessModeRead, Type: asymkey_model.KeyTypeDeploy,
	}))
	require.NoError(t, db.Insert(db.DefaultContext, &asymkey_model.DeployKey{KeyID: 900, RepoID: 1, Name: "dk", Mode: perm.AccessModeRead}))
	mockRateLimit(t, sshClass(2, 100), "")

	for range 2 {
		code, body := servCommand(t, 900, "198.51.100.1", "git-upload-pack", 1)
		assert.Equal(t, http.StatusOK, code)
		assert.Contains(t, body, `"DeployKeyKeyID"`)
	}
	code, _ := servCommand(t, 900, "198.51.100.1", "git-upload-pack", 1)
	assert.Equal(t, http.StatusTooManyRequests, code)
	// the owner's own key has its own budget
	code, _ = servCommand(t, 1, "198.51.100.1", "git-upload-pack", 1)
	assert.Equal(t, http.StatusOK, code)

	// ExemptAdmins applies to the keys of an admin, not to deploy keys
	ratelimit.ResetForTest()
	t.Cleanup(test.MockVariableValue(&setting.RateLimit.ExemptAdmins, true))
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	user.IsAdmin = true
	require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, user, "is_admin"))
	for range 5 {
		code, _ = servCommand(t, 1, "198.51.100.1", "git-upload-pack", 1)
		assert.Equal(t, http.StatusOK, code)
	}
	servCommand(t, 900, "198.51.100.1", "git-upload-pack", 1)
	servCommand(t, 900, "198.51.100.1", "git-upload-pack", 1)
	code, _ = servCommand(t, 900, "198.51.100.1", "git-upload-pack", 1)
	assert.Equal(t, http.StatusTooManyRequests, code)
}

func TestRateLimitServDisabled(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ratelimit.ResetForTest()
	for range 5 {
		code, _ := servCommand(t, 1, "198.51.100.1", "git-upload-pack", 1)
		assert.Equal(t, http.StatusOK, code)
	}
	// enabled, but the class is off
	mockRateLimit(t, sshClass(0, 0), "")
	for range 5 {
		code, _ := servCommand(t, 1, "198.51.100.1", "git-upload-pack", 1)
		assert.Equal(t, http.StatusOK, code)
	}
}

// heavyRoutes are the web and API routes of the heavy class; each takes a request from a signed-out client.
var heavyRoutes = []struct{ path, contentType string }{
	{"/user2/repo1/search?q=Description", "text/html"},
	{"/user2/repo1/blame/branch/master/README.md", "text/html"},
	{"/user2/repo1/commit/65f1bf27bc3bf70f64657658635e66094edbcb4d", "text/html"},
	{"/user2/repo1/commit/65f1bf27bc3bf70f64657658635e66094edbcb4d.diff", "text/plain"},
	{"/user2/repo1/compare/master...master", "text/html"},
	{"/user2/repo1/pulls/2.patch", "text/plain"},
	{"/user2/commitsonpr/pulls/1/files", "text/html"},
	{"/user2/commitsonpr/pulls/1/commits/c5626fc9eff57eb1bb7b796b01d4d0f2f3f792a2", "text/html"},
	{"/user2/repo1/blob_excerpt/65f1bf27bc3bf70f64657658635e66094edbcb4d?last_left=0&last_right=0&left=1&right=1&left_hunk_size=1&right_hunk_size=1&path=README.md&filelang=&data_query=", "text/plain"},
	{"/user2/repo1/commit/65f1bf27bc3bf70f64657658635e66094edbcb4d/load-branches-and-tags", "text/plain"},
	{"/api/v1/repos/user2/repo1/search/code?q=Description", "application/json"},
	{"/api/v1/repos/user2/repo1/compare/master...master", "application/json"},
	{"/api/v1/repos/user2/repo1/git/commits/65f1bf27bc3bf70f64657658635e66094edbcb4d.diff", "application/json"},
	{"/api/v1/repos/user2/repo1/pulls/2.diff", "application/json"},
}

func TestRateLimitHeavy(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.Heavy: {AuthenticatedRate: slow, AuthenticatedBurst: 3, AnonymousRate: slow, AnonymousBurst: 2},
		ratelimit.Web:   {AuthenticatedRate: slow, AuthenticatedBurst: 100, AnonymousRate: slow, AnonymousBurst: 100},
		ratelimit.API:   {AuthenticatedRate: slow, AuthenticatedBurst: 100, AnonymousRate: slow, AnonymousBurst: 100},
	}, "192.0.2.0/24")

	t.Run("heavy routes are limited, in the shape of their group", func(t *testing.T) {
		for i, route := range heavyRoutes {
			ip := fmt.Sprintf("198.51.100.%d", i+1)
			for range 2 {
				resp := MakeRequest(t, fromIP(NewRequest(t, "GET", route.path), ip), NoExpectedStatus)
				assert.NotEqual(t, http.StatusTooManyRequests, resp.Code, route.path)
				assert.Equal(t, "2", resp.Header().Get("X-RateLimit-Limit"), route.path)
			}
			resp := MakeRequest(t, fromIP(NewRequest(t, "GET", route.path), ip), http.StatusTooManyRequests)
			assert.NotEmpty(t, resp.Header().Get("Retry-After"), route.path)
			assert.Equal(t, "0", resp.Header().Get("X-RateLimit-Remaining"), route.path)
			assert.Contains(t, resp.Header().Get("Content-Type"), route.contentType, route.path)
		}
	})

	t.Run("normal browsing never draws on the heavy budget", func(t *testing.T) {
		// 198.51.100.1 exhausted its anonymous heavy bucket above
		for _, path := range []string{"/user2/repo1", "/user2/repo1/src/branch/master/README.md", "/user2/repo1/issues", "/user2/repo1/pulls", "/user2/repo1/pulls/2", "/api/v1/repos/user2/repo1", "/api/v1/version"} {
			for range 4 {
				resp := MakeRequest(t, fromIP(NewRequest(t, "GET", path), "198.51.100.1"), NoExpectedStatus)
				assert.NotEqual(t, http.StatusTooManyRequests, resp.Code, path)
				assert.Equal(t, "100", resp.Header().Get("X-RateLimit-Limit"), path)
			}
		}
	})

	t.Run("signed in users have their own budget", func(t *testing.T) {
		session := loginUser(t, "user2")
		for range 3 {
			resp := session.MakeRequest(t, fromIP(NewRequest(t, "GET", "/user2/repo1/commit/65f1bf27bc3bf70f64657658635e66094edbcb4d.diff"), "198.51.100.1"), NoExpectedStatus)
			assert.NotEqual(t, http.StatusTooManyRequests, resp.Code)
		}
		session.MakeRequest(t, fromIP(NewRequest(t, "GET", "/user2/repo1/commit/65f1bf27bc3bf70f64657658635e66094edbcb4d.diff"), "198.51.100.1"), http.StatusTooManyRequests)

		token := getUserToken(t, "user2", auth_model.AccessTokenScopeAll)
		// the token is the same user: it shares the exhausted budget
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/repos/user2/repo1/git/commits/65f1bf27bc3bf70f64657658635e66094edbcb4d.diff"), "198.51.100.2").AddTokenAuth(token), http.StatusTooManyRequests)
	})

	t.Run("exempt addresses are not limited", func(t *testing.T) {
		for range 5 {
			resp := MakeRequest(t, fromIP(NewRequest(t, "GET", "/user2/repo1/commit/65f1bf27bc3bf70f64657658635e66094edbcb4d.diff"), "192.0.2.9"), NoExpectedStatus)
			assert.NotEqual(t, http.StatusTooManyRequests, resp.Code)
			assert.Empty(t, resp.Header().Get("X-RateLimit-Limit"))
		}
	})

	t.Run("a heavy request also takes a token of the group class", func(t *testing.T) {
		resp := MakeRequest(t, fromIP(NewRequest(t, "GET", "/user2/repo1/blame/branch/master/README.md"), "198.51.100.150"), http.StatusOK)
		assert.Equal(t, "2", resp.Header().Get("X-RateLimit-Limit"))
		assert.Equal(t, 98, ratelimit.Check(ratelimit.Web, "198.51.100.150:1", ratelimit.IPKey("198.51.100.150:1"), false).Remaining)
	})

	t.Run("diff XHR gets the plain 429", func(t *testing.T) {
		const path = "/user2/commitsonpr/pulls/1/files?file-only=true&files=test1.txt"
		for range 2 {
			MakeRequest(t, fromIP(NewRequest(t, "GET", path), "198.51.100.152"), http.StatusOK)
		}
		resp := MakeRequest(t, fromIP(NewRequest(t, "GET", path), "198.51.100.152"), http.StatusTooManyRequests)
		assert.Contains(t, resp.Header().Get("Content-Type"), "text/plain")
	})

	t.Run("a commit page view costs two heavy tokens", func(t *testing.T) {
		const ip = "198.51.100.151"
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/user2/repo1/commit/65f1bf27bc3bf70f64657658635e66094edbcb4d"), ip), http.StatusOK)
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/user2/repo1/commit/65f1bf27bc3bf70f64657658635e66094edbcb4d/load-branches-and-tags"), ip), http.StatusOK)
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/user2/repo1/commit/65f1bf27bc3bf70f64657658635e66094edbcb4d/load-branches-and-tags"), ip), http.StatusTooManyRequests)
	})
}

func TestRateLimitHeavyOff(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.Heavy: {AuthenticatedRate: 0, AuthenticatedBurst: 1, AnonymousRate: 0, AnonymousBurst: 1},
		ratelimit.Web:   {AuthenticatedRate: slow, AuthenticatedBurst: 100, AnonymousRate: slow, AnonymousBurst: 100},
		ratelimit.API:   {AuthenticatedRate: slow, AuthenticatedBurst: 100, AnonymousRate: slow, AnonymousBurst: 100},
	}, "")

	for _, route := range heavyRoutes {
		for range 5 {
			resp := MakeRequest(t, fromIP(NewRequest(t, "GET", route.path), "198.51.100.1"), NoExpectedStatus)
			assert.NotEqual(t, http.StatusTooManyRequests, resp.Code, route.path)
			assert.Equal(t, "100", resp.Header().Get("X-RateLimit-Limit"), route.path)
		}
	}
}

func TestRateLimitHeavyArchive(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	mockRateLimit(t, map[string]setting.RateLimitClass{
		ratelimit.Heavy: {AuthenticatedRate: slow, AuthenticatedBurst: 2, AnonymousRate: slow, AnonymousBurst: 2},
	}, "")
	forget := func() { require.NoError(t, db.TruncateBeans(db.DefaultContext, &repo_model.RepoArchiver{})) }
	remaining := func(ip string) int {
		return ratelimit.Check(ratelimit.Heavy, ip+":1", ratelimit.IPKey(ip+":1"), false).Remaining
	}
	forget()

	t.Run("a full download cycle costs one token", func(t *testing.T) {
		const ip = "198.51.100.10"
		for i := 0; ; i++ {
			require.Less(t, i, 100)
			resp := MakeRequest(t, fromIP(NewRequest(t, "POST", "/user2/repo1/archive/master.zip"), ip), http.StatusOK)
			var done struct{ Complete bool }
			DecodeJSON(t, resp, &done)
			if done.Complete {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/user2/repo1/archive/master.zip"), ip), http.StatusOK)
		// 2 tokens, 1 for the build, 1 for this check
		assert.Equal(t, 0, remaining(ip))
	})

	t.Run("a ready archive is free", func(t *testing.T) {
		for range 5 {
			MakeRequest(t, fromIP(NewRequest(t, "GET", "/user2/repo1/archive/master.zip"), "198.51.100.11"), http.StatusOK)
			MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/repos/user2/repo1/archive/master.zip"), "198.51.100.11"), http.StatusOK)
		}
		assert.Equal(t, 1, remaining("198.51.100.11"))
	})

	t.Run("a generating archive is not charged", func(t *testing.T) {
		forget()
		const ip = "198.51.100.14"
		require.NoError(t, db.Insert(db.DefaultContext, &repo_model.RepoArchiver{RepoID: 1, Type: git.ZIP, Status: repo_model.ArchiverGenerating, CommitID: "65f1bf27bc3bf70f64657658635e66094edbcb4d"}))
		for range 5 {
			MakeRequest(t, fromIP(NewRequest(t, "POST", "/user2/repo1/archive/master.zip"), ip), http.StatusOK)
		}
		assert.Equal(t, 1, remaining(ip))
	})

	t.Run("builds are limited", func(t *testing.T) {
		for i, path := range []string{"/user2/repo1/archive/master.zip", "/api/v1/repos/user2/repo1/archive/master.zip", "/api/v1/repos/user2/repo1/zipball/master"} {
			ip := fmt.Sprintf("198.51.100.%d", 20+i)
			for range 2 {
				forget()
				MakeRequest(t, fromIP(NewRequest(t, "GET", path), ip), http.StatusOK)
			}
			forget()
			resp := MakeRequest(t, fromIP(NewRequest(t, "GET", path), ip), http.StatusTooManyRequests)
			assert.NotEmpty(t, resp.Header().Get("Retry-After"), path)
		}
	})
}
