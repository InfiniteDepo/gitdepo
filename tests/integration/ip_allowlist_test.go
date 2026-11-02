// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	"forgejo.org/modules/git"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	ipallowlist_service "forgejo.org/services/ipallowlist"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	ipBlocked = "198.51.100.7"
	ipAllowed = "10.1.2.3"
)

// setIPAllowlist enforces 10.0.0.0/8 on every surface, changed by edit, and returns a function that turns it off
func setIPAllowlist(t *testing.T, edit func(*setting.IPAllowlistState)) func() {
	t.Helper()
	s := setting.IPAllowlistState{
		Enabled: true, Web: true, API: true, Git: true, SSH: true, Packages: true, ExemptAdmins: true,
		Entries: []setting.IPAllowlistEntry{{CIDR: netip.MustParsePrefix("10.0.0.0/8"), Description: "corporate"}},
	}
	if edit != nil {
		edit(&s)
	}
	require.NoError(t, ipallowlist_service.Set(db.DefaultContext, nil, s))
	return func() { ipAllowlistOff(t) }
}

func ipAllowlistOff(t *testing.T) {
	t.Helper()
	require.NoError(t, ipallowlist_service.Set(db.DefaultContext, nil, setting.IPAllowlistState{ExemptAdmins: true}))
}

// from makes the request come from ip, as a direct TCP peer
func from(ip string, rw *RequestWrapper) *RequestWrapper {
	rw.RemoteAddr = net.JoinHostPort(ip, "1234")
	return rw
}

func ipRefusal(ip string) string {
	return "access from " + ip + " is not allowed by the IP allowlist"
}

func tokenID(t *testing.T, token string) int64 {
	t.Helper()
	tok, err := auth_model.GetAccessTokenBySHA(db.DefaultContext, token)
	require.NoError(t, err)
	return tok.ID
}

// AC1: a site admin edits the entries and settings on the admin page; non-admins get 403 on the page and the API
func TestIPAllowlistAdminPage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer ipAllowlistOff(t)
	user2 := loginUser(t, "user2")
	user2Token := getTokenForLoggedInUser(t, user2, auth_model.AccessTokenScopeWriteAdmin)
	user2.MakeRequest(t, NewRequest(t, "GET", "/admin/ip-allowlist"), http.StatusForbidden)
	user2.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/ip-allowlist", map[string]string{"enabled": "on"}), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/ip-allowlist").AddTokenAuth(user2Token), http.StatusForbidden)
	assert.True(t, setting.GetIPAllowlist(db.DefaultContext).ExemptAdmins, "admins are exempt by default")

	admin := loginUser(t, "user1")
	resp := admin.MakeRequest(t, from(ipAllowed, NewRequest(t, "GET", "/admin/ip-allowlist")), http.StatusOK)
	assert.Contains(t, resp.Body.String(), "Your current IP: "+ipAllowed)
	NewHTMLParser(t, resp.Body).AssertElement(t, "input[name=exempt_admins][checked]", true)

	save := func(entries string) {
		t.Helper()
		admin.MakeRequest(t, from(ipAllowed, NewRequestWithValues(t, "POST", "/admin/ip-allowlist", map[string]string{
			"enabled": "on", "git": "on", "api": "on", "exempt_admins": "on", "entries": entries, "exempt_users": "user4", "exempt_tokens": "",
		})), http.StatusSeeOther)
	}
	save("10.0.0.0/8 corporate\n2001:db8::1/32  VPN egress\n")
	s := setting.GetIPAllowlist(db.DefaultContext)
	assert.True(t, s.Enabled && s.Git && s.API && s.ExemptAdmins)
	assert.False(t, s.Web || s.SSH || s.Packages)
	assert.Equal(t, []int64{4}, s.ExemptUserIDs)
	require.Len(t, s.Entries, 2)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), s.Entries[0].CIDR)
	assert.Equal(t, "corporate", s.Entries[0].Description)
	assert.Equal(t, netip.MustParsePrefix("2001:db8::/32"), s.Entries[1].CIDR)
	assert.Equal(t, "VPN egress", s.Entries[1].Description)
	assert.EqualValues(t, 1, s.Entries[1].CreatedByID)
	assert.NotZero(t, s.Entries[1].CreatedUnix)

	created := s.Entries[0].CreatedUnix
	save("10.0.0.0/8 corporate")
	s = setting.GetIPAllowlist(db.DefaultContext)
	require.Len(t, s.Entries, 1)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), s.Entries[0].CIDR)
	assert.Equal(t, created, s.Entries[0].CreatedUnix)

	// an invalid CIDR is refused and changes nothing
	admin.MakeRequest(t, from(ipAllowed, NewRequestWithValues(t, "POST", "/admin/ip-allowlist", map[string]string{"enabled": "on", "entries": "10.0.0.0/33 nope"})), http.StatusSeeOther)
	assert.Len(t, setting.GetIPAllowlist(db.DefaultContext).Entries, 1)
	assert.True(t, setting.GetIPAllowlist(db.DefaultContext).Git)
}

// AC2: with the list off or empty nothing changes, also for clients with an unknown address
func TestIPAllowlistOff(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	check := func() {
		t.Helper()
		for _, ip := range []string{ipBlocked, ""} {
			rw := func(rw *RequestWrapper) *RequestWrapper {
				if ip != "" {
					return from(ip, rw)
				}
				return rw
			}
			MakeRequest(t, rw(NewRequest(t, "GET", "/user2/repo1")), http.StatusOK)
			MakeRequest(t, rw(NewRequest(t, "GET", "/api/v1/repos/user2/repo1")), http.StatusOK)
			MakeRequest(t, rw(NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack")).AddBasicAuth("user2"), http.StatusOK)
		}
	}
	check()
	defer setIPAllowlist(t, func(s *setting.IPAllowlistState) { s.Enabled = false })()
	check()
	setIPAllowlist(t, func(s *setting.IPAllowlistState) { s.Entries = nil })
	check()
}

// AC3: exempt users and tokens work from a blocked IP; admins only while "exempt admins" is on
func TestIPAllowlistExemptions(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	user2Token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeReadRepository)
	user2Other := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeReadRepository)
	adminToken := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeReadRepository)
	get := func(token string, status int) {
		t.Helper()
		MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/api/v1/repos/user2/repo1")).AddTokenAuth(token), status)
	}
	defer setIPAllowlist(t, nil)()
	get(user2Token, http.StatusForbidden)
	get(adminToken, http.StatusOK)

	setIPAllowlist(t, func(s *setting.IPAllowlistState) { s.ExemptUserIDs = []int64{2} })
	get(user2Token, http.StatusOK)
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack")).AddBasicAuth("user2"), http.StatusOK)

	setIPAllowlist(t, func(s *setting.IPAllowlistState) {
		s.ExemptTokens = []setting.IPAllowlistToken{{ID: tokenID(t, user2Token)}}
	})
	assert.Equal(t, []setting.IPAllowlistToken{{ID: tokenID(t, user2Token), UID: 2}}, setting.GetIPAllowlist(db.DefaultContext).ExemptTokens)
	get(user2Token, http.StatusOK)
	req := from(ipBlocked, NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack"))
	req.SetBasicAuth("user2", user2Token)
	MakeRequest(t, req, http.StatusOK)
	get(user2Other, http.StatusForbidden)
	// the password isn't the token
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack")).AddBasicAuth("user2"), http.StatusForbidden)

	// a listed token that changed owner isn't silently moved to the new owner
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE access_token SET uid = 4 WHERE id = ?", tokenID(t, user2Token))
	require.NoError(t, err)
	err = ipallowlist_service.Set(db.DefaultContext, nil, setting.GetIPAllowlist(db.DefaultContext))
	require.ErrorContains(t, err, "now belongs to another user")
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE access_token SET uid = 2 WHERE id = ?", tokenID(t, user2Token))
	require.NoError(t, err)

	setIPAllowlist(t, func(s *setting.IPAllowlistState) { s.ExemptAdmins = false })
	get(adminToken, http.StatusForbidden)

	// exemptions must exist
	err = ipallowlist_service.Set(db.DefaultContext, nil, setting.IPAllowlistState{ExemptUserIDs: []int64{99999}})
	require.Error(t, err)
	err = ipallowlist_service.Set(db.DefaultContext, nil, setting.IPAllowlistState{ExemptTokens: []setting.IPAllowlistToken{{ID: 99999}}})
	require.Error(t, err)
}

// AC4: each enforced surface refuses blocked IPs with its own message, allows listed IPs, and a surface that is off
// isn't enforced
func TestIPAllowlistEnforcement(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	user2 := loginUser(t, "user2")
	user2Token := getTokenForLoggedInUser(t, user2, auth_model.AccessTokenScopeReadRepository)
	defer setIPAllowlist(t, nil)()

	// web
	resp := MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1")), http.StatusForbidden)
	assert.Contains(t, resp.Body.String(), "Access is only allowed from approved networks. Your IP: "+ipBlocked)
	user2.MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1")), http.StatusForbidden)
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/no/such/page")), http.StatusForbidden)
	MakeRequest(t, from(ipAllowed, NewRequest(t, "GET", "/user2/repo1")), http.StatusOK)
	user2.MakeRequest(t, from("::ffff:"+ipAllowed, NewRequest(t, "GET", "/user2/repo1")), http.StatusOK)
	// the sign-in pages stay reachable, so exempt users can sign in
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user/login")), http.StatusOK)

	// API
	resp = MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/api/v1/repos/user2/repo1")).AddTokenAuth(user2Token), http.StatusForbidden)
	assert.JSONEq(t, `{"message":"IP address not allowed","ip":"`+ipBlocked+`"}`, resp.Body.String())
	MakeRequest(t, from(ipAllowed, NewRequest(t, "GET", "/api/v1/repos/user2/repo1")).AddTokenAuth(user2Token), http.StatusOK)
	// the check runs before sudo: a non-exempt admin can't pass as an exempt user
	adminToken := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeReadRepository)
	setIPAllowlist(t, func(s *setting.IPAllowlistState) { s.ExemptAdmins, s.ExemptUserIDs = false, []int64{2} })
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/api/v1/repos/user2/repo1?sudo=user2")).AddTokenAuth(adminToken), http.StatusForbidden)
	setIPAllowlist(t, nil)

	// git over HTTPS and LFS
	resp = MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack")).AddBasicAuth("user2"), http.StatusForbidden)
	assert.Equal(t, ipRefusal(ipBlocked), strings.TrimSpace(resp.Body.String()))
	MakeRequest(t, from(ipAllowed, NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack")).AddBasicAuth("user2"), http.StatusOK)
	req := NewRequestWithJSON(t, "POST", "/user2/repo1.git/info/lfs/objects/batch", map[string]any{"operation": "download"}).AddBasicAuth("user2")
	req.Header.Set("Accept", "application/vnd.git-lfs+json")
	MakeRequest(t, from(ipBlocked, req), http.StatusForbidden)

	// packages
	resp = MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/api/packages/user2/generic/ipallow/1.0/file.txt")).AddBasicAuth("user2"), http.StatusForbidden)
	assert.Equal(t, ipRefusal(ipBlocked), strings.TrimSpace(resp.Body.String()))
	MakeRequest(t, from(ipAllowed, NewRequest(t, "GET", "/api/packages/user2/generic/ipallow/1.0/file.txt")).AddBasicAuth("user2"), http.StatusNotFound)

	// surfaces that are off aren't enforced: git and API on, the web UI off
	setIPAllowlist(t, func(s *setting.IPAllowlistState) { s.Web, s.Packages = false, false })
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user/login")), http.StatusOK)
	user2.MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1")), http.StatusOK)
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/api/packages/user2/generic/ipallow/1.0/file.txt")).AddBasicAuth("user2"), http.StatusNotFound)
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/api/v1/repos/user2/repo1")).AddTokenAuth(user2Token), http.StatusForbidden)
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack")).AddBasicAuth("user2"), http.StatusForbidden)
	// mixed routes: a token is checked as the API, a session as the web UI
	resp = MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1/archive/master.zip")).AddTokenAuth(user2Token), http.StatusForbidden)
	assert.JSONEq(t, `{"message":"IP address not allowed","ip":"`+ipBlocked+`"}`, resp.Body.String())
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1/raw/branch/master/README.md")).AddTokenAuth(user2Token), http.StatusForbidden)
	user2.MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1/raw/branch/master/README.md")), http.StatusOK)
}

// AC4, AC12: git over HTTPS with a real client, through the trusted local proxy address, and SSH at serv level
func TestIPAllowlistGitAndSSH(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		u.Path = "user2/repo1.git"
		u.User = url.UserPassword("user2", userPassword)
		defer setIPAllowlist(t, nil)()

		clone := func(ip string) (string, error) {
			_, stderr, err := git.NewCommand(git.DefaultContext, "-c").AddDynamicArguments("http.extraHeader=X-Forwarded-For: "+ip).
				AddArguments("clone").AddDynamicArguments(u.String(), t.TempDir()).RunStdString(&git.RunOpts{})
			return stderr, err
		}
		stderr, err := clone(ipBlocked)
		require.Error(t, err)
		assert.Contains(t, stderr, "remote: "+ipRefusal(ipBlocked))
		_, err = clone(ipAllowed)
		require.NoError(t, err)

		// AC5: internal calls (on their own listener) are never blocked
		_, _, err = private.ServNoCommand(t.Context(), 1)
		require.NoError(t, err)

		// SSH: serv refuses blocked and unknown client addresses, with the message git shows on stderr
		_, extra := private.ServCommand(t.Context(), 1, "user2", "repo1", perm.AccessModeRead, ipBlocked, "git-upload-pack")
		assert.Equal(t, ipRefusal(ipBlocked), extra.UserMsg)
		_, extra = private.ServCommand(t.Context(), 1, "user2", "repo1", perm.AccessModeRead, "", "git-upload-pack")
		assert.Equal(t, ipRefusal("unknown"), extra.UserMsg)
		_, extra = private.ServCommand(t.Context(), 1, "user2", "repo1", perm.AccessModeRead, "not an ip&mode=4", "git-upload-pack")
		assert.Equal(t, ipRefusal("unknown"), extra.UserMsg)
		_, extra = private.ServCommand(t.Context(), 1, "user2", "repo1", perm.AccessModeRead, ipAllowed, "git-upload-pack")
		require.NoError(t, extra.Error)

		// exempt users pass, and SSH that is off isn't enforced
		setIPAllowlist(t, func(s *setting.IPAllowlistState) { s.ExemptUserIDs = []int64{2} })
		_, extra = private.ServCommand(t.Context(), 1, "user2", "repo1", perm.AccessModeRead, ipBlocked, "git-upload-pack")
		require.NoError(t, extra.Error)
		setIPAllowlist(t, func(s *setting.IPAllowlistState) { s.SSH = false })
		_, extra = private.ServCommand(t.Context(), 1, "user2", "repo1", perm.AccessModeRead, "", "git-upload-pack")
		require.NoError(t, extra.Error)
	})
}

// AC5: health checks and assets are never blocked; internal calls are, in TestIPAllowlistGitAndSSH
func TestIPAllowlistNeverBlocked(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer setIPAllowlist(t, nil)()
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/api/healthz")), http.StatusOK)
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/assets/img/logo.svg")), http.StatusOK)
	// /metrics sits next to /api/healthz, outside every group that checks the list
	if setting.Metrics.Enabled {
		MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/metrics")), NoExpectedStatus)
	}
}

// AC7: the address comes from X-Forwarded-For only through a trusted proxy (the untrusted case is also covered by
// TestClientIPFromTrustedProxyOnly in routers/common)
func TestIPAllowlistClientIP(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer setIPAllowlist(t, nil)()
	resp := MakeRequest(t, from("127.0.0.1", NewRequest(t, "GET", "/user2/repo1")).SetHeader("X-Forwarded-For", ipBlocked), http.StatusForbidden)
	assert.Contains(t, resp.Body.String(), "Your IP: "+ipBlocked)
	MakeRequest(t, from("127.0.0.1", NewRequest(t, "GET", "/user2/repo1")).SetHeader("X-Forwarded-For", ipAllowed), http.StatusOK)
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1")).SetHeader("X-Forwarded-For", ipAllowed), http.StatusForbidden)
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1")).SetHeader("X-Real-IP", ipAllowed), http.StatusForbidden)
	MakeRequest(t, from("127.0.0.1", NewRequest(t, "GET", "/user2/repo1")).SetHeader("X-Forwarded-For", ipBlocked).SetHeader("X-Real-IP", ipAllowed), http.StatusForbidden)
}

// AC8: the admin page shows the current IP and warns before locking it out; the API refuses that unless force=true
func TestIPAllowlistSelfLockout(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer ipAllowlistOff(t)
	admin := loginUser(t, "user1")
	token := getTokenForLoggedInUser(t, admin, auth_model.AccessTokenScopeWriteAdmin)
	form := map[string]string{"enabled": "on", "web": "on", "exempt_admins": "on", "entries": "10.0.0.0/8 corporate"}

	resp := admin.MakeRequest(t, from(ipBlocked, NewRequestWithValues(t, "POST", "/admin/ip-allowlist", form)), http.StatusOK)
	htmlDoc := NewHTMLParser(t, resp.Body)
	assert.Contains(t, htmlDoc.Find(".admin-setting-content .warning.message").Text(), ipBlocked)
	htmlDoc.AssertElement(t, "input[name=force]", true)
	assert.False(t, setting.GetIPAllowlist(db.DefaultContext).Enabled)
	form["force"] = "on"
	admin.MakeRequest(t, from(ipBlocked, NewRequestWithValues(t, "POST", "/admin/ip-allowlist", form)), http.StatusSeeOther)
	assert.True(t, setting.GetIPAllowlist(db.DefaultContext).Enabled)
	ipAllowlistOff(t)

	opt := &api.EditIPAllowlistOption{Enabled: true, Surfaces: api.IPAllowlistSurfaces{API: true}, Entries: []api.IPAllowlistEntry{{CIDR: "10.0.0.0/8"}}}
	resp = MakeRequest(t, from(ipBlocked, NewRequestWithJSON(t, "PUT", "/api/v1/admin/ip-allowlist", opt)).AddTokenAuth(token), http.StatusConflict)
	assert.Contains(t, resp.Body.String(), ipBlocked)
	assert.False(t, setting.GetIPAllowlist(db.DefaultContext).Enabled)
	MakeRequest(t, from(ipBlocked, NewRequestWithJSON(t, "PUT", "/api/v1/admin/ip-allowlist?force=true", opt)).AddTokenAuth(token), http.StatusOK)
	assert.True(t, setting.GetIPAllowlist(db.DefaultContext).Enabled)
	MakeRequest(t, from(ipAllowed, NewRequestWithJSON(t, "PUT", "/api/v1/admin/ip-allowlist", opt)).AddTokenAuth(token), http.StatusOK)
}

// AC9: [ip_allowlist] ENABLED = false wins over the database
func TestIPAllowlistConfigOverride(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	token := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeWriteAdmin)
	defer setIPAllowlist(t, nil)()
	defer test.MockVariableValue(&setting.IPAllowlist.Enabled, optional.Some(false))()

	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1")), http.StatusOK)
	var a api.IPAllowlist
	DecodeJSON(t, MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/api/v1/admin/ip-allowlist")).AddTokenAuth(token), http.StatusOK), &a)
	assert.True(t, a.FromConfig)
	assert.False(t, a.Enabled)
	MakeRequest(t, from(ipAllowed, NewRequestWithJSON(t, "PUT", "/api/v1/admin/ip-allowlist", &api.EditIPAllowlistOption{})).AddTokenAuth(token), http.StatusUnprocessableEntity)
}

// AC10: the CLI works on the database without the web server, and disable restores access
func TestIPAllowlistCLI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer ipAllowlistOff(t)
	_, err := runMainApp("admin", "ip-allowlist", "add", "--cidr", "10.0.0.0/8", "--description", "corporate")
	require.NoError(t, err)
	_, err = runMainApp("admin", "ip-allowlist", "add", "--cidr", "2001:db8::/32")
	require.NoError(t, err)
	_, err = runMainApp("admin", "ip-allowlist", "add", "--cidr", "nope")
	require.Error(t, err)
	out, err := runMainApp("admin", "ip-allowlist", "list")
	require.NoError(t, err)
	assert.Contains(t, out, "10.0.0.0/8\tcorporate")
	assert.Contains(t, out, "2001:db8::/32")
	_, err = runMainApp("admin", "ip-allowlist", "remove", "--cidr", "2001:db8::/32")
	require.NoError(t, err)
	config.GetDynGetter().InvalidateCache()
	s := setting.GetIPAllowlist(db.DefaultContext)
	require.Len(t, s.Entries, 1)
	assert.Equal(t, "corporate", s.Entries[0].Description)

	s.Enabled, s.Web = true, true
	require.NoError(t, ipallowlist_service.Set(db.DefaultContext, nil, s))
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1")), http.StatusForbidden)
	_, err = runMainApp("admin", "ip-allowlist", "disable")
	require.NoError(t, err)
	config.GetDynGetter().InvalidateCache()
	MakeRequest(t, from(ipBlocked, NewRequest(t, "GET", "/user2/repo1")), http.StatusOK)
	assert.Len(t, setting.GetIPAllowlist(db.DefaultContext).Entries, 1)
}

// AC11: GET/PUT /admin/ip-allowlist for site admins with the admin scope, with validation
func TestAPIIPAllowlist(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer ipAllowlistOff(t)
	session := loginUser(t, "user1")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteAdmin)
	readToken := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadAdmin)
	user2Token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeReadRepository)
	put := func(token string, opt *api.EditIPAllowlistOption, status int) {
		t.Helper()
		MakeRequest(t, from(ipAllowed, NewRequestWithJSON(t, "PUT", "/api/v1/admin/ip-allowlist", opt)).AddTokenAuth(token), status)
	}

	var a api.IPAllowlist
	DecodeJSON(t, MakeRequest(t, from(ipAllowed, NewRequest(t, "GET", "/api/v1/admin/ip-allowlist")).AddTokenAuth(readToken), http.StatusOK), &a)
	assert.True(t, a.ExemptAdmins)
	assert.Equal(t, ipAllowed, a.YourIP)

	opt := &api.EditIPAllowlistOption{
		Enabled: true, Surfaces: api.IPAllowlistSurfaces{Git: true, SSH: true},
		Entries:        []api.IPAllowlistEntry{{CIDR: "10.0.0.1/8", Description: "corporate"}, {CIDR: "2001:db8::/32"}},
		ExemptUserIDs:  []int64{4},
		ExemptTokenIDs: []int64{tokenID(t, user2Token)},
	}
	put(readToken, opt, http.StatusForbidden)
	put(user2Token, opt, http.StatusForbidden)
	put(token, opt, http.StatusOK)
	DecodeJSON(t, MakeRequest(t, from(ipAllowed, NewRequest(t, "GET", "/api/v1/admin/ip-allowlist")).AddTokenAuth(readToken), http.StatusOK), &a)
	assert.True(t, a.Enabled)
	assert.Equal(t, api.IPAllowlistSurfaces{Git: true, SSH: true}, a.Surfaces)
	assert.True(t, a.ExemptAdmins, "omitted exempt_admins keeps the default")
	require.Len(t, a.Entries, 2)
	assert.Equal(t, "10.0.0.0/8", a.Entries[0].CIDR)
	assert.Equal(t, "corporate", a.Entries[0].Description)
	assert.Equal(t, []int64{4}, a.ExemptUserIDs)
	assert.Equal(t, []*api.IPAllowlistToken{{ID: tokenID(t, user2Token), UserID: 2}}, a.ExemptTokens)

	no := false
	opt.ExemptAdmins = &no
	put(token, opt, http.StatusOK)
	assert.False(t, setting.GetIPAllowlist(db.DefaultContext).ExemptAdmins)

	for name, edit := range map[string]func(o *api.EditIPAllowlistOption){
		"invalid CIDR":     func(o *api.EditIPAllowlistOption) { o.Entries = []api.IPAllowlistEntry{{CIDR: "10.0.0.0"}} },
		"long description": func(o *api.EditIPAllowlistOption) { o.Entries[0].Description = strings.Repeat("x", 256) },
		"unknown user":     func(o *api.EditIPAllowlistOption) { o.ExemptUserIDs = []int64{99999} },
		"unknown token":    func(o *api.EditIPAllowlistOption) { o.ExemptTokenIDs = []int64{99999} },
		"too many entries": func(o *api.EditIPAllowlistOption) {
			o.Entries = nil
			for i := range 501 {
				o.Entries = append(o.Entries, api.IPAllowlistEntry{CIDR: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)})
			}
		},
	} {
		bad := *opt
		bad.Entries = append([]api.IPAllowlistEntry(nil), opt.Entries...)
		edit(&bad)
		t.Run(name, func(t *testing.T) { put(token, &bad, http.StatusUnprocessableEntity) })
	}
	assert.Len(t, setting.GetIPAllowlist(db.DefaultContext).Entries, 2)
}
