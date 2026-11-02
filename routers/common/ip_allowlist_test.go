// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package common

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/web"

	"github.com/stretchr/testify/assert"
)

// AC7: the client IP comes from X-Forwarded-For/X-Real-IP only when the TCP peer is a trusted proxy
func TestClientIPFromTrustedProxyOnly(t *testing.T) {
	defer test.MockVariableValue(&setting.ReverseProxyLimit, 1)()
	newRoute := func(trusted ...string) *web.Route {
		defer test.MockVariableValue(&setting.ReverseProxyTrustedProxies, trusted)()
		r := web.NewRoute()
		r.Use(ProtocolMiddlewares()...)
		r.Get("/", func(w http.ResponseWriter, req *http.Request) {
			_, _ = w.Write([]byte(setting.IPFromRemoteAddr(req.RemoteAddr).String() + " " + ClientIP(req).String()))
		})
		return r
	}
	r := newRoute("127.0.0.0/8", "::1")
	// clientIP returns the address the rest of the code sees as RemoteAddr, and ClientIP, which the allowlist uses
	clientIP := func(r *web.Route, peer string, header http.Header) (string, string) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = peer
		req.Header = header
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)
		remote, client, _ := strings.Cut(resp.Body.String(), " ")
		return remote, client
	}
	assertIP := func(r *web.Route, want, peer string, header http.Header) {
		t.Helper()
		remote, client := clientIP(r, peer, header)
		assert.Equal(t, want, remote)
		assert.Equal(t, want, client)
	}

	// an untrusted peer can't spoof its address with either header
	assertIP(r, "198.51.100.7", "198.51.100.7:1234", http.Header{"X-Forwarded-For": {"10.1.2.3"}})
	assertIP(r, "198.51.100.7", "198.51.100.7:1234", http.Header{"X-Real-Ip": {"10.1.2.3"}})

	// a trusted proxy sets the client address
	assertIP(r, "198.51.100.7", "127.0.0.1:1234", http.Header{"X-Forwarded-For": {"198.51.100.7"}})
	assertIP(r, "198.51.100.7", "[::1]:1234", http.Header{"X-Real-Ip": {"198.51.100.7"}})
	assertIP(r, "198.51.100.7", "127.0.0.1:1234", http.Header{"X-Forwarded-For": {"10.1.2.3, 198.51.100.7"}})
	// a proxy that adds its own X-Forwarded-For line keeps the client's line first: the last address wins
	assertIP(r, "198.51.100.7", "127.0.0.1:1234", http.Header{"X-Forwarded-For": {"10.1.2.3", "198.51.100.7"}})
	// nginx setting X-Real-IP and appending X-Forwarded-For: they agree
	assertIP(r, "198.51.100.7", "127.0.0.1:1234", http.Header{"X-Forwarded-For": {"10.1.2.3, 198.51.100.7"}, "X-Real-Ip": {"198.51.100.7"}})

	// when the headers disagree, RemoteAddr stays as before, but the allowlist sees no client IP
	for _, header := range []http.Header{
		// a proxy that only appends X-Forwarded-For passes on the client's forged X-Real-IP (Caddy)
		{"X-Forwarded-For": {"198.51.100.7"}, "X-Real-Ip": {"10.1.2.3"}},
		// a proxy that only sets X-Real-IP passes on the client's forged X-Forwarded-For (minimal nginx)
		{"X-Forwarded-For": {"10.1.2.3"}, "X-Real-Ip": {"198.51.100.7"}},
	} {
		remote, client := clientIP(r, "127.0.0.1:1234", header)
		assert.Equal(t, header.Get("X-Real-Ip"), remote)
		assert.Equal(t, "invalid IP", client)
	}

	// IPv4-mapped entries trust the IPv4 peer, as proxy.ForwardedHeaders does
	for _, trusted := range []string{"::ffff:127.0.0.1", "::ffff:127.0.0.0/104"} {
		r := newRoute(trusted)
		assertIP(r, "198.51.100.7", "127.0.0.1:1234", http.Header{"X-Forwarded-For": {"10.1.2.3", "198.51.100.7"}})
		remote, client := clientIP(r, "127.0.0.1:1234", http.Header{"X-Forwarded-For": {"198.51.100.7"}, "X-Real-Ip": {"10.1.2.3"}})
		assert.Equal(t, "10.1.2.3", remote, trusted)
		assert.Equal(t, "invalid IP", client, trusted)
	}

	// "*" trusts every peer
	r = newRoute("*")
	assertIP(r, "198.51.100.7", "203.0.113.9:1234", http.Header{"X-Forwarded-For": {"10.1.2.3", "198.51.100.7"}})
	remote, client := clientIP(r, "203.0.113.9:1234", http.Header{"X-Forwarded-For": {"198.51.100.7"}, "X-Real-Ip": {"10.1.2.3"}})
	assert.Equal(t, "10.1.2.3", remote)
	assert.Equal(t, "invalid IP", client)
}
