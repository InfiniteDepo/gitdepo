// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package httplib

import (
	"context"
	"net/http"
	"net/netip"

	"forgejo.org/modules/setting"
)

type ambiguousClientIPKey struct{}

type ambiguousClientIP struct {
	peer       string
	candidates []string
}

// WithAmbiguousClientIP marks a request whose trusted proxy sent disagreeing X-Real-IP and X-Forwarded-For headers:
// its RemoteAddr may be an address the client chose. peer is the trusted proxy's own address and candidates the
// header addresses that parse as IPs, for the audit log.
func WithAmbiguousClientIP(req *http.Request, peer string, candidates []string) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), ambiguousClientIPKey{}, ambiguousClientIP{peer, candidates}))
}

// IsClientIPAmbiguous reports whether WithAmbiguousClientIP marked the request.
func IsClientIPAmbiguous(req *http.Request) bool {
	_, _, ok := AmbiguousClientIP(req)
	return ok
}

// AmbiguousClientIP returns what WithAmbiguousClientIP stored.
func AmbiguousClientIP(req *http.Request) (peer string, candidates []string, ok bool) {
	v, ok := req.Context().Value(ambiguousClientIPKey{}).(ambiguousClientIP)
	return v.peer, v.candidates, ok
}

// ClientIP returns the client address of the request, invalid if it can't be parsed or a trusted proxy sent
// disagreeing X-Real-IP and X-Forwarded-For headers.
func ClientIP(req *http.Request) netip.Addr {
	if IsClientIPAmbiguous(req) {
		return netip.Addr{}
	}
	return setting.IPFromRemoteAddr(req.RemoteAddr)
}
