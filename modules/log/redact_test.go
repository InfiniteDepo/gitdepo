// Copyright 2026 The gitdepo contributors.
// SPDX-License-Identifier: GPL-3.0-or-later

package log

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedact(t *testing.T) {
	const r = "[REDACTED]"
	for in, want := range map[string]string{
		// headers, plain and JSON-encoded
		"Authorization: Bearer abc.def-123":      "Authorization: " + r,
		"authorization=token 0123456789abcdef":   "authorization=" + r,
		`{"Authorization":"Basic dXNlcjpwdw=="}`: `{"Authorization":"` + r + `"}`,
		"Cookie: i_like_gitea=abc; lang=en":      "Cookie: " + r,
		"Set-Cookie: sess=abc; Path=/":           "Set-Cookie: " + r,
		"X-Api-Key: s3cr3t":                      "X-Api-Key: " + r,
		"proxy-authorization: Basic abc123==":    "proxy-authorization: " + r,
		"sent Bearer abcdef123456 to host":       "sent Bearer " + r + " to host",
		// URL query parameters and free text pairs
		"GET /x?access_token=abc123&page=2":                                     "GET /x?access_token=" + r + "&page=2",
		"GET /x?page=2&token=abc":                                               "GET /x?page=2&token=" + r,
		"/x?private_token=a&X-Amz-Signature=b&session_id=c&auth=d&credential=e": "/x?private_token=" + r + "&X-Amz-Signature=" + r + "&session_id=" + r + "&auth=" + r + "&credential=" + r,
		"pass=hunter2 and bypass=1":                                             "pass=" + r + " and bypass=1",
		`Referer: "https://h/x?a=1&access_token=abc"`:                           `Referer: "https://h/x?a=1&access_token=` + r + `"`,
		"/login/oauth?code=abcd&state=zz":                                       "/login/oauth?code=" + r + "&state=zz",
		"/x?client_secret=aa&password=bb&key=cc&secret=dd":                      "/x?client_secret=" + r + "&password=" + r + "&key=" + r + "&secret=" + r,
		"/x?API_KEY=aa&refresh_token=bb":                                        "/x?API_KEY=" + r + "&refresh_token=" + r,
		"login failed password=hunter2 for u":                                   "login failed password=" + r + " for u",
		`{"password":"hunter2","user":"a"}`:                                     `{"password":"` + r + `","user":"a"}`,
		// URL userinfo
		"clone https://bob:pw123@example.com/a.git": "clone https://bob:" + r + "@example.com/a.git",
		// known token shapes
		"tok gta_0123456789abcdef0123":                                        "tok " + r,
		"tok glpat-0123456789abcdefghij":                                      "tok " + r,
		"tok eyJhbGciOiJI.eyJzdWIiOiIx.c2lnbmF0dXJl":                          "tok " + r,
		"k NRAK-0123456789ABCDEF end":                                         "k " + r + " end",
		"-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----": r,
		// already JSON-escaped by log.Error("%q", body), token-only userinfo, token <value>, xox shapes
		`"{\"password\":\"hunter2\",\"user\":\"a\"}"`:              `"{\"password\":\"` + r + `\",\"user\":\"a\"}"`,
		"clone https://abc123def456@example.com/a.git":             "clone https://" + r + "@example.com/a.git",
		"curl -H token 0123456789abcdef":                           "curl -H token " + r,
		"slack xoxr-0123456789abcdef":                              "slack " + r,
		"code=abc&client_code=zz&user-code=1&barcode=123&design=4": "code=" + r + "&client_code=" + r + "&user-code=" + r + "&barcode=123&design=4",
		`{"code":"abc","sig":"d"}`:                                 `{"code":"` + r + `","sig":"` + r + `"}`,
		`"{\"Cookie\":\"sess=abc\",\"Host\":\"h\"}"`:               `"{\"Cookie\":\"` + r + `\",\"Host\":\"h\"}"`,
		// negatives: must stay untouched
		"commit 0123456789abcdef0123456789abcdef01234567 pushed": "commit 0123456789abcdef0123456789abcdef01234567 pushed",
		"basic settings page and bearer of news":                 "basic settings page and bearer of news",
		"pass the token validation, 7 codes, key words":          "pass the token validation, 7 codes, key words",
		"GET /user/settings?tab=keys&page=2":                     "GET /user/settings?tab=keys&page=2",
		"page=2&state=zz&tab=keys":                               "page=2&state=zz&tab=keys",
	} {
		assert.Equal(t, want, Redact(in), in)
	}
}

func TestRedactSecretLiteral(t *testing.T) {
	RegisterSecret("sup3r-s3cret-literal")
	assert.Equal(t, "boom [REDACTED] boom", Redact("boom sup3r-s3cret-literal boom"))
}

func TestRedactLongInput(t *testing.T) {
	in := strings.Repeat("a=b&", 100000) + "password=x"
	assert.True(t, strings.HasSuffix(Redact(in), "password=[REDACTED]"))
}
