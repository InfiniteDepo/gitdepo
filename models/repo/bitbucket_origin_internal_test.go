// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseBitbucketOriginKeyword(t *testing.T) {
	for _, tc := range []struct {
		keyword, host, key, slug string
	}{
		{"PAY/api", "", "PAY", "api"},
		{"pay/API", "", "PAY", "api"},
		{"PAY/api.git", "", "PAY", "api"},
		{"https://bb.example.com/scm/pay/api.git", "bb.example.com", "PAY", "api"},
		{"https://BB.Example.COM/scm/pay/api.git", "bb.example.com", "PAY", "api"},
		{"https://bb.example.com/bitbucket/scm/pay/api", "bb.example.com", "PAY", "api"},
		{"https://jdoe@bb.example.com/scm/pay/api.git", "bb.example.com", "PAY", "api"},
		{"https://jdoe:secret@bb.example.com/scm/pay/api.git", "bb.example.com", "PAY", "api"},
		{"http://bb.example.com:7990/projects/PAY/repos/api/browse", "bb.example.com", "PAY", "api"},
		{"https://bb.example.com/projects/PAY/repos/api", "bb.example.com", "PAY", "api"},
		{"ssh://git@bb.example.com:7999/pay/api.git", "bb.example.com", "PAY", "api"},
		{"ssh://git@bb.example.com/pay/api", "bb.example.com", "PAY", "api"},
	} {
		host, key, slug, ok := parseBitbucketOriginKeyword(tc.keyword)
		if assert.True(t, ok, tc.keyword) {
			assert.Equal(t, []string{tc.host, tc.key, tc.slug}, []string{host, key, slug}, tc.keyword)
		}
	}

	for _, keyword := range []string{
		"", "api", "PAY/", "/api", "org/project/repo", "PAY/api/extra", "PAY/a pi", "PA%/api", "PAY/a_%",
		"https://bb.example.com/pay/api", "https://bb.example.com/scm/pay", "https://bb.example.com/scm/pay/api/x",
		"https://bb.example.com/projects/PAY/api", "ftp://bb.example.com/scm/pay/api", "file:///scm/pay/api",
		"ssh://git@bb.example.com/scm/pay/api", "https://bb%25.example.com/scm/pay/api", "https://bb_x.example.com/scm/pay/api",
		"https://[::1]/scm/pay/api", "https:///scm/pay/api",
		strings.Repeat("A", maxBitbucketOriginKeyword-2) + "/ab", // one byte over the cap
	} {
		_, _, _, ok := parseBitbucketOriginKeyword(keyword)
		assert.False(t, ok, keyword)
		assert.Nil(t, bitbucketOriginKeywordCond(keyword), keyword)
	}
	_, _, _, ok := parseBitbucketOriginKeyword(strings.Repeat("A", maxBitbucketOriginKeyword-3) + "/ab")
	assert.True(t, ok, "at the cap")
}

func TestBitbucketOriginBrowseURL(t *testing.T) {
	for server, want := range map[string]string{
		"https://bb.example.com":         "https://bb.example.com/projects/PAY/repos/api/browse",
		"http://bb.example.com:7990/ctx": "http://bb.example.com:7990/ctx/projects/PAY/repos/api/browse",
		"https://user:pw@bb.example.com": "",
		"javascript:alert(1)":            "",
		"ftp://bb.example.com":           "",
		"https://bb.example.com?x=1":     "",
		"//bb.example.com":               "",
		"bb.example.com":                 "",
	} {
		assert.Equal(t, want, (&BitbucketOrigin{Server: server, ProjectKey: "PAY", Slug: "api"}).BrowseURL(), server)
	}
	assert.Equal(t, "PAY/api", (&BitbucketOrigin{ProjectKey: "PAY", Slug: "api"}).Path())
}
