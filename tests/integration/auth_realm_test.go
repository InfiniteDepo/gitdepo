// Copyright 2026 The gitdepo contributors.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"testing"

	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
)

// The realm is shown in the browser's and git's login prompt.
func TestAuthRealmNamesTheProduct(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	req := NewRequest(t, "GET", "/user2/repo2.git/info/refs?service=git-upload-pack")
	resp := MakeRequest(t, req, http.StatusUnauthorized)
	assert.Equal(t, `Basic realm="gitdepo"`, resp.Header().Get("WWW-Authenticate"))

	// user31 has private visibility (models/fixtures/user.yml); a public owner like user2 sends no challenge
	req = NewRequest(t, "GET", "/api/packages/user31/generic/pkg/1.0/file.bin")
	resp = MakeRequest(t, req, http.StatusUnauthorized)
	assert.Equal(t, `Basic realm="gitdepo Package API"`, resp.Header().Get("WWW-Authenticate"))

	req = NewRequest(t, "GET", "/api/packages/user2/generic/pkg/1.0/file.bin")
	resp = MakeRequest(t, req, NoExpectedStatus)
	assert.Empty(t, resp.Header().Get("WWW-Authenticate"))
}
