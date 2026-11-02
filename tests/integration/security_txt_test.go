// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"testing"

	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
)

func TestSecurityTxt(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	body := MakeRequest(t, NewRequest(t, "GET", "/.well-known/security.txt"), http.StatusOK).Body.String()
	assert.Contains(t, body, "Contact: https://github.com/InfiniteDepo/gitdepo/security/advisories/new")
	assert.Contains(t, body, "Policy: https://github.com/InfiniteDepo/gitdepo/blob/develop/SECURITY.md")
	assert.NotContains(t, body, "mailto:")
	assert.NotContains(t, body, "PGP")
	assert.NotContains(t, body, "Encryption:")
}
