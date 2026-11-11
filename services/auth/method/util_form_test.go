// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package method

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A token in a form body is not read (and the body is left alone); one in the query string still is.
func TestTokenFromFormQueryOnly(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader("access_token=abc&token=def"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	assert.False(t, tokenFromForm(req).Has())
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, "access_token=abc&token=def", string(body))

	has, token := tokenFromForm(httptest.NewRequest("GET", "/?access_token=abc", nil)).Get()
	assert.True(t, has)
	assert.Equal(t, "abc", token)
	has, token = tokenFromForm(httptest.NewRequest("POST", "/?token=def", strings.NewReader("access_token=abc"))).Get()
	assert.True(t, has)
	assert.Equal(t, "def", token)
}
