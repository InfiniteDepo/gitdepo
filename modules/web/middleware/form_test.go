// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func formRequest(method, body string) *http.Request {
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req.WithContext(WithFormState(req.Context()))
}

func TestParseForm(t *testing.T) {
	require.NoError(t, ParseForm(formRequest("POST", "a=1")))

	for _, body := range []string{"a=%zz", "a=1" + strings.Repeat("&f=1", 10000)} {
		req := formRequest("POST", body)
		require.Error(t, ParseForm(req))
		require.Error(t, ParseForm(req), "the recorded error is returned again")
	}

	require.NoError(t, ParseForm(formRequest("GET", "")))
}

func TestRefuseForm(t *testing.T) {
	rec := httptest.NewRecorder()
	assert.Panics(t, func() { RefuseForm(rec, errors.New("x")) })
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	req := httptest.NewRequest("POST", "/", strings.NewReader("a=1&b=2"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = http.MaxBytesReader(httptest.NewRecorder(), req.Body, 3)
	err := ParseForm(req.WithContext(WithFormState(req.Context())))
	require.Error(t, err)
	assert.Equal(t, http.StatusRequestEntityTooLarge, FormErrorStatus(err))
}
