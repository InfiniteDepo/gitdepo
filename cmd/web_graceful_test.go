// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFCGIHandlerRecover(t *testing.T) {
	serve := func(v any) {
		fcgiHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(v) })).
			ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}

	assert.NotPanics(t, func() { serve(http.ErrAbortHandler) })
	assert.PanicsWithValue(t, "boom", func() { serve("boom") })
}
