// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package httplib

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.7:1234"
	assert.Equal(t, "192.0.2.7", ClientIP(req).String())

	req.RemoteAddr = "not an address"
	assert.False(t, ClientIP(req).IsValid())

	req.RemoteAddr = "192.0.2.7:1234"
	assert.False(t, ClientIP(WithAmbiguousClientIP(req, "10.0.0.1", nil)).IsValid(), "a trusted proxy's disagreeing headers")
}
