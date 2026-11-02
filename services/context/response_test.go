// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package context

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type deadlineWriter struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *deadlineWriter) SetWriteDeadline(t time.Time) error {
	w.deadline = t
	return nil
}

// http.ResponseController reaches the server's writer through the wrapper (the export time limit sets a write
// deadline with it).
func TestResponseUnwrap(t *testing.T) {
	inner := &deadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	at := time.Now().Add(time.Minute)
	require.NoError(t, http.NewResponseController(WrapResponseWriter(inner)).SetWriteDeadline(at))
	assert.Equal(t, at, inner.deadline)
}
