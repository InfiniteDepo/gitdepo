// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package context

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"forgejo.org/modules/json"
	"forgejo.org/modules/log"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessLoggerStructuredFields(t *testing.T) {
	w := log.NewEventWriterBuffer("access-json", log.WriterMode{Level: log.INFO, Format: "json"}).(log.EventWriterBuffer)
	logger := log.GetManager().GetLogger("access")
	logger.ReplaceAllWriters(w)
	defer logger.ReplaceAllWriters()

	handler := AccessLogger()(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte("hello"))
	}))
	req := httptest.NewRequest("GET", "/x?access_token=abc&page=2", nil)
	req.Header.Set("User-Agent", "agent/1")
	req.RemoteAddr = "203.0.113.7:4711"
	handler.ServeHTTP(WrapResponseWriter(httptest.NewRecorder()), req)

	huge := strings.Repeat("a", 900*1024)
	req = httptest.NewRequest("GET", "/"+huge, nil)
	req.Header.Set("User-Agent", huge)
	handler.ServeHTTP(WrapResponseWriter(httptest.NewRecorder()), req)
	logger.ReplaceAllWriters() // flushes the writer

	lines := strings.Split(strings.TrimSpace(w.GetString()), "\n")
	require.Len(t, lines, 2)
	var small, big map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &small))
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &big))

	assert.Equal(t, "203.0.113.7", small["ip"])
	assert.Equal(t, "GET", small["method"])
	assert.Equal(t, "/x?access_token=[REDACTED]&page=2", small["path"])
	assert.Equal(t, "agent/1", small["user_agent"])
	assert.InDelta(t, 200, small["status"], 0)
	assert.InDelta(t, 5, small["bytes"], 0)
	assert.Empty(t, small["user"])
	assert.Contains(t, small, "duration_ms")

	// the 1 MB request is capped before it reaches the writer queue, and again by the formatter
	assert.LessOrEqual(t, len(big["path"].(string)), 2048+len("…[truncated]"))
	assert.LessOrEqual(t, len(big["user_agent"].(string)), 2048+len("…[truncated]"))
	assert.LessOrEqual(t, len(lines[1]), 64*1024)
}

func TestCapAccessLogField(t *testing.T) {
	assert.Equal(t, "short", capAccessLogField("short"))
	assert.Len(t, capAccessLogField(strings.Repeat("a", 5000)), maxAccessLogField)
}

func TestAccessLoggerFollowsTheWriters(t *testing.T) {
	logger := log.GetManager().GetLogger("access")
	logger.ReplaceAllWriters()
	handler := AccessLogger()(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte("ok")) }))

	// no writer: the request passes through untouched; the logger would panic on this plain recorder (it is no ResponseWriter)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/a", nil))
	assert.Equal(t, "ok", rec.Body.String())

	// a writer added later (a log destination) turns it on without rebuilding the middleware
	w := log.NewEventWriterBuffer("access-late", log.WriterMode{Level: log.INFO, Format: "json"}).(log.EventWriterBuffer)
	logger.AddWriters(w)
	handler.ServeHTTP(WrapResponseWriter(httptest.NewRecorder()), httptest.NewRequest("GET", "/b", nil))
	logger.ReplaceAllWriters()
	assert.Contains(t, w.GetString(), `"path":"/b"`)
	assert.NotContains(t, w.GetString(), `"path":"/a"`)
}
