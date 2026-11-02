// Copyright 2026 The spoved contributors.
// SPDX-License-Identifier: GPL-3.0-or-later

package log

import (
	"strings"
	"testing"
	"time"

	"forgejo.org/modules/json"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func formatJSON(t *testing.T, e *Event) map[string]any {
	t.Helper()
	b := EventFormatJSONMessage(&WriterMode{StacktraceLevel: ERROR}, e)
	require.True(t, strings.HasSuffix(string(b), "\n"))
	assert.Equal(t, 1, strings.Count(string(b), "\n"))
	m := map[string]any{}
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

func TestEventFormatJSON(t *testing.T) {
	SetAppVersion("1.2.3")
	ts := time.Date(2026, 10, 9, 8, 0, 0, 5_000_000, time.UTC)

	m := formatJSON(t, &Event{Time: ts, Level: WARN, Logger: DEFAULT, MsgSimpleText: "a \"quoted\"\nline\t\x01 ü <b>"})
	assert.InDelta(t, float64(ts.UnixMilli()), m["timestamp"], 0)
	assert.Equal(t, "a \"quoted\"\nline\t\x01 ü <b>", m["message"])
	assert.Equal(t, "warn", m["level"])
	assert.Equal(t, "application", m["logtype"])
	assert.Equal(t, DEFAULT, m["logger"])
	assert.Equal(t, "gitdepo", m["service"])
	assert.Equal(t, "1.2.3", m["app_version"])
	assert.NotEmpty(t, m["hostname"])
	assert.NotContains(t, m, "stacktrace")

	for _, name := range []string{"access", "router", "xorm", "ssh"} {
		assert.Equal(t, name, formatJSON(t, &Event{Logger: name, Level: INFO})["logtype"])
	}

	m = formatJSON(t, &Event{
		Level: ERROR, Logger: "access", Stacktrace: "at token=abc",
		MsgSimpleText: "GET /x?access_token=abc",
		Fields:        map[string]any{"ip": "1.2.3.4", "status": 200, "path": "/x?password=zz", "message": "forged", "service": "forged"},
	})
	assert.Equal(t, "GET /x?access_token=[REDACTED]", m["message"])
	assert.Equal(t, "at token=[REDACTED]", m["stacktrace"])
	assert.Equal(t, "1.2.3.4", m["ip"])
	assert.InDelta(t, 200, m["status"], 0)
	assert.Equal(t, "/x?password=[REDACTED]", m["path"])
	assert.Equal(t, "gitdepo", m["service"], "fields must not override core keys")

	m = formatJSON(t, &Event{Level: INFO, MsgSimpleText: strings.Repeat("é", 40000)})
	assert.LessOrEqual(t, len(m["message"].(string)), 32*1024+len("…[truncated]"))
	assert.True(t, strings.HasSuffix(m["message"].(string), "…[truncated]"))
}

func TestWriterModeFormatJSON(t *testing.T) {
	text := NewEventWriterBuffer("t", WriterMode{Level: INFO, Flags: FlagsFromString("none")}).(EventWriterBuffer)
	js := NewEventWriterBuffer("j", WriterMode{Level: INFO, Format: "json"}).(EventWriterBuffer)
	l := NewLoggerWithWriters(t.Context(), "access", text, js)
	l.Info("hello %s", "x")
	l.Close()
	assert.Equal(t, "hello x\n", text.GetString(), "text output must stay unchanged")
	assert.Contains(t, js.GetString(), `"message":"hello x"`)
	assert.Contains(t, js.GetString(), `"logger":"access"`)
}

func TestLogWithFields(t *testing.T) {
	js := NewEventWriterBuffer("j", WriterMode{Level: INFO, Format: "json"}).(EventWriterBuffer)
	l := NewLoggerWithWriters(t.Context(), "access", js)
	l.LogWithFields(0, INFO, map[string]any{"status": 204}, "%s", "line")
	l.Close()
	assert.Contains(t, js.GetString(), `"status":204`)
}
