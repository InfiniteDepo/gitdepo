// Copyright 2026 The spoved contributors.
// SPDX-License-Identifier: GPL-3.0-or-later

package log

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"forgejo.org/modules/json"
)

// ServiceName is the "service" field of every JSON log event.
const ServiceName = "gitdepo"

const (
	maxJSONMessage = 32 * 1024
	maxJSONField   = 2 * 1024 // path, user agent, ... come from the client
	maxJSONLine    = 4 * 1024 // the message of a structured (access) event repeats URI, referer and user agent
)

var (
	appVersion atomic.Value // string
	hostname   = sync.OnceValue(func() string { h, _ := os.Hostname(); return h })
)

// SetAppVersion sets the "app_version" field of JSON log events (the log package can't import setting).
func SetAppVersion(v string) { appVersion.Store(v) }

// clean redacts s and cuts it to max bytes. Literal secrets go first, over all of s; the rest of Redact only sees
// the head of s (2 x max), because a client can send 1 MB headers and redaction costs about 1 ms per KB.
func clean(s string, max int) string {
	s = truncate(redactLiterals(s), 2*max)
	return truncate(Redact(s), max)
}

// truncate cuts s to max bytes; callers redact first, so a secret can't be cut into an unrecognisable piece
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return strings.ToValidUTF8(s[:max], "") + "…[truncated]"
}

// EventFormatJSONMessage formats the event as one redacted JSON object per line.
func EventFormatJSONMessage(mode *WriterMode, event *Event) []byte {
	maxMessage := maxJSONMessage
	if event.Fields != nil {
		maxMessage = maxJSONLine
	}
	m := make(map[string]any, len(event.Fields)+9)
	for k, v := range event.Fields {
		if s, ok := v.(string); ok {
			v = clean(s, maxJSONField)
		}
		m[k] = v
	}
	logtype := event.Logger
	if logtype == "" || logtype == DEFAULT {
		logtype = "application"
	}
	ver, _ := appVersion.Load().(string)
	if _, ok := m["timestamp"].(int64); !ok { // a caller shipping a stored event gives the time it happened
		m["timestamp"] = event.Time.UnixMilli()
	}
	m["message"] = clean(strings.TrimSuffix(event.MsgSimpleText, "\n"), maxMessage)
	m["level"] = event.Level.String()
	m["logtype"] = logtype
	m["logger"] = event.Logger
	m["hostname"] = hostname()
	m["service"] = ServiceName
	m["app_version"] = ver
	if event.Stacktrace != "" && mode.StacktraceLevel <= event.Level {
		m["stacktrace"] = clean(event.Stacktrace, maxJSONMessage)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return []byte(`{"message":"log event could not be encoded","service":"` + ServiceName + "\"}\n")
	}
	return append(b, '\n')
}
