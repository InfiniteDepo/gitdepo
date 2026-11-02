// Copyright 2026 The gitdepo contributors.
// SPDX-License-Identifier: GPL-3.0-or-later

package log

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"forgejo.org/modules/json"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type lokiPush struct {
	Streams []struct {
		Stream map[string]string `json:"stream"`
		Values [][]string        `json:"values"`
	} `json:"streams"`
}

func lokiItem(logtype, level string, ts int64, msg string) shipItem {
	return shipItem{logger: logtype, data: fmt.Appendf(nil, `{"timestamp":%d,"logtype":%q,"level":%q,"message":%q}`, ts, logtype, level, msg)}
}

func TestLokiEncode(t *testing.T) {
	f := lokiFormat{HTTPShipOption{Format: "loki"}}
	body := f.Encode([]shipItem{
		lokiItem("audit", "info", 3000, "c"),
		lokiItem("audit", "warn", 1000, "w"),
		lokiItem("audit", "info", 2000, "b"),
		lokiItem("test", "info", 500, "t"),
		{logger: "audit", data: []byte(`not json`)},
		lokiItem("evil\"x", "FATAL{", 1, "x"), // labels are a closed set, never copied
	})
	var p lokiPush
	require.NoError(t, json.Unmarshal(body, &p))
	byLabel := map[string][][]string{}
	for _, s := range p.Streams {
		assert.Equal(t, "gitdepo", s.Stream["service"])
		assert.Len(t, s.Stream, 3)
		byLabel[s.Stream["logtype"]+"/"+s.Stream["level"]] = append(byLabel[s.Stream["logtype"]+"/"+s.Stream["level"]], s.Values...)
	}
	info := byLabel["audit/info"]
	require.Len(t, info, 2)
	assert.Equal(t, "2000000000", info[0][0]) // ns strings, sorted by time inside a stream
	assert.Equal(t, "3000000000", info[1][0])
	assert.Contains(t, info[0][1], `"message":"b"`)
	assert.Len(t, byLabel["audit/warn"], 1)
	assert.Len(t, byLabel["test/info"], 1)
	for k := range byLabel {
		assert.NotContains(t, k, "evil")
		assert.NotContains(t, k, "FATAL")
	}
	// the unparsable line is kept, under a clamped label
	var found bool
	for _, vs := range byLabel {
		for _, v := range vs {
			found = found || v[1] == "not json"
		}
	}
	assert.True(t, found)
}

func TestLokiHeadersAndValidate(t *testing.T) {
	f := lokiFormat{HTTPShipOption{Format: "loki", Headers: map[string]string{"Authorization": testHTTPSecret}}}
	assert.Equal(t, testHTTPSecret, f.Headers().Get("Authorization"))
	assert.Equal(t, "application/json", f.Headers().Get("Content-Type"))
	require.NoError(t, HTTPShipOption{Format: "loki", Endpoint: "https://loki.example.org/loki/api/v1/push"}.Validate())
	require.Error(t, HTTPShipOption{Format: "loki", Endpoint: "https://u:p@loki.example.org/x"}.Validate())
	require.Error(t, HTTPShipOption{Format: "loki", Key: "abcdefgh12", Endpoint: "https://loki.example.org/x"}.Validate())
}

func TestLokiDelivery(t *testing.T) {
	s := newHTTPServer(t, 204)
	sh := newHTTPShipper("loki-test", HTTPShipOption{Format: "loki", Endpoint: s.URL + "/loki/api/v1/push", Headers: map[string]string{"X-Scope-OrgID": "tenant-0001"}})
	sh.interval = time.Hour
	_, _ = sh.Write(append([]byte("audit\n"), lokiItem("audit", "info", 1000, "m").data...))
	require.NoError(t, sh.Close())
	require.Equal(t, 1, s.count())
	assert.Equal(t, "tenant-0001", s.headers[0].Get("X-Scope-OrgID"))
	var p lokiPush
	require.NoError(t, json.Unmarshal([]byte(s.bodies[0]), &p))
	require.Len(t, p.Streams, 1)
	assert.Equal(t, "audit", p.Streams[0].Stream["logtype"])
	assert.EqualValues(t, 1, statOf("loki-test", "audit").Sent)
}

// The fallback output of a full queue is json.Marshal(event); structured fields stay out of it.
func TestEventFieldsStayOutOfFallbackOutput(t *testing.T) {
	b, err := json.Marshal(&Event{Fields: map[string]any{"ip": "203.0.113.77", "user_agent": "UA-secret-agent"}})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "203.0.113.77")
	assert.NotContains(t, string(b), "UA-secret-agent")
}

// M2: `data` is shipped as a string field, so it is redacted and capped like every other field.
func TestJSONFormatRedactsAndCapsDataString(t *testing.T) {
	const secret = "audit-secret-value-0001"
	RegisterSecret(secret)
	data := `{"k":"` + secret + `"}`
	out := EventFormatJSONMessage(&WriterMode{}, &Event{Logger: "audit", Level: INFO, MsgSimpleText: "x.y", Fields: map[string]any{"data": data}})
	assert.NotContains(t, string(out), secret)
	big := strings.Repeat("a", 10*1024)
	out = EventFormatJSONMessage(&WriterMode{}, &Event{Logger: "audit", Level: INFO, MsgSimpleText: "x.y", Fields: map[string]any{"data": big}})
	var m map[string]any
	require.NoError(t, json.Unmarshal(out, &m))
	assert.Contains(t, m["data"], "truncated")
	assert.Less(t, len(m["data"].(string)), 3*1024)
}
