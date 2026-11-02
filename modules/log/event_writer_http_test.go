// Copyright 2026 The gitdepo contributors.
// SPDX-License-Identifier: GPL-3.0-or-later

package log

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"forgejo.org/modules/json"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testHTTPSecret = "Bearer s3cr3t-header-value-0123"

type httpServer struct {
	*httptest.Server
	mu      sync.Mutex
	status  int
	headers []http.Header
	bodies  []string
}

func newHTTPServer(t *testing.T, status int) *httpServer {
	s := &httpServer{status: status}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.headers = append(s.headers, r.Header.Clone())
		s.bodies = append(s.bodies, string(b))
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte("remote body that must never be returned"))
	}))
	t.Cleanup(s.Close)
	t.Cleanup(mockVar(&ShipTransport, s.Client().Transport))
	return s
}

func (s *httpServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bodies)
}

func TestHTTPShipperGenericDelivery(t *testing.T) {
	for _, ndjson := range []bool{false, true} {
		t.Run(fmt.Sprintf("ndjson=%v", ndjson), func(t *testing.T) {
			s := newHTTPServer(t, 200)
			name := fmt.Sprintf("http-test-%v", ndjson)
			sh := newHTTPShipper(name, HTTPShipOption{
				Format: "http", Endpoint: s.URL, NDJSON: ndjson,
				Headers: map[string]string{"Authorization": testHTTPSecret, "X-Team": "ops"},
			})
			sh.interval = time.Hour
			t.Cleanup(func() { _ = sh.Close() })

			_, _ = sh.Write(ev("access", "one"))
			_, _ = sh.Write(ev("default", "two"))
			require.NoError(t, sh.Close())

			require.Equal(t, 1, s.count())
			h, body := s.headers[0], s.bodies[0]
			assert.Equal(t, testHTTPSecret, h.Get("Authorization"))
			assert.Equal(t, "ops", h.Get("X-Team"))
			assert.Empty(t, h.Get("Content-Encoding"))
			assert.Empty(t, h.Get("Api-Key"))
			if ndjson {
				assert.Equal(t, "application/x-ndjson", h.Get("Content-Type"))
				lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
				require.Len(t, lines, 2)
				var m map[string]any
				require.NoError(t, json.Unmarshal([]byte(lines[0]), &m))
				assert.Equal(t, "one", m["message"])
			} else {
				assert.Equal(t, "application/json", h.Get("Content-Type"))
				var events []map[string]any
				require.NoError(t, json.Unmarshal([]byte(body), &events))
				require.Len(t, events, 2)
				assert.Equal(t, "two", events[1]["message"])
			}
			assert.EqualValues(t, 2, statOf(name, "access").Sent+statOf(name, "default").Sent)
		})
	}
}

func TestHTTPShipOptionKeepsSecretsOut(t *testing.T) {
	o := HTTPShipOption{Format: "newrelic", Endpoint: "https://example.org/x", Key: testNRKey, Headers: map[string]string{"Authorization": testHTTPSecret}}
	for _, out := range []string{o.String(), o.GoString(), fmt.Sprintf("%v %+v %#v", o, o, o)} {
		assert.NotContains(t, out, testNRKey)
		assert.NotContains(t, out, testHTTPSecret)
	}
	b, err := json.Marshal(o)
	require.NoError(t, err)
	assert.NotContains(t, string(b), testNRKey)
	assert.NotContains(t, string(b), testHTTPSecret)
}

func TestHTTPShipOptionValidate(t *testing.T) {
	ok := []HTTPShipOption{
		{Format: "http", Endpoint: "https://logs.example.org/in"},
		{Format: "http", Endpoint: "http://localhost:8080/in"},
		{Format: "http", Endpoint: "http://127.0.0.1/in"},
		{Format: "http", Endpoint: "http://[::1]:9/in"},
		{Format: "newrelic", Endpoint: "https://log-api.newrelic.com/log/v1", Key: "k"},
	}
	for _, o := range ok {
		require.NoError(t, o.Validate(), o.Endpoint)
	}
	bad := []HTTPShipOption{
		{Format: "http", Endpoint: "http://logs.example.org/in"},
		{Format: "http", Endpoint: "http://127.0.0.1.example.org/in"},
		{Format: "http", Endpoint: "https://user:pw@logs.example.org/in"},
		{Format: "http", Endpoint: "https://logs.example.org/in?token=abc"},
		{Format: "http", Endpoint: "https://logs.example.org/in#frag"},
		{Format: "http", Endpoint: "ftp://logs.example.org/in"},
		{Format: "http", Endpoint: "https:///in"},
		{Format: "http", Endpoint: ""},
		{Format: "newrelic", Endpoint: "https://log-api.newrelic.com/log/v1"}, // no key
		{Format: "other", Endpoint: "https://logs.example.org/in"},
	}
	for _, o := range bad {
		err := o.Validate()
		require.Error(t, err, o.Endpoint)
		assert.NotContains(t, err.Error(), "pw")
		assert.NotContains(t, err.Error(), "abc")
	}
}

func TestProbeHTTPUsesDialHookAndHidesRemote(t *testing.T) {
	s := newHTTPServer(t, 500)
	opt := HTTPShipOption{Format: "http", Endpoint: s.URL, Headers: map[string]string{"Authorization": testHTTPSecret}}

	code, err := ProbeHTTP(t.Context(), "probe-status", opt, []byte(`{"logtype":"test"}`))
	require.NoError(t, err)
	assert.Equal(t, 500, code)
	assert.Equal(t, 1, s.count())

	// a dial hook that refuses stops the request before it reaches the server; the error carries no secret
	t.Cleanup(mockVar(&ShipTransport, nil))
	opt.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial denied for " + testHTTPSecret)
	}
	code, err = ProbeHTTP(t.Context(), "probe-dial", opt, []byte(`{"logtype":"test"}`))
	require.Error(t, err)
	assert.Zero(t, code)
	assert.NotContains(t, err.Error(), testHTTPSecret)
	assert.Equal(t, 1, s.count())
}

func TestShippingStatusRecordsClassesOnly(t *testing.T) {
	s := newHTTPServer(t, 503)
	sh := newHTTPShipper("status-test", HTTPShipOption{Format: "http", Endpoint: s.URL})
	sh.interval = time.Hour
	sh.sleep = func(context.Context, time.Duration) bool { return true }
	t.Cleanup(func() { _ = sh.Close(); ForgetShipping("status-test") })

	_, _ = sh.Write(ev("default", "a"))
	sh.flush(t.Context(), 1)
	ok, lastErr := ShippingStatus("status-test")
	assert.True(t, ok.IsZero())
	assert.Equal(t, "status 5xx", lastErr)

	s.mu.Lock()
	s.status = 200
	s.mu.Unlock()
	_, _ = sh.Write(ev("default", "b"))
	sh.flush(t.Context(), 1)
	ok, _ = ShippingStatus("status-test")
	assert.WithinDuration(t, time.Now(), ok, 5*time.Second)

	ForgetShipping("status-test")
	ok, lastErr = ShippingStatus("status-test")
	assert.True(t, ok.IsZero())
	assert.Empty(t, lastErr)
	assert.Zero(t, statOf("status-test", "default").Sent)
}

func TestHTTPWriterDumpHasNoSecrets(t *testing.T) {
	m := NewManager()
	defer m.Close()
	mode := WriterMode{Level: INFO, Format: "json", WriterOption: HTTPShipOption{
		Format: "http", Endpoint: "https://logs.example.org/in", Headers: map[string]string{"Authorization": testHTTPSecret},
	}}
	_, err := m.NewSharedWriter("ship-dump", "http", mode)
	require.NoError(t, err)
	l := m.GetLogger("default")
	l.AddWriters(m.GetSharedWriter("ship-dump"))
	b, err := json.Marshal(m.DumpLoggers())
	require.NoError(t, err)
	assert.Contains(t, string(b), "logs.example.org")
	assert.NotContains(t, string(b), testHTTPSecret)
}

func TestHTTPWritersRedactEveryFormat(t *testing.T) {
	for _, tc := range []struct {
		format string
		opt    HTTPShipOption
	}{
		{"http", HTTPShipOption{Format: "http", Headers: map[string]string{"X-A": "header-value-for-redaction-test"}}},
		{"ndjson", HTTPShipOption{Format: "http", NDJSON: true}},
		{"newrelic", HTTPShipOption{Format: "newrelic", Key: testNRKey}},
	} {
		t.Run(tc.format, func(t *testing.T) {
			s := newHTTPServer(t, 200)
			tc.opt.Endpoint = s.URL
			m := NewManager()
			defer m.Close()
			name := "redact-" + tc.format
			w, err := m.NewSharedWriter(name, "http", WriterMode{Level: INFO, Format: "json", WriterOption: tc.opt})
			require.NoError(t, err)
			l := m.GetLogger("access")
			l.AddWriters(w)
			l.LogWithFields(0, INFO, map[string]any{"path": "/x?access_token=SUPERSECRETTOKEN0123&page=2"}, "GET /x?access_token=SUPERSECRETTOKEN0123")
			_ = l.RemoveWriter(name)
			m.RemoveSharedWriter(name) // flushes
			ForgetShipping(name)

			require.Equal(t, 1, s.count())
			body := s.bodies[0]
			if tc.format == "newrelic" {
				zr, err := gzip.NewReader(strings.NewReader(body))
				require.NoError(t, err)
				b, _ := io.ReadAll(zr)
				body = string(b)
			}
			assert.NotContains(t, body, "SUPERSECRETTOKEN0123")
			assert.Contains(t, body, "access_token=[REDACTED]")
		})
	}
}
