// Copyright 2026 The gitdepo contributors.
// SPDX-License-Identifier: GPL-3.0-or-later

package log

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"forgejo.org/modules/json"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testNRKey = "NRAK-TESTKEY0123456789"

type nrServer struct {
	*httptest.Server
	mu         sync.Mutex
	statuses   []int // consumed one per request; the last one repeats
	retryAfter string
	bodies     [][]map[string]any
	headers    []http.Header
}

func newNRServer(t *testing.T, statuses ...int) *nrServer {
	s := &nrServer{statuses: statuses}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		code := s.statuses[0]
		if len(s.statuses) > 1 {
			s.statuses = s.statuses[1:]
		}
		s.headers = append(s.headers, r.Header.Clone())
		zr, err := gzip.NewReader(r.Body)
		if err == nil {
			var events []map[string]any
			b, _ := io.ReadAll(zr)
			if json.Unmarshal(b, &events) == nil {
				s.bodies = append(s.bodies, events)
			}
		}
		if s.retryAfter != "" {
			w.Header().Set("Retry-After", s.retryAfter)
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(s.Close)
	defer mockVar(&NewRelicTransport, s.Client().Transport)()
	return s
}

func (s *nrServer) requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.headers)
}

func (s *nrServer) events() (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.bodies {
		n += len(b)
	}
	return n
}

func testShipper(t *testing.T, s *nrServer, sleeps *[]time.Duration) *newRelicShipper {
	t.Helper()
	t.Cleanup(mockVar(&NewRelicTransport, s.Client().Transport))
	sh := newNewRelicShipper("nr-test", NewRelicOption{Endpoint: s.URL + "/log/v1", Key: testNRKey})
	sh.interval = time.Hour
	sh.sleep = func(ctx context.Context, d time.Duration) bool {
		if sleeps != nil {
			*sleeps = append(*sleeps, d)
		}
		return true
	}
	t.Cleanup(func() { _ = sh.Close() })
	return sh
}

func ev(logger, msg string) []byte {
	return []byte(logger + "\n" + fmt.Sprintf(`{"message":%q,"logger":%q}`, msg, logger) + "\n")
}

func statOf(writer, logger string) ShippingStat {
	for _, st := range ShippingStatsSnapshot() {
		if st.Writer == writer && st.Logger == logger {
			return st
		}
	}
	return ShippingStat{}
}

func TestNewRelicShipperDelivery(t *testing.T) {
	srv := newNRServer(t, 202)
	sh := testShipper(t, srv, nil)
	before := statOf("nr-test", "default").Sent

	_, _ = sh.Write(ev("default", "one"))
	_, _ = sh.Write(ev("default", "two"))
	require.NoError(t, sh.Close())

	require.Equal(t, 1, srv.requests())
	assert.Equal(t, testNRKey, srv.headers[0].Get("Api-Key"))
	assert.Equal(t, "gzip", srv.headers[0].Get("Content-Encoding"))
	assert.Equal(t, "application/json", srv.headers[0].Get("Content-Type"))
	require.Len(t, srv.bodies[0], 2)
	assert.Equal(t, "one", srv.bodies[0][0]["message"])
	assert.Equal(t, before+2, statOf("nr-test", "default").Sent)
}

func TestNewRelicShipperBatchBySizeAndTime(t *testing.T) {
	srv := newNRServer(t, 202)
	sh := testShipper(t, srv, nil)
	big := strings.Repeat("x", 300*1024)
	for range 4 { // 1.2 MB >= batch size: wakes the flusher without waiting for the ticker
		_, _ = sh.Write(ev("default", big))
	}
	assert.Eventually(t, func() bool { return srv.events() >= 3 }, 5*time.Second, 10*time.Millisecond)
	srv.mu.Lock()
	for _, b := range srv.bodies {
		assert.LessOrEqual(t, len(b), 3, "a batch is at most 1 MB")
	}
	srv.mu.Unlock()

	// time: a tiny event is only sent when the ticker fires
	srv2 := newNRServer(t, 202)
	sh2 := testShipper(t, srv2, nil)
	sh2.interval = 20 * time.Millisecond
	_, _ = sh2.Write(ev("default", "tiny"))
	assert.Eventually(t, func() bool { return srv2.events() == 1 }, 5*time.Second, 10*time.Millisecond)
}

func TestNewRelicShipperRetry(t *testing.T) {
	for _, code := range []int{429, 503} {
		srv := newNRServer(t, code, code, 202)
		var sleeps []time.Duration
		sh := testShipper(t, srv, &sleeps)
		errsBefore, sentBefore := statOf("nr-test", "default").Errors, statOf("nr-test", "default").Sent
		sh.interval = 5 * time.Millisecond
		_, _ = sh.Write(ev("default", "retry"))
		assert.Eventually(t, func() bool { return statOf("nr-test", "default").Sent == sentBefore+1 }, 5*time.Second, 5*time.Millisecond)
		require.NoError(t, sh.Close())
		assert.Equal(t, 3, srv.requests(), code)
		require.Len(t, sleeps, 2)
		assert.Less(t, sleeps[0], sleeps[1], "exponential backoff")
		assert.Equal(t, errsBefore+2, statOf("nr-test", "default").Errors)
	}

	// gives up after the max attempts and counts the drop
	srv := newNRServer(t, 503)
	sh := testShipper(t, srv, nil)
	dropBefore := statOf("nr-test", "default").Dropped
	sh.interval = 5 * time.Millisecond
	_, _ = sh.Write(ev("default", "never"))
	assert.Eventually(t, func() bool { return statOf("nr-test", "default").Dropped == dropBefore+1 }, 5*time.Second, 5*time.Millisecond)
	require.NoError(t, sh.Close())
	assert.Equal(t, newRelicMaxAttempts, srv.requests())
	assert.Equal(t, dropBefore+1, statOf("nr-test", "default").Dropped)
}

func TestNewRelicShipperAuthFailureStops(t *testing.T) {
	for _, code := range []int{401, 403} {
		srv := newNRServer(t, code)
		sh := testShipper(t, srv, nil)
		sh.interval = 5 * time.Millisecond
		stderr := captureStderr(t, func() {
			_, _ = sh.Write(ev("default", "a"))
			assert.Eventually(t, func() bool { return sh.disabled.Load() }, 5*time.Second, 5*time.Millisecond)
			_, _ = sh.Write(ev("default", "b"))
			require.NoError(t, sh.Close())
		})
		assert.Equal(t, 1, srv.requests(), "no retry, nothing sent after disabling")
		assert.Equal(t, 1, strings.Count(stderr, "rejected the credentials"), stderr)
		assert.NotContains(t, stderr, testNRKey)
	}
}

func TestNewRelicShipperOtherClientErrorAndRedirect(t *testing.T) {
	for _, code := range []int{400, 413, 422} {
		srv := newNRServer(t, code)
		sh := testShipper(t, srv, nil)
		sh.interval = 5 * time.Millisecond
		dropped := statOf("nr-test", "default").Dropped
		_, _ = sh.Write(ev("default", "bad"))
		assert.Eventually(t, func() bool { return statOf("nr-test", "default").Dropped == dropped+1 }, 5*time.Second, 5*time.Millisecond)
		require.NoError(t, sh.Close())
		assert.Equal(t, 1, srv.requests(), "no retry for HTTP %d", code)
	}

	// redirects are never followed, so the key can't be forwarded
	other := newNRServer(t, 202)
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	defer mockVar(&NewRelicTransport, redir.Client().Transport)()
	sh := newNewRelicShipper("nr-redir", NewRelicOption{Endpoint: redir.URL, Key: testNRKey})
	_, _ = sh.Write(ev("default", "x"))
	require.NoError(t, sh.Close())
	assert.Equal(t, 0, other.requests())
}

func TestNewRelicShipperBufferFullDropsOldest(t *testing.T) {
	srv := newNRServer(t, 202)
	sh := testShipper(t, srv, nil)
	sh.maxEvents = 3
	dropBefore := statOf("nr-test", "default").Dropped
	for i := range 5 {
		_, _ = sh.Write(ev("default", fmt.Sprint("m", i)))
	}
	assert.Equal(t, dropBefore+2, statOf("nr-test", "default").Dropped)
	require.NoError(t, sh.Close())
	require.Equal(t, 3, srv.events())
	assert.Equal(t, "m2", srv.bodies[0][0]["message"], "the oldest events were dropped")
}

func TestNewRelicShipperNeverBlocks(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	defer srv.Close()
	defer close(block)
	defer mockVar(&NewRelicTransport, srv.Client().Transport)()
	sh := newNewRelicShipper("nr-hang", NewRelicOption{Endpoint: srv.URL, Key: testNRKey})
	sh.timeout = 200 * time.Millisecond
	sh.interval = 5 * time.Millisecond
	start := time.Now()
	for range 1000 {
		_, _ = sh.Write(ev("default", "x"))
	}
	assert.Less(t, time.Since(start), time.Second)
	start = time.Now()
	require.NoError(t, sh.Close())
	assert.Less(t, time.Since(start), 3*time.Second, "close is bounded")
}

func TestNewRelicOptionValidateAndSecrecy(t *testing.T) {
	ok := NewRelicOption{Endpoint: "https://log-api.newrelic.com/log/v1", Key: testNRKey}
	require.NoError(t, ok.Validate())
	for _, o := range []NewRelicOption{
		{Endpoint: ok.Endpoint},
		{Endpoint: "http://log-api.newrelic.com/log/v1", Key: testNRKey},
		{Endpoint: "log-api.newrelic.com", Key: testNRKey},
		{Endpoint: "https://u:p@log-api.newrelic.com/", Key: testNRKey},
		{Endpoint: "https://log-api.newrelic.com/?x=1", Key: testNRKey},
		{Endpoint: "", Key: testNRKey},
	} {
		err := o.Validate()
		require.Error(t, err, o.Endpoint)
		assert.NotContains(t, err.Error(), testNRKey)
		assert.NotContains(t, err.Error(), "u:p")
	}
	b, err := json.Marshal(ok)
	require.NoError(t, err)
	assert.NotContains(t, string(b), testNRKey)
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		assert.NotContains(t, fmt.Sprintf(f, ok), testNRKey, f)
		assert.NotContains(t, fmt.Sprintf(f, &ok), testNRKey, f)
	}
}

func TestNewRelicWriterEndToEnd(t *testing.T) {
	srv := newNRServer(t, 202)
	defer mockVar(&NewRelicTransport, srv.Client().Transport)()
	w := NewEventWriterNewRelic("newrelic", WriterMode{Level: INFO, WriterOption: NewRelicOption{Endpoint: srv.URL, Key: testNRKey}})
	l := NewLoggerWithWriters(t.Context(), "router", w)
	l.Info("key %s and Authorization: Bearer abcdef123456", testNRKey)
	l.Close()
	require.Equal(t, 1, srv.events())
	e := srv.bodies[0][0]
	assert.Equal(t, "router", e["logtype"])
	assert.Equal(t, "key [REDACTED] and Authorization: [REDACTED]", e["message"])
}

func TestNewRelicNothingStartsWhenUnused(t *testing.T) {
	called := false
	defer mockVar[http.RoundTripper](&NewRelicTransport, roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, io.EOF
	}))()
	text := NewEventWriterBuffer("t", WriterMode{Level: INFO, Flags: FlagsFromString("none")}).(EventWriterBuffer)
	l := NewLoggerWithWriters(t.Context(), "default", text)
	l.Info("plain")
	l.Close()
	assert.Equal(t, "plain\n", text.GetString())
	assert.False(t, called)
	// a configured-but-idle writer starts no goroutine and makes no request
	w := NewEventWriterNewRelic("idle", WriterMode{WriterOption: NewRelicOption{Endpoint: "https://x.invalid/", Key: testNRKey}})
	assert.Nil(t, w.Base().OutputWriteCloser.(*newRelicShipper).done)
	assert.False(t, called)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestShippingStatsAreSortedAndCopied(t *testing.T) {
	addShipping("w-sort", "b", 1, 0, 0)
	addShipping("w-sort", "a", 1, 2, 3)
	var got []ShippingStat
	for _, st := range ShippingStatsSnapshot() {
		if st.Writer == "w-sort" {
			got = append(got, st)
		}
	}
	require.Len(t, got, 2)
	assert.Equal(t, ShippingStat{Writer: "w-sort", Logger: "a", Sent: 1, Dropped: 2, Errors: 3}, got[0])
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = old
	_ = w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}

func mockVar[T any](p *T, v T) func() {
	old := *p
	*p = v
	return func() { *p = old }
}

func TestNewRelicShipperRetryAfterAndBackoffAcrossBatches(t *testing.T) {
	srv := newNRServer(t, 429)
	srv.retryAfter = "70" // above the 60 s cap
	var sleeps []time.Duration
	sh := testShipper(t, srv, &sleeps)
	sh.interval = 5 * time.Millisecond
	drops := statOf("nr-test", "default").Dropped
	_, _ = sh.Write(ev("default", "first"))
	assert.Eventually(t, func() bool { return statOf("nr-test", "default").Dropped == drops+1 }, 5*time.Second, 5*time.Millisecond)
	_, _ = sh.Write(ev("default", "second"))
	assert.Eventually(t, func() bool { return statOf("nr-test", "default").Dropped == drops+2 }, 5*time.Second, 5*time.Millisecond)
	require.NoError(t, sh.Close())

	// 4 waits inside the first batch, then the second batch waits before its first attempt as well
	require.Len(t, sleeps, 4+5)
	assert.Equal(t, time.Minute, sleeps[0], "Retry-After is honoured up to a minute")
	assert.GreaterOrEqual(t, sleeps[4], 24*time.Second, "backoff state is kept across batches")
}

func TestNewRelicShipperNetworkErrorLeaksNothing(t *testing.T) {
	defer mockVar[http.RoundTripper](&NewRelicTransport, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("dial failed for %s with %v", r.URL, r.Header)
	}))()
	sh := newNewRelicShipper("nr-neterr", NewRelicOption{Endpoint: "https://nr.invalid/log", Key: testNRKey})
	sh.interval = 5 * time.Millisecond
	sh.sleep = func(context.Context, time.Duration) bool { return true }
	stderr := captureStderr(t, func() {
		_, _ = sh.Write(ev("default", "x"))
		assert.Eventually(t, func() bool { return statOf("nr-neterr", "default").Dropped == 1 }, 5*time.Second, 5*time.Millisecond)
		require.NoError(t, sh.Close())
	})
	assert.NotContains(t, stderr, testNRKey)
	assert.Equal(t, uint64(5), statOf("nr-neterr", "default").Errors)
}

func TestNewRelicQueueCountsFormattedBytes(t *testing.T) {
	srv := newNRServer(t, 202)
	sh := testShipper(t, srv, nil)
	sh.maxBytes = 100 * 1024
	before := statOf("nr-test", "default").Dropped
	big := strings.Repeat("x", 40*1024)
	for range 5 {
		_, _ = sh.Write(ev("default", big))
	}
	assert.Equal(t, before+3, statOf("nr-test", "default").Dropped, "5 x 40 KB don't fit in 100 KB: the 3 oldest go")
}

func TestEventFormatJSONFieldCapsAndRedactionOrder(t *testing.T) {
	const marker = len("…[truncated]")
	secret := " access_token=SECRETVALUE0123"
	// an event without Fields has the 32 KB message cap; the secret straddles the final cut, and the 2x pre-cut
	for name, pad := range map[string]int{"final cut": maxJSONMessage - 8, "pre-cut": 2*maxJSONMessage - 8} {
		m := formatJSON(t, &Event{Level: INFO, Logger: "default", MsgSimpleText: strings.Repeat("a", pad) + secret})
		msg := m["message"].(string)
		assert.NotContains(t, msg, "SECRET", name)
		assert.NotContains(t, msg, "access_token=S", name)
		assert.LessOrEqual(t, len(msg), maxJSONMessage+marker, name)
	}

	// structured (access) events: 4 KB message, 2 KB for every client controlled field, each checked on its own
	huge := strings.Repeat("x", 900*1024)
	m := formatJSON(t, &Event{
		Level: INFO, Logger: "access", MsgSimpleText: huge,
		Fields: map[string]any{"user_agent": huge, "path": "/?" + huge, "user": huge, "ip": huge},
	})
	assert.LessOrEqual(t, len(m["message"].(string)), maxJSONLine+marker)
	assert.Greater(t, len(m["message"].(string)), maxJSONField, "the message cap is the larger one")
	for _, f := range []string{"user_agent", "path", "user", "ip"} {
		assert.LessOrEqual(t, len(m[f].(string)), maxJSONField+marker, f)
		assert.Greater(t, len(m[f].(string)), maxJSONField-1, f)
	}
	m = formatJSON(t, &Event{Level: INFO, Logger: "access", MsgSimpleText: "x", Fields: map[string]any{"path": strings.Repeat("a", maxJSONField-8) + "?password=zz"}})
	assert.NotContains(t, m["path"], "zz")
	assert.Equal(t, "/x?token=[REDACTED]", formatJSON(t, &Event{Level: INFO, Fields: map[string]any{"path": "/x?token=" + strings.Repeat("t", 5000)}})["path"])

	// the rendered access line carries the same credentials as the path field
	line := `203.0.113.7 - - [09/Oct/2026:10:00:00 +0000] "GET /x?password=hunter2&page=2 HTTP/1.1" 200 5 "https://h/r?access_token=REFTOKEN123" "agent"`
	m = formatJSON(t, &Event{Level: INFO, Logger: "access", MsgSimpleText: line})
	assert.NotContains(t, m["message"], "hunter2")
	assert.NotContains(t, m["message"], "REFTOKEN123")
	assert.Contains(t, m["message"], "page=2")
}

func TestFormatJSONThroughFileAndConnWriters(t *testing.T) {
	// a real file writer
	file := filepath.Join(t.TempDir(), "json.log")
	fw := NewEventWriterFile("f", WriterMode{Level: INFO, Format: "json", WriterOption: WriterFileOption{FileName: file}})
	l := NewLoggerWithWriters(t.Context(), "access", fw)
	l.LogWithFields(0, INFO, map[string]any{"status": 200, "path": "/x?token=abc"}, "GET /x?token=abc")
	l.Close()
	b, err := os.ReadFile(file)
	require.NoError(t, err)
	m := map[string]any{}
	require.NoError(t, json.Unmarshal(b, &m))
	assert.Equal(t, "access", m["logtype"])
	assert.InDelta(t, 200, m["status"], 0)
	assert.Equal(t, "/x?token=[REDACTED]", m["path"])

	// a real conn writer
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		got <- line
	}()
	cw := NewEventWriterConn("c", WriterMode{Level: INFO, Format: "json", WriterOption: WriterConnOption{Addr: ln.Addr().String(), Protocol: "tcp"}})
	l = NewLoggerWithWriters(t.Context(), "xorm", cw)
	l.Warn("Authorization: Bearer abcdef123456")
	select {
	case line := <-got:
		m = map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		assert.Equal(t, "xorm", m["logtype"])
		assert.Equal(t, "warn", m["level"])
		assert.Equal(t, "Authorization: [REDACTED]", m["message"])
	case <-time.After(5 * time.Second):
		t.Fatal("no event on the conn writer")
	}
	l.Close()
}

func TestJSONFormattingRunsInWriterGoroutine(t *testing.T) {
	release := make(chan struct{})
	w := NewEventWriterBuffer("lazy", WriterMode{Level: INFO})
	w.Base().FormatEvent = func(*WriterMode, *Event) []byte { <-release; return []byte("late\n") }
	l := NewLoggerWithWriters(t.Context(), "default", w)
	returned := make(chan struct{})
	go func() { l.Info("never formatted by the caller"); close(returned) }()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("log.Info waited for the formatter")
	}
	close(release)
	l.Close()
	assert.Equal(t, "late\n", w.(EventWriterBuffer).GetString())
}

func TestParseRetryAfter(t *testing.T) {
	assert.Equal(t, 7*time.Second, parseRetryAfter("7"))
	assert.Equal(t, time.Minute, parseRetryAfter("100000"))
	assert.Equal(t, time.Duration(0), parseRetryAfter("-5"))
	assert.Equal(t, time.Duration(0), parseRetryAfter("junk"))
	assert.Equal(t, time.Duration(0), parseRetryAfter(""))
	d := parseRetryAfter(time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat))
	assert.InDelta(t, 30*time.Second, d, float64(2*time.Second))
	assert.Equal(t, time.Duration(0), parseRetryAfter(time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)))
}

func TestNewRelicShipperFlushOnClose(t *testing.T) {
	srv := newNRServer(t, 202)
	sh := testShipper(t, srv, nil) // 1 h ticker: only Close can send
	for i := range 3 {
		_, _ = sh.Write(ev("default", fmt.Sprint("m", i)))
	}
	assert.Equal(t, 0, srv.requests())
	start := time.Now()
	require.NoError(t, sh.Close())
	assert.Less(t, time.Since(start), newRelicFinalTimeout+time.Second)
	assert.Equal(t, 3, srv.events())
	require.NoError(t, sh.Close(), "Close is idempotent")
}

func TestNewRelicShipperWriteAfterCloseStartsNothing(t *testing.T) {
	srv := newNRServer(t, 202)
	sh := testShipper(t, srv, nil)
	require.NoError(t, sh.Close())
	before := statOf("nr-test", "default").Dropped
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() { _, _ = sh.Write(ev("default", "late")) })
	}
	wg.Wait()
	assert.Nil(t, sh.done, "no flusher goroutine after close")
	assert.Equal(t, before+10, statOf("nr-test", "default").Dropped)
	assert.Equal(t, 0, srv.requests())
}

func TestNewRelicShipperDropsOversizedItem(t *testing.T) {
	srv := newNRServer(t, 202)
	sh := testShipper(t, srv, nil)
	before := statOf("nr-test", "default").Dropped
	_, _ = sh.Write(ev("default", strings.Repeat("x", newRelicBatchBytes+1)))
	_, _ = sh.Write(ev("default", "ok"))
	assert.Equal(t, before+1, statOf("nr-test", "default").Dropped)
	require.NoError(t, sh.Close())
	assert.Equal(t, 1, srv.events())
}

func TestNewRelicDumpWritersLacksKey(t *testing.T) {
	w := NewEventWriterNewRelic("dump", WriterMode{Level: INFO, WriterOption: NewRelicOption{Endpoint: "https://nr.invalid/log", Key: "NRAK-DUMPKEY0123456789"}})
	l := NewLoggerWithWriters(t.Context(), "default", w)
	defer l.Close()
	b, err := json.Marshal(l.DumpWriters())
	require.NoError(t, err)
	assert.Contains(t, string(b), "nr.invalid")
	assert.NotContains(t, string(b), "NRAK-DUMPKEY")
}

func TestHugeClientInputIsBounded(t *testing.T) {
	huge := strings.Repeat("a=b&token=c&", 75000) // 900 KB
	start := time.Now()
	b := EventFormatJSONMessage(&WriterMode{}, &Event{
		Level: INFO, Logger: "access", MsgSimpleText: "GET /?" + huge + " " + huge,
		Fields: map[string]any{"path": "/?" + huge, "user_agent": huge, "user": huge, "ip": huge},
	})
	assert.Less(t, time.Since(start), 2*time.Second)
	assert.Less(t, len(b), 128*1024, "JSON escaping can grow & and < up to 6x")
	assert.Less(t, len(b), newRelicBatchBytes)

	m := formatJSON(t, &Event{Level: INFO, Logger: "access", MsgSimpleText: "x", Fields: map[string]any{"path": strings.Repeat("a", 900*1024) + "?password=zz"}})
	assert.LessOrEqual(t, len(m["path"].(string)), maxJSONField+len("…[truncated]"))
}

func TestSSHLoggerLogtype(t *testing.T) {
	m := NewManager()
	defer m.Close()
	w := NewEventWriterBuffer("j", WriterMode{Level: INFO, Format: "json"}).(EventWriterBuffer)
	m.GetLogger("ssh").AddWriters(w)
	m.GetLogger("ssh").Info("accepted")
	m.GetLogger("ssh").Close()
	assert.Contains(t, w.GetString(), `"logtype":"ssh"`)
}
