// Copyright 2026 The gitdepo contributors.
// SPDX-License-Identifier: GPL-3.0-or-later

package log

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"forgejo.org/modules/json"
)

// ShipTransport replaces the HTTP transport of the HTTP shipping writers. It is only set by tests.
var ShipTransport http.RoundTripper

// HTTPShipOption holds the settings of an "http" writer. The key and the header values never leave it: not in JSON (the
// admin configuration page dumps writer options), not in formatted output, not in errors.
type HTTPShipOption struct {
	Format   string // "newrelic", "http" or "loki"
	Endpoint string
	Key      string            `json:"-"` // newrelic only
	Headers  map[string]string `json:"-"` // http and loki only
	NDJSON   bool              // http only: one event per line instead of a JSON array
	// DialContext, if set, makes every connection and disables the proxy; it checks the resolved address.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error) `json:"-"`
}

func (o HTTPShipOption) String() string {
	return "HTTPShipOption{Format:" + o.Format + " Endpoint:" + o.Endpoint + "}"
}
func (o HTTPShipOption) GoString() string { return o.String() }

// Validate returns an error that names the setting and never contains the key or a header value.
func (o HTTPShipOption) Validate() error {
	if o.Format != "newrelic" && o.Format != "http" && o.Format != "loki" {
		return errors.New("unknown format")
	}
	if o.Format == "newrelic" && o.Key == "" {
		return errors.New("a key is required")
	}
	if o.Format == "loki" && (o.Key != "" || o.NDJSON) { // Loki auth is a custom header; a key would be silently unused
		return errors.New("a key and NDJSON are not used by Loki")
	}
	u, err := url.Parse(o.Endpoint)
	if err != nil || u.Host == "" {
		return errors.New("the endpoint must be an https:// URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return errors.New("the endpoint must be an https:// URL (http:// only for localhost)")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the endpoint must not contain credentials, a query or a fragment")
	}
	return nil
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.Unmap().IsLoopback()
}

// NewEventWriterHTTP ships JSON events to an HTTP endpoint. Nothing runs until the first event is written.
func NewEventWriterHTTP(name string, mode WriterMode) EventWriter {
	w := NewEventWriterBase(name, "http", mode)
	// the shipper needs the logger name for its counters: it is the first line of every message
	w.FormatEvent = func(m *WriterMode, e *Event) []byte {
		return append([]byte(e.Logger+"\n"), EventFormatJSONMessage(m, e)...)
	}
	opt, _ := mode.WriterOption.(HTTPShipOption)
	if err := opt.Validate(); err != nil {
		FallbackErrorf("log writer %q is disabled: %v", name, err)
		w.OutputWriteCloser = nopCloser{io.Discard}
		return w
	}
	RegisterSecret(opt.Key)
	for _, v := range opt.Headers {
		RegisterSecret(v)
	}
	w.OutputWriteCloser = newHTTPShipper(name, opt)
	return w
}

func init() {
	RegisterEventWriter("http", NewEventWriterHTTP)
}

type shipItem struct {
	logger string
	data   []byte
}

type httpShipper struct {
	name     string
	opt      HTTPShipOption
	format   shipFormat
	client   *http.Client
	interval time.Duration
	timeout  time.Duration
	sleep    func(context.Context, time.Duration) bool // false when ctx is done

	maxEvents, maxBytes int

	failures   int           // consecutive failed attempts, kept across batches (flusher goroutine only)
	retryAfter time.Duration // from the last Retry-After header

	disabled atomic.Bool // set after 401/403
	logged   atomic.Bool // set after the first "other 4xx" message

	mu     sync.Mutex
	buf    []shipItem
	size   int
	closed bool

	closeOnce sync.Once
	ctx       context.Context // these four are set under mu when the flusher starts
	cancel    context.CancelFunc
	wake      chan struct{}
	done      chan struct{}
}

func newHTTPShipper(name string, opt HTTPShipOption) *httpShipper {
	rt := ShipTransport
	if rt == nil {
		rt = NewRelicTransport
	}
	if rt == nil {
		t := &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     90 * time.Second,
		}
		if opt.DialContext != nil {
			// the dial hook checks the resolved address, which a proxy would hide
			t.Proxy, t.DialContext = nil, opt.DialContext
		}
		rt = t
	}
	var format shipFormat = httpFormat{opt}
	switch opt.Format {
	case "newrelic":
		format = newRelicFormat{opt}
	case "loki":
		format = lokiFormat{opt}
	}
	return &httpShipper{
		name:   name,
		opt:    opt,
		format: format,
		client: &http.Client{
			Transport: rt,
			// never follow redirects: Go would forward the key and headers to a same-domain target
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		interval:  5 * time.Second,
		timeout:   10 * time.Second,
		maxEvents: newRelicMaxEvents,
		maxBytes:  newRelicMaxBytes,
		sleep: func(ctx context.Context, d time.Duration) bool {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				return true
			case <-ctx.Done():
				return false
			}
		},
	}
}

func (s *httpShipper) count(items []shipItem, sent, dropped, errs bool) {
	per := map[string]uint64{}
	for _, it := range items {
		per[it.logger]++
	}
	for logger, n := range per {
		var a, b, c uint64
		if sent {
			a = n
		}
		if dropped {
			b = n
		}
		if errs {
			c = 1 // one error per failed attempt and logger
		}
		addShipping(s.name, logger, a, b, c)
	}
}

// Write only appends to the bounded buffer, so it never waits for the network.
func (s *httpShipper) Write(p []byte) (int, error) {
	logger, data, _ := strings.Cut(string(p), "\n")
	it := shipItem{logger, []byte(strings.TrimSuffix(data, "\n"))}
	if s.disabled.Load() {
		s.count([]shipItem{it}, false, true, false)
		return len(p), nil
	}
	s.mu.Lock()
	if s.closed || len(it.data) > newRelicBatchBytes { // the formatter caps events far below a batch
		s.mu.Unlock()
		s.count([]shipItem{it}, false, true, false)
		return len(p), nil
	}
	if s.cancel == nil { // first event: the flusher exists only from now on
		s.ctx, s.cancel = context.WithCancel(context.Background())
		s.wake = make(chan struct{}, 1)
		s.done = make(chan struct{})
		go s.loop()
	}
	s.buf = append(s.buf, it)
	s.size += len(it.data)
	var dropped []shipItem
	for len(s.buf) > s.maxEvents || s.size > s.maxBytes {
		dropped = append(dropped, s.buf[0])
		s.size -= len(s.buf[0].data)
		s.buf = s.buf[1:]
	}
	full := s.size >= newRelicBatchBytes
	s.mu.Unlock()

	s.count(dropped, false, true, false)
	if full {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
	return len(p), nil
}

func (s *httpShipper) loop() {
	defer close(s.done)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		case <-s.wake:
		}
		s.flush(s.ctx, newRelicMaxAttempts)
	}
}

// take removes up to one batch from the buffer; when shipping is disabled it discards everything.
func (s *httpShipper) take() []shipItem {
	s.mu.Lock()
	n, size := 0, 0
	for n < len(s.buf) && (n == 0 || size+len(s.buf[n].data)+1 <= newRelicBatchBytes || s.disabled.Load()) {
		size += len(s.buf[n].data) + 1
		n++
	}
	items := s.buf[:n:n]
	s.buf = s.buf[n:]
	s.size -= size - n
	s.mu.Unlock()
	if s.disabled.Load() {
		s.count(items, false, true, false)
		return nil
	}
	return items
}

func (s *httpShipper) requeue(items []shipItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(slices.Clip(items), s.buf...)
	for _, it := range items {
		s.size += len(it.data)
	}
}

func (s *httpShipper) flush(ctx context.Context, attempts int) {
	for {
		items := s.take()
		if len(items) == 0 || !s.send(ctx, items, attempts) {
			return
		}
	}
}

func (s *httpShipper) post(ctx context.Context, body []byte) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.opt.Endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("invalid request")
	}
	req.Header = s.format.Headers() // only here, so no error or log line can carry the request
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	s.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, nil
}

// parseRetryAfter reads seconds or an HTTP date; the result is between 0 and newRelicMaxRetryAfter.
func parseRetryAfter(h string) time.Duration {
	var d time.Duration
	if secs, err := strconv.Atoi(h); err == nil {
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(h); err == nil {
		d = time.Until(t)
	}
	return max(0, min(d, newRelicMaxRetryAfter))
}

func backoff(attempt int) time.Duration {
	d := min(time.Second<<min(attempt, 6), 30*time.Second)
	return d + time.Duration((rand.Float64()*0.4-0.2)*float64(d))
}

// send reports false when the batch was put back because ctx ended.
func (s *httpShipper) send(ctx context.Context, items []shipItem, attempts int) bool {
	body := s.format.Encode(items)
	for range attempts {
		// back off before every attempt after a failure, also for the first attempt of the next batch, so a
		// dead endpoint is not hit again on every tick (the final flush on close makes one attempt without waiting)
		if s.failures > 0 && attempts > 1 {
			wait := max(backoff(s.failures-1), s.retryAfter)
			s.retryAfter = 0
			if !s.sleep(ctx, wait) {
				s.requeue(items)
				return false
			}
		}
		code, err := s.post(ctx, body)
		switch {
		case err != nil && ctx.Err() != nil:
			s.requeue(items)
			return false
		case err == nil && code/100 == 2:
			s.failures = 0
			setShippingStatus(s.name, true, "")
			s.count(items, true, false, false)
			return true
		case err == nil && (code == http.StatusUnauthorized || code == http.StatusForbidden):
			setShippingStatus(s.name, false, statusClass(code))
			if s.disabled.CompareAndSwap(false, true) {
				FallbackErrorf("log writer %q: %s rejected the credentials (HTTP %d); shipping is disabled until restart", s.name, s.format.Label(), code)
			}
			s.count(items, false, true, true)
			return true
		case err == nil && code != http.StatusTooManyRequests && code < 500:
			setShippingStatus(s.name, false, statusClass(code))
			if s.logged.CompareAndSwap(false, true) {
				FallbackErrorf("log writer %q: %s rejected a batch (HTTP %d); dropping it", s.name, s.format.Label(), code)
			}
			s.count(items, false, true, true)
			return true
		}
		s.failures++
		setShippingStatus(s.name, false, failureClass(code, err))
		s.count(items, false, false, true)
	}
	s.count(items, false, true, false)
	return true
}

// Close stops the flusher and makes one last attempt for what is buffered, within a short deadline.
func (s *httpShipper) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		cancel, done := s.cancel, s.done
		s.mu.Unlock()
		if cancel == nil {
			return
		}
		cancel()
		<-done
		ctx, cancel := context.WithTimeout(context.Background(), newRelicFinalTimeout)
		defer cancel()
		s.flush(ctx, 1)
		s.mu.Lock()
		rest := s.buf
		s.buf, s.size = nil, 0
		s.mu.Unlock()
		s.count(rest, false, true, false)
	})
	return nil
}

// statusClass and failureClass name an outcome without anything the remote or the network said.
func statusClass(code int) string {
	return fmt.Sprintf("status %dxx", code/100)
}

func failureClass(code int, err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return statusClass(code)
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return "timeout"
	}
	return "connection failed"
}

// ProbeHTTP sends one event to the endpoint and returns the status code. The error is a class only ("connection
// failed" or "timeout"), never the text of the network error or the remote's answer.
func ProbeHTTP(ctx context.Context, name string, opt HTTPShipOption, event []byte) (int, error) {
	s := newHTTPShipper(name, opt)
	code, err := s.post(ctx, s.format.Encode([]shipItem{{logger: "test", data: event}}))
	if err != nil {
		return 0, errors.New(failureClass(0, err))
	}
	return code, nil
}

type shipFormat interface {
	Headers() http.Header
	Encode(items []shipItem) []byte
	Label() string
}

type newRelicFormat struct{ opt HTTPShipOption }

func (newRelicFormat) Label() string { return "New Relic" }

func (f newRelicFormat) Headers() http.Header {
	return http.Header{"Api-Key": {f.opt.Key}, "Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}}
}

func (newRelicFormat) Encode(items []shipItem) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(jsonArray(items))
	_ = zw.Close()
	return buf.Bytes()
}

type httpFormat struct{ opt HTTPShipOption }

func (httpFormat) Label() string { return "the HTTP destination" }

func (f httpFormat) Headers() http.Header {
	h := http.Header{}
	for k, v := range f.opt.Headers {
		h.Set(k, v)
	}
	h.Set("Content-Type", "application/json")
	if f.opt.NDJSON {
		h.Set("Content-Type", "application/x-ndjson")
	}
	return h
}

func (f httpFormat) Encode(items []shipItem) []byte {
	if !f.opt.NDJSON {
		return jsonArray(items)
	}
	var buf bytes.Buffer
	for _, it := range items {
		buf.Write(it.data)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// lokiFormat posts to Loki's push API. The labels come from closed sets, never from the event's text.
type lokiFormat struct{ opt HTTPShipOption }

func (lokiFormat) Label() string { return "Loki" }

func (f lokiFormat) Headers() http.Header {
	h := http.Header{}
	for k, v := range f.opt.Headers {
		h.Set(k, v)
	}
	h.Set("Content-Type", "application/json")
	return h
}

var (
	lokiLogtypes = []string{"application", "access", "router", "ssh", "audit", "test"}
	lokiLevels   = []string{"trace", "debug", "info", "warn", "error", "fatal"}
)

type lokiValue struct {
	ts   int64 // ns
	line string
}

func (lokiFormat) Encode(items []shipItem) []byte {
	type key struct{ logtype, level string }
	groups := map[key][]lokiValue{}
	var order []key
	now := time.Now().UnixNano()
	for _, it := range items {
		var e struct {
			Timestamp int64  `json:"timestamp"` // ms
			Logtype   string `json:"logtype"`
			Level     string `json:"level"`
		}
		k, ts := key{"application", "info"}, now
		if json.Unmarshal(it.data, &e) == nil { // an unparsable line is kept under the default labels
			if slices.Contains(lokiLogtypes, e.Logtype) {
				k.logtype = e.Logtype
			}
			if slices.Contains(lokiLevels, e.Level) {
				k.level = e.Level
			}
			if e.Timestamp > 0 {
				ts = e.Timestamp * int64(time.Millisecond)
			}
		}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], lokiValue{ts, string(it.data)})
	}
	type stream struct {
		Stream map[string]string `json:"stream"`
		Values [][2]string       `json:"values"`
	}
	streams := make([]stream, 0, len(order))
	for _, k := range order {
		vs := groups[k]
		slices.SortStableFunc(vs, func(a, b lokiValue) int { return cmp.Compare(a.ts, b.ts) })
		st := stream{Stream: map[string]string{"service": ServiceName, "logtype": k.logtype, "level": k.level}}
		for _, v := range vs {
			st.Values = append(st.Values, [2]string{strconv.FormatInt(v.ts, 10), v.line})
		}
		streams = append(streams, st)
	}
	b, _ := json.Marshal(map[string]any{"streams": streams})
	return b
}

func jsonArray(items []shipItem) []byte {
	b := []byte("[")
	for i, it := range items {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, it.data...)
	}
	return append(b, ']')
}
