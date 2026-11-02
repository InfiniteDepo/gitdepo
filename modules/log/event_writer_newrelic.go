// Copyright 2026 The gitdepo contributors.
// SPDX-License-Identifier: GPL-3.0-or-later

package log

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

// NewRelicTransport replaces the HTTP transport of the New Relic writers. It is only set by tests.
var NewRelicTransport http.RoundTripper

const (
	newRelicBatchBytes    = 1 << 20
	newRelicMaxBytes      = 16 << 20
	newRelicMaxEvents     = 10000
	newRelicMaxAttempts   = 5
	newRelicFinalTimeout  = 1500 * time.Millisecond
	newRelicMaxRetryAfter = time.Minute
)

// NewRelicOption holds the settings of a "newrelic" writer. The key never leaves it: not in JSON (the admin
// configuration page dumps writer options), not in formatted output, not in errors.
type NewRelicOption struct {
	Endpoint string
	Key      string `json:"-"`
}

func (o NewRelicOption) String() string   { return "NewRelicOption{Endpoint:" + o.Endpoint + "}" }
func (o NewRelicOption) GoString() string { return o.String() }

// Validate returns an error that names the setting and never contains the key.
func (o NewRelicOption) Validate() error {
	if o.Key == "" {
		return errors.New("KEY or KEY_URI is required")
	}
	u, err := url.Parse(o.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("ENDPOINT must be an https:// URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("ENDPOINT must not contain credentials, a query or a fragment")
	}
	return nil
}

// NewEventWriterNewRelic ships JSON events to the New Relic Log API. Nothing runs until the first event is written.
func NewEventWriterNewRelic(name string, mode WriterMode) EventWriter {
	w := NewEventWriterBase(name, "newrelic", mode)
	// the shipper needs the logger name for its counters: it is the first line of every message
	w.FormatEvent = func(m *WriterMode, e *Event) []byte {
		return append([]byte(e.Logger+"\n"), EventFormatJSONMessage(m, e)...)
	}
	opt, _ := mode.WriterOption.(NewRelicOption)
	if err := opt.Validate(); err != nil {
		FallbackErrorf("log writer %q is disabled: %v", name, err)
		w.OutputWriteCloser = nopCloser{io.Discard}
		return w
	}
	RegisterSecret(opt.Key)
	w.OutputWriteCloser = newNewRelicShipper(name, opt)
	return w
}

func init() {
	RegisterEventWriter("newrelic", NewEventWriterNewRelic)
}

// newRelicShipper is the generic shipper with the New Relic format.
type newRelicShipper = httpShipper

func newNewRelicShipper(name string, opt NewRelicOption) *newRelicShipper {
	return newHTTPShipper(name, HTTPShipOption{Format: "newrelic", Endpoint: opt.Endpoint, Key: opt.Key})
}
