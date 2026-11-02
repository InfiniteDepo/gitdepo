// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"errors"
	"regexp"
	"slices"
	"strings"

	"forgejo.org/modules/log"
)

// The kinds of log destination.
const (
	LogShippingNewRelic = "newrelic"
	LogShippingHTTP     = "http"
	LogShippingLoki     = "loki"
)

// logShippingLoggers maps a log type to the logger it listens on.
var logShippingLoggers = map[string]string{"application": "default", "access": "access", "router": "router", "git": "ssh", "audit": "audit"}

var (
	logShippingNameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	logShippingIDRe     = regexp.MustCompile(`^[a-z0-9]{8}$`)
	logShippingHeaderRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	// headers the shipper sets itself or that change how the request is framed
	logShippingForbiddenHeaders = []string{"host", "content-length", "content-encoding", "content-type", "transfer-encoding", "connection", "upgrade", "te", "trailer", "expect"}
)

// LogShippingMaxHeaders and LogShippingMaxHeaderValue cap the custom headers of a destination.
const (
	LogShippingMaxHeaders     = 10
	LogShippingMaxHeaderValue = 1024
)

// LogShippingHeader is a custom header; its value is encrypted like a key.
type LogShippingHeader struct {
	Name     string `json:"name"`
	ValueEnc string `json:"value_enc"`
}

// LogShippingDestination is where one set of logs is shipped to. KeyEnc and the header values are encrypted with
// the secret key; nothing else here is secret.
type LogShippingDestination struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Type       string              `json:"type"`
	Endpoint   string              `json:"endpoint"`
	KeyEnc     string              `json:"key_enc,omitempty"`
	Headers    []LogShippingHeader `json:"headers,omitempty"`
	NDJSON     bool                `json:"ndjson,omitempty"`
	Enabled    bool                `json:"enabled"`
	LogTypes   []string            `json:"log_types"`
	Level      string              `json:"level"`
	Expression string              `json:"expression,omitempty"`
	Exclusion  string              `json:"exclusion,omitempty"`
}

// LogShippingState is the instance's log destinations, stored as JSON in the "log_shipping.destinations" system setting.
type LogShippingState struct {
	Destinations []LogShippingDestination `json:"destinations"`
}

// LogShippingLogTypes returns the log types a destination can select.
func LogShippingLogTypes() []string {
	return []string{"application", "access", "router", "git", "audit"}
}

// HasLogType reports whether the destination selects the log type ("all" selects every one but audit, whose events
// carry IP addresses and user agents and must be named).
func (d LogShippingDestination) HasLogType(t string) bool {
	return slices.Contains(d.LogTypes, t) || (t != "audit" && slices.Contains(d.LogTypes, "all"))
}

// StreamsAudit reports whether the destination is enabled and selects the audit log.
func (d LogShippingDestination) StreamsAudit() bool { return d.Enabled && d.HasLogType("audit") }

// Loggers returns the sorted, distinct loggers the destination listens on.
func (d LogShippingDestination) Loggers() []string {
	var out []string
	for t, logger := range logShippingLoggers {
		if d.HasLogType(t) {
			out = append(out, logger)
		}
	}
	slices.Sort(out)
	return out
}

// Validate checks the shape of the destination; it never looks at the network or the decrypted key.
// The errors never contain the endpoint's userinfo, query or any header value.
func (d LogShippingDestination) Validate() error {
	if !logShippingIDRe.MatchString(d.ID) {
		return errors.New("invalid ID")
	}
	if !logShippingNameRe.MatchString(d.Name) {
		return errors.New("the name must be 1-32 lower-case letters, digits or dashes")
	}
	switch d.Type {
	case LogShippingNewRelic:
		if d.KeyEnc == "" {
			return errors.New("a key is required")
		}
		if len(d.Headers) > 0 || d.NDJSON {
			return errors.New("custom headers and NDJSON are for HTTP destinations only")
		}
	case LogShippingHTTP:
	case LogShippingLoki:
		if d.KeyEnc != "" || d.NDJSON { // auth is a custom header; a key would be silently unused
			return errors.New("a key and NDJSON are not used by Loki")
		}
	default:
		return errors.New("unknown destination type")
	}
	// the format name only selects the key rule, which is checked above
	if err := (log.HTTPShipOption{Format: LogShippingHTTP, Endpoint: d.Endpoint}).Validate(); err != nil {
		return err
	}
	if len(d.LogTypes) == 0 {
		return errors.New("select at least one log type")
	}
	for _, t := range d.LogTypes {
		if _, ok := logShippingLoggers[t]; !ok && t != "all" {
			return errors.New("unknown log type")
		}
	}
	if !slices.Contains([]string{"trace", "debug", "info", "warn", "error"}, d.Level) {
		return errors.New("unknown level")
	}
	for _, expr := range []string{d.Expression, d.Exclusion} {
		if _, err := regexp.Compile(expr); err != nil {
			return errors.New("invalid regular expression")
		}
	}
	if len(d.Headers) > LogShippingMaxHeaders {
		return errors.New("too many headers")
	}
	seen := map[string]bool{}
	for _, h := range d.Headers {
		lower := strings.ToLower(h.Name)
		if !logShippingHeaderRe.MatchString(h.Name) || slices.Contains(logShippingForbiddenHeaders, lower) || strings.HasPrefix(lower, "proxy-") {
			return errors.New("invalid header name")
		}
		if seen[lower] {
			return errors.New("duplicate header name")
		}
		seen[lower] = true
		if h.ValueEnc == "" {
			return errors.New("a header needs a value")
		}
	}
	return nil
}

// String and GoString leave out the encrypted key and header values, so a log line or a dump can't carry them.
func (d LogShippingDestination) String() string {
	return "LogShippingDestination{ID:" + d.ID + " Name:" + d.Name + " Type:" + d.Type + " Endpoint:" + d.Endpoint + "}"
}

func (d LogShippingDestination) GoString() string { return d.String() }
