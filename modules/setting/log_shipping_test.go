// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validDestination() LogShippingDestination {
	return LogShippingDestination{
		ID: "ab12cd34", Name: "newrelic-eu", Type: "newrelic", Endpoint: "https://log-api.eu.newrelic.com/log/v1",
		KeyEnc: "x", Enabled: true, LogTypes: []string{"access", "application"}, Level: "info",
	}
}

func TestLogShippingDestinationValidate(t *testing.T) {
	require.NoError(t, validDestination().Validate())

	mutate := func(f func(d *LogShippingDestination)) LogShippingDestination {
		d := validDestination()
		f(&d)
		return d
	}
	generic := func(f func(d *LogShippingDestination)) LogShippingDestination {
		return mutate(func(d *LogShippingDestination) {
			d.Type, d.KeyEnc = "http", ""
			f(d)
		})
	}
	headers := func(n int) []LogShippingHeader {
		h := make([]LogShippingHeader, n)
		for i := range h {
			h[i] = LogShippingHeader{Name: "X-H" + strings.Repeat("a", i), ValueEnc: "v"}
		}
		return h
	}
	bad := map[string]LogShippingDestination{
		"empty name":       mutate(func(d *LogShippingDestination) { d.Name = "" }),
		"upper-case name":  mutate(func(d *LogShippingDestination) { d.Name = "NewRelic" }),
		"name with slash":  mutate(func(d *LogShippingDestination) { d.Name = "a/b" }),
		"long name":        mutate(func(d *LogShippingDestination) { d.Name = strings.Repeat("a", 33) }),
		"bad id":           mutate(func(d *LogShippingDestination) { d.ID = "../x" }),
		"unknown type":     mutate(func(d *LogShippingDestination) { d.Type = "splunk" }),
		"newrelic no key":  mutate(func(d *LogShippingDestination) { d.KeyEnc = "" }),
		"http endpoint":    mutate(func(d *LogShippingDestination) { d.Endpoint = "http://example.org/x" }),
		"userinfo":         mutate(func(d *LogShippingDestination) { d.Endpoint = "https://u:p@example.org/x" }),
		"query":            mutate(func(d *LogShippingDestination) { d.Endpoint = "https://example.org/x?k=v" }),
		"fragment":         mutate(func(d *LogShippingDestination) { d.Endpoint = "https://example.org/x#f" }),
		"unknown log type": mutate(func(d *LogShippingDestination) { d.LogTypes = []string{"nope"} }),
		"database log":     mutate(func(d *LogShippingDestination) { d.LogTypes = []string{"database"} }),
		"no log type":      mutate(func(d *LogShippingDestination) { d.LogTypes = nil }),
		"bad level":        mutate(func(d *LogShippingDestination) { d.Level = "loud" }),
		"bad expression":   mutate(func(d *LogShippingDestination) { d.Expression = "(" }),
		"bad exclusion":    mutate(func(d *LogShippingDestination) { d.Exclusion = "(" }),
		"newrelic headers": mutate(func(d *LogShippingDestination) { d.Headers = headers(1) }),
		"newrelic ndjson":  mutate(func(d *LogShippingDestination) { d.NDJSON = true }),
		"header name":      generic(func(d *LogShippingDestination) { d.Headers = []LogShippingHeader{{Name: "bad name", ValueEnc: "v"}} }),
		"header name long": generic(func(d *LogShippingDestination) {
			d.Headers = []LogShippingHeader{{Name: strings.Repeat("a", 65), ValueEnc: "v"}}
		}),
		"too many headers": generic(func(d *LogShippingDestination) { d.Headers = headers(11) }),
		"duplicate header": generic(func(d *LogShippingDestination) {
			d.Headers = []LogShippingHeader{{Name: "X-A", ValueEnc: "v"}, {Name: "x-a", ValueEnc: "v"}}
		}),
		"header without val": generic(func(d *LogShippingDestination) { d.Headers = []LogShippingHeader{{Name: "X-A"}} }),
	}
	for _, name := range []string{"Host", "content-length", "Content-Encoding", "CONTENT-TYPE", "Transfer-Encoding", "Connection", "Upgrade", "TE", "trailer", "Expect", "Proxy-Authorization", "proxy-x"} {
		bad["forbidden header "+name] = generic(func(d *LogShippingDestination) { d.Headers = []LogShippingHeader{{Name: name, ValueEnc: "v"}} })
	}
	for name, d := range bad {
		err := d.Validate()
		require.Error(t, err, name)
		assert.NotContains(t, err.Error(), "p@", name)
	}

	assert.NoError(t, generic(func(d *LogShippingDestination) {
		d.Headers = []LogShippingHeader{{Name: "Authorization", ValueEnc: "v"}}
		d.NDJSON = true
	}).Validate())
	assert.NoError(t, generic(func(d *LogShippingDestination) { d.Endpoint = "http://localhost:8080/in" }).Validate())
}

func TestLogShippingLoggers(t *testing.T) {
	d := validDestination()
	assert.Equal(t, []string{"access", "default"}, d.Loggers())
	d.LogTypes = []string{"all"}
	assert.Equal(t, []string{"access", "default", "router", "ssh"}, d.Loggers())
	d.LogTypes = []string{"git", "router", "git"}
	assert.Equal(t, []string{"router", "ssh"}, d.Loggers())
	assert.True(t, d.HasLogType("git"))
	assert.False(t, d.HasLogType("access"))

	// "all" never selects audit (IPs and user agents): it must be named
	d.LogTypes = []string{"all"}
	assert.False(t, d.HasLogType("audit"))
	assert.False(t, d.StreamsAudit())
	d.LogTypes = []string{"all", "audit"}
	assert.Equal(t, []string{"access", "audit", "default", "router", "ssh"}, d.Loggers())
	assert.True(t, d.StreamsAudit())
	d.Enabled = false
	assert.False(t, d.StreamsAudit())
	assert.Contains(t, LogShippingLogTypes(), "audit")
}

func TestLogShippingLoki(t *testing.T) {
	loki := func(f func(d *LogShippingDestination)) LogShippingDestination {
		d := validDestination()
		d.Type, d.Endpoint, d.KeyEnc, d.LogTypes = LogShippingLoki, "https://loki.example.org/loki/api/v1/push", "", []string{"audit"}
		f(&d)
		return d
	}
	require.NoError(t, loki(func(d *LogShippingDestination) {
		d.Headers = []LogShippingHeader{{Name: "Authorization", ValueEnc: "v"}}
	}).Validate())
	require.Error(t, loki(func(d *LogShippingDestination) { d.KeyEnc = "x" }).Validate(), "a key would be silently unused")
	require.Error(t, loki(func(d *LogShippingDestination) { d.NDJSON = true }).Validate())
	require.Error(t, loki(func(d *LogShippingDestination) { d.Endpoint = "https://u:p@loki.example.org/x" }).Validate())
}

func TestLogShippingDestinationStringHidesSecrets(t *testing.T) {
	d := validDestination()
	d.KeyEnc = "KEYCIPHER"
	d.Headers = []LogShippingHeader{{Name: "X-A", ValueEnc: "VALUECIPHER"}}
	for _, out := range []string{d.String(), d.GoString(), fmt.Sprintf("%v %+v %#v", d, d, d)} {
		assert.NotContains(t, out, "KEYCIPHER")
		assert.NotContains(t, out, "VALUECIPHER")
	}
}
