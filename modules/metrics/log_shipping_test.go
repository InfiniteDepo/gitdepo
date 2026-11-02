// Copyright 2026 The gitdepo contributors.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"forgejo.org/modules/log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogShippingCollectorEmptyWithoutWriter(t *testing.T) { // must run first: the counters are global
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(NewLogShippingCollector()))
	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	assert.NotContains(t, rec.Body.String(), "log_shipping_sent_total{")
}

func TestLogShippingCollector(t *testing.T) {
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(NewLogShippingCollector()))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }))
	defer srv.Close()
	log.NewRelicTransport = srv.Client().Transport
	defer func() { log.NewRelicTransport = nil }()

	w := log.NewEventWriterNewRelic("metrics-test", log.WriterMode{Level: log.INFO, WriterOption: log.NewRelicOption{Endpoint: srv.URL, Key: "NRAK-METRICSKEY0123456789"}})
	l := log.NewLoggerWithWriters(t.Context(), "xorm", w)
	l.Info("hello")
	l.Close()

	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	assert.Contains(t, body, `gitea_log_shipping_sent_total{logger="xorm",writer="metrics-test"} 1`)
	assert.Contains(t, body, `gitea_log_shipping_dropped_total{logger="xorm",writer="metrics-test"} 0`)
	assert.Contains(t, body, `gitea_log_shipping_errors_total{logger="xorm",writer="metrics-test"} 0`)
	assert.NotContains(t, body, "NRAK")
}
