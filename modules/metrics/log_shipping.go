// Copyright 2026 The gitdepo contributors.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import (
	"forgejo.org/modules/log"

	"github.com/prometheus/client_golang/prometheus"
)

// LogShippingCollector exposes the counters of the log shipping writers (e.g. "newrelic").
type LogShippingCollector struct {
	sent, dropped, errors *prometheus.Desc
}

func NewLogShippingCollector() *LogShippingCollector {
	desc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(namespace+"log_shipping_"+name+"_total", help, []string{"writer", "logger"}, nil)
	}
	return &LogShippingCollector{
		sent:    desc("sent", "Log events delivered to the remote log service"),
		dropped: desc("dropped", "Log events dropped before delivery (buffer full, rejected or undeliverable)"),
		errors:  desc("errors", "Failed attempts to deliver log events"),
	}
}

func (c *LogShippingCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.sent
	ch <- c.dropped
	ch <- c.errors
}

func (c *LogShippingCollector) Collect(ch chan<- prometheus.Metric) {
	for _, st := range log.ShippingStatsSnapshot() {
		ch <- prometheus.MustNewConstMetric(c.sent, prometheus.CounterValue, float64(st.Sent), st.Writer, st.Logger)
		ch <- prometheus.MustNewConstMetric(c.dropped, prometheus.CounterValue, float64(st.Dropped), st.Writer, st.Logger)
		ch <- prometheus.MustNewConstMetric(c.errors, prometheus.CounterValue, float64(st.Errors), st.Writer, st.Logger)
	}
}
