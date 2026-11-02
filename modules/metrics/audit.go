// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import (
	audit_model "forgejo.org/models/audit"

	"github.com/prometheus/client_golang/prometheus"
)

// AuditCollector exposes the audit entries this process wrote, per category, and the activity entries it could not
// write.
type AuditCollector struct {
	events, writeErrors *prometheus.Desc
}

func NewAuditCollector() *AuditCollector {
	return &AuditCollector{
		events:      prometheus.NewDesc(namespace+"audit_events_total", "Audit log entries written by this process", []string{"category"}, nil),
		writeErrors: prometheus.NewDesc(namespace+"audit_write_errors_total", "Audit activity entries this process could not write", nil, nil),
	}
}

func (c *AuditCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.events
	ch <- c.writeErrors
}

func (c *AuditCollector) Collect(ch chan<- prometheus.Metric) {
	for _, category := range audit_model.Categories {
		ch <- prometheus.MustNewConstMetric(c.events, prometheus.CounterValue, float64(audit_model.Written[category].Load()), category)
	}
	ch <- prometheus.MustNewConstMetric(c.writeErrors, prometheus.CounterValue, float64(audit_model.WriteErrors.Load()))
}
