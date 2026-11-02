// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import (
	"fmt"
	"net/http/httptest"
	"testing"

	audit_model "forgejo.org/models/audit"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditCollector(t *testing.T) {
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(NewAuditCollector()))
	audit_model.Written["repo"].Add(3)
	defer audit_model.Written["repo"].Add(-3)
	audit_model.WriteErrors.Add(2)
	defer audit_model.WriteErrors.Add(-2)

	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, c := range audit_model.Categories {
		assert.Contains(t, body, fmt.Sprintf(`gitea_audit_events_total{category=%q} %d`, c, audit_model.Written[c].Load()))
	}
	assert.Contains(t, body, `gitea_audit_events_total{category="repo"} 3`)
	assert.Contains(t, body, "gitea_audit_write_errors_total 2")
}
