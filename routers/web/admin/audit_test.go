// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"net/url"
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditLocation(t *testing.T) {
	assert.Equal(t, time.UTC, auditLocation(""))
	assert.Equal(t, time.UTC, auditLocation("No/Such_Zone"), "a zone tzdata lacks falls back")
	assert.Equal(t, "Europe/Berlin", auditLocation("Europe/Berlin").String())
}

func TestAuditTimeValue(t *testing.T) {
	berlin := auditLocation("Europe/Berlin")
	for _, tc := range []struct {
		in   any
		want string
	}{
		{float64(1760648400), "2025-10-16 23:00:00 (1760648400)"},
		{float64(1760648400.5), "1760648400.5"},
		{"1760648400", "1760648400"},
		{float64(1e15), "1000000000000000"},
		{float64(-5), "-5"},
		{true, "true"},
	} {
		assert.Equal(t, tc.want, auditTimeValue(tc.in, berlin), "%v", tc.in)
	}
}

func TestAuditRowTimestamps(t *testing.T) {
	e := &audit_model.Entry{Action: "auth.refused.aggregated", IP: "10.0.0.1", Data: `{"count":7,"first":1760648400,"last":1760648460,"expires":"1760648400","other":1760648400}`}
	r := newAuditRow(e, time.UTC, nil)
	assert.Equal(t, "2025-10-16 21:00:00 (1760648400)", r.Details["first"])
	assert.Equal(t, "1760648400", r.Details["expires"], "a string stays raw")
	assert.Equal(t, "1760648400", r.Details["other"], "an unknown key stays raw")
	assert.EqualValues(t, 7, r.AggregatedCount)
	assert.Equal(t, "2025-10-16 21:00:00", r.AggregatedFirst)
	assert.Equal(t, "2025-10-16 21:01:00", r.AggregatedLast)
	q, err := url.ParseQuery(strings.TrimPrefix(r.AggregatedLink, "?"))
	require.NoError(t, err)
	assert.Equal(t, url.Values{
		"category": {"all"}, "action": {"auth.refused"}, "ip": {"10.0.0.1"},
		"since": {"2025-10-16T21:00:00Z"}, "before": {"2025-10-16T21:01:01Z"},
	}, q)

	for _, e := range []*audit_model.Entry{
		{Action: "auth.refused", Data: `{"count":7,"first":1,"last":2}`},              // not an aggregate
		{Action: "auth.refused.aggregated", Data: `{"count":0,"first":1,"last":2}`},   // nothing counted
		{Action: "auth.refused.aggregated", Data: `{"count":3,"first":"x","last":2}`}, // no usable window
		{Action: "auth.refused.aggregated", Data: `not json`},
	} {
		r := newAuditRow(e, time.UTC, nil)
		assert.Empty(t, r.AggregatedLink, e.Data)
		assert.Zero(t, r.AggregatedCount, e.Data)
	}
}

func TestUnsealedCount(t *testing.T) {
	assert.Equal(t, "0", unsealedCount(0))
	assert.Equal(t, "10000", unsealedCount(audit_model.UnsealedCountCap-1))
	assert.Equal(t, "10000+", unsealedCount(audit_model.UnsealedCountCap))
}
