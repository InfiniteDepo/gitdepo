// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/json"
	"forgejo.org/modules/ratelimit"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func refusalEntries(t *testing.T, action string) []*audit_model.Entry {
	t.Helper()
	var entries []*audit_model.Entry
	require.NoError(t, db.GetEngine(t.Context()).Where("action = ?", action).OrderBy("id").Find(&entries))
	return entries
}

func TestRecordConnectionRefused(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	audit_model.ResetActivity()
	t.Cleanup(audit_model.ResetActivity)

	// four refusals of one IPv4 address and two of two addresses in one IPv6 /64: one entry each, the rest counted
	for range 4 {
		RecordConnectionRefused(t.Context(), ratelimit.SSHConnect, "198.51.100.9:4000")
	}
	RecordConnectionRefused(t.Context(), ratelimit.SSHConnect, "[2001:db8:1:2::1]:4000")
	RecordConnectionRefused(t.Context(), ratelimit.SSHConnect, "[2001:db8:1:2::2]:4001")
	RecordConnectionRefused(t.Context(), ratelimit.Auth, "198.51.100.9:4002")

	first := refusalEntries(t, "auth.refused")
	require.Len(t, first, 3, "one per address (an IPv6 /64) and class")
	byIP := map[string]*audit_model.Entry{}
	for _, e := range first {
		byIP[e.IP+"|"+e.Data] = e
		assert.Equal(t, audit_model.ResultRefused, e.Result)
		assert.Equal(t, audit_model.ActorAnonymous, e.ActorType)
		assert.Zero(t, e.SubjectUserID)
	}
	assert.Contains(t, byIP, "198.51.100.9|"+`{"class":"ssh_connect","reason":"rate_limit"}`)
	assert.Contains(t, byIP, "198.51.100.9|"+`{"class":"auth","reason":"rate_limit"}`)
	assert.Contains(t, byIP, "2001:db8:1:2::1|"+`{"class":"ssh_connect","reason":"rate_limit"}`)

	audit_model.FlushAggregated(t.Context(), true)
	agg := refusalEntries(t, "auth.refused.aggregated")
	require.Len(t, agg, 2)
	counts := map[string]any{}
	for _, e := range agg {
		var data map[string]any
		require.NoError(t, json.Unmarshal([]byte(e.Data), &data))
		counts[e.IP] = data["count"]
	}
	assert.EqualValues(t, 3, counts["198.51.100.9"])
	assert.EqualValues(t, 1, counts["2001:db8:1:2::1"])
}
