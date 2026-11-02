// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"testing"
	"time"

	"forgejo.org/modules/setting"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
)

func storedRetention(t *testing.T) setting.AuditRetentionState {
	t.Helper()
	bumpSettingsRevision(t)
	return setting.Config().AuditRetention.Value(t.Context())
}

// AC7
func TestAdminAuditRetention(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	storeRetention(t, setting.AuditRetentionState{}) // system settings outlive PrepareTestEnv
	admin := loginUser(t, "user1")

	page := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit/retention"), http.StatusOK).Body.String()
	assert.Contains(t, page, "Retention: 1 year")
	assert.Contains(t, page, "The log holds")
	assert.Regexp(t, `>1 year · about [\d,]+ entries, [\d.]+ [KMG]?i?B</option>`, page, "the sign-in is in the log, so each choice has a projection")
	assert.NotContains(t, page, "audit-retention-short")

	since := auditMaxID(t)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/audit/retention", map[string]string{"days": "90"}), http.StatusSeeOther)
	e := auditOne(t, since, "admin.setting.changed")
	assert.Contains(t, e.Data, "audit.retention_days")
	s := storedRetention(t)
	assert.Equal(t, 90, s.Days)
	assert.Equal(t, 365, s.PreviousDays)
	assert.InDelta(t, time.Now().Add(setting.AuditRetentionLowerDelay).Unix(), s.EffectiveFrom, 60)

	assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit/retention"), http.StatusOK).Body.String(),
		"The retention is shorter than 1 year.", "the hint follows the chosen value, not the one still in force")

	// both pages show the pending lowering and the retention in force
	for _, path := range []string{"/admin/audit/retention", "/admin/audit"} {
		body := admin.MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK).Body.String()
		assert.Contains(t, body, "Retention: 1 year", path)
		assert.Contains(t, body, "lowering to 90 days takes effect", path)
	}

	// raising applies at once and clears the lowering; previous_days and effective_from from the form are ignored (M2)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/audit/retention", map[string]string{
		"days": "730", "previous_days": "30", "effective_from": "9999999999",
	}), http.StatusSeeOther)
	s = storedRetention(t)
	assert.Equal(t, setting.AuditRetentionState{Days: 730}, s)
	body := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusOK).Body.String()
	assert.Contains(t, body, "Retention: 2 years")
	assert.NotContains(t, body, "lowering to")

	for _, bad := range []string{"31", "0", "-1", "abc", ""} {
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/audit/retention", map[string]string{"days": bad}), http.StatusBadRequest)
	}
	assert.Equal(t, 730, storedRetention(t).Days)
}

// Only a site admin changes the retention; an auditor reads the audit page but can't open the form.
func TestAdminAuditRetentionPermissions(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	storeRetention(t, setting.AuditRetentionState{})
	setUserFlag(t, 2, "is_auditor", true)
	for _, name := range []string{"user2", "user4"} {
		sess := loginUser(t, name)
		sess.MakeRequest(t, NewRequest(t, "GET", "/admin/audit/retention"), http.StatusForbidden)
		sess.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/audit/retention", map[string]string{"days": "30"}), http.StatusForbidden)
	}
	assert.Equal(t, setting.AuditRetentionDefault, storedRetention(t).Effective(time.Now()))

	body := loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusOK).Body.String()
	assert.Contains(t, body, "Retention: 1 year")
	assert.NotContains(t, body, `href="/admin/audit/retention"`, "the auditor gets no link to the form")
}
