// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package system_test

import (
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/system"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/json"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func lastSettingEntry(t *testing.T, since int64) map[string]any {
	t.Helper()
	var entries []*audit_model.Entry
	require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND action = ?", since, "admin.setting.changed").Find(&entries))
	if len(entries) == 0 {
		return nil
	}
	require.Len(t, entries, 1)
	data := map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(entries[0].Data), &data))
	return data
}

func maxAuditID(t *testing.T) int64 {
	var id int64
	_, err := db.GetEngine(t.Context()).Table("audit_event").Select("COALESCE(MAX(id), 0)").Get(&id)
	require.NoError(t, err)
	return id
}

func TestSetSettingsAudit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithCLI(t.Context())
	key := "repository.personal_repos"

	since := maxAuditID(t)
	require.NoError(t, system.SetSettings(ctx, map[string]string{key: `{"mode":"disabled"}`, "audit.other": "s3cret"}))
	data := lastSettingEntry(t, since)
	assert.Equal(t, []any{"audit.other", key}, data["keys"])
	assert.Equal(t, map[string]any{key: nil}, data["before"])
	assert.Equal(t, map[string]any{key: map[string]any{"mode": "disabled"}}, data["after"])
	hashed := data["hashed"].(map[string]any)["audit.other"].(map[string]any)
	assert.Len(t, hashed["after"], 64)
	assert.NotContains(t, hashed, "before")

	since = maxAuditID(t)
	require.NoError(t, system.SetSettings(ctx, map[string]string{key: `{"mode":"disabled"}`}))
	assert.Nil(t, lastSettingEntry(t, since), "unchanged")

	// a value too long to keep is recorded as its hash
	long := `{"mode":"` + strings.Repeat("x", 3000) + `"}`
	since = maxAuditID(t)
	require.NoError(t, system.SetSettings(ctx, map[string]string{key: long}))
	data = lastSettingEntry(t, since)
	assert.Equal(t, true, data["truncated"])
	assert.NotContains(t, data, "after")
	assert.Contains(t, data["hashed"], key)

	// log shipping records its destinations itself
	since = maxAuditID(t)
	require.NoError(t, system.SetSettings(ctx, map[string]string{"log_shipping.destinations": `{}`}))
	assert.Nil(t, lastSettingEntry(t, since))

	// values that would pass the data cap together: the ones over the budget are recorded as hashes
	var keys []string
	for _, k := range audit_model.Fields["setting"] {
		if k != "keys" && k != "hashed" {
			keys = append(keys, k)
		}
	}
	value := func(c string) string { return `"` + strings.Repeat(c, 1990) + `"` }
	all := func(c string) map[string]string {
		m := map[string]string{}
		for _, k := range keys {
			m[k] = value(c)
		}
		return m
	}
	require.NoError(t, system.SetSettings(ctx, all("a")))
	since = maxAuditID(t)
	require.NoError(t, system.SetSettings(ctx, all("b")))
	data = lastSettingEntry(t, since)
	assert.Equal(t, true, data["truncated"])
	assert.NotEmpty(t, data["after"])
	assert.NotEmpty(t, data["hashed"])
	assert.Len(t, data["keys"], len(keys))
}
