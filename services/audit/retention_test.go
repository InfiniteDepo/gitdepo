// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var lastRevision int

// setRetention stores the setting and moves the revision past every earlier test's, so a cached value is not served.
func setRetention(t *testing.T, s setting.AuditRetentionState) {
	t.Helper()
	b, err := json.Marshal(s)
	require.NoError(t, err)
	require.NoError(t, system_model.SetSettings(t.Context(), map[string]string{setting.Config().AuditRetention.DynKey(): string(b)}))
	lastRevision = max(lastRevision, system_model.GetRevision(t.Context())) + 1
	_, err = db.Exec(t.Context(), "UPDATE system_setting SET version=? WHERE setting_key='revision'", lastRevision)
	require.NoError(t, err)
	config.GetDynGetter().InvalidateCache()
}

// aged seals n entries made daysAgo days ago, behind a genesis entry of the same age.
func aged(t *testing.T, n, daysAgo int) {
	t.Helper()
	require.NoError(t, unittest.PrepareTestDatabase())
	at := time.Now().AddDate(0, 0, -daysAgo)
	timeutil.MockSet(at)
	defer timeutil.MockUnset()
	for range n {
		require.NoError(t, db.Insert(t.Context(), &audit_model.Entry{
			CreatedUnix: timeutil.TimeStamp(at.Unix()), Category: "auth", Action: "auth.signin", Result: "success", ActorType: "user", ActorID: 2,
		}))
	}
	require.NoError(t, SealAll(t.Context()))
}

func cleanup(t *testing.T) {
	t.Helper()
	require.NoError(t, Cleanup(audit_model.WithSystem(t.Context(), "cron:cleanup_audit_log")))
}

func sealedCount(t *testing.T) int64 {
	t.Helper()
	n, err := db.GetEngine(t.Context()).Where("seq IS NOT NULL").Count(new(audit_model.Entry))
	require.NoError(t, err)
	return n
}

// AC8
func TestCleanup(t *testing.T) {
	t.Run("the default is 365 days", func(t *testing.T) {
		aged(t, 3, 400)
		cleanup(t)
		assert.EqualValues(t, 1, sealedCount(t)) // the head entry stays
		aged(t, 3, 300)
		cleanup(t)
		assert.EqualValues(t, 4, sealedCount(t))
		mustVerify(t)
	})
	t.Run("a pending lowering is not applied early (also for a manual run)", func(t *testing.T) {
		aged(t, 3, 100)
		now := time.Now()
		setRetention(t, setting.AuditRetentionState{Days: 30, PreviousDays: 365, EffectiveFrom: now.Add(time.Hour).Unix()})
		cleanup(t)
		assert.EqualValues(t, 4, sealedCount(t))
		setRetention(t, setting.AuditRetentionState{Days: 30, PreviousDays: 365, EffectiveFrom: now.Add(-time.Hour).Unix()})
		cleanup(t)
		assert.EqualValues(t, 1, sealedCount(t))
	})
	t.Run("batches until nothing is left, one entry each", func(t *testing.T) {
		defer test.MockVariableValue(&PurgeBatchSize, 2)()
		aged(t, 6, 100) // genesis + 6 = 7 sealed, 6 purgeable
		setRetention(t, setting.AuditRetentionState{Days: 30})
		cleanup(t)
		assert.EqualValues(t, 1, sealedCount(t))
		var purges []*audit_model.Entry
		require.NoError(t, db.GetEngine(t.Context()).Where("action = ?", "audit.purge").Find(&purges))
		assert.Len(t, purges, 3)
		mustVerify(t)
		cleanup(t) // nothing more: no new entry
		n, err := db.GetEngine(t.Context()).Where("action = ?", "audit.purge").Count(new(audit_model.Entry))
		require.NoError(t, err)
		assert.EqualValues(t, 3, n)
	})
	t.Run("the setting is read before any audit query", func(t *testing.T) {
		aged(t, 2, 100)
		setRetention(t, setting.AuditRetentionState{Days: 30})
		h := hookSQL(t)
		config.GetDynGetter().InvalidateCache()
		cleanup(t)
		h.mu.Lock()
		defer h.mu.Unlock()
		firstAudit, firstSetting := -1, -1
		for i, s := range h.sqls {
			if firstAudit < 0 && strings.Contains(s, "audit_") {
				firstAudit = i
			}
			if firstSetting < 0 && strings.Contains(s, "system_setting") {
				firstSetting = i
			}
		}
		assert.GreaterOrEqual(t, firstSetting, 0)
		assert.Less(t, firstSetting, firstAudit)
	})
}

// SetRetention computes from the stored row under its lock, not from a cached or earlier read.
func TestSetRetentionUsesStoredRow(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := audit_model.WithSystem(t.Context(), "test")
	read := func() (s setting.AuditRetentionState) {
		v, has, err := system_model.GetSettingForUpdate(t.Context(), setting.Config().AuditRetention.DynKey())
		require.NoError(t, err)
		require.True(t, has)
		require.NoError(t, json.Unmarshal([]byte(v), &s))
		return s
	}
	require.NoError(t, SetRetention(ctx, 90))
	assert.Equal(t, 90, read().Days)
	assert.Equal(t, 365, read().PreviousDays)

	// another pod stored 730 days; this one's cache still holds the lowering to 90
	b, err := json.Marshal(setting.AuditRetentionState{Days: 730})
	require.NoError(t, err)
	require.NoError(t, system_model.SetSettings(ctx, map[string]string{setting.Config().AuditRetention.DynKey(): string(b)}))
	require.NoError(t, SetRetention(ctx, 30))
	s := read()
	assert.Equal(t, 30, s.Days)
	assert.Equal(t, 730, s.PreviousDays)

	require.Error(t, SetRetention(ctx, 31))
	assert.Equal(t, s, read())
}

func TestGetVolume(t *testing.T) {
	now := time.Now()
	t.Run("empty", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		v, err := GetVolume(t.Context(), now)
		require.NoError(t, err)
		assert.Equal(t, Volume{}, *v)
	})
	t.Run("sealed, purged and unsealed entries", func(t *testing.T) {
		aged(t, 4, 100) // genesis + 4 sealed, 100 days ago
		setRetention(t, setting.AuditRetentionState{Days: 30})
		cleanup(t) // keeps the head entry and records a purge
		setRetention(t, setting.AuditRetentionState{})
		for range 59 {
			require.NoError(t, db.Insert(t.Context(), &audit_model.Entry{
				CreatedUnix: timeutil.TimeStamp(now.AddDate(0, 0, -10).Unix()), Category: "auth", Action: "auth.signin", Result: "success",
			}))
		}
		all, err := db.GetEngine(t.Context()).Count(new(audit_model.Entry))
		require.NoError(t, err)
		v, err := GetVolume(t.Context(), now)
		require.NoError(t, err)
		assert.Equal(t, all, v.Kept, "head entry, purge entry and the unsealed ones")
		assert.EqualValues(t, 2, v.PerDay, "60 entries (59 + the purge) in the last 30 days")
	})
	t.Run("a log younger than 30 days averages over its age", func(t *testing.T) {
		aged(t, 9, 3) // genesis + 9 three days ago
		v, err := GetVolume(t.Context(), now)
		require.NoError(t, err)
		assert.EqualValues(t, 10, v.Kept)
		assert.EqualValues(t, 3, v.PerDay)
	})
}
