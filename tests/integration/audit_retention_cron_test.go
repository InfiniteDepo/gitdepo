// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	audit_service "forgejo.org/services/audit"
	"forgejo.org/services/cron"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func storeRetention(t *testing.T, s setting.AuditRetentionState) {
	t.Helper()
	b, err := json.Marshal(s)
	require.NoError(t, err)
	require.NoError(t, system_model.SetSettings(t.Context(), map[string]string{setting.Config().AuditRetention.DynKey(): string(b)}))
	bumpSettingsRevision(t)
}

// agedChain seals a genesis entry and n entries made daysAgo days ago.
func agedChain(t *testing.T, n, daysAgo int) time.Time {
	t.Helper()
	at := time.Now().AddDate(0, 0, -daysAgo)
	timeutil.MockSet(at)
	defer timeutil.MockUnset()
	for range n {
		require.NoError(t, db.Insert(t.Context(), &audit_model.Entry{
			CreatedUnix: timeutil.TimeStamp(at.Unix()), Category: "auth", Action: "auth.signin", Result: "success", ActorType: "user", ActorID: 2,
		}))
	}
	require.NoError(t, audit_service.SealAll(t.Context()))
	return at
}

// AC7, AC8: the nightly task, as a site admin runs it by hand and under maintenance mode.
func TestAuditRetentionCron(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	t.Cleanup(func() { storeRetention(t, setting.AuditRetentionState{}) }) // system settings outlive the test
	task := cron.GetTask("cleanup_audit_log")
	require.NotNil(t, task)
	assert.True(t, task.IsEnabled())
	var spec string
	for _, row := range cron.ListTasks() {
		if row.Name == "cleanup_audit_log" {
			spec = row.Spec
		}
	}
	assert.Equal(t, "@midnight", spec)

	at := agedChain(t, 3, 100)
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	sess := loginUser(t, "user1")
	oldest := "Oldest entry: " + at.UTC().Format("2006-01-02")
	assert.Contains(t, sess.MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusOK).Body.String(), oldest)

	// a pending lowering is not applied early, also on a manual run
	storeRetention(t, setting.AuditRetentionState{Days: 30, PreviousDays: 365, EffectiveFrom: time.Now().Add(time.Hour).Unix()})
	since := auditMaxID(t)
	task.RunWithUser(asActor(t, 1, "user1"), admin, nil)
	assert.Empty(t, auditActions(t, since, "audit.purge"))

	// maintenance read-only stops the task, even with the lowering in force
	storeRetention(t, setting.AuditRetentionState{Days: 30})
	since = auditMaxID(t)
	func() {
		defer test.MockVariableValue(&setting.Maintenance.Mode, setting.MaintenanceReadOnly)()
		task.RunWithUser(asActor(t, 1, "user1"), admin, nil)
		task.Run()
	}()
	assert.Empty(t, auditActions(t, since, "audit.purge"))
	assert.Empty(t, auditActions(t, since, "admin.cron.run"))

	// by hand as a site admin: the entry names that admin and the task
	task.RunWithUser(asActor(t, 1, "user1"), admin, nil)
	purge := auditActions(t, since, "audit.purge")
	require.Len(t, purge, 1)
	assert.Equal(t, audit_model.ActorUser, purge[0].ActorType)
	assert.EqualValues(t, 1, purge[0].ActorID)
	assert.Contains(t, purge[0].Data, `"task":"cleanup_audit_log"`)
	assert.Contains(t, purge[0].Data, `"retention_days":30`)

	// the page header still names the oldest entry left (the head entry of the chain) and the retention
	body := sess.MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusOK).Body.String()
	assert.Contains(t, body, oldest)
	assert.Contains(t, body, "Retention: 30 days")

	// a scheduled run is the system actor
	storeRetention(t, setting.AuditRetentionState{Days: 30})
	agedMore := auditMaxID(t)
	timeutil.MockSet(time.Now().AddDate(0, 0, -100))
	require.NoError(t, db.Insert(t.Context(), &audit_model.Entry{
		CreatedUnix: timeutil.TimeStamp(time.Now().Unix()), Category: "auth", Action: "auth.signin", Result: "success", ActorType: "user", ActorID: 2,
	}))
	require.NoError(t, db.Insert(t.Context(), &audit_model.Entry{
		CreatedUnix: timeutil.TimeStamp(time.Now().Unix()), Category: "auth", Action: "auth.signin", Result: "success", ActorType: "user", ActorID: 2,
	}))
	require.NoError(t, audit_service.SealAll(t.Context()))
	timeutil.MockUnset()
	task.Run()
	purge = auditActions(t, agedMore, "audit.purge")
	require.NotEmpty(t, purge)
	assert.Equal(t, audit_model.ActorSystem, purge[0].ActorType)
}
