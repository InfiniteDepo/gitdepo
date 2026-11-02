// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package cron

import (
	"context"
	"errors"
	"testing"

	audit_model "forgejo.org/models/audit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCronPausedInMaintenance(t *testing.T) {
	runs := 0
	task := &Task{Name: "maintenance test", config: &BaseConfig{}, fun: func(context.Context, *user_model.User, Config) error {
		runs++
		return nil
	}}

	defer test.MockVariableValue(&setting.Maintenance.Mode, setting.MaintenanceReadOnly)()
	task.Run()
	assert.Equal(t, 0, runs)

	setting.Maintenance.Mode = setting.MaintenanceOff
	task.Run()
	assert.Equal(t, 1, runs)
}

func TestCronAuditActor(t *testing.T) {
	var got *audit_model.Actor
	task := &Task{Name: "actor test", config: &BaseConfig{}, fun: func(ctx context.Context, _ *user_model.User, _ Config) error {
		got = audit_model.ActorFromContext(ctx)
		return nil
	}}
	defer test.MockVariableValue(&setting.Maintenance.Mode, setting.MaintenanceOff)()
	var recorded []*audit_model.Entry
	defer test.MockVariableValue(&audit_model.InsertEntry, func(_ context.Context, e *audit_model.Entry) error {
		recorded = append(recorded, e)
		return nil
	})()

	task.Run()
	assert.Equal(t, audit_model.SystemActor("cron:actor test"), got)
	assert.Empty(t, recorded, "a scheduled run records nothing")

	admin := &audit_model.Actor{Type: audit_model.ActorUser, ID: 1, Name: "user1", IP: "192.0.2.1"}
	task.RunWithUser(audit_model.WithActor(t.Context(), admin), &user_model.User{ID: 1, Name: "user1"}, nil)
	assert.Equal(t, &audit_model.Actor{Type: audit_model.ActorUser, ID: 1, Name: "user1", IP: "192.0.2.1", Task: "actor test"}, got)
	assert.Empty(t, admin.Task, "the request's actor is not changed")
	require.Len(t, recorded, 1)
	assert.Equal(t, "admin.cron.run", recorded[0].Action)
	assert.EqualValues(t, 1, recorded[0].ActorID)
	assert.Equal(t, "actor test", recorded[0].TargetName)

	// a run by hand while the task is already running doesn't run, and records nothing
	require.True(t, taskStatusTable.StartIfNotRunning(task.Name))
	task.RunWithUser(audit_model.WithActor(t.Context(), admin), &user_model.User{ID: 1, Name: "user1"}, nil)
	taskStatusTable.Stop(task.Name)
	assert.Len(t, recorded, 1)

	// a run by hand that can't be recorded doesn't run
	got = nil
	defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error {
		return errors.New("audit down")
	})()
	task.RunWithUser(audit_model.WithActor(t.Context(), admin), &user_model.User{ID: 1, Name: "user1"}, nil)
	assert.Nil(t, got)
}
