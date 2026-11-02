// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"context"
	"strconv"
	"testing"
	"time"

	"forgejo.org/modules/setting/config"

	"github.com/stretchr/testify/assert"
)

type maintenanceGetter struct{ v string }

func (g *maintenanceGetter) GetValue(_ context.Context, key string) (string, bool) {
	return g.v, key == "maintenance.state"
}
func (g *maintenanceGetter) GetRevision(context.Context) int { return len(g.v) }
func (g *maintenanceGetter) InvalidateCache()                {}

func TestGetMaintenance(t *testing.T) {
	g := &maintenanceGetter{}
	old := Maintenance
	defer func() { Maintenance = old }()
	Maintenance.Mode = ""
	config.SetDynGetter(g)
	defer config.SetDynGetter(nil)
	ctx := t.Context()

	future := strconv.FormatInt(time.Now().Unix()+3600, 10)
	g.v = `{"mode":"read-only","message":"Upgrade","until":` + future + `,"set_by_name":"user1"}`
	s := GetMaintenance(ctx)
	assert.True(t, s.ReadOnly())
	assert.False(t, s.Full())
	assert.Equal(t, "user1", s.SetByName)
	assert.Equal(t, "This instance is in read-only mode: Upgrade", s.Refusal())
	assert.NotEmpty(t, s.RetryAfter())

	// an end time in the past turns the mode off, with no admin action
	g.v = `{"mode":"maintenance","until":` + strconv.FormatInt(time.Now().Unix()-1, 10) + `}`
	s = GetMaintenance(ctx)
	assert.False(t, s.ReadOnly())

	g.v = `{"mode":"maintenance"}`
	s = GetMaintenance(ctx)
	assert.True(t, s.ReadOnly())
	assert.True(t, s.Full())
	assert.Empty(t, s.RetryAfter())
	assert.Equal(t, "This instance is in maintenance mode", s.Refusal())

	// app.ini wins over the database
	Maintenance.Mode, Maintenance.Message = MaintenanceReadOnly, "From ini"
	s = GetMaintenance(ctx)
	assert.True(t, s.FromConfig)
	assert.False(t, s.Full())
	assert.Equal(t, "This instance is in read-only mode: From ini", s.Refusal())
	Maintenance.Mode = MaintenanceOff
	assert.False(t, GetMaintenance(ctx).ReadOnly())
}
