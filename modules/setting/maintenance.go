// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"context"
	"slices"
	"strconv"
	"time"

	"forgejo.org/modules/log"
)

const (
	MaintenanceOff      = "off"
	MaintenanceReadOnly = "read-only"
	MaintenanceFull     = "maintenance"
)

// MaintenanceModes are the valid maintenance modes.
var MaintenanceModes = []string{MaintenanceOff, MaintenanceReadOnly, MaintenanceFull}

// Maintenance is the [maintenance] section of app.ini. A set MODE overrides the state stored in the database.
var Maintenance = struct {
	Mode    string
	Message string
}{}

func loadMaintenanceFrom(rootCfg ConfigProvider) {
	sec := rootCfg.Section("maintenance")
	Maintenance.Mode = sec.Key("MODE").String()
	Maintenance.Message = sec.Key("MESSAGE").String()
	if Maintenance.Mode != "" && !slices.Contains(MaintenanceModes, Maintenance.Mode) {
		log.Fatal("[maintenance] MODE must be one of %v, got %q", MaintenanceModes, Maintenance.Mode)
	}
}

// MaintenanceState is the instance's maintenance mode, stored as JSON in the "maintenance.state" system setting.
type MaintenanceState struct {
	Mode       string `json:"mode"`
	Message    string `json:"message"`
	Until      int64  `json:"until"` // unix seconds, 0 for no end time
	SetByID    int64  `json:"set_by_id"`
	SetByName  string `json:"set_by_name"`
	FromConfig bool   `json:"-"`
}

// GetMaintenance returns the current maintenance state: the app.ini MODE if set, otherwise the database state.
// A state whose end time has passed is off.
func GetMaintenance(ctx context.Context) MaintenanceState {
	if Maintenance.Mode != "" {
		return MaintenanceState{Mode: Maintenance.Mode, Message: Maintenance.Message, FromConfig: true}
	}
	s := Config().Maintenance.Value(ctx)
	if s.Until > 0 && s.Until <= time.Now().Unix() {
		return MaintenanceState{Mode: MaintenanceOff}
	}
	return s
}

// ReadOnly reports whether writes are refused, in both read-only and full maintenance mode.
func (s MaintenanceState) ReadOnly() bool {
	return s.Mode == MaintenanceReadOnly || s.Mode == MaintenanceFull
}

// Full reports whether only site admins may use the instance.
func (s MaintenanceState) Full() bool {
	return s.Mode == MaintenanceFull
}

// RetryAfter returns the Retry-After header value in seconds, or "" when there is no end time.
func (s MaintenanceState) RetryAfter() string {
	if s.Until == 0 {
		return ""
	}
	return strconv.FormatInt(max(s.Until-time.Now().Unix(), 1), 10)
}

// Refusal is the English message shown when a request is refused, e.g. by git as "remote: ...".
func (s MaintenanceState) Refusal() string {
	msg := "This instance is in read-only mode"
	if s.Full() {
		msg = "This instance is in maintenance mode"
	}
	if s.Message != "" {
		msg += ": " + s.Message
	}
	return msg
}
