// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

import "time"

// Maintenance is the instance's read-only or maintenance mode
type Maintenance struct {
	// enum: off,read-only,maintenance
	Mode string `json:"mode"`
	// Message shown to users
	Message string `json:"message"`
	// When the mode turns itself off, null if never
	// swagger:strfmt date-time
	Until *time.Time `json:"until"`
	// Who last changed the mode
	SetBy string `json:"set_by"`
	// Whether [maintenance] MODE in the configuration file sets the mode, so it can't be changed
	FromConfig bool `json:"from_config"`
}

// EditMaintenanceOption options for changing the maintenance mode
type EditMaintenanceOption struct {
	// required: true
	// enum: off,read-only,maintenance
	Mode string `json:"mode" binding:"Required;In(off,read-only,maintenance)"`
	// Message shown to users
	Message string `json:"message" binding:"MaxSize(255)"`
	// When the mode turns itself off, must be in the future; null for never
	// swagger:strfmt date-time
	Until *time.Time `json:"until"`
}
