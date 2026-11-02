// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package common

import (
	"testing"

	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/assert"
)

func TestIsMaintenanceAdmin(t *testing.T) {
	assert.False(t, IsMaintenanceAdmin(nil))
	assert.True(t, IsMaintenanceAdmin(&user_model.User{IsAdmin: true, IsActive: true}))
	assert.False(t, IsMaintenanceAdmin(&user_model.User{IsAdmin: false, IsActive: true}))
	assert.False(t, IsMaintenanceAdmin(&user_model.User{IsAdmin: true, IsActive: false}))
	assert.False(t, IsMaintenanceAdmin(&user_model.User{IsAdmin: true, IsActive: true, ProhibitLogin: true}))
}
