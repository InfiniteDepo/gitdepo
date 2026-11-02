// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package user_test

import (
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateUserRefusedInMaintenance(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Maintenance.Mode, setting.MaintenanceReadOnly)()

	u := &user_model.User{Name: "maintenance-user", Email: "maintenance-user@example.com", Passwd: "password"}
	require.ErrorIs(t, user_model.CreateUser(db.DefaultContext, u), util.ErrPermissionDenied)
	require.ErrorIs(t, user_model.AdminCreateUser(db.DefaultContext, u), util.ErrPermissionDenied)
	unittest.AssertNotExistsBean(t, &user_model.User{Name: "maintenance-user"})

	setting.Maintenance.Mode = setting.MaintenanceOff
	require.NoError(t, user_model.CreateUser(db.DefaultContext, u))
	assert.NotZero(t, u.ID)
}
