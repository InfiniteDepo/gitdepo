// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package oauth2app

import (
	"testing"

	"forgejo.org/models/db"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	unittest.MainTest(m)
}

func setPolicy(t *testing.T, st setting.OAuth2AppPolicyState) {
	v, err := json.Marshal(st)
	require.NoError(t, err)
	require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{"oauth2.app_policy": string(v)}))
	config.GetDynGetter().InvalidateCache()
}

// AC4: one function decides for every mode; org 3 is owned by user 2, org 6 by user 5.
func TestMayManage(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	owner3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	member := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	owner6 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	inactiveAdmin := *admin
	inactiveAdmin.IsActive = false
	prohibitedOwner := *owner3
	prohibitedOwner.ProhibitLogin = true

	may := func(u *user_model.User, ownerID int64) bool {
		ok, err := MayManage(db.DefaultContext, u, ownerID)
		require.NoError(t, err)
		return ok
	}

	// no stored setting (fresh install and upgrade): site admins only
	assert.True(t, may(admin, 1))
	assert.True(t, may(admin, 0))
	assert.False(t, may(owner3, 3))
	assert.False(t, may(owner3, 2))
	assert.False(t, may(nil, 1))

	setPolicy(t, setting.OAuth2AppPolicyState{Mode: "garbage"}) // unknown mode fails closed
	assert.False(t, may(owner3, 3))

	setPolicy(t, setting.OAuth2AppPolicyState{Mode: setting.OAuth2AppPolicyOrgs, OrgIDs: []int64{3}})
	assert.True(t, may(owner3, 3))
	assert.False(t, may(owner3, 2), "no personal apps")
	assert.False(t, may(owner3, 6), "not the owner of that org")
	assert.False(t, may(member, 3), "member, not owner")
	assert.False(t, may(owner6, 6), "org not selected")
	assert.False(t, may(owner3, 0))
	assert.True(t, may(admin, 6))
	assert.False(t, may(&prohibitedOwner, 3))
	assert.False(t, may(&inactiveAdmin, 3))

	setPolicy(t, setting.OAuth2AppPolicyState{Mode: setting.OAuth2AppPolicyEveryone})
	assert.True(t, may(member, 4))
	assert.True(t, may(owner3, 3))
	assert.False(t, may(&prohibitedOwner, 2), "login prohibited never passes")
	assert.False(t, may(&inactiveAdmin, 1), "inactive never passes")
	assert.False(t, may(member, 0), "instance-wide apps are admin only")
}
