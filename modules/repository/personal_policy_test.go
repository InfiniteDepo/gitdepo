// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"testing"

	"forgejo.org/models/db"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func storePersonalRepos(t *testing.T, raw string) {
	t.Helper()
	require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().PersonalRepos.DynKey(): raw}))
	config.GetDynGetter().InvalidateCache()
}

func TestCheckPersonalRepoPolicy(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(func() { storePersonalRepos(t, "") })
	user := func(id int64) *user_model.User { return unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: id}) }
	individual, org, admin := user(2), user(3), user(1)
	inactiveAdmin, prohibitedAdmin, botAdmin := user(1), user(1), user(1)
	inactiveAdmin.IsActive = false
	prohibitedAdmin.ProhibitLogin = true
	botAdmin.Type = user_model.UserTypeBot

	check := func(doer, owner *user_model.User, private bool) error {
		return CheckPersonalRepoPolicy(db.DefaultContext, doer, owner, private)
	}
	refused := func(t *testing.T, err error, mode string) {
		t.Helper()
		var e ErrPersonalRepoPolicy
		require.ErrorAs(t, err, &e)
		assert.Equal(t, mode, e.Mode)
		require.ErrorIs(t, err, util.ErrPermissionDenied)
	}

	for _, tc := range []struct {
		stored string
		mode   string
	}{
		{"", setting.PersonalReposAllowed},
		{`{"mode":"allowed"}`, setting.PersonalReposAllowed},
		{`{"mode":"private_only"}`, setting.PersonalReposPrivateOnly},
		{`{"mode":"disabled"}`, setting.PersonalReposDisabled},
		{`{"mode":"public"}`, setting.PersonalReposDisabled}, // unknown mode
		{`{"mode":`, setting.PersonalReposDisabled},          // can't be parsed
	} {
		t.Run(tc.stored, func(t *testing.T) {
			storePersonalRepos(t, tc.stored)
			assert.Equal(t, tc.mode, setting.Config().PersonalRepos.Value(db.DefaultContext).EffectiveMode())

			for _, private := range []bool{true, false} {
				// organizations are never restricted, usable admins as doer or owner are exempt
				require.NoError(t, check(individual, org, private))
				require.NoError(t, check(nil, org, private))
				require.NoError(t, check(admin, individual, private))
				require.NoError(t, check(individual, admin, private))

				for _, doer := range []*user_model.User{individual, nil, inactiveAdmin, prohibitedAdmin, botAdmin} {
					err := check(doer, individual, private)
					switch {
					case tc.mode == setting.PersonalReposAllowed, tc.mode == setting.PersonalReposPrivateOnly && private:
						require.NoError(t, err)
					default:
						refused(t, err, tc.mode)
					}
				}
			}
		})
	}
}
