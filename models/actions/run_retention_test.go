// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// user_setting has no fixture: drop the settings of the previous test, and of this one when it ends.
func resetUserSettings(t *testing.T) {
	t.Helper()
	reset := func() {
		_, err := db.GetEngine(db.DefaultContext).Exec("DELETE FROM user_setting")
		require.NoError(t, err)
	}
	reset()
	t.Cleanup(reset)
}

// AC2: the effective retention is the shortest positive of repository, organization, instance default and maximum.
func TestEffectiveRunRetentionDays(t *testing.T) {
	for _, c := range []struct {
		name                string
		repo, org, def, max int64
		want                int64
	}{
		{"nothing set keeps forever", 0, 0, 0, 0, 0},
		{"instance default", 0, 0, 30, 0, 30},
		{"repository shortens the default", 7, 0, 30, 0, 7},
		{"repository can't lengthen the default", 90, 0, 30, 0, 30},
		{"organization is a ceiling", 0, 14, 0, 0, 14},
		{"repository can't lengthen the organization", 60, 14, 0, 0, 14},
		{"repository shortens the organization", 3, 14, 0, 0, 3},
		{"maximum caps an override", 400, 0, 0, 100, 100},
		{"maximum applies without any other setting", 0, 0, 0, 100, 100},
		{"maximum caps the default", 0, 0, 365, 100, 100},
		{"a shorter value wins over the maximum", 5, 0, 0, 100, 5},
		{"a huge value is clamped", 1 << 40, 0, 0, 0, MaxRunRetentionDays},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer test.MockVariableValue(&setting.Actions.RunRetentionDays, c.def)()
			defer test.MockVariableValue(&setting.Actions.RunRetentionMaxDays, c.max)()
			assert.Equal(t, c.want, EffectiveRunRetentionDays(c.repo, c.org))
		})
	}
}

// AC2: the settings come from one query for repositories and one for organizations.
func TestFindRunRetentionSettings(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	resetUserSettings(t)
	unittest.AssertSuccessfulInsert(t, &repo_model.RepoUnit{RepoID: 4, Type: unit.TypeActions, Config: &repo_model.ActionsConfig{RunRetentionDays: 7}})
	unittest.AssertSuccessfulInsert(t, &repo_model.RepoUnit{RepoID: 3, Type: unit.TypeActions, Config: &repo_model.ActionsConfig{DisabledWorkflows: []string{"a.yml"}}})
	unittest.AssertSuccessfulInsert(t, &repo_model.RepoUnit{RepoID: 1, Type: unit.TypeActions, Config: &repo_model.ActionsConfig{RunRetentionDays: MaxRunRetentionDays + 1}})
	require.NoError(t, SetOrgRunRetentionDays(t.Context(), 3, 14))
	// not an organization, and a value that doesn't parse
	require.NoError(t, user_model.SetUserSetting(t.Context(), 2, orgRunRetentionKey, "5"))
	require.NoError(t, user_model.SetUserSetting(t.Context(), 6, orgRunRetentionKey, "-1"))

	repoDays, orgDays, err := FindRunRetentionSettings(t.Context())
	require.NoError(t, err)
	assert.Equal(t, map[int64]int64{4: 7}, repoDays)
	assert.Equal(t, map[int64]int64{3: 14}, orgDays)

	days, err := GetOrgRunRetentionDays(t.Context(), 3)
	require.NoError(t, err)
	assert.EqualValues(t, 14, days)
	require.NoError(t, SetOrgRunRetentionDays(t.Context(), 3, 0))
	days, err = GetOrgRunRetentionDays(t.Context(), 3)
	require.NoError(t, err)
	assert.Zero(t, days)
}

func TestRepoRunRetentionDays(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	resetUserSettings(t)
	defer test.MockVariableValue(&setting.Actions.RunRetentionDays, 30)()
	unittest.AssertSuccessfulInsert(t, &repo_model.RepoUnit{RepoID: 3, Type: unit.TypeActions, Config: &repo_model.ActionsConfig{RunRetentionDays: 20}})
	unittest.AssertSuccessfulInsert(t, &repo_model.RepoUnit{RepoID: 4, Type: unit.TypeActions, Config: &repo_model.ActionsConfig{}})
	require.NoError(t, SetOrgRunRetentionDays(t.Context(), 3, 10))

	days := func(id int64) int64 {
		d, err := RepoRunRetentionDays(t.Context(), unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: id}))
		require.NoError(t, err)
		return d
	}
	assert.EqualValues(t, 10, days(3)) // the organization's ceiling beats the repository's 20
	assert.EqualValues(t, 30, days(4)) // a user's repository: instance default
}
