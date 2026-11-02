// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package quota

import (
	"testing"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/lfs"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setSiteSizeLimit(t *testing.T, limit int64) {
	t.Helper()
	v, err := json.Marshal(setting.PersonalReposState{Mode: setting.PersonalReposAllowed, SizeLimit: limit})
	require.NoError(t, err)
	require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().PersonalRepos.DynKey(): string(v)}))
	config.GetDynGetter().InvalidateCache()
	t.Cleanup(func() {
		require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().PersonalRepos.DynKey(): ""}))
		config.GetDynGetter().InvalidateCache()
	})
}

func TestEffectivePersonalRepoSizeLimit(t *testing.T) {
	individual := &user_model.User{Type: user_model.UserTypeIndividual}
	org := &user_model.User{Type: user_model.UserTypeOrganization}
	admin := &user_model.User{Type: user_model.UserTypeIndividual, IsAdmin: true, IsActive: true}
	inactiveAdmin := &user_model.User{Type: user_model.UserTypeIndividual, IsAdmin: true}
	prohibitedAdmin := &user_model.User{Type: user_model.UserTypeIndividual, IsAdmin: true, IsActive: true, ProhibitLogin: true}
	bot := &user_model.User{Type: user_model.UserTypeBot}
	with := func(limit int64) *user_model.User {
		return &user_model.User{Type: user_model.UserTypeIndividual, PersonalRepoSizeLimit: limit}
	}

	assert.Zero(t, EffectivePersonalRepoSizeLimit(individual, 0), "the site limit is off")
	assert.Zero(t, EffectivePersonalRepoSizeLimit(with(7), 0), "overrides only apply while the site limit is on")
	assert.EqualValues(t, 100, EffectivePersonalRepoSizeLimit(individual, 100))
	assert.EqualValues(t, 100, EffectivePersonalRepoSizeLimit(bot, 100))
	assert.Zero(t, EffectivePersonalRepoSizeLimit(org, 100))
	assert.Zero(t, EffectivePersonalRepoSizeLimit(admin, 100))
	assert.EqualValues(t, 100, EffectivePersonalRepoSizeLimit(inactiveAdmin, 100))
	assert.EqualValues(t, 100, EffectivePersonalRepoSizeLimit(prohibitedAdmin, 100))
	assert.Zero(t, EffectivePersonalRepoSizeLimit(with(-1), 100), "unlimited")
	assert.EqualValues(t, 500, EffectivePersonalRepoSizeLimit(with(500), 100), "higher")
	assert.EqualValues(t, 50, EffectivePersonalRepoSizeLimit(with(50), 100), "lower")
}

func TestPersonalRepoLimitReached(t *testing.T) {
	assert.False(t, PersonalRepoLimit{Used: 10}.Reached(), "no limit")
	assert.False(t, PersonalRepoLimit{Used: 9, Limit: 10}.Reached(), "one byte under")
	assert.True(t, PersonalRepoLimit{Used: 10, Limit: 10}.Reached(), "at the limit")
	assert.True(t, PersonalRepoLimit{Used: 11, Limit: 10}.Reached(), "over")
	assert.Equal(t, "Personal repository size limit reached (1 KiB of 1 KiB used). Delete content in the web UI to write again.", PersonalRepoLimit{Used: 1024, Limit: 1024}.MessageFor(2, 2))
	assert.NotContains(t, PersonalRepoLimit{Used: 1024, Limit: 1024}.MessageFor(4, 2), "KiB", "only the owner sees the numbers")
	assert.Equal(t, "1.5 MiB", FormatSize(3<<19))
	assert.Equal(t, "512 B", FormatSize(512))
	assert.Equal(t, "2 GiB", FormatSize(2<<30))
}

func TestGetPersonalRepoUsage(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	// user5 owns repo4 only
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 4})
	require.EqualValues(t, 5, repo.OwnerID)
	require.NoError(t, repo_model.UpdateRepoSize(ctx, repo.ID, 1000, 300, 20))
	used, err := GetPersonalRepoUsage(ctx, 5)
	require.NoError(t, err)
	assert.EqualValues(t, 1020, used, "git and wiki; the stored LFS size is not used")

	// LFS objects count as stored now, without a size refresh
	_, err = git_model.NewLFSMetaObject(ctx, repo.ID, lfs.Pointer{Oid: "0000000000000000000000000000000000000000000000000000000000000001", Size: 4000})
	require.NoError(t, err)
	used, err = GetPersonalRepoUsage(ctx, 5)
	require.NoError(t, err)
	assert.EqualValues(t, 5020, used)

	// repositories in the trash count
	_, err = db.Exec(ctx, "UPDATE repository SET trashed_unix = 1 WHERE id = ?", repo.ID)
	require.NoError(t, err)
	used, err = GetPersonalRepoUsage(ctx, 5)
	require.NoError(t, err)
	assert.EqualValues(t, 5020, used)

	usages, err := GetPersonalRepoUsages(ctx, []int64{5, 9999})
	require.NoError(t, err)
	assert.Equal(t, map[int64]int64{5: 5020}, usages)
}

func TestGetPersonalRepoLimitAndEvaluate(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	defer test.MockVariableValue(&setting.Quota.Enabled, false)()
	require.NoError(t, repo_model.UpdateRepoSize(ctx, 4, 1000, 0, 0))

	evaluate := func(uid int64) bool {
		ok, err := EvaluateForUser(ctx, uid, LimitSubjectSizeReposAll)
		require.NoError(t, err)
		return ok
	}

	// off: nothing is refused
	l, err := GetPersonalRepoLimit(ctx, 5)
	require.NoError(t, err)
	assert.Equal(t, PersonalRepoLimit{}, l)
	assert.True(t, evaluate(5))

	for limit, ok := range map[int64]bool{1001: true, 1000: false, 999: false} {
		setSiteSizeLimit(t, limit)
		l, err := GetPersonalRepoLimit(ctx, 5)
		require.NoError(t, err)
		assert.Equal(t, PersonalRepoLimit{Used: 1000, Limit: limit}, l)
		assert.Equal(t, ok, evaluate(5), "limit %d, independent of [quota]", limit)
	}

	// still at 999: organizations, admins, unlimited users and pseudo users are never locked
	assert.True(t, evaluate(3))
	assert.True(t, evaluate(1))
	assert.True(t, evaluate(-2))
	require.NoError(t, user_model.UpdateUserCols(ctx, &user_model.User{ID: 5, PersonalRepoSizeLimit: -1}, "personal_repo_size_limit"))
	assert.True(t, evaluate(5))
	require.NoError(t, user_model.UpdateUserCols(ctx, &user_model.User{ID: 5, PersonalRepoSizeLimit: 2000}, "personal_repo_size_limit"))
	assert.True(t, evaluate(5), "a higher override")

	rows, total, err := FindPersonalRepoOverLimit(ctx, 100)
	require.NoError(t, err)
	names := map[string]PersonalRepoOverLimit{}
	for _, r := range rows {
		names[r.Name] = *r
	}
	assert.Len(t, rows, int(total))
	assert.NotContains(t, names, "user5", "under its override")
	assert.NotContains(t, names, "user1", "admin")
	assert.NotContains(t, names, "org3", "organization")
	require.NoError(t, user_model.UpdateUserCols(ctx, &user_model.User{ID: 5, PersonalRepoSizeLimit: 1000}, "personal_repo_size_limit"))
	rows, _, err = FindPersonalRepoOverLimit(ctx, 100)
	require.NoError(t, err)
	found := false
	for _, r := range rows {
		if r.Name == "user5" {
			found = true
			assert.Equal(t, PersonalRepoOverLimit{ID: 5, Name: "user5", Used: 1000, Limit: 1000}, *r)
		}
	}
	assert.True(t, found)
}
