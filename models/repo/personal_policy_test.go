// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo_test

import (
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
)

func TestFindPersonalRepoViolators(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext

	rows, total, err := repo_model.FindPersonalRepoViolators(ctx, setting.PersonalReposAllowed, 100)
	require.NoError(t, err)
	assert.Empty(t, rows)
	assert.Zero(t, total)

	totals := map[string]int64{}
	for _, mode := range []string{setting.PersonalReposPrivateOnly, setting.PersonalReposDisabled} {
		rows, total, err := repo_model.FindPersonalRepoViolators(ctx, mode, 100)
		require.NoError(t, err)
		require.NotZero(t, total, mode)
		assert.Len(t, rows, int(total), mode)
		totals[mode] = total
		for _, r := range rows {
			owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: r.OwnerID})
			assert.False(t, owner.IsOrganization(), r.OwnerName)
			assert.False(t, owner.IsAdmin, r.OwnerName)
			assert.Equal(t, owner.Name, r.OwnerName)
			cond := builder.Eq{"owner_id": r.OwnerID, "trashed_unix": 0}
			if mode == setting.PersonalReposPrivateOnly {
				cond["is_private"] = false
			}
			assert.Equal(t, unittest.GetCountByCond(t, "repository", cond), r.NumRepos, r.OwnerName)
		}
	}
	assert.GreaterOrEqual(t, totals[setting.PersonalReposDisabled], totals[setting.PersonalReposPrivateOnly])

	// user1 is the admin and owns no repository; make user2 a usable admin: it isn't listed any more
	_, err = db.GetEngine(ctx).ID(2).Cols("is_admin").Update(&user_model.User{IsAdmin: true})
	require.NoError(t, err)
	rows, total, err = repo_model.FindPersonalRepoViolators(ctx, setting.PersonalReposDisabled, 1)
	require.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, totals[setting.PersonalReposDisabled]-1, total)
	assert.NotEqual(t, "user2", rows[0].OwnerName)
}
