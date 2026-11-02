// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package user_test

import (
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/structs"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AC17: the lookups and listings skip a trashed account (an organization in the trash or a tombstone); only the
// lookup for the trash service sees it, and the name stays taken.
func TestTrashedAccountHidden(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET trashed_unix = 1700000000 WHERE id IN (3, 27)")
	require.NoError(t, err)

	for _, id := range []int64{3, 27} {
		_, err := user_model.GetUserByID(ctx, id)
		require.True(t, user_model.IsErrUserNotExist(err), id)
		u, err := user_model.GetUserByIDIncludingTrashed(ctx, id)
		require.NoError(t, err)
		assert.True(t, u.IsTrashed())
		users, err := user_model.GetUserByIDs(ctx, []int64{id})
		require.NoError(t, err)
		assert.Empty(t, users)
		users, err = user_model.GetPossibleUserByIDs(ctx, []int64{id})
		require.NoError(t, err)
		assert.Empty(t, users)
		name, err := user_model.GetUserNameByID(ctx, id)
		require.NoError(t, err)
		assert.Empty(t, name)
	}
	for _, name := range []string{"org3", "ORG3", "user27"} {
		_, err := user_model.GetUserByName(ctx, name)
		require.True(t, user_model.IsErrUserNotExist(err), name)
		exists, err := user_model.IsUserExist(ctx, 0, name)
		require.NoError(t, err)
		assert.True(t, exists, "%s stays reserved", name)
	}
	ids, err := user_model.GetUserIDsByNames(ctx, []string{"org3", "user27", "user2"}, true)
	require.NoError(t, err)
	assert.Equal(t, []int64{2}, ids)

	for _, opts := range []*user_model.SearchUserOptions{
		{Type: user_model.UserTypeOrganization, Actor: unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}), Visible: []structs.VisibleType{structs.VisibleTypePublic, structs.VisibleTypeLimited, structs.VisibleTypePrivate}},
		{Type: user_model.UserTypeIndividual, Actor: unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})},
	} {
		users, _, err := user_model.SearchUsers(ctx, opts)
		require.NoError(t, err)
		for _, u := range users {
			assert.NotContains(t, []int64{3, 27}, u.ID)
		}
	}

	mailable, err := user_model.GetMaileableUsersByIDs(ctx, []int64{27, 2}, false)
	require.NoError(t, err)
	for _, u := range mailable {
		assert.NotEqual(t, int64(27), u.ID)
	}
}
