// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo_test

import (
	"testing"

	actions_model "forgejo.org/models/actions"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"github.com/stretchr/testify/require"
)

// Deleting a project deletes its Actions secrets and variables and nothing else.
func TestDeleteRepoGroupActions(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	a, err := repo_model.CreateRepoGroup(ctx, org3, "pa", "")
	require.NoError(t, err)
	b, err := repo_model.CreateRepoGroup(ctx, org3, "pb", "")
	require.NoError(t, err)
	for _, g := range []int64{0, a.ID, b.ID} {
		_, err = secret_model.InsertEncryptedSecret(ctx, 3, g, 0, "TOKEN", "x")
		require.NoError(t, err)
		_, err = actions_model.InsertVariable(ctx, 3, g, 0, "TOKEN", "x")
		require.NoError(t, err)
	}

	require.NoError(t, repo_model.DeleteRepoGroup(ctx, a))
	unittest.AssertNotExistsBean(t, &secret_model.Secret{OwnerID: 3, GroupID: a.ID})
	unittest.AssertNotExistsBean(t, &actions_model.ActionVariable{OwnerID: 3, GroupID: a.ID})
	for _, g := range []int64{0, b.ID} {
		unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{OwnerID: 3, GroupID: g})
		unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{OwnerID: 3, GroupID: g})
	}
}
