// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo_test

import (
	"testing"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	webhook_model "forgejo.org/models/webhook"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newGroupHook(t *testing.T, owner, group int64) int64 {
	t.Helper()
	w := &webhook_model.Webhook{OwnerID: owner, GroupID: group, URL: "http://example.com/h", HTTPMethod: "POST", ContentType: webhook_model.ContentTypeJSON, Type: "forgejo", Events: "{}"}
	require.NoError(t, webhook_model.CreateWebhook(db.DefaultContext, w, ""))
	_, err := webhook_model.CreateHookTask(db.DefaultContext, &webhook_model.HookTask{HookID: w.ID, PayloadContent: "{}", PayloadVersion: 2})
	require.NoError(t, err)
	return w.ID
}

func assertHook(t *testing.T, id int64, exists bool) {
	t.Helper()
	if exists {
		unittest.AssertExistsAndLoadBean(t, &webhook_model.Webhook{ID: id})
		unittest.AssertExistsAndLoadBean(t, &webhook_model.HookTask{HookID: id})
	} else {
		unittest.AssertNotExistsBean(t, &webhook_model.Webhook{ID: id})
		unittest.AssertNotExistsBean(t, &webhook_model.HookTask{HookID: id})
	}
}

func TestDeleteRepoGroupWebhooks(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	a, err := repo_model.CreateRepoGroup(ctx, org3, "pa", "")
	require.NoError(t, err)
	b, err := repo_model.CreateRepoGroup(ctx, org3, "pb", "")
	require.NoError(t, err)
	hookA, hookB, orgHook := newGroupHook(t, 3, a.ID), newGroupHook(t, 3, b.ID), newGroupHook(t, 3, 0)

	require.NoError(t, repo_model.DeleteRepoGroup(ctx, a))
	assertHook(t, hookA, false)
	assertHook(t, hookB, true)
	assertHook(t, orgHook, true)
}

func TestOrphanedGroupWebhooks(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	group, err := repo_model.CreateRepoGroup(ctx, org3, "pa", "")
	require.NoError(t, err)
	ok := newGroupHook(t, 3, group.ID)
	orgHook := newGroupHook(t, 3, 0)
	missing := newGroupHook(t, 3, group.ID+99) // the project is gone
	otherOrg := newGroupHook(t, 17, group.ID)  // the project is another organization's
	notOrg := newGroupHook(t, 2, group.ID)     // the owner is a user

	n, err := webhook_model.CountOrphanedGroupWebhooks(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 3, n)
	require.NoError(t, webhook_model.DeleteOrphanedGroupWebhooks(ctx))
	assertHook(t, ok, true)
	assertHook(t, orgHook, true)
	for _, id := range []int64{missing, otherOrg, notOrg} {
		assertHook(t, id, false)
	}
}
