// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package webhook

import (
	"slices"
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/optional"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hookIDs(ws []*Webhook) []int64 {
	ids := make([]int64, 0, len(ws))
	for _, w := range ws {
		ids = append(ids, w.ID)
	}
	slices.Sort(ids)
	return ids
}

// Project hooks (owner_id = the organization, group_id = the project) never show up in a reader of organization
// hooks, and the other way round: every reader binds group_id.
func TestProjectWebhookReaders(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	_, err := db.Exec(ctx, "DELETE FROM `webhook`")
	require.NoError(t, err)
	mk := func(owner, group, repo int64, system bool) int64 {
		w := &Webhook{OwnerID: owner, GroupID: group, RepoID: repo, IsSystemWebhook: system, URL: "http://example.com/h", HTTPMethod: "POST", ContentType: ContentTypeJSON, IsActive: true, Type: "forgejo", Events: "{}"}
		require.NoError(t, CreateWebhook(ctx, w, ""))
		return w.ID
	}
	repoHook := mk(0, 0, 1, false)
	orgHook := mk(3, 0, 0, false)
	projA := mk(3, 10, 0, false)
	projB := mk(3, 11, 0, false)
	otherOrg := mk(6, 10, 0, false) // the same group ID under another owner
	system := mk(0, 0, 0, true)
	def := mk(0, 0, 0, false)

	list := func(opts ListWebhookOptions) []int64 {
		ws, err := db.Find[Webhook](ctx, opts)
		require.NoError(t, err)
		return hookIDs(ws)
	}
	assert.Equal(t, []int64{orgHook}, list(ListWebhookOptions{OwnerID: 3}), "the organization list has no project hook")
	assert.Equal(t, []int64{projA}, list(ListWebhookOptions{OwnerID: 3, GroupID: 10}))
	assert.Equal(t, []int64{projB}, list(ListWebhookOptions{OwnerID: 3, GroupID: 11, IsActive: optional.Some(true)}))
	assert.Equal(t, []int64{otherOrg}, list(ListWebhookOptions{OwnerID: 6, GroupID: 10}))
	assert.Empty(t, list(ListWebhookOptions{GroupID: 10}), "a project without its owner matches nothing")
	assert.Equal(t, []int64{repoHook}, list(ListWebhookOptions{RepoID: 1}))

	_, err = GetWebhookByOwnerID(ctx, 3, projA)
	require.ErrorIs(t, err, ErrWebhookNotExist{ID: projA})
	got, err := GetWebhookByOwnerID(ctx, 3, orgHook)
	require.NoError(t, err)
	assert.Equal(t, orgHook, got.ID)

	got, err = GetWebhookByGroupID(ctx, 3, 10, projA)
	require.NoError(t, err)
	assert.EqualValues(t, 10, got.GroupID)
	for _, c := range [][3]int64{{3, 11, projA}, {6, 10, projA}, {3, 10, orgHook}, {3, 0, projA}, {3, 10, otherOrg}, {3, 10, repoHook}, {3, 10, system}} {
		_, err = GetWebhookByGroupID(ctx, c[0], c[1], c[2])
		require.ErrorIs(t, err, ErrWebhookNotExist{ID: c[2]}, "%v", c)
	}

	// the admin readers only see their own rows
	sys, _, err := GetSystemWebhooks(ctx, db.ListOptions{ListAll: true}, false)
	require.NoError(t, err)
	assert.Equal(t, []int64{system}, hookIDs(sys))
	defs, _, err := GetDefaultWebhooks(ctx)
	require.NoError(t, err)
	assert.Equal(t, []int64{def}, hookIDs(defs))
	for _, id := range []int64{projA, orgHook} {
		_, err = GetSystemOrDefaultWebhook(ctx, id)
		require.ErrorIs(t, err, ErrWebhookNotExist{ID: id})
	}
	require.ErrorIs(t, DeleteDefaultSystemWebhook(ctx, projA), ErrWebhookNotExist{ID: projA})

	// deleting takes the same scope, with the deliveries
	_, err = CreateHookTask(ctx, &HookTask{HookID: projA, PayloadContent: "{}", PayloadVersion: 2})
	require.NoError(t, err)
	require.ErrorIs(t, DeleteWebhookByOwnerID(ctx, 3, projA), ErrWebhookNotExist{ID: projA})
	require.ErrorIs(t, DeleteWebhookByGroupID(ctx, 3, 11, projA), ErrWebhookNotExist{ID: projA})
	require.ErrorIs(t, DeleteWebhookByGroupID(ctx, 6, 10, projA), ErrWebhookNotExist{ID: projA})
	require.ErrorIs(t, DeleteWebhookByGroupID(ctx, 3, 10, orgHook), ErrWebhookNotExist{ID: orgHook})
	unittest.AssertExistsAndLoadBean(t, &Webhook{ID: projA})
	require.NoError(t, DeleteWebhookByGroupID(ctx, 3, 10, projA))
	unittest.AssertNotExistsBean(t, &Webhook{ID: projA})
	unittest.AssertNotExistsBean(t, &HookTask{HookID: projA})
	unittest.AssertExistsAndLoadBean(t, &Webhook{ID: projB})
}
