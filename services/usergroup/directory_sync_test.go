// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package usergroup

import (
	"testing"

	org_model "forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/container"

	"github.com/stretchr/testify/require"
	"xorm.io/builder"
)

func TestSyncDirectoryGroups(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()
	const sourceID, otherSourceID = 7, 8

	devs, admins, manual, other := newGroup(t, "devs"), newGroup(t, "admins"), newGroup(t, "manual"), newGroup(t, "other")
	user := loadUser(t, 5)
	require.NoError(t, AddMember(ctx, manual, user))
	require.NoError(t, addMember(ctx, other, user, otherSourceID))

	team2 := loadTeam(t, 2)
	require.NoError(t, LinkTeam(ctx, devs, team2))

	mapping := map[string]container.Set[string]{
		"cn=devs":    container.SetOf("Devs", "unknown-group"),
		"cn=admins":  container.SetOf("admins"),
		"cn=manual":  container.SetOf("manual"),
		"cn=other":   container.SetOf("other"),
		"cn=devs-ii": container.SetOf("devs"),
	}
	sync := func(remove bool, dirGroups ...string) {
		t.Helper()
		require.NoError(t, SyncDirectoryGroups(ctx, user, sourceID, container.SetOf(dirGroups...), mapping, remove))
	}
	assertMember := func(g *org_model.UserGroup, loginSourceID int64) {
		t.Helper()
		unittest.AssertExistsAndLoadBean(t, &org_model.UserGroupUser{GroupID: g.ID, UID: user.ID, LoginSourceID: loginSourceID}, builder.Eq{"login_source_id": loginSourceID})
	}
	assertNotMember := func(g *org_model.UserGroup) {
		t.Helper()
		unittest.AssertNotExistsBean(t, &org_model.UserGroupUser{GroupID: g.ID, UID: user.ID})
	}

	t.Run("add, keeping existing rows, ignoring unknown groups", func(t *testing.T) {
		sync(true, "cn=devs", "cn=admins", "cn=manual", "cn=other", "cn=unmapped")
		assertMember(devs, sourceID)
		assertMember(admins, sourceID)
		assertMember(manual, 0)
		assertMember(other, otherSourceID)
		assertTeamMember(t, team2, user.ID, org_model.MembershipReasonAddedByUserGroup)
	})

	t.Run("removal off", func(t *testing.T) {
		sync(false)
		assertMember(devs, sourceID)
		assertMember(admins, sourceID)
	})

	t.Run("still mapped from another directory group", func(t *testing.T) {
		sync(true, "cn=devs-ii", "cn=admins")
		assertMember(devs, sourceID)
	})

	t.Run("remove only own rows", func(t *testing.T) {
		sync(true)
		assertNotMember(devs)
		assertNotMember(admins)
		assertMember(manual, 0)
		assertMember(other, otherSourceID)
		assertNotTeamMember(t, team2, user.ID)
	})
}

func TestSyncDirectoryGroupsLastOwner(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := ownCtx()

	// team 15 is the owners team of org 22 and has no members
	owners := loadTeam(t, 15)
	group := newGroup(t, "org22-owners")
	require.NoError(t, LinkTeam(ctx, group, owners))
	user := loadUser(t, 5)
	mapping := map[string]container.Set[string]{"cn=owners": container.SetOf("org22-owners")}

	require.NoError(t, SyncDirectoryGroups(ctx, user, 7, container.SetOf("cn=owners"), mapping, true))
	assertTeamMember(t, owners, user.ID, org_model.MembershipReasonAddedByUserGroup)

	// the directory wins: the user leaves the group, but stays the last owner of the organization
	require.NoError(t, SyncDirectoryGroups(ctx, user, 7, nil, mapping, true))
	unittest.AssertNotExistsBean(t, &org_model.UserGroupUser{GroupID: group.ID, UID: user.ID})
	assertTeamMember(t, owners, user.ID, org_model.MembershipReasonAddedByUser)
}
