// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"sync"
	"testing"
	"time"

	"forgejo.org/models"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type teamGroupFixture struct {
	admin, owner, writer, adminMember *user_model.User // writer: team 2 (write), adminMember: team 12 (admin)
	org                               *organization.Organization
	pay, web                          *repo_model.RepoGroup
}

func prepareTeamGroup(t *testing.T) *teamGroupFixture {
	t.Helper()
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	f := &teamGroupFixture{
		admin:       unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}),
		owner:       unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}),
		writer:      unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}),
		adminMember: unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 28}),
		org:         organization.OrgFromUser(unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})),
	}
	var err error
	f.pay, err = repo_model.CreateRepoGroup(ctx, f.org.AsUser(), "pay", "")
	require.NoError(t, err)
	f.web, err = repo_model.CreateRepoGroup(ctx, f.org.AsUser(), "web", "")
	require.NoError(t, err)
	return f
}

func (f *teamGroupFixture) repo(t *testing.T, name string, groupID int64) *repo_model.Repository {
	t.Helper()
	repo, err := CreateRepositoryDirectly(t.Context(), f.admin, f.org.AsUser(), CreateRepoOptions{Name: name, GroupID: groupID, IsPrivate: true})
	require.NoError(t, err)
	return repo
}

func accessMode(t *testing.T, repoID int64, u *user_model.User) perm.AccessMode {
	t.Helper()
	repo, err := repo_model.GetRepositoryByIDIncludingTrashed(t.Context(), repoID)
	require.NoError(t, err)
	p, err := access_model.GetUserRepoPermission(t.Context(), repo, u)
	require.NoError(t, err)
	return p.AccessMode
}

func teamRow(t *testing.T, teamID, repoID int64) *organization.TeamRepo {
	t.Helper()
	row := new(organization.TeamRepo)
	has, err := db.GetEngine(t.Context()).Where("team_id = ? AND repo_id = ?", teamID, repoID).Get(row)
	require.NoError(t, err)
	if !has {
		return nil
	}
	return row
}

func consistent(t *testing.T) {
	t.Helper()
	unittest.CheckConsistencyFor(t, &user_model.User{}, &repo_model.Repository{}, &organization.Team{})
}

func TestLinkTeamToRepoGroup(t *testing.T) {
	f := prepareTeamGroup(t)
	ctx := t.Context()
	inPay := f.repo(t, "api", f.pay.ID)
	trashed := f.repo(t, "old", f.pay.ID)
	require.NoError(t, TrashRepository(ctx, f.admin, trashed))
	inWeb := f.repo(t, "site", f.web.ID)
	root := f.repo(t, "root", 0)
	assert.Equal(t, perm.AccessModeNone, accessMode(t, inPay.ID, f.writer))

	// the link grants every repository of the project, trashed ones too, with the team's mode
	require.NoError(t, LinkTeamToRepoGroup(ctx, f.owner, f.org, 2, f.pay.ID))
	assert.Equal(t, perm.AccessModeWrite, accessMode(t, inPay.ID, f.writer))
	assert.True(t, teamRow(t, 2, trashed.ID).ViaGroup)
	assert.Nil(t, teamRow(t, 2, inWeb.ID))
	assert.Nil(t, teamRow(t, 2, root.ID))
	require.ErrorIs(t, LinkTeamToRepoGroup(ctx, f.owner, f.org, 2, f.pay.ID), util.ErrAlreadyExist)
	unittest.CheckTeamGroupRows(t)

	// a repository created in the linked project gets it too
	created := f.repo(t, "new", f.pay.ID)
	assert.True(t, teamRow(t, 2, created.ID).ViaGroup)

	// a direct row of another repository stays when unlinking; the link's rows go
	require.NoError(t, LinkTeamToRepoGroup(ctx, f.owner, f.org, 2, f.web.ID))
	require.NoError(t, UnlinkTeamFromRepoGroup(ctx, f.owner, f.org, 2, f.web.ID))
	assert.Nil(t, teamRow(t, 2, inWeb.ID))
	require.NoError(t, UnlinkTeamFromRepoGroup(ctx, f.owner, f.org, 2, f.pay.ID))
	for _, id := range []int64{inPay.ID, trashed.ID, created.ID} {
		assert.Nil(t, teamRow(t, 2, id))
	}
	assert.Equal(t, perm.AccessModeNone, accessMode(t, inPay.ID, f.writer))
	require.ErrorIs(t, UnlinkTeamFromRepoGroup(ctx, f.owner, f.org, 2, f.pay.ID), util.ErrNotExist)
	unittest.CheckTeamGroupRows(t)

	// who may: an acting owner or a site admin; another org's team or project is not found
	require.ErrorIs(t, LinkTeamToRepoGroup(ctx, f.writer, f.org, 2, f.pay.ID), util.ErrPermissionDenied)
	require.ErrorIs(t, LinkTeamToRepoGroup(ctx, f.owner, f.org, 3, f.pay.ID), util.ErrNotExist) // team 3 is org6's
	other, err := repo_model.CreateRepoGroup(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 17}), "other", "")
	require.NoError(t, err)
	require.ErrorIs(t, LinkTeamToRepoGroup(ctx, f.owner, f.org, 2, other.ID), util.ErrNotExist)
	require.NoError(t, LinkTeamToRepoGroup(ctx, f.admin, f.org, 2, f.pay.ID))
	org3 := f.org.AsUser()
	org3.RequireTwoFactor = true
	require.NoError(t, user_model.UpdateUserCols(ctx, org3, "require_two_factor"))
	require.ErrorIs(t, UnlinkTeamFromRepoGroup(ctx, f.owner, f.org, 2, f.pay.ID), util.ErrPermissionDenied, "2FA-blocked owner")
	org3.RequireTwoFactor, org3.IsArchived = false, true
	require.NoError(t, user_model.UpdateUserCols(ctx, org3, "require_two_factor", "is_archived"))
	require.True(t, organization.IsErrOrgArchived(UnlinkTeamFromRepoGroup(ctx, f.owner, f.org, 2, f.pay.ID)))
	org3.IsArchived = false
	require.NoError(t, user_model.UpdateUserCols(ctx, org3, "is_archived"))

	require.NoError(t, DeleteRepositoryDirectly(ctx, trashed.ID, DeleteRepositoryOpts{}))
	consistent(t)
}

// Removing a repository from a team never takes what a link grants, and adding it again is a duplicate.
func TestTeamGroupDirectRows(t *testing.T) {
	f := prepareTeamGroup(t)
	ctx := t.Context()
	inPay := f.repo(t, "api", f.pay.ID)
	other := f.repo(t, "other", f.web.ID)
	team, err := organization.GetTeamByID(ctx, 2)
	require.NoError(t, err)

	// a direct row, then the link: removing the direct row keeps the link's grant
	require.NoError(t, models.AddRepository(ctx, team, inPay))
	require.NoError(t, LinkTeamToRepoGroup(ctx, f.owner, f.org, team.ID, f.pay.ID))
	assert.False(t, teamRow(t, team.ID, inPay.ID).ViaGroup)
	require.NoError(t, RemoveRepositoryFromTeam(ctx, team, inPay.ID))
	assert.True(t, teamRow(t, team.ID, inPay.ID).ViaGroup)
	assert.Equal(t, perm.AccessModeWrite, accessMode(t, inPay.ID, f.writer))

	// removing a via row does nothing (adding it again is refused as a duplicate: see the integration test)
	require.NoError(t, RemoveRepositoryFromTeam(ctx, team, inPay.ID))
	assert.True(t, teamRow(t, team.ID, inPay.ID).ViaGroup)

	// "remove all" keeps the repositories of linked projects
	require.NoError(t, models.AddRepository(ctx, team, other))
	require.NoError(t, models.RemoveAllRepositories(ctx, team))
	assert.Nil(t, teamRow(t, team.ID, other.ID))
	assert.True(t, teamRow(t, team.ID, inPay.ID).ViaGroup)
	team, err = organization.GetTeamByID(ctx, 2)
	require.NoError(t, err)
	assert.Equal(t, 1, team.NumRepos)
	consistent(t)

	// a team that includes all repositories keeps them as direct rows when unlinked
	owners, err := organization.GetTeamByID(ctx, 1)
	require.NoError(t, err)
	require.NoError(t, LinkTeamToRepoGroup(ctx, f.owner, f.org, owners.ID, f.pay.ID))
	require.NoError(t, UnlinkTeamFromRepoGroup(ctx, f.owner, f.org, owners.ID, f.pay.ID))
	assert.False(t, teamRow(t, owners.ID, inPay.ID).ViaGroup)

	// deleting the team removes its links
	require.NoError(t, models.DeleteTeam(ctx, team))
	unittest.AssertNotExistsBean(t, &organization.TeamGroup{TeamID: team.ID})
	assert.Nil(t, teamRow(t, team.ID, inPay.ID))
	consistent(t)
}

// Moves, transfers and project deletion keep the rows in step with the links.
func TestTeamGroupMoveAndDelete(t *testing.T) {
	f := prepareTeamGroup(t)
	ctx := t.Context()
	repo := f.repo(t, "api", 0)
	team7, err := organization.GetTeamByID(ctx, 7)
	require.NoError(t, err)
	require.NoError(t, models.AddRepository(ctx, team7, repo)) // a direct row, which every move keeps
	require.NoError(t, LinkTeamToRepoGroup(ctx, f.owner, f.org, 2, f.pay.ID))
	require.NoError(t, LinkTeamToRepoGroup(ctx, f.owner, f.org, 12, f.web.ID))

	require.NoError(t, MoveRepository(ctx, f.owner, reloadRepo(t, repo.ID), f.pay.ID))
	assert.Equal(t, perm.AccessModeWrite, accessMode(t, repo.ID, f.writer))
	assert.Equal(t, perm.AccessModeNone, accessMode(t, repo.ID, f.adminMember))
	require.NoError(t, MoveRepository(ctx, f.owner, reloadRepo(t, repo.ID), f.web.ID))
	assert.Equal(t, perm.AccessModeNone, accessMode(t, repo.ID, f.writer))
	assert.Equal(t, perm.AccessModeAdmin, accessMode(t, repo.ID, f.adminMember))
	require.NoError(t, MoveRepository(ctx, f.owner, reloadRepo(t, repo.ID), 0))
	assert.Equal(t, perm.AccessModeNone, accessMode(t, repo.ID, f.adminMember))
	assert.False(t, teamRow(t, 7, repo.ID).ViaGroup)
	consistent(t)

	// a transfer out of the organization leaves no row
	require.NoError(t, MoveRepository(ctx, f.owner, reloadRepo(t, repo.ID), f.pay.ID))
	require.NoError(t, TransferOwnership(ctx, f.admin, f.owner, reloadRepo(t, repo.ID), nil))
	unittest.AssertNotExistsBean(t, &organization.TeamRepo{RepoID: repo.ID})
	consistent(t)

	// deleting an empty project, and an organization, removes their links
	require.NoError(t, DeleteRepoGroup(ctx, f.org.AsUser(), f.web))
	unittest.AssertNotExistsBean(t, &organization.TeamGroup{GroupID: f.web.ID})
	org6 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 6})
	g6, err := repo_model.CreateRepoGroup(ctx, org6, "g", "")
	require.NoError(t, err)
	require.NoError(t, db.Insert(ctx, &organization.TeamGroup{OrgID: 6, TeamID: 3, GroupID: g6.ID}))
	require.NoError(t, organization.DeleteOrganization(ctx, organization.OrgFromUser(org6)))
	unittest.AssertNotExistsBean(t, &organization.TeamGroup{OrgID: 6})
	consistent(t)
}

// A creator who gets admin through a linked team gets no collaborator row, so unlinking revokes their access.
func TestTeamGroupCreator(t *testing.T) {
	f := prepareTeamGroup(t)
	ctx := t.Context()
	require.NoError(t, LinkTeamToRepoGroup(ctx, f.owner, f.org, 12, f.pay.ID))
	repo, err := CreateRepositoryDirectly(ctx, f.adminMember, f.org.AsUser(), CreateRepoOptions{Name: "mine", GroupID: f.pay.ID, IsPrivate: true})
	require.NoError(t, err)
	assert.Equal(t, perm.AccessModeAdmin, accessMode(t, repo.ID, f.adminMember))
	unittest.AssertNotExistsBean(t, &repo_model.Collaboration{RepoID: repo.ID, UserID: f.adminMember.ID})
	require.NoError(t, UnlinkTeamFromRepoGroup(ctx, f.owner, f.org, 12, f.pay.ID))
	assert.Equal(t, perm.AccessModeNone, accessMode(t, repo.ID, f.adminMember))
	consistent(t)
}

// Links and moves of the same repositories at the same time all finish and stay consistent.
func TestTeamGroupLockOrder(t *testing.T) {
	f := prepareTeamGroup(t)
	a := f.repo(t, "a", f.pay.ID)
	b := f.repo(t, "b", f.web.ID)
	for i := range 6 {
		var wg sync.WaitGroup
		errs := make([]error, 4)
		ra, rb := reloadRepo(t, a.ID), reloadRepo(t, b.ID)
		ta, tb := f.web.ID, f.pay.ID
		if ra.GroupID == f.web.ID {
			ta, tb = f.pay.ID, f.web.ID
		}
		link := LinkTeamToRepoGroup
		if i%2 == 1 {
			link = UnlinkTeamFromRepoGroup
		}
		wg.Add(4)
		go func() { defer wg.Done(); errs[0] = MoveRepository(db.DefaultContext, f.admin, ra, ta) }()
		go func() { defer wg.Done(); errs[1] = MoveRepository(db.DefaultContext, f.admin, rb, tb) }()
		go func() { defer wg.Done(); errs[2] = link(db.DefaultContext, f.owner, f.org, 2, f.pay.ID) }()
		go func() { defer wg.Done(); errs[3] = link(db.DefaultContext, f.owner, f.org, 7, f.web.ID) }()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Minute):
			t.Fatal("links and moves wait for each other")
		}
		for _, err := range errs {
			require.NoError(t, err)
		}
		unittest.CheckTeamGroupRows(t)
	}
	consistent(t)
}

// Removing a repository from a team, alone or with "remove all", while the project is linked, unlinked or the
// repository moved: the rows always match the links afterwards.
func TestTeamGroupRemoveRace(t *testing.T) {
	f := prepareTeamGroup(t)
	ctx := t.Context()
	a := f.repo(t, "a", f.pay.ID)
	for i := range 8 {
		team, err := organization.GetTeamByID(ctx, 2)
		require.NoError(t, err)
		ra := reloadRepo(t, a.ID)
		if row := teamRow(t, team.ID, a.ID); row == nil {
			require.NoError(t, models.AddRepository(ctx, team, ra))
		} else if row.ViaGroup {
			_, err := db.GetEngine(ctx).Where("team_id = ? AND repo_id = ?", team.ID, a.ID).Cols("via_group").Update(&organization.TeamRepo{})
			require.NoError(t, err)
		}
		link := LinkTeamToRepoGroup
		if unittest.BeanExists(t, &organization.TeamGroup{TeamID: team.ID, GroupID: f.pay.ID}) {
			link = UnlinkTeamFromRepoGroup
		}
		target := f.web.ID
		if ra.GroupID == f.web.ID {
			target = f.pay.ID
		}
		remove := func() error { return RemoveRepositoryFromTeam(db.DefaultContext, team, a.ID) }
		if i%2 == 1 {
			remove = func() error { return models.RemoveAllRepositories(db.DefaultContext, team) }
		}

		var wg sync.WaitGroup
		errs := make([]error, 3)
		wg.Add(3)
		go func() { defer wg.Done(); errs[0] = remove() }()
		go func() { defer wg.Done(); errs[1] = link(db.DefaultContext, f.owner, f.org, team.ID, f.pay.ID) }()
		go func() { defer wg.Done(); errs[2] = MoveRepository(db.DefaultContext, f.admin, ra, target) }()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Minute):
			t.Fatal("removals, links and moves wait for each other")
		}
		if errs[0] != nil { // the repository or the team's projects changed meanwhile
			require.ErrorIs(t, errs[0], util.ErrInvalidArgument)
		}
		require.NoError(t, errs[1])
		require.NoError(t, errs[2])
		unittest.CheckTeamGroupRows(t)
	}
	consistent(t)
}
