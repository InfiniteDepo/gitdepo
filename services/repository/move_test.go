// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func reloadRepo(t *testing.T, id int64) *repo_model.Repository {
	t.Helper()
	repo, err := repo_model.GetRepositoryByIDIncludingTrashed(t.Context(), id)
	require.NoError(t, err)
	require.NoError(t, repo.LoadOwner(t.Context()))
	return repo
}

func repoDir(parts ...string) string {
	return filepath.Join(append([]string{setting.RepoRootPath}, parts...)...)
}

func TestMoveRepository(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	pay, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)
	web, err := repo_model.CreateRepoGroup(ctx, org3, "web", "")
	require.NoError(t, err)
	repo, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "api", AutoInit: true, Readme: "Default"})
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(repoDir("org3", "api.wiki.git"), os.ModePerm))

	// root → project
	require.NoError(t, MoveRepository(ctx, owner, reloadRepo(t, repo.ID), pay.ID))
	repo = reloadRepo(t, repo.ID)
	assert.Equal(t, "org3/pay/api", repo.FullName())
	assertDir(t, true, repoDir("org3", "pay", "api.git"))
	assertDir(t, true, repoDir("org3", "pay", "api.wiki.git"))
	assertDir(t, false, repoDir("org3", "api.git"))
	assertDir(t, false, repoDir("org3", "api.wiki.git"))
	unittest.AssertNotExistsBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "api"})
	id, err := repo_model.GetRedirect(ctx, org3.ID, 0, "api")
	require.NoError(t, err)
	assert.Equal(t, repo.ID, id)

	// project → project
	require.NoError(t, MoveRepository(ctx, owner, repo, web.ID))
	repo = reloadRepo(t, repo.ID)
	assert.Equal(t, "org3/web/api", repo.FullName())
	assertDir(t, true, repoDir("org3", "web", "api.git"))
	assertDir(t, false, repoDir("org3", "pay", "api.git"))
	unittest.AssertExistsAndLoadBean(t, &repo_model.Redirect{OwnerID: org3.ID, GroupID: pay.ID, LowerName: "api", RedirectRepoID: repo.ID})

	// project → root: the root redirect of its own old path is replaced
	require.NoError(t, MoveRepository(ctx, admin, repo, 0))
	repo = reloadRepo(t, repo.ID)
	assert.Equal(t, "org3/api", repo.FullName())
	assertDir(t, true, repoDir("org3", "api.git"))
	assertDir(t, true, repoDir("org3", "api.wiki.git"))
	assertDir(t, false, repoDir("org3", "web", "api.git"))
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "api"})
	_, err = repo_model.GetRedirect(ctx, org3.ID, 0, "api")
	require.True(t, repo_model.IsErrRedirectNotExist(err))
	unittest.AssertExistsAndLoadBean(t, &repo_model.Redirect{OwnerID: org3.ID, GroupID: web.ID, LowerName: "api", RedirectRepoID: repo.ID})

	unittest.CheckConsistencyFor(t, &user_model.User{}, &repo_model.Repository{})
}

// A refused move changes nothing: no row, no claim, no redirect, no directory.
func TestMoveRepositoryRefused(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	member := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	org17 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 17})
	pay, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)
	other, err := repo_model.CreateRepoGroup(ctx, org17, "other", "")
	require.NoError(t, err)
	nested, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "repo3", GroupID: pay.ID}) // a root repository's name
	require.NoError(t, err)
	_, err = CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "web", GroupID: pay.ID})
	require.NoError(t, err)
	web, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "web"})
	require.NoError(t, err)
	trashed, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "old"})
	require.NoError(t, err)
	require.NoError(t, TrashRepository(ctx, admin, trashed))
	oldInPay, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "old", GroupID: pay.ID})
	require.NoError(t, err)
	named, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "Pay2", GroupID: pay.ID})
	require.NoError(t, err)
	_, err = repo_model.CreateRepoGroup(ctx, org3, "pay2", "")
	require.NoError(t, err)

	count := func() [3]int {
		return [3]int{unittest.GetCount(t, &repo_model.RepoGroupNameClaim{}), unittest.GetCount(t, &repo_model.Redirect{}), unittest.GetCount(t, &repo_model.Repository{GroupID: pay.ID})}
	}
	before := count()
	check := func(name string, err error, is func(error) bool, repo *repo_model.Repository) {
		t.Helper()
		assert.True(t, is(err), "%s: %v", name, err)
		assert.Equal(t, before, count(), name)
		assert.Equal(t, repo.GroupID, reloadRepo(t, repo.ID).GroupID, name)
		assertDir(t, true, repo.RepoPath())
	}
	isTaken := repo_model.IsErrRepoAlreadyExist

	check("root repository holds the name", MoveRepository(ctx, owner, reloadRepo(t, nested.ID), 0), isTaken, nested)
	check("trashed root repository holds the name", MoveRepository(ctx, owner, reloadRepo(t, oldInPay.ID), 0), isTaken, oldInPay)
	check("project holds the name", MoveRepository(ctx, owner, reloadRepo(t, named.ID), 0), isTaken, named)
	check("same leaf in the target", MoveRepository(ctx, owner, reloadRepo(t, web.ID), pay.ID), isTaken, web)
	check("project of another organization", MoveRepository(ctx, owner, reloadRepo(t, web.ID), other.ID),
		func(err error) bool { return err == repo_model.ErrRepoGroupNotExist }, web)
	check("same place", MoveRepository(ctx, owner, reloadRepo(t, nested.ID), pay.ID),
		func(err error) bool { return errors.Is(err, util.ErrInvalidArgument) }, nested)
	check("member who isn't an owner", MoveRepository(ctx, member, reloadRepo(t, web.ID), 0),
		func(err error) bool { return err == util.ErrPermissionDenied }, web)

	// a 2FA-blocked owner can't, a site admin can
	org3.RequireTwoFactor = true
	require.NoError(t, user_model.UpdateUserCols(ctx, org3, "require_two_factor"))
	check("2FA-blocked owner", MoveRepository(ctx, owner, reloadRepo(t, web.ID), 0),
		func(err error) bool { return err == util.ErrPermissionDenied }, web)
	org3.RequireTwoFactor = false
	require.NoError(t, user_model.UpdateUserCols(ctx, org3, "require_two_factor"))

	// a pending transfer and an archived organization
	pending := reloadRepo(t, web.ID)
	pending.Status = repo_model.RepositoryPendingTransfer
	check("pending transfer", MoveRepository(ctx, owner, pending, pay.ID), func(err error) bool { return err != nil }, web)
	org3.IsArchived = true
	require.NoError(t, user_model.UpdateUserCols(ctx, org3, "is_archived"))
	check("archived organization", MoveRepository(ctx, admin, reloadRepo(t, nested.ID), 0), organization.IsErrOrgArchived, nested)
	org3.IsArchived = false
	require.NoError(t, user_model.UpdateUserCols(ctx, org3, "is_archived"))

	// the files at the target are refused after the claims changed in the transaction: all of it is rolled back
	require.NoError(t, os.MkdirAll(repoDir("org3", "pay", "free.git"), os.ModePerm))
	free, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "free"})
	require.NoError(t, err)
	before = count()
	check("files at the target", MoveRepository(ctx, owner, reloadRepo(t, free.ID), pay.ID), repo_model.IsErrRepoFilesAlreadyExist, free)
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "free"})

	// the wiki can't move after the repository did: the repository moves back
	require.NoError(t, os.RemoveAll(repoDir("org3", "pay", "free.git")))
	require.NoError(t, os.MkdirAll(repoDir("org3", "free.wiki.git"), os.ModePerm))
	require.NoError(t, os.MkdirAll(repoDir("org3", "pay", "free.wiki.git"), os.ModePerm))
	check("wiki files at the target", MoveRepository(ctx, owner, reloadRepo(t, free.ID), pay.ID), repo_model.IsErrRepoFilesAlreadyExist, free)
	assertDir(t, false, repoDir("org3", "pay", "free.git"))
	assertDir(t, true, repoDir("org3", "free.wiki.git"))

	// users have no projects
	userRepo := reloadRepo(t, 1)
	require.ErrorIs(t, MoveRepository(ctx, admin, userRepo, pay.ID), repo_model.ErrRepoGroupNotExist)
	require.NoError(t, DeleteRepositoryDirectly(ctx, trashed.ID, DeleteRepositoryOpts{}))

	unittest.CheckConsistencyFor(t, &user_model.User{}, &repo_model.Repository{})
}

// A project and a repository moving into it are never both deleted and filled.
func TestMoveRepositoryDeletedProject(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	pay, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)
	repo, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "api"})
	require.NoError(t, err)

	require.NoError(t, MoveRepository(ctx, admin, reloadRepo(t, repo.ID), pay.ID))
	require.ErrorIs(t, DeleteRepoGroup(ctx, org3, pay), repo_model.ErrRepoGroupNotEmpty)
	require.NoError(t, MoveRepository(ctx, admin, reloadRepo(t, repo.ID), 0))
	require.NoError(t, DeleteRepoGroup(ctx, org3, pay))
	require.ErrorIs(t, MoveRepository(ctx, admin, reloadRepo(t, repo.ID), pay.ID), repo_model.ErrRepoGroupNotExist)
	assert.EqualValues(t, 0, reloadRepo(t, repo.ID).GroupID)
	// the project's redirects went with it
	unittest.AssertNotExistsBean(t, &repo_model.Redirect{OwnerID: org3.ID, GroupID: pay.ID})
}

// Opposite moves and a project rename at the same time all finish: the locks are taken in one order.
func TestMoveRepositoryLockOrder(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	g1, err := repo_model.CreateRepoGroup(ctx, org3, "g1", "")
	require.NoError(t, err)
	g2, err := repo_model.CreateRepoGroup(ctx, org3, "g2", "")
	require.NoError(t, err)
	a, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "a", GroupID: g1.ID})
	require.NoError(t, err)
	b, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "b", GroupID: g2.ID})
	require.NoError(t, err)

	for i := range 10 {
		var wg sync.WaitGroup
		errs := make([]error, 3)
		ra, rb := reloadRepo(t, a.ID), reloadRepo(t, b.ID)
		ta, tb := g2.ID, g1.ID
		if ra.GroupID == g2.ID {
			ta, tb = g1.ID, g2.ID
		}
		group, err := repo_model.GetRepoGroupByID(ctx, org3.ID, g1.ID)
		require.NoError(t, err)
		wg.Add(3)
		go func() { defer wg.Done(); errs[0] = MoveRepository(db.DefaultContext, admin, ra, ta) }()
		go func() { defer wg.Done(); errs[1] = MoveRepository(db.DefaultContext, admin, rb, tb) }()
		go func() {
			defer wg.Done()
			errs[2] = RenameRepoGroup(db.DefaultContext, org3, group, []string{"g1x", "g1"}[i%2])
		}()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Minute):
			t.Fatal("the moves and the rename wait for each other")
		}
		for _, err := range errs {
			require.NoError(t, err)
		}
		for _, id := range []int64{a.ID, b.ID} {
			assertDir(t, true, reloadRepo(t, id).RepoPath())
		}
	}
	unittest.CheckConsistencyFor(t, &user_model.User{}, &repo_model.Repository{})
}

// Project names follow the same reuse rule as repository names: a live redirect refuses them.
func TestRepoGroupRedirectReuse(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	pay, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)
	repo, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "api"})
	require.NoError(t, err)

	// a repository moved away leaves a root redirect: neither a project nor a repository takes its name
	require.NoError(t, MoveRepository(ctx, admin, reloadRepo(t, repo.ID), pay.ID))
	_, err = repo_model.CreateRepoGroup(ctx, org3, "api", "")
	require.True(t, repo_model.IsErrRepoAlreadyExist(err))
	require.True(t, repo_model.IsErrRepoAlreadyExist(RenameRepoGroup(ctx, org3, pay, "API")))
	_, err = CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "api"})
	require.True(t, repo_model.IsErrRepoAlreadyExist(err))
	unittest.AssertExistsAndLoadBean(t, &repo_model.Redirect{OwnerID: org3.ID, LowerName: "api"})

	// a renamed project leaves a project redirect: a root repository can't take its name, renaming back can
	require.NoError(t, RenameRepoGroup(ctx, org3, pay, "billing"))
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupRedirect{OwnerID: org3.ID, LowerName: "pay", RedirectGroupID: pay.ID})
	_, err = CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "pay"})
	require.True(t, repo_model.IsErrRepoAlreadyExist(err))
	_, err = repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.True(t, repo_model.IsErrRepoAlreadyExist(err))
	require.NoError(t, RenameRepoGroup(ctx, org3, pay, "pay"))
	unittest.AssertNotExistsBean(t, &repo_model.RepoGroupRedirect{OwnerID: org3.ID, LowerName: "pay"})
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupRedirect{OwnerID: org3.ID, LowerName: "billing", RedirectGroupID: pay.ID})

	// a repository renamed in a project leaves a redirect there; renaming back to it is fine
	repo = reloadRepo(t, repo.ID)
	require.NoError(t, ChangeRepositoryName(ctx, admin, repo, "api2"))
	unittest.AssertExistsAndLoadBean(t, &repo_model.Redirect{OwnerID: org3.ID, GroupID: pay.ID, LowerName: "api", RedirectRepoID: repo.ID})
	_, err = CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "api", GroupID: pay.ID})
	require.True(t, repo_model.IsErrRepoAlreadyExist(err))
	require.NoError(t, ChangeRepositoryName(ctx, admin, reloadRepo(t, repo.ID), "api"))

	// once an owner removes a redirect, the name is free
	redirects, _, err := repo_model.FindRedirects(ctx, org3.ID)
	require.NoError(t, err)
	require.Len(t, redirects, 2) // org3/api, org3/pay/api2
	require.Zero(t, redirects[0].GroupID)
	require.ErrorIs(t, repo_model.DeleteOwnerRedirect(ctx, 17, redirects[0].ID, false), util.ErrNotExist, "another owner's redirect")
	require.ErrorIs(t, repo_model.DeleteOwnerRedirect(ctx, org3.ID, redirects[0].ID, true), util.ErrNotExist, "a project redirect of that ID")
	require.NoError(t, repo_model.DeleteOwnerRedirect(ctx, org3.ID, redirects[0].ID, false))
	_, err = repo_model.CreateRepoGroup(ctx, org3, "api", "")
	require.NoError(t, err)

	unittest.CheckConsistencyFor(t, &user_model.User{}, &repo_model.Repository{})
}

// Every path that puts a repository at a name of an organization refuses a name with a live redirect, and leaves
// the repository, its claims and its directories where they were.
func TestRedirectReuseRefused(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := audit_model.WithSystem(t.Context(), "test")
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	pay, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)

	// org3/taken redirects to org3/taken2, and org3/pay/inpay to org3/pay/inpay2
	taken, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "taken"})
	require.NoError(t, err)
	require.NoError(t, ChangeRepositoryName(ctx, admin, taken, "taken2"))
	inPay, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "inpay", GroupID: pay.ID})
	require.NoError(t, err)
	require.NoError(t, ChangeRepositoryName(ctx, admin, reloadRepo(t, inPay.ID), "inpay2"))

	unchanged := func(name string, err error, repo *repo_model.Repository) {
		t.Helper()
		assert.True(t, repo_model.IsErrRepoAlreadyExist(err), "%s: %v", name, err)
		got := reloadRepo(t, repo.ID)
		assert.Equal(t, repo.FullName(), got.FullName(), name)
		assertDir(t, true, got.RepoPath())
		unittest.CheckRepoGroupNameClaims(t)
	}

	// rename onto a redirect, at the root and in a project
	root, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "root"})
	require.NoError(t, err)
	unchanged("rename at the root", ChangeRepositoryName(ctx, admin, reloadRepo(t, root.ID), "taken"), root)
	nested, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "nested", GroupID: pay.ID})
	require.NoError(t, err)
	unchanged("rename in a project", ChangeRepositoryName(ctx, admin, reloadRepo(t, nested.ID), "inpay"), nested)

	// move onto a redirect: out of the project to the root, and into the project
	named, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "taken", GroupID: pay.ID})
	require.NoError(t, err)
	unchanged("move to the root", MoveRepository(ctx, admin, reloadRepo(t, named.ID), 0), named)
	rootInpay, err := CreateRepositoryDirectly(ctx, admin, org3, CreateRepoOptions{Name: "inpay"})
	require.NoError(t, err)
	unchanged("move into the project", MoveRepository(ctx, admin, reloadRepo(t, rootInpay.ID), pay.ID), rootInpay)

	// transfer into the organization onto a redirect
	incoming, err := CreateRepositoryDirectly(ctx, user2, user2, CreateRepoOptions{Name: "taken"})
	require.NoError(t, err)
	unchanged("transfer", TransferOwnership(audit_model.WithSystem(ctx, "test"), admin, org3, reloadRepo(t, incoming.ID), nil), incoming)
	unittest.AssertNotExistsBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "taken"})

	// trash restore into the organization, with a new owner or a new name
	require.NoError(t, TrashRepository(ctx, admin, reloadRepo(t, incoming.ID)))
	unchanged("restore to a new owner", MoveTrashedRepository(ctx, admin, org3, reloadRepo(t, incoming.ID), ""), incoming)
	require.NoError(t, TrashRepository(ctx, admin, reloadRepo(t, root.ID)))
	unchanged("restore with a new name", MoveTrashedRepository(ctx, admin, nil, reloadRepo(t, root.ID), "taken"), root)

	// renaming back to its own old name is fine
	require.NoError(t, ChangeRepositoryName(ctx, admin, reloadRepo(t, taken.ID), "taken"))
}
