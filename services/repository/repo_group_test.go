// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repository

import (
	"context"
	"path/filepath"
	"testing"

	"forgejo.org/models"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertDir(t *testing.T, exists bool, path string) {
	t.Helper()
	isDir, err := util.IsDir(path)
	require.NoError(t, err)
	assert.Equal(t, exists, isDir, path)
}

func TestRepoGroupCreate(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	org17 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 17})
	pay, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)
	other, err := repo_model.CreateRepoGroup(ctx, org17, "other", "")
	require.NoError(t, err)

	repo, err := CreateRepositoryDirectly(ctx, doer, org3, CreateRepoOptions{Name: "api", GroupID: pay.ID})
	require.NoError(t, err)
	assert.Equal(t, "org3/pay/api", repo.FullName())
	assertDir(t, true, filepath.Join(setting.RepoRootPath, "org3", "pay", "api.git"))
	assertDir(t, false, filepath.Join(setting.RepoRootPath, "org3", "api.git"))
	unittest.AssertNotExistsBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "api"})

	// the root keeps its own names: a root repository "api" is fine, one named like the project is not
	_, err = CreateRepositoryDirectly(ctx, doer, org3, CreateRepoOptions{Name: "api"})
	require.NoError(t, err)
	_, err = CreateRepositoryDirectly(ctx, doer, org3, CreateRepoOptions{Name: "Pay"})
	require.True(t, repo_model.IsErrRepoAlreadyExist(err))
	_, err = CreateRepositoryDirectly(ctx, doer, org3, CreateRepoOptions{Name: "api", GroupID: pay.ID})
	require.True(t, repo_model.IsErrRepoAlreadyExist(err), "a name is unique in its project")

	// another owner's project is not found, and the project name comes from the project row
	_, err = CreateRepositoryDirectly(ctx, doer, org3, CreateRepoOptions{Name: "web", GroupID: other.ID})
	require.ErrorIs(t, err, repo_model.ErrRepoGroupNotExist)
	forged := &repo_model.Repository{OwnerID: org3.ID, OwnerName: org3.Name, Name: "forged", LowerName: "forged", GroupID: pay.ID, GroupName: "../user2"}
	require.NoError(t, db.WithTx(ctx, func(ctx context.Context) error {
		return repo_module.CreateRepositoryByExample(ctx, doer, org3, forged, false, false)
	}))
	assert.Equal(t, "pay", unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: forged.ID}).GroupName)

	unittest.CheckConsistencyFor(t, &user_model.User{}, &repo_model.Repository{})
}

// Every way to create a repository writes the claim through CreateRepositoryByExample.
func TestRepoGroupClaimOnForkTemplateAdopt(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	_, err := repo_model.CreateRepoGroup(ctx, org3, "taken", "")
	require.NoError(t, err)

	base := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.NoError(t, base.LoadOwner(ctx))
	_, err = ForkRepositoryAndUpdates(ctx, doer, org3, ForkRepoOptions{BaseRepo: base, Name: "taken"})
	require.True(t, repo_model.IsErrRepoAlreadyExist(err), "fork")
	_, err = ForkRepositoryAndUpdates(ctx, doer, org3, ForkRepoOptions{BaseRepo: base, Name: "forked"})
	require.NoError(t, err)
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "forked"})

	template := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 44})
	_, err = GenerateRepository(ctx, doer, org3, template, GenerateRepoOptions{Name: "taken", Topics: true})
	require.True(t, repo_model.IsErrRepoAlreadyExist(err), "template")
	_, err = GenerateRepository(ctx, doer, org3, template, GenerateRepoOptions{Name: "generated", Topics: true})
	require.NoError(t, err)
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "generated"})

	for _, name := range []string{"taken", "adopted"} {
		require.NoError(t, unittest.CopyDir("../../modules/git/tests/repos/repo1_bare", filepath.Join(setting.RepoRootPath, "org3", name+".git")))
	}
	_, err = AdoptRepository(ctx, doer, org3, CreateRepoOptions{Name: "taken"})
	require.True(t, repo_model.IsErrRepoAlreadyExist(err), "adopt")
	_, err = AdoptRepository(ctx, doer, org3, CreateRepoOptions{Name: "adopted"})
	require.NoError(t, err)
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "adopted"})

	unittest.CheckConsistencyFor(t, &user_model.User{}, &repo_model.Repository{})
}

func TestRepoGroupRenameRepo(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	pay, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)

	// a root repository can't take a project's name: the directories and the name stay as they were
	root, err := CreateRepositoryDirectly(ctx, doer, org3, CreateRepoOptions{Name: "web"})
	require.NoError(t, err)
	require.True(t, repo_model.IsErrRepoAlreadyExist(ChangeRepositoryName(ctx, doer, root, "pay")))
	assert.Equal(t, "web", root.Name)
	assertDir(t, true, filepath.Join(setting.RepoRootPath, "org3", "web.git"))
	assertDir(t, false, filepath.Join(setting.RepoRootPath, "org3", "pay.git"))
	assert.Equal(t, "web", unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: root.ID}).LowerName)

	// the claim moves with a root repository's name
	require.NoError(t, ChangeRepositoryName(ctx, doer, root, "site"))
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "site"})
	unittest.AssertNotExistsBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "web"})
	// the old name redirects, so a project gets it only once an owner removed the redirect
	_, err = repo_model.CreateRepoGroup(ctx, org3, "web", "")
	require.True(t, repo_model.IsErrRepoAlreadyExist(err))
	redirect := unittest.AssertExistsAndLoadBean(t, &repo_model.Redirect{OwnerID: org3.ID, LowerName: "web", RedirectRepoID: root.ID})
	require.NoError(t, repo_model.DeleteOwnerRedirect(ctx, org3.ID, redirect.ID, false))
	_, err = repo_model.CreateRepoGroup(ctx, org3, "web", "")
	require.NoError(t, err, "the old name is free for a project")

	// a repository in a project is renamed within it, with no claim and a redirect in the project only
	nested, err := CreateRepositoryDirectly(ctx, doer, org3, CreateRepoOptions{Name: "api", GroupID: pay.ID})
	require.NoError(t, err)
	require.NoError(t, ChangeRepositoryName(ctx, doer, nested, "repo5")) // a root repository's name
	assertDir(t, true, filepath.Join(setting.RepoRootPath, "org3", "pay", "repo5.git"))
	assertDir(t, false, filepath.Join(setting.RepoRootPath, "org3", "pay", "api.git"))
	assertDir(t, true, filepath.Join(setting.RepoRootPath, "org3", "repo5.git"))
	unittest.AssertExistsAndLoadBean(t, &repo_model.Redirect{OwnerID: org3.ID, GroupID: pay.ID, LowerName: "api", RedirectRepoID: nested.ID})
	_, err = repo_model.GetRedirect(ctx, org3.ID, 0, "api")
	require.True(t, repo_model.IsErrRedirectNotExist(err))

	// a mixed-case name keeps its case; the directories and lower_name are lowercase
	for _, repo := range []*repo_model.Repository{root, nested} {
		require.NoError(t, ChangeRepositoryName(ctx, doer, repo, "Mixed-Case"))
		stored := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
		assert.Equal(t, "Mixed-Case", stored.Name)
		assert.Equal(t, "mixed-case", stored.LowerName)
		assert.Equal(t, "mixed-case.git", filepath.Base(stored.RepoPath()))
		gitRepo, err := git.OpenRepository(ctx, stored.RepoPath())
		require.NoError(t, err)
		gitRepo.Close()
	}
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "mixed-case"})

	unittest.CheckConsistencyFor(t, &user_model.User{}, &repo_model.Repository{})
}

func TestRepoGroupTransfer(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	pay, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)

	// the claim moves with the owner
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.NoError(t, repo.LoadOwner(ctx))
	require.NoError(t, TransferOwnership(ctx, doer, org3, repo, nil))
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "repo1"})
	unittest.AssertNotExistsBean(t, &repo_model.RepoGroupNameClaim{OwnerID: user2.ID, LowerName: "repo1"})

	// a root repository named like a project can't come in
	repo2 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
	require.NoError(t, repo2.LoadOwner(ctx))
	require.NoError(t, ChangeRepositoryName(ctx, doer, repo2, "pay"))
	require.True(t, repo_model.IsErrRepoAlreadyExist(TransferOwnership(ctx, doer, org3, repo2, nil)))

	// a repository in a project lands at the root of the new owner, and its old path redirects
	nested, err := CreateRepositoryDirectly(ctx, doer, org3, CreateRepoOptions{Name: "api", GroupID: pay.ID})
	require.NoError(t, err)
	require.NoError(t, nested.LoadOwner(ctx))
	require.NoError(t, models.CreatePendingRepositoryTransfer(ctx, doer, user2, nested.ID, nil))
	require.NoError(t, CancelRepositoryTransfer(ctx, nested, false))
	require.NoError(t, TransferOwnership(ctx, doer, user2, nested, nil))
	nested = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: nested.ID})
	assert.Equal(t, "user2/api", nested.FullName())
	assertDir(t, true, filepath.Join(setting.RepoRootPath, "user2", "api.git"))
	assertDir(t, false, filepath.Join(setting.RepoRootPath, "org3", "pay", "api.git"))
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupNameClaim{OwnerID: user2.ID, LowerName: "api"})
	unittest.AssertExistsAndLoadBean(t, &repo_model.Redirect{OwnerID: org3.ID, GroupID: pay.ID, LowerName: "api", RedirectRepoID: nested.ID})

	unittest.CheckConsistencyFor(t, &user_model.User{}, &repo_model.Repository{})
}

func TestRepoGroupTrashAndDelete(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	pay, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)

	// a trashed root repository keeps its name; renaming it in the trash moves the claim
	root, err := CreateRepositoryDirectly(ctx, doer, org3, CreateRepoOptions{Name: "web"})
	require.NoError(t, err)
	require.NoError(t, TrashRepository(ctx, doer, root))
	_, err = repo_model.CreateRepoGroup(ctx, org3, "web", "")
	require.True(t, repo_model.IsErrRepoAlreadyExist(err))
	root, err = repo_model.GetRepositoryByIDIncludingTrashed(ctx, root.ID)
	require.NoError(t, err)
	require.True(t, repo_model.IsErrRepoAlreadyExist(MoveTrashedRepository(ctx, doer, nil, root, "pay")))
	assertDir(t, true, filepath.Join(setting.RepoRootPath, "org3", "web.git"))
	root, err = repo_model.GetRepositoryByIDIncludingTrashed(ctx, root.ID)
	require.NoError(t, err)
	assert.Equal(t, "web", root.Name)
	require.NoError(t, MoveTrashedRepository(ctx, doer, nil, root, "site"))
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "site"})
	unittest.CheckRepoGroupNameClaims(t)

	// a trashed repository in a project moves to the root of another owner
	nested, err := CreateRepositoryDirectly(ctx, doer, org3, CreateRepoOptions{Name: "repo3", GroupID: pay.ID}) // a root repository's name
	require.NoError(t, err)
	require.NoError(t, TrashRepository(ctx, doer, nested))
	nested, err = repo_model.GetRepositoryByIDIncludingTrashed(ctx, nested.ID)
	require.NoError(t, err)
	require.NoError(t, MoveTrashedRepository(ctx, doer, user2, nested, "moved-out"))
	nested, err = repo_model.GetRepositoryByIDIncludingTrashed(ctx, nested.ID)
	require.NoError(t, err)
	assert.Equal(t, "user2/moved-out", nested.FullName())
	assertDir(t, true, filepath.Join(setting.RepoRootPath, "user2", "moved-out.git"))
	assertDir(t, false, filepath.Join(setting.RepoRootPath, "org3", "pay", "repo3.git"))
	assertDir(t, false, filepath.Join(setting.RepoRootPath, "org3", "pay", "moved-out.git"))
	unittest.CheckRepoGroupNameClaims(t)

	// deleting it leaves the claim of the root repository with the same name
	require.NoError(t, DeleteRepositoryDirectly(ctx, nested.ID, DeleteRepositoryOpts{}))
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "repo3"})
	_, err = repo_model.CreateRepoGroup(ctx, org3, "repo3", "")
	require.True(t, repo_model.IsErrRepoAlreadyExist(err))
	unittest.CheckRepoGroupNameClaims(t)

	// deleting a root repository releases its name
	require.NoError(t, DeleteRepositoryDirectly(ctx, root.ID, DeleteRepositoryOpts{}))
	unittest.AssertNotExistsBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID, LowerName: "site"})

	unittest.CheckConsistencyFor(t, &user_model.User{}, &repo_model.Repository{})
}

func TestRepoGroupRenameDeleteDirs(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	group, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)
	repo, err := CreateRepositoryDirectly(ctx, doer, org3, CreateRepoOptions{Name: "api", GroupID: group.ID})
	require.NoError(t, err)

	require.True(t, repo_model.IsErrRepoAlreadyExist(RenameRepoGroup(ctx, org3, group, "repo3")))
	assertDir(t, true, filepath.Join(setting.RepoRootPath, "org3", "pay"))

	require.NoError(t, RenameRepoGroup(ctx, org3, group, "billing"))
	assertDir(t, false, filepath.Join(setting.RepoRootPath, "org3", "pay"))
	repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
	assert.Equal(t, filepath.Join(setting.RepoRootPath, "org3", "billing", "api.git"), repo.RepoPath())
	gitRepo, err := git.OpenRepository(ctx, repo.RepoPath())
	require.NoError(t, err)
	gitRepo.Close()

	require.ErrorIs(t, DeleteRepoGroup(ctx, org3, group), repo_model.ErrRepoGroupNotEmpty)
	require.NoError(t, DeleteRepositoryDirectly(ctx, repo.ID, DeleteRepositoryOpts{}))
	require.NoError(t, DeleteRepoGroup(ctx, org3, group))
	assertDir(t, false, filepath.Join(setting.RepoRootPath, "org3", "billing"))

	unittest.CheckConsistencyFor(t, &user_model.User{}, &repo_model.Repository{})
}
