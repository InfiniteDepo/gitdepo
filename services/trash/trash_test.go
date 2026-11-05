// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package trash

import (
	"path/filepath"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setTrashed(t *testing.T, id, unix int64) {
	t.Helper()
	_, err := db.GetEngine(t.Context()).Exec("UPDATE `repository` SET trashed_unix = ? WHERE id = ?", unix, id)
	require.NoError(t, err)
}

// AC13/AC14: an expired item is purged, a younger one is left, and a purge claimed long ago (a crash) is retried
// while a fresh claim is left alone.
func TestPurgeExpired(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Trash.RetentionDays, 30)()
	now := time.Now().Unix()
	day := int64(24 * 3600)

	setTrashed(t, 1, now-31*day)             // expired
	setTrashed(t, 2, now-29*day)             // not yet
	setTrashed(t, 3, -(now - int64(7*3600))) // purge claimed seven hours ago, never finished
	setTrashed(t, 4, -(now - int64(60)))     // purge claimed a minute ago, still running
	require.NoError(t, PurgeExpired(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})))

	unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: 1})
	unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
	unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: 3})
	unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 4})
}

// AC6: restoring brings the repository back and counts it for its owner again.
func TestRestore(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: repo.OwnerID})
	setTrashed(t, repo.ID, timeutil.TimeStampNow().AsTime().Unix())
	_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET num_repos = num_repos - 1 WHERE id = ?", owner.ID)
	require.NoError(t, err)

	require.NoError(t, RestoreRepo(t.Context(), owner, repo.ID, RestoreOptions{}))
	require.ErrorIs(t, RestoreRepo(t.Context(), owner, repo.ID, RestoreOptions{}), ErrTrashConflict)

	restored, err := repo_model.GetRepositoryByID(t.Context(), repo.ID)
	require.NoError(t, err)
	assert.False(t, restored.IsTrashed())
	assert.Equal(t, owner.NumRepos, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: owner.ID}).NumRepos)
}

// Restore puts a repository back at its place by the name it has, never taking a project's name, and purging an
// organization removes its projects and every name claim.
func TestRepoGroupRestoreAndOrgPurge(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := audit_model.WithSystem(t.Context(), "test")
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	pay, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)
	nested, err := repo_service.CreateRepositoryDirectly(ctx, doer, org3, repo_service.CreateRepoOptions{Name: "api", GroupID: pay.ID})
	require.NoError(t, err)

	root, err := repo_service.CreateRepositoryDirectly(ctx, doer, org3, repo_service.CreateRepoOptions{Name: "web"})
	require.NoError(t, err)
	require.NoError(t, repo_service.TrashRepository(ctx, doer, root))
	err = RestoreRepo(ctx, doer, root.ID, RestoreOptions{NewName: "pay"})
	require.True(t, repo_model.IsErrRepoAlreadyExist(err), "%v", err)
	require.NoError(t, RestoreRepo(ctx, doer, root.ID, RestoreOptions{}))
	assert.Equal(t, "web", unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: root.ID}).Name)

	// restored by group_id: into the project under its new name, and the project can't be deleted meanwhile
	require.NoError(t, repo_service.TrashRepository(ctx, doer, nested))
	require.ErrorIs(t, repo_service.DeleteRepoGroup(ctx, org3, pay), repo_model.ErrRepoGroupNotEmpty)
	require.NoError(t, repo_service.RenameRepoGroup(ctx, org3, pay, "billing"))
	require.NoError(t, RestoreRepo(ctx, doer, nested.ID, RestoreOptions{}))
	restored, err := repo_model.GetRepositoryByPath(ctx, org3.ID, "billing", "api")
	require.NoError(t, err)
	assert.Equal(t, nested.ID, restored.ID)
	assert.Equal(t, filepath.Join(setting.RepoRootPath, "org3", "billing", "api.git"), restored.RepoPath())
	gitRepo, err := git.OpenRepository(ctx, restored.RepoPath())
	require.NoError(t, err)
	gitRepo.Close()

	// with a new name in the project: the old name redirects in the project
	require.NoError(t, repo_service.TrashRepository(ctx, doer, restored))
	require.NoError(t, RestoreRepo(ctx, doer, nested.ID, RestoreOptions{NewName: "api2"}))
	_, err = repo_model.GetRepositoryByPath(ctx, org3.ID, "billing", "api2")
	require.NoError(t, err)
	unittest.AssertExistsAndLoadBean(t, &repo_model.Redirect{OwnerID: org3.ID, GroupID: pay.ID, LowerName: "api", RedirectRepoID: nested.ID})

	// to another owner: at its root
	moved, err := repo_service.CreateRepositoryDirectly(ctx, doer, org3, repo_service.CreateRepoOptions{Name: "moved", GroupID: pay.ID, AutoInit: true, Readme: "Default"})
	require.NoError(t, err)
	require.NoError(t, repo_service.TrashRepository(ctx, doer, moved))
	require.NoError(t, RestoreRepo(ctx, doer, moved.ID, RestoreOptions{NewOwner: "user2"}))
	moved = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: moved.ID})
	assert.Equal(t, "user2/moved", moved.FullName())
	assert.Equal(t, filepath.Join(setting.RepoRootPath, "user2", "moved.git"), moved.RepoPath())
	gitRepo, err = git.OpenRepository(ctx, moved.RepoPath())
	require.NoError(t, err)
	gitRepo.Close()
	unittest.CheckConsistencyFor(t, &user_model.User{}, &repo_model.Repository{})

	require.NoError(t, org_service.TrashOrganization(ctx, doer, organization.OrgFromUser(org3)))
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroup{ID: pay.ID}) // the trash takes the projects along
	require.NoError(t, PurgeOrg(ctx, doer, org3.ID))
	unittest.AssertNotExistsBean(t, &repo_model.RepoGroup{OwnerID: org3.ID})
	unittest.AssertNotExistsBean(t, &repo_model.RepoGroupNameClaim{OwnerID: org3.ID})
	unittest.CheckRepoGroupNameClaims(t)
}

// A team's rows through a linked project stay while the repository is in the trash, and its count follows.
func TestTeamGroupTrashRestore(t *testing.T) {
	unittest.PrepareTestEnv(t)
	ctx := t.Context()
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	pay, err := repo_model.CreateRepoGroup(ctx, org3, "pay", "")
	require.NoError(t, err)
	repo, err := repo_service.CreateRepositoryDirectly(ctx, doer, org3, repo_service.CreateRepoOptions{Name: "api", GroupID: pay.ID})
	require.NoError(t, err)
	numRepos := func() int {
		return unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2}).NumRepos
	}
	before := numRepos()

	require.NoError(t, repo_service.LinkTeamToRepoGroup(ctx, doer, organization.OrgFromUser(org3), 2, pay.ID))
	assert.Equal(t, before+1, numRepos())
	require.NoError(t, repo_service.TrashRepository(ctx, doer, repo))
	assert.Equal(t, before, numRepos())
	require.NoError(t, RestoreRepo(ctx, doer, repo.ID, RestoreOptions{}))
	assert.Equal(t, before+1, numRepos())

	// unlinked and linked again while in the trash: counted only once it is back
	require.NoError(t, repo_service.TrashRepository(ctx, doer, repo))
	require.NoError(t, repo_service.UnlinkTeamFromRepoGroup(ctx, doer, organization.OrgFromUser(org3), 2, pay.ID))
	require.NoError(t, repo_service.LinkTeamToRepoGroup(ctx, doer, organization.OrgFromUser(org3), 2, pay.ID))
	assert.Equal(t, before, numRepos())
	require.NoError(t, RestoreRepo(ctx, doer, repo.ID, RestoreOptions{}))
	assert.Equal(t, before+1, numRepos())
	unittest.CheckConsistencyFor(t, &user_model.User{}, &repo_model.Repository{}, &organization.Team{})
}

// A restore to a new owner applies that owner's dependency graph switch at once: an organization that is off
// deletes the rows the repository kept in the trash.
func TestRestoreToNewOwnerAppliesDependencyGraph(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.DependencyGraph.Enabled, true))
	ctx := audit_model.WithSystem(t.Context(), "test")
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, user_model.SetUserSetting(ctx, 3, repo_model.DependencyGraphOrgKey, "false")) // org3 is off
	t.Cleanup(func() {
		require.NoError(t, user_model.DeleteUserSetting(db.DefaultContext, 3, repo_model.DependencyGraphOrgKey))
	})

	repo, err := repo_service.CreateRepositoryDirectly(ctx, doer, user2, repo_service.CreateRepoOptions{Name: "dep-restore", AutoInit: true, Readme: "Default"})
	require.NoError(t, err)
	require.NoError(t, repo_model.ReplaceRepoDependencies(ctx, &repo_model.DependencyScan{RepoID: repo.ID, CommitSHA: "abc", Status: repo_model.DependencyScanOK},
		[]*repo_model.Dependency{{RepoID: repo.ID, Ecosystem: "Go", Name: "x", Version: "v1"}}))
	require.NoError(t, repo_service.TrashRepository(ctx, doer, repo))
	require.NoError(t, RestoreRepo(ctx, doer, repo.ID, RestoreOptions{NewOwner: "org3"}))

	unittest.AssertNotExistsBean(t, &repo_model.Dependency{RepoID: repo.ID})
	scan, err := repo_model.GetRepoDependencyScan(ctx, repo.ID)
	require.NoError(t, err)
	assert.Nil(t, scan)
}
