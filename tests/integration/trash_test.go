// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"forgejo.org/models"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	webhook_model "forgejo.org/models/webhook"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"
	trash_service "forgejo.org/services/trash"
	user_service "forgejo.org/services/user"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// repo 1 (user2/repo1) is public with issues, PRs, a wiki and releases; user1 is the site admin,
// user2 the owner, user4 a stranger.
const trashRepoID = 1

func trashRepo(t *testing.T) *repo_model.Repository {
	t.Helper()
	repo, err := repo_model.GetRepositoryByIDIncludingTrashed(t.Context(), trashRepoID)
	require.NoError(t, err)
	return repo
}

// prepareTrash prepares the test environment with the trash on (the test configs turn it off).
func prepareTrash(t *testing.T) func() {
	t.Helper()
	cleanup := tests.PrepareTestEnv(t)
	reset := test.MockVariableValue(&setting.Trash.RetentionDays, 365)
	return func() {
		reset()
		cleanup()
	}
}

// moveToTrash deletes repo 1 as its owner through the web UI.
func moveToTrash(t *testing.T) {
	t.Helper()
	loginUser(t, "user2").MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings", map[string]string{
		"action":    "delete",
		"repo_name": "user2/repo1",
	}), http.StatusSeeOther)
	require.True(t, trashRepo(t).IsTrashed())
}

func adminTrashToken(t *testing.T) string {
	t.Helper()
	return getUserToken(t, "user1", auth_model.AccessTokenScopeAll)
}

// AC1: deleting via web and via API moves the repository to the trash and keeps its data; there is no
// repo-delete CLI command, so these are the only entry points besides the admin page.
func TestTrashDelete(t *testing.T) {
	defer prepareTrash(t)()

	issues := unittest.GetCount(t, &issues_model.Issue{RepoID: trashRepoID})
	before := time.Now().Unix()

	moveToTrash(t)

	repo := trashRepo(t)
	assert.GreaterOrEqual(t, repo.TrashedUnix.AsTime().Unix(), before)
	assert.Equal(t, "user2", repo.TrashedByName)
	assert.Equal(t, "user2", repo.TrashedOwnerName)
	assert.Equal(t, "repo1", repo.TrashedName)
	assert.Equal(t, int64(2), repo.TrashedByID)
	assert.Equal(t, issues, unittest.GetCount(t, &issues_model.Issue{RepoID: trashRepoID}))
	assert.DirExists(t, repo_model.RepoPath("user2", "repo1"))

	t.Run("API", func(t *testing.T) {
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/repo2").AddTokenAuth(token), http.StatusNoContent)
		repo2, err := repo_model.GetRepositoryByIDIncludingTrashed(t.Context(), 2)
		require.NoError(t, err)
		assert.True(t, repo2.IsTrashed())
	})
}

// AC2: RETENTION_DAYS=0 deletes immediately as before.
func TestTrashRetentionZero(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	loginUser(t, "user2").MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings", map[string]string{
		"action": "delete", "repo_name": "user2/repo1",
	}), http.StatusSeeOther)
	unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: trashRepoID})
}

// AC2: a changed retention applies to items already in the trash, counted from their deletion date.
func TestTrashRetentionChanged(t *testing.T) {
	defer prepareTrash(t)()
	moveToTrash(t)
	timeutil.MockSet(time.Now().Add(100 * 24 * time.Hour))
	defer timeutil.MockUnset()

	require.NoError(t, trash_service.PurgeExpired(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})))
	assert.True(t, trashRepo(t).IsTrashed())

	setting.Trash.RetentionDays = 30
	require.NoError(t, trash_service.PurgeExpired(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})))
	unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: trashRepoID})
}

// AC3: a trashed repository is invisible to everyone but site admins, on web and API.
func TestTrashInvisible(t *testing.T) {
	defer prepareTrash(t)()
	moveToTrash(t)

	for _, user := range []string{"user2", "user4", "user5"} { // owner, stranger, collaborator or member
		session := loginUser(t, user)
		token := getUserToken(t, user, auth_model.AccessTokenScopeAll)
		session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1"), http.StatusNotFound)
		session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/issues"), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1").AddTokenAuth(token), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repositories/1").AddTokenAuth(token), http.StatusNotFound)
	}
	MakeRequest(t, NewRequest(t, "GET", "/user2/repo1"), http.StatusNotFound)

	// Site admins reach the repository only through the trash.
	admin := loginUser(t, "user1")
	admin.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1"), http.StatusNotFound)

	t.Run("listings and search", func(t *testing.T) {
		var search api.SearchResults
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/search?q=repo1"), http.StatusOK)
		DecodeJSON(t, resp, &search)
		for _, r := range search.Data {
			assert.NotEqual(t, int64(trashRepoID), r.ID)
		}
		body := loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/explore/repos?q=repo1"), http.StatusOK).Body.String()
		assert.NotContains(t, body, `/user2/repo1"`)
		body = loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/"), http.StatusOK).Body.String()
		assert.NotContains(t, body, `/user2/repo1"`)
	})

	t.Run("git over HTTP", func(t *testing.T) {
		// the answer is the same as for a repository that never existed
		for _, service := range []string{"git-upload-pack", "git-receive-pack"} {
			missing := MakeRequest(t, NewRequest(t, "GET", "/user2/never-existed.git/info/refs?service="+service).AddBasicAuth("user2"), NoExpectedStatus)
			trashed := MakeRequest(t, NewRequest(t, "GET", "/user2/repo1.git/info/refs?service="+service).AddBasicAuth("user2"), NoExpectedStatus)
			assert.Equal(t, missing.Code, trashed.Code, service)
		}
		// receive-pack may answer for a missing repository when push-to-create is on; reading is always refused
		MakeRequest(t, NewRequest(t, "GET", "/user2/repo1.git/info/refs?service=git-upload-pack").AddBasicAuth("user2"), http.StatusNotFound)
	})

	t.Run("owner counters", func(t *testing.T) {
		user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		live := unittest.GetCount(t, &repo_model.Repository{OwnerID: 2}, "trashed_unix = 0")
		assert.Equal(t, live, user.NumRepos)
	})
}

// AC4: the name stays reserved for create, fork, transfer, rename and adopt.
func TestTrashNameReserved(t *testing.T) {
	defer prepareTrash(t)()
	moveToTrash(t)
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeAll)

	t.Run("create", func(t *testing.T) {
		req := NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "repo1"}).AddTokenAuth(token)
		MakeRequest(t, req, http.StatusConflict)
	})
	t.Run("rename", func(t *testing.T) {
		req := NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo2", &api.EditRepoOption{Name: new("repo1")}).AddTokenAuth(token)
		MakeRequest(t, req, http.StatusUnprocessableEntity)
	})
	t.Run("transfer", func(t *testing.T) {
		// user4 creates repo1; moving it to user2 must fail while user2/repo1 is in the trash
		user4 := getUserToken(t, "user4", auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "repo1"}).AddTokenAuth(user4), http.StatusCreated)
		admin := adminTrashToken(t)
		req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user4/repo1/transfer", &api.TransferRepoOption{NewOwner: "user2"}).AddTokenAuth(admin)
		resp := MakeRequest(t, req, NoExpectedStatus)
		assert.Contains(t, []int{http.StatusConflict, http.StatusUnprocessableEntity}, resp.Code)
	})
	t.Run("fork", func(t *testing.T) {
		req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user5/repo4/forks", &api.CreateForkOption{Name: new("repo1")}).AddTokenAuth(token)
		MakeRequest(t, req, http.StatusConflict)
	})
}

// AC5: the admin trash lists items with the data of the record, a total size and keyword search.
func TestTrashAdminList(t *testing.T) {
	defer prepareTrash(t)()
	moveToTrash(t)
	token := adminTrashToken(t)

	var list []*api.TrashItem
	resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/trash?q=repo1").AddTokenAuth(token), http.StatusOK)
	DecodeJSON(t, resp, &list)
	require.Len(t, list, 1)
	assert.Equal(t, "repo", list[0].Type)
	assert.Equal(t, "user2/repo1", list[0].FullName)
	assert.Equal(t, "user2", list[0].DeletedBy)
	assert.InDelta(t, 365, list[0].DaysRemaining, 1)

	resp = MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/trash?q=nothing-like-it").AddTokenAuth(token), http.StatusOK)
	DecodeJSON(t, resp, &list)
	assert.Empty(t, list)

	body := loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", "/admin/trash?q=repo1"), http.StatusOK).Body.String()
	assert.Contains(t, body, "user2/repo1")
}

// AC6: restore brings the repository back unchanged: same ID, owner, name, issues and counters.
func TestTrashRestore(t *testing.T) {
	defer prepareTrash(t)()
	before := trashRepo(t)
	issues := unittest.GetCount(t, &issues_model.Issue{RepoID: trashRepoID})
	pulls := unittest.GetCount(t, &issues_model.PullRequest{BaseRepoID: trashRepoID})
	releases := unittest.GetCount(t, &repo_model.Release{RepoID: trashRepoID})
	hooks := unittest.GetCount(t, &webhook_model.Webhook{RepoID: trashRepoID})
	collaborators := unittest.GetCount(t, &repo_model.Collaboration{RepoID: trashRepoID})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	numRepos := owner.NumRepos

	moveToTrash(t)
	loginUser(t, "user1").MakeRequest(t, NewRequest(t, "POST", "/admin/trash/1/restore"), http.StatusSeeOther)

	after := trashRepo(t)
	assert.False(t, after.IsTrashed())
	assert.Equal(t, before.ID, after.ID)
	assert.Equal(t, before.OwnerID, after.OwnerID)
	assert.Equal(t, before.LowerName, after.LowerName)
	assert.Equal(t, issues, unittest.GetCount(t, &issues_model.Issue{RepoID: trashRepoID}))
	assert.Equal(t, pulls, unittest.GetCount(t, &issues_model.PullRequest{BaseRepoID: trashRepoID}))
	assert.Equal(t, releases, unittest.GetCount(t, &repo_model.Release{RepoID: trashRepoID}))
	assert.Equal(t, hooks, unittest.GetCount(t, &webhook_model.Webhook{RepoID: trashRepoID}))
	assert.Equal(t, collaborators, unittest.GetCount(t, &repo_model.Collaboration{RepoID: trashRepoID}))
	owner = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	assert.Equal(t, numRepos, owner.NumRepos)
	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/user2/repo1"), http.StatusOK)

	t.Run("API", func(t *testing.T) {
		moveToTrash(t)
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/admin/trash/repo/1/restore").AddTokenAuth(adminTrashToken(t)), http.StatusNoContent)
		assert.False(t, trashRepo(t).IsTrashed())
	})

	t.Run("team links", func(t *testing.T) {
		admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		repo3 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}) // org3's, in teams
		links := unittest.GetCount(t, &organization.TeamRepo{RepoID: repo3.ID})
		require.Positive(t, links)

		require.NoError(t, repo_service.TrashRepository(t.Context(), admin, repo3))
		assert.Equal(t, links, unittest.GetCount(t, &organization.TeamRepo{RepoID: repo3.ID}), "trashing keeps the team links")
		require.NoError(t, trash_service.RestoreRepo(t.Context(), admin, repo3.ID, trash_service.RestoreOptions{}))
		assert.Equal(t, links, unittest.GetCount(t, &organization.TeamRepo{RepoID: repo3.ID}))
	})
}

// AC7: purge needs the typed name; afterwards the data is gone and the name is free.
func TestTrashPurge(t *testing.T) {
	defer prepareTrash(t)()
	moveToTrash(t)
	admin := loginUser(t, "user1")

	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/trash/1/purge", map[string]string{"confirm_name": "user2/other"}), http.StatusSeeOther)
	assert.True(t, trashRepo(t).IsTrashed(), "wrong name must not purge")

	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/trash/1/purge", map[string]string{"confirm_name": "user2/repo1"}), http.StatusSeeOther)
	unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: trashRepoID})
	assert.NoDirExists(t, repo_model.RepoPath("user2", "repo1"))

	token := getUserToken(t, "user2", auth_model.AccessTokenScopeAll)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "repo1"}).AddTokenAuth(token), http.StatusCreated)

	t.Run("in a project", func(t *testing.T) {
		doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		pay, err := repo_model.CreateRepoGroup(t.Context(), org3, "pay", "")
		require.NoError(t, err)
		repo, err := repo_service.CreateRepositoryDirectly(t.Context(), doer, org3, repo_service.CreateRepoOptions{Name: "api", GroupID: pay.ID})
		require.NoError(t, err)
		require.NoError(t, repo_service.TrashRepository(t.Context(), doer, repo))
		purge := fmt.Sprintf("/admin/trash/%d/purge", repo.ID)

		assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/trash"), http.StatusOK).Body.String(), "org3/pay/api")
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", purge, map[string]string{"confirm_name": "org3/api"}), http.StatusSeeOther)
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", purge, map[string]string{"confirm_name": "org3/pay/api"}), http.StatusSeeOther)
		unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: repo.ID})
	})
}

// AC9: no non-admin reaches any trash endpoint.
func TestTrashAdminOnly(t *testing.T) {
	defer prepareTrash(t)()
	moveToTrash(t)

	for _, user := range []string{"user2", "user4", "org3-owner"} {
		if user == "org3-owner" {
			user = "user2" // owner of org3
		}
		session := loginUser(t, user)
		token := getUserToken(t, user, auth_model.AccessTokenScopeAll)
		session.MakeRequest(t, NewRequest(t, "GET", "/admin/trash"), http.StatusForbidden)
		session.MakeRequest(t, NewRequest(t, "POST", "/admin/trash/1/restore"), http.StatusForbidden)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/trash/1/purge", map[string]string{"confirm_name": "user2/repo1"}), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/trash").AddTokenAuth(token), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/admin/trash/repo/1/restore").AddTokenAuth(token), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/trash/repo/1").AddTokenAuth(token), http.StatusForbidden)
	}
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/trash"), http.StatusUnauthorized)
	assert.True(t, trashRepo(t).IsTrashed())
}

// AC10: the API list, restore and delete need a site admin token with the admin scope.
func TestTrashAPI(t *testing.T) {
	defer prepareTrash(t)()
	moveToTrash(t)

	noAdminScope := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteRepository)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/trash").AddTokenAuth(noAdminScope), http.StatusForbidden)

	token := adminTrashToken(t)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/trash").AddTokenAuth(token), http.StatusOK)
	MakeRequest(t, NewRequest(t, "POST", "/api/v1/admin/trash/org/1/restore").AddTokenAuth(token), http.StatusNotFound) // not a trashed organization
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/trash/repo/1").AddTokenAuth(token), http.StatusNoContent)
	unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: trashRepoID})
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/trash/repo/1").AddTokenAuth(token), http.StatusNotFound)
}

// AC12: the delete dialog tells owners about the trash; the help link is optional.
func TestTrashDeleteDialog(t *testing.T) {
	defer prepareTrash(t)()

	body := loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings"), http.StatusOK).Body.String()
	assert.Contains(t, body, "365")
	assert.NotContains(t, body, "restore-help")

	setting.Trash.RestoreHelpURL = "https://helpdesk.example.org/restore"
	defer func() { setting.Trash.RestoreHelpURL = "" }()
	body = loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings"), http.StatusOK).Body.String()
	assert.Contains(t, body, "https://helpdesk.example.org/restore")

	// Owners see no trash in the UI.
	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/admin/trash"), http.StatusForbidden)
}

// AC13: the purge purges items past retention and leaves younger ones. The cron task is paused in maintenance mode
// by Task.RunWithUser, which services/cron/maintenance_test.go covers for every task.
func TestTrashPurgeExpired(t *testing.T) {
	defer prepareTrash(t)()
	moveToTrash(t)

	timeutil.MockSet(time.Now().Add(364 * 24 * time.Hour))
	defer timeutil.MockUnset()
	require.NoError(t, trash_service.PurgeExpired(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})))
	assert.True(t, trashRepo(t).IsTrashed())

	timeutil.MockSet(time.Now().Add(366 * 24 * time.Hour))
	require.NoError(t, trash_service.PurgeExpired(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})))
	unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: trashRepoID})
}

// AC14: a second purge or restore of an item that is already claimed fails.
func TestTrashRace(t *testing.T) {
	defer prepareTrash(t)()
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})

	t.Run("sequential", func(t *testing.T) {
		moveToTrash(t)
		require.NoError(t, trash_service.RestoreRepo(t.Context(), admin, trashRepoID, trash_service.RestoreOptions{}))
		require.ErrorIs(t, trash_service.RestoreRepo(t.Context(), admin, trashRepoID, trash_service.RestoreOptions{}), trash_service.ErrTrashConflict)
		require.ErrorIs(t, trash_service.Purge(t.Context(), admin, trashRepoID), trash_service.ErrTrashConflict)

		moveToTrash(t)
		require.NoError(t, trash_service.Purge(t.Context(), admin, trashRepoID))
		require.Error(t, trash_service.RestoreRepo(t.Context(), admin, trashRepoID, trash_service.RestoreOptions{}))
		require.Error(t, trash_service.Purge(t.Context(), admin, trashRepoID))
	})
}

// AC14: of concurrent restores and purges of one item exactly one wins.
func TestTrashRaceConcurrent(t *testing.T) {
	defer prepareTrash(t)()
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	moveToTrash(t)
	var wg sync.WaitGroup
	results := make([]error, 4)
	for i := range results {
		wg.Go(func() {
			if i%2 == 0 {
				results[i] = trash_service.RestoreRepo(t.Context(), admin, trashRepoID, trash_service.RestoreOptions{})
			} else {
				results[i] = trash_service.Purge(t.Context(), admin, trashRepoID)
			}
		})
	}
	wg.Wait()
	wins := 0
	for _, err := range results {
		if err == nil {
			wins++
		}
	}
	assert.Equal(t, 1, wins, "exactly one claim wins: %v", results)
}

// F1: a user or org that still has trashed repos is not deleted without a purge, and the purge path
// uses the current owner name.
func TestTrashOwnerLifecycle(t *testing.T) {
	defer prepareTrash(t)()
	moveToTrash(t)
	ctx := t.Context()

	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.Error(t, user_service.DeleteUser(t.Context(), user, false), "non-purge delete is refused while repos are in the trash")
	unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

	t.Run("renamed owner purges the right dir", func(t *testing.T) {
		require.NoError(t, user_service.RenameUser(ctx, user, "user2-renamed"))
		require.NoError(t, trash_service.Purge(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}), trashRepoID))
		assert.NoDirExists(t, repo_model.RepoPath("user2-renamed", "repo1"))
	})
}

// F1: with TRASH_USER_REPOS off, the purge user deletion removes the owner's trashed repositories too.
func TestTrashPurgeUserDeletion(t *testing.T) {
	defer prepareTrash(t)()
	defer test.MockVariableValue(&setting.Trash.TrashUserRepos, false)()
	moveToTrash(t)
	require.NoError(t, user_service.DeleteUser(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), true))
	unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: trashRepoID})
}

// F4: the creation limit still counts trashed repositories.
func TestTrashCreationLimit(t *testing.T) {
	defer prepareTrash(t)()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	total, err := repo_model.CountRepositories(t.Context(), repo_model.CountRepositoryOptions{OwnerID: owner.ID})
	require.NoError(t, err)
	defer test.MockVariableValue(&setting.Repository.MaxCreationLimit, int(total))()
	owner.MaxRepoCreation = -1
	require.NoError(t, user_model.UpdateUserCols(t.Context(), owner, "max_repo_creation"))
	doer := &user_model.User{ID: 99} // not an admin

	moveToTrash(t)
	owner = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.Equal(t, int(total)-1, owner.NumRepos)
	assert.True(t, repo_model.IsErrReachLimitOfRepo(repo_model.CheckRepoCreationLimit(t.Context(), doer, owner)), "the trashed repository still counts")
}

// F4: a fork counts against the creation limit like any new repository, trashed ones included.
func TestTrashForkLimit(t *testing.T) {
	defer prepareTrash(t)()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	total, err := repo_model.CountRepositories(t.Context(), repo_model.CountRepositoryOptions{OwnerID: owner.ID})
	require.NoError(t, err)
	defer test.MockVariableValue(&setting.Repository.MaxCreationLimit, int(total))()
	defer test.MockVariableValue(&setting.Repository.AllowForkWithoutMaximumLimit, false)()
	owner.MaxRepoCreation = -1
	require.NoError(t, user_model.UpdateUserCols(t.Context(), owner, "max_repo_creation"))

	moveToTrash(t)
	owner = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	base := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 10})
	_, err = repo_service.ForkRepositoryIfNotExists(t.Context(), &user_model.User{ID: 99}, owner, repo_service.ForkRepoOptions{BaseRepo: base, Name: "fork-over-limit"})
	assert.True(t, repo_model.IsErrReachLimitOfRepo(err), "the trashed repository still counts for forks: %v", err)
}

// Purging a repository closes the pull requests from its branches into other repositories, like any permanent deletion.
func TestTrashPurgeClosesPulls(t *testing.T) {
	defer prepareTrash(t)()
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	head := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 11}) // head of the open pull request of issue 8
	require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 8}).IsClosed)

	require.NoError(t, repo_service.TrashRepository(t.Context(), admin, head))
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 8}).IsClosed, "trashing leaves it open")
	require.NoError(t, trash_service.Purge(t.Context(), admin, head.ID))
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 8}).IsClosed)
}

// Team repository counts leave trashed repositories out, and the purge doesn't take them off a second time.
func TestTrashTeamCounts(t *testing.T) {
	defer prepareTrash(t)()
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}) // org3's, in several teams
	var links []*organization.TeamRepo
	require.NoError(t, db.GetEngine(t.Context()).Where("repo_id = ?", repo.ID).Find(&links))
	require.NotEmpty(t, links)
	counts := func() map[int64]int {
		res := map[int64]int{}
		for _, l := range links {
			res[l.TeamID] = unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: l.TeamID}).NumRepos
		}
		return res
	}
	before := counts()
	minusOne := map[int64]int{}
	for id, n := range before {
		minusOne[id] = n - 1
	}

	require.NoError(t, repo_service.TrashRepository(t.Context(), admin, repo))
	assert.Equal(t, minusOne, counts())
	require.NoError(t, trash_service.RestoreRepo(t.Context(), admin, repo.ID, trash_service.RestoreOptions{}))
	assert.Equal(t, before, counts())
	require.NoError(t, repo_service.TrashRepository(t.Context(), admin, repo))
	require.NoError(t, trash_service.Purge(t.Context(), admin, repo.ID))
	assert.Equal(t, minusOne, counts())
}

// F1: a user or an organization whose only repository is in the trash is not deleted, and says why: not a 500.
func TestTrashOwnerRefusals(t *testing.T) {
	defer prepareTrash(t)()
	admin := adminTrashToken(t)
	admin1 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})

	t.Run("user", func(t *testing.T) {
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/users", &api.CreateUserOption{
			Username: "trashonly", Email: "trashonly@example.com", Password: "password1234!", MustChangePassword: new(false),
		}).AddTokenAuth(admin), http.StatusCreated)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/users/trashonly/repos", &api.CreateRepoOption{Name: "only"}).AddTokenAuth(admin), http.StatusCreated)
		user := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "trashonly"})
		repo, err := repo_model.GetRepositoryByName(t.Context(), user.ID, "only")
		require.NoError(t, err)
		require.NoError(t, repo_service.TrashRepository(t.Context(), admin1, repo))

		resp := MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/users/trashonly").AddTokenAuth(admin), http.StatusUnprocessableEntity)
		assert.Contains(t, resp.Body.String(), "ownership of repositories")
		loginUser(t, "user1").MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/admin/users/%d/delete", user.ID)), http.StatusSeeOther)
		require.ErrorAs(t, user_service.DeleteUser(t.Context(), user, false), &models.ErrUserOwnRepos{})
		unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: user.ID})
	})

	t.Run("organization", func(t *testing.T) {
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeAll)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "trashorg"}).AddTokenAuth(token), http.StatusCreated)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/trashorg/repos", &api.CreateRepoOption{Name: "only"}).AddTokenAuth(token), http.StatusCreated)
		org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{Name: "trashorg"})
		repo, err := repo_model.GetRepositoryByName(t.Context(), org.ID, "only")
		require.NoError(t, err)
		require.NoError(t, repo_service.TrashRepository(t.Context(), admin1, repo))

		// the owner's deletion goes to the trash (the repository in it stays a separate item); the hard delete is refused
		require.ErrorAs(t, org_service.DeleteOrganization(t.Context(), org, false), &models.ErrUserOwnRepos{})
		unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: org.ID})
		MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/orgs/trashorg").AddTokenAuth(token), http.StatusNoContent)
		assert.True(t, trashedAccount(t, org.ID).IsTrashed())
		assert.False(t, trashRepoByID(t, repo.ID).TrashedWithOwner)
	})
}
