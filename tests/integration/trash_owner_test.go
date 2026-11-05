// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	packages_model "forgejo.org/models/packages"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"
	trash_service "forgejo.org/services/trash"
	user_service "forgejo.org/services/user"
	"forgejo.org/tests"

	runnerv1 "code.forgejo.org/forgejo/actions-proto/runner/v1"
	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// org3 (id 3) is owned by user2 and has the repositories 3, 5 and 32; user1 is the site admin.
const trashOrgID = 3

var trashOrgRepoIDs = []int64{3, 5, 32}

func trashAdminUser(t *testing.T) *user_model.User {
	t.Helper()
	return unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
}

func trashedAccount(t *testing.T, id int64) *user_model.User {
	t.Helper()
	u, err := user_model.GetUserByIDIncludingTrashed(t.Context(), id)
	require.NoError(t, err)
	return u
}

// missingRepoDirs creates the bare repositories that the fixtures name but the test data lacks (the purge opens them).
func missingRepoDirs(t *testing.T) {
	t.Helper()
	for _, p := range [][2]string{{"org3", "repo21"}, {"user27", "template2"}} {
		path := repo_model.RepoPath(p[0], p[1])
		if _, err := os.Stat(path); err != nil {
			require.NoError(t, git.InitRepository(t.Context(), path, true, "sha1"))
		}
	}
}

// deleteOrg3 deletes org3 as its owner through the web UI.
func deleteOrg3(t *testing.T) {
	t.Helper()
	loginUser(t, "user2").MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/delete", map[string]string{
		"org_name": "org3",
	}), http.StatusSeeOther)
	require.True(t, trashedAccount(t, trashOrgID).IsTrashed())
}

func trashRepoByID(t *testing.T, id int64) *repo_model.Repository {
	t.Helper()
	repo, err := repo_model.GetRepositoryByIDIncludingTrashed(t.Context(), id)
	require.NoError(t, err)
	return repo
}

// AC15: deleting an organization trashes it with all its repositories as one item; repositories trashed earlier
// stay separate, and restoring the organization brings back only the group.
func TestTrashOrgDeleteAndRestore(t *testing.T) {
	defer prepareTrash(t)()
	admin := trashAdminUser(t)
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: trashOrgID})
	numRepos := org.NumRepos
	earlier := trashRepoByID(t, 5)
	require.NoError(t, repo_service.DeleteRepository(t.Context(), admin, earlier, false)) // trashed on its own first
	teamRepos := unittest.GetCount(t, &organization.TeamRepo{OrgID: trashOrgID})

	deleteOrg3(t)

	for _, id := range trashOrgRepoIDs {
		repo := trashRepoByID(t, id)
		assert.True(t, repo.IsTrashed(), id)
		assert.Equal(t, id != 5, repo.TrashedWithOwner, "only repositories trashed with the organization belong to its item: %d", id)
	}
	assert.Equal(t, "user2", trashedAccount(t, trashOrgID).TrashedByName)
	assert.Equal(t, "org3", trashedAccount(t, trashOrgID).TrashedName)

	t.Run("listing", func(t *testing.T) {
		var list []*api.TrashItem
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/trash?type=org").AddTokenAuth(adminTrashToken(t)), http.StatusOK), &list)
		require.Len(t, list, 1)
		assert.Equal(t, "org", list[0].Type)
		assert.Equal(t, "org3", list[0].FullName)
		assert.EqualValues(t, 3, list[0].RepoCount)
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/trash").AddTokenAuth(adminTrashToken(t)), http.StatusOK), &list)
		for _, item := range list {
			assert.Equal(t, "repo", item.Type)
			assert.NotEqual(t, "org3/repo3", item.FullName, "repositories deleted with the organization are not separate items")
		}
		require.Len(t, list, 1)
		assert.Equal(t, "org3/repo5", list[0].FullName)

		body := loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", "/admin/trash?type=org"), http.StatusOK).Body.String()
		assert.Contains(t, body, "org3")
	})

	t.Run("a repository of the group is not restored alone", func(t *testing.T) {
		require.ErrorIs(t, trash_service.RestoreRepo(t.Context(), admin, 3, trash_service.RestoreOptions{}), trash_service.ErrTrashedWithOrg)
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/admin/trash/repo/3/restore").AddTokenAuth(adminTrashToken(t)), http.StatusUnprocessableEntity)
		loginUser(t, "user1").MakeRequest(t, NewRequest(t, "POST", "/admin/trash/3/restore"), http.StatusSeeOther)
		assert.True(t, trashRepoByID(t, 3).IsTrashed())
	})

	MakeRequest(t, NewRequest(t, "POST", "/api/v1/admin/trash/org/3/restore").AddTokenAuth(adminTrashToken(t)), http.StatusNoContent)
	assert.False(t, trashedAccount(t, trashOrgID).IsTrashed())
	assert.False(t, trashRepoByID(t, 3).IsTrashed())
	assert.False(t, trashRepoByID(t, 32).IsTrashed())
	assert.True(t, trashRepoByID(t, 5).IsTrashed(), "trashed earlier: stays in the trash")
	assert.False(t, trashRepoByID(t, 3).TrashedWithOwner)
	org = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: trashOrgID})
	assert.Equal(t, numRepos-1, org.NumRepos, "the repository trashed earlier is still out")
	assert.Equal(t, teamRepos, unittest.GetCount(t, &organization.TeamRepo{OrgID: trashOrgID}))
	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org3"), http.StatusOK)
	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org3/repo3"), http.StatusOK)
	teams, err := organization.FindOrgTeams(t.Context(), trashOrgID)
	require.NoError(t, err)
	for _, team := range teams {
		count, err := db.GetEngine(t.Context()).Table("team_repo").Join("INNER", "repository", "repository.id = team_repo.repo_id").
			Where("team_repo.team_id = ? AND repository.trashed_unix = 0", team.ID).Count()
		require.NoError(t, err)
		assert.EqualValues(t, team.NumRepos, count, "team %s", team.Name)
	}

	// the repository trashed earlier restores normally once its owner is back
	require.NoError(t, trash_service.RestoreRepo(t.Context(), admin, 5, trash_service.RestoreOptions{}))
	assert.False(t, trashRepoByID(t, 5).IsTrashed())
}

// AC15: with RETENTION_DAYS=0 nothing is trashed and an organization with repositories is still refused.
func TestTrashOrgRetentionZero(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	loginUser(t, "user2").MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/delete", map[string]string{"org_name": "org3"}), http.StatusSeeOther)
	assert.False(t, trashedAccount(t, trashOrgID).IsTrashed())
	assert.False(t, trashRepoByID(t, 3).IsTrashed())
}

// AC15: deleting through the API trashes the organization too.
func TestTrashOrgDeleteAPI(t *testing.T) {
	defer prepareTrash(t)()
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeAll)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/orgs/org3").AddTokenAuth(token), http.StatusNoContent)
	assert.True(t, trashedAccount(t, trashOrgID).IsTrashed())
	assert.True(t, trashRepoByID(t, 3).TrashedWithOwner)
}

// AC17: a trashed organization is invisible on every entry point, for everyone including site admins.
func TestTrashOrgInvisible(t *testing.T) {
	defer prepareTrash(t)()
	owner := loginUser(t, "user2")
	ownerToken := getUserToken(t, "user2", auth_model.AccessTokenScopeAll)

	// something to look for once it's gone
	packageURL := "/api/packages/org3/generic/trashpkg/1.0/file.bin"
	MakeRequest(t, NewRequestWithBody(t, "PUT", packageURL, strings.NewReader("content")).AddTokenAuth(ownerToken), http.StatusCreated)
	MakeRequest(t, NewRequest(t, "GET", packageURL).AddTokenAuth(ownerToken), http.StatusOK)

	deleteOrg3(t)

	for _, user := range []string{"user1", "user2", "user4"} { // site admin, org owner, member
		session := loginUser(t, user)
		token := getUserToken(t, user, auth_model.AccessTokenScopeAll)
		session.MakeRequest(t, NewRequest(t, "GET", "/org3"), http.StatusNotFound)
		session.MakeRequest(t, NewRequest(t, "GET", "/org3/repo21"), http.StatusNotFound)
		session.MakeRequest(t, NewRequest(t, "GET", "/org/org3/teams"), http.StatusNotFound)
		session.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings"), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3").AddTokenAuth(token), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/repos").AddTokenAuth(token), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/members").AddTokenAuth(token), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/teams").AddTokenAuth(token), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/users/org3").AddTokenAuth(token), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo21").AddTokenAuth(token), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", packageURL).AddTokenAuth(token), http.StatusNotFound)
	}
	MakeRequest(t, NewRequest(t, "GET", "/org3"), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3"), http.StatusNotFound)

	t.Run("git over HTTP", func(t *testing.T) {
		MakeRequest(t, NewRequest(t, "GET", "/org3/repo21.git/info/refs?service=git-upload-pack").AddBasicAuth("user2"), http.StatusNotFound)
	})

	t.Run("listings", func(t *testing.T) {
		for _, path := range []string{"/explore/organizations?q=org3", "/explore/repos?q=repo21", "/explore/users?q=org3", "/"} {
			body := owner.MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK).Body.String()
			assert.NotContains(t, body, `href="/org3"`, path)
			assert.NotContains(t, body, `href="/org3/repo21"`, path)
		}
		adminToken := adminTrashToken(t)
		for _, path := range []string{"/api/v1/user/orgs", "/api/v1/users/user2/orgs", "/api/v1/orgs", "/api/v1/admin/orgs", "/api/v1/users/search?q=org3", "/api/v1/repos/search?q=repo21"} {
			body := MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(adminToken), http.StatusOK).Body.String()
			assert.NotContains(t, body, `"org3"`, path)
		}
		body := MakeRequest(t, NewRequest(t, "GET", "/api/v1/user/orgs").AddTokenAuth(ownerToken), http.StatusOK).Body.String()
		assert.NotContains(t, body, `"org3"`)
		for _, path := range []string{"/admin/orgs?q=org3", "/admin/users?q=org3"} {
			body := loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK).Body.String()
			assert.NotContains(t, body, `href="/org3"`, path)
		}
		teams, err := organization.GetUserTeams(t.Context(), 2)
		require.NoError(t, err)
		for _, team := range teams {
			assert.NotEqual(t, int64(trashOrgID), team.OrgID)
		}
		count, err := organization.GetOrganizationCount(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}))
		require.NoError(t, err)
		assert.Positive(t, count, "memberships stay, so a member can't be deleted while the organization may come back")
	})

	t.Run("restoring brings the package back", func(t *testing.T) {
		require.NoError(t, trash_service.RestoreOrg(t.Context(), trashAdminUser(t), trashOrgID, trash_service.RestoreOptions{}))
		MakeRequest(t, NewRequest(t, "GET", packageURL).AddTokenAuth(ownerToken), http.StatusOK)
	})
}

// AC17: the organization's runners are not served while it is in the trash.
func TestTrashOrgRunner(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.Trash.RetentionDays, 365)()
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeAll)
		var regToken struct {
			Token string `json:"token"`
		}
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/actions/runners/registration-token").AddTokenAuth(token), http.StatusOK), &regToken)
		runner := newMockRunner()
		runner.doRegister(t, "org-runner", regToken.Token, []string{"ubuntu"})
		_, _, err := runner.fetchTaskOrError(t, 1)
		require.NoError(t, err)

		deleteOrg3(t)

		_, _, err = runner.fetchTaskOrError(t, 1)
		require.Error(t, err)
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
		_, err = newMockRunner().client.runnerServiceClient.Register(t.Context(), connect.NewRequest(&runnerv1.RegisterRequest{Name: "again", Token: regToken.Token}))
		require.Error(t, err)

		require.NoError(t, trash_service.RestoreOrg(t.Context(), trashAdminUser(t), trashOrgID, trash_service.RestoreOptions{}))
		_, _, err = runner.fetchTaskOrError(t, 1)
		require.NoError(t, err)
	})
}

// AC17: the name stays reserved while the organization is in the trash.
func TestTrashOrgNameReserved(t *testing.T) {
	defer prepareTrash(t)()
	deleteOrg3(t)
	adminToken := adminTrashToken(t)

	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "org3"}).AddTokenAuth(adminToken), http.StatusUnprocessableEntity)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "ORG3"}).AddTokenAuth(adminToken), http.StatusUnprocessableEntity)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/users", &api.CreateUserOption{
		Username: "org3", Email: "org3-new@example.com", Password: "password1234",
	}).AddTokenAuth(adminToken), http.StatusUnprocessableEntity)
	user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	require.Error(t, user_service.RenameUser(audit_model.WithSystem(t.Context(), "test"), user4, "org3"))
	require.Error(t, user_service.AdminRenameUser(audit_model.WithSystem(t.Context(), "test"), user4, "org3"))
	// nobody creates a repository under it
	resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: "fresh"}).AddTokenAuth(adminToken), NoExpectedStatus)
	assert.Equal(t, http.StatusNotFound, resp.Code)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/transfer", &api.TransferRepoOption{NewOwner: "org3"}).AddTokenAuth(adminToken), http.StatusNotFound)
}

// AC17/AC9: only site admins reach the organization part of the trash, on every route.
func TestTrashOrgAdminOnly(t *testing.T) {
	defer prepareTrash(t)()
	deleteOrg3(t)

	for _, user := range []string{"user2", "user4"} {
		session := loginUser(t, user)
		token := getUserToken(t, user, auth_model.AccessTokenScopeAll)
		session.MakeRequest(t, NewRequest(t, "GET", "/admin/trash?type=org"), http.StatusForbidden)
		session.MakeRequest(t, NewRequest(t, "POST", "/admin/trash/org/3/restore"), http.StatusForbidden)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/trash/org/3/purge", map[string]string{"confirm_name": "org3"}), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/trash?type=org").AddTokenAuth(token), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/admin/trash/org/3/restore").AddTokenAuth(token), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/trash/org/3").AddTokenAuth(token), http.StatusForbidden)
	}
	noAdminScope := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteOrganization)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/trash?type=org").AddTokenAuth(noAdminScope), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "POST", "/api/v1/admin/trash/org/3/restore").AddTokenAuth(noAdminScope), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/trash/org/3").AddTokenAuth(noAdminScope), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/trash?type=org"), http.StatusUnauthorized)

	admin := adminTrashToken(t)
	for _, method := range []string{"POST", "DELETE"} { // unknown kinds and items that are not in the trash
		path := "/api/v1/admin/trash/other/3"
		if method == "POST" {
			path += "/restore"
		}
		MakeRequest(t, NewRequest(t, method, path).AddTokenAuth(admin), http.StatusNotFound)
	}
	MakeRequest(t, NewRequest(t, "POST", "/api/v1/admin/trash/org/2/restore").AddTokenAuth(admin), http.StatusNotFound) // a user
	MakeRequest(t, NewRequest(t, "POST", "/api/v1/admin/trash/org/17/restore").AddTokenAuth(admin), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/trash/org/17").AddTokenAuth(admin), http.StatusNotFound) // live organization
	loginUser(t, "user1").MakeRequest(t, NewRequest(t, "POST", "/admin/trash/org/17/restore"), http.StatusNotFound)
	assert.True(t, trashedAccount(t, trashOrgID).IsTrashed())
}

// AC17/AC7: purging an organization needs its typed name and takes all its repositories in the trash with it;
// afterwards the name is free.
func TestTrashOrgPurge(t *testing.T) {
	defer prepareTrash(t)()
	missingRepoDirs(t)
	MakeRequest(t, NewRequestWithBody(t, "PUT", "/api/packages/org3/generic/purgepkg/1.0/file.bin", strings.NewReader("content")).AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeAll)), http.StatusCreated)
	versions, _, err := packages_model.SearchVersions(t.Context(), &packages_model.PackageSearchOptions{OwnerID: trashOrgID})
	require.NoError(t, err)
	require.NotEmpty(t, versions)
	require.NoError(t, repo_service.DeleteRepository(t.Context(), trashAdminUser(t), trashRepoByID(t, 5), false)) // trashed earlier, separate
	deleteOrg3(t)
	admin := loginUser(t, "user1")

	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/trash/org/3/purge", map[string]string{"confirm_name": "org4"}), http.StatusSeeOther)
	assert.True(t, trashedAccount(t, trashOrgID).IsTrashed(), "a wrong name must not purge")

	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/trash/org/3/purge", map[string]string{"confirm_name": "org3"}), http.StatusSeeOther)
	unittest.AssertNotExistsBean(t, &user_model.User{ID: trashOrgID})
	for _, id := range trashOrgRepoIDs {
		unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: id})
	}
	assert.NoDirExists(t, user_model.UserPath("org3"))
	unittest.AssertNotExistsBean(t, &organization.Team{OrgID: trashOrgID})
	versions, _, err = packages_model.SearchVersions(t.Context(), &packages_model.PackageSearchOptions{OwnerID: trashOrgID, IncludeTrashed: true})
	require.NoError(t, err)
	assert.Empty(t, versions, "its packages went with it")
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "org3"}).AddTokenAuth(adminTrashToken(t)), http.StatusCreated)

	t.Run("API", func(t *testing.T) {
		id := org3NewID(t)
		MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/orgs/org3").AddTokenAuth(adminTrashToken(t)), http.StatusNoContent)
		MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/trash/org/"+id).AddTokenAuth(adminTrashToken(t)), http.StatusNoContent)
		MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/trash/org/"+id).AddTokenAuth(adminTrashToken(t)), http.StatusNotFound)
	})
}

// the id of the organization named org3, trashed or not
func org3NewID(t *testing.T) string {
	t.Helper()
	return strconv.FormatInt(unittest.AssertExistsAndLoadBean(t, &user_model.User{LowerName: "org3"}).ID, 10)
}

// AC13/AC17: the cron purge takes an organization past retention with its repositories and leaves a younger one.
func TestTrashOrgPurgeExpired(t *testing.T) {
	defer prepareTrash(t)()
	missingRepoDirs(t)
	deleteOrg3(t)

	timeutil.MockSet(time.Now().Add(364 * 24 * time.Hour))
	defer timeutil.MockUnset()
	require.NoError(t, trash_service.PurgeExpired(t.Context(), trashAdminUser(t)))
	assert.True(t, trashedAccount(t, trashOrgID).IsTrashed())

	timeutil.MockSet(time.Now().Add(366 * 24 * time.Hour))
	require.NoError(t, trash_service.PurgeExpired(t.Context(), trashAdminUser(t)))
	unittest.AssertNotExistsBean(t, &user_model.User{ID: trashOrgID})
	for _, id := range trashOrgRepoIDs {
		unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: id})
	}
}

// AC14: a second purge or restore of an organization that is claimed already fails, and the purge never touches
// a repository that is live.
func TestTrashOrgRace(t *testing.T) {
	defer prepareTrash(t)()
	admin := trashAdminUser(t)
	deleteOrg3(t)

	require.NoError(t, trash_service.RestoreOrg(t.Context(), admin, trashOrgID, trash_service.RestoreOptions{}))
	require.ErrorIs(t, trash_service.RestoreOrg(t.Context(), admin, trashOrgID, trash_service.RestoreOptions{}), trash_service.ErrTrashConflict)
	require.ErrorIs(t, trash_service.PurgeOrg(t.Context(), admin, trashOrgID), trash_service.ErrTrashConflict)

	deleteOrg3(t)
	// a repository that got created while the organization was being trashed makes the purge refuse and give the claim back
	_, err := db.GetEngine(t.Context()).Exec("UPDATE `repository` SET trashed_unix = 0, trashed_with_owner = ? WHERE id = 3", false)
	require.NoError(t, err)
	require.ErrorIs(t, trash_service.PurgeOrg(t.Context(), admin, trashOrgID), trash_service.ErrOrgHasLiveRepos)
	assert.Positive(t, int64(trashedAccount(t, trashOrgID).TrashedUnix), "the claim was released")
	assert.False(t, trashRepoByID(t, 3).IsTrashed())
}

// Amended AC6: restoring with a new owner and/or name, and when the owner is gone.
func TestTrashRestoreNewOwnerAndName(t *testing.T) {
	defer prepareTrash(t)()
	admin := trashAdminUser(t)
	ctx := t.Context()
	user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	require.NoError(t, repo_service.DeleteRepository(ctx, admin, trashRepoByID(t, 5), false))
	deleteOrg3(t)
	teamLinks := unittest.GetCount(t, &organization.TeamRepo{RepoID: 5})
	require.Positive(t, teamLinks)

	t.Run("needs a new owner while the owner is in the trash", func(t *testing.T) {
		require.ErrorIs(t, trash_service.RestoreRepo(ctx, admin, 5, trash_service.RestoreOptions{}), trash_service.ErrNeedNewOwner)
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/admin/trash/repo/5/restore").AddTokenAuth(adminTrashToken(t)), http.StatusUnprocessableEntity)
		assert.True(t, trashRepoByID(t, 5).IsTrashed())
	})

	t.Run("the new owner must be a live user or organization", func(t *testing.T) {
		for _, owner := range []string{"nobody-like-it", "org3", "Ghost", "forgejo-actions", "user2/x"} {
			require.ErrorIs(t, trash_service.RestoreRepo(ctx, admin, 5, trash_service.RestoreOptions{NewOwner: owner}), trash_service.ErrInvalidNewOwner, owner)
		}
		assert.True(t, trashRepoByID(t, 5).IsTrashed())
	})

	t.Run("the name must be free and valid", func(t *testing.T) {
		// user4 already has a repository named like the one being restored
		_, err := repo_service.CreateRepositoryDirectly(ctx, user4, user4, repo_service.CreateRepoOptions{Name: "repo5"})
		require.NoError(t, err)
		err = trash_service.RestoreRepo(ctx, admin, 5, trash_service.RestoreOptions{NewOwner: "user4"})
		require.Error(t, err)
		assert.True(t, trash_service.IsBadTarget(err), err)
		err = trash_service.RestoreRepo(ctx, admin, 5, trash_service.RestoreOptions{NewOwner: "user4", NewName: "bad name!"})
		require.Error(t, err)
		assert.True(t, trash_service.IsBadTarget(err), err)
		assert.True(t, trashRepoByID(t, 5).IsTrashed())

		// the new name is free under the old owner but taken under the new one: refused before any file moves
		_, err = repo_service.CreateRepositoryDirectly(ctx, user4, user4, repo_service.CreateRepoOptions{Name: "clashx"})
		require.NoError(t, err)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/trash/repo/5/restore", &api.RestoreTrashOption{NewOwner: "user4", NewName: "clashx"}).AddTokenAuth(adminTrashToken(t)), http.StatusUnprocessableEntity)
		assert.True(t, trashRepoByID(t, 5).IsTrashed())
		assert.Equal(t, "repo5", trashRepoByID(t, 5).Name)
		assert.DirExists(t, repo_model.RepoPath("org3", "repo5"))
		assert.NoDirExists(t, repo_model.RepoPath("org3", "clashx"))
	})

	t.Run("restore under a new owner and name", func(t *testing.T) {
		numRepos := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}).NumRepos
		oldOrg := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: trashOrgID})
		resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/trash/repo/5/restore", &api.RestoreTrashOption{NewOwner: "user4", NewName: "moved5"}).AddTokenAuth(adminTrashToken(t)), http.StatusNoContent)
		_ = resp
		repo := trashRepoByID(t, 5)
		assert.False(t, repo.IsTrashed())
		assert.Equal(t, int64(4), repo.OwnerID)
		assert.Equal(t, "user4", repo.OwnerName)
		assert.Equal(t, "moved5", repo.Name)
		assert.DirExists(t, repo_model.RepoPath("user4", "moved5"))
		assert.NoDirExists(t, repo_model.RepoPath("org3", "repo5"))
		assert.Zero(t, unittest.GetCount(t, &organization.TeamRepo{RepoID: 5}), "no stale team access")
		assert.Equal(t, numRepos+1, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}).NumRepos)
		assert.Equal(t, oldOrg.NumRepos, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: trashOrgID}).NumRepos, "the organization's count left the trashed repository out already")
		teams, err := organization.FindOrgTeams(ctx, trashOrgID)
		require.NoError(t, err)
		for _, team := range teams {
			assert.GreaterOrEqual(t, team.NumRepos, 0, team.Name)
		}
		loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", "/user4/moved5"), http.StatusOK)
		// the teams of the old organization have no access any more
		loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/user4/moved5/settings"), http.StatusNotFound)
	})

	t.Run("only the name", func(t *testing.T) {
		require.NoError(t, trash_service.RestoreOrg(ctx, admin, trashOrgID, trash_service.RestoreOptions{}))
		require.NoError(t, repo_service.DeleteRepository(ctx, admin, trashRepoByID(t, 3), false))
		require.NoError(t, trash_service.RestoreRepo(ctx, admin, 3, trash_service.RestoreOptions{NewName: "renamed3"}))
		repo := trashRepoByID(t, 3)
		assert.False(t, repo.IsTrashed())
		assert.Equal(t, "renamed3", repo.Name)
		assert.DirExists(t, repo_model.RepoPath("org3", "renamed3"))
		loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org3/renamed3"), http.StatusOK)
	})

	t.Run("web form", func(t *testing.T) {
		require.NoError(t, repo_service.DeleteRepository(ctx, admin, trashRepoByID(t, 3), false))
		loginUser(t, "user1").MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/trash/3/restore", map[string]string{"new_owner": "user4", "new_name": "from-form"}), http.StatusSeeOther)
		repo := trashRepoByID(t, 3)
		assert.False(t, repo.IsTrashed())
		assert.Equal(t, "user4", repo.OwnerName)
		assert.Equal(t, "from-form", repo.Name)
	})
}

// B2: purging an organization leaves a repository that was moved to another owner meanwhile.
func TestTrashOrgPurgeSkipsMovedRepo(t *testing.T) {
	defer prepareTrash(t)()
	missingRepoDirs(t)
	admin := trashAdminUser(t)
	require.NoError(t, repo_service.DeleteRepository(t.Context(), admin, trashRepoByID(t, 5), false))
	deleteOrg3(t)
	_, err := db.GetEngine(t.Context()).Exec("UPDATE `repository` SET owner_id = 4, owner_name = 'user4' WHERE id = 5") // what another pod's restore did
	require.NoError(t, err)

	require.NoError(t, trash_service.PurgeOrg(t.Context(), admin, trashOrgID))
	unittest.AssertNotExistsBean(t, &user_model.User{ID: trashOrgID})
	assert.True(t, trashRepoByID(t, 5).IsTrashed(), "not the organization's any more")
}

// AC15: an organization can be restored under a new name.
func TestTrashOrgRestoreNewName(t *testing.T) {
	defer prepareTrash(t)()
	deleteOrg3(t)
	body := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/trash/org/3/restore", &api.RestoreTrashOption{NewOwner: "user4"}).AddTokenAuth(adminTrashToken(t)), http.StatusUnprocessableEntity).Body.String()
	assert.Contains(t, body, "owner")
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/trash/org/3/restore", &api.RestoreTrashOption{NewName: "user2"}).AddTokenAuth(adminTrashToken(t)), http.StatusUnprocessableEntity)
	assert.True(t, trashedAccount(t, trashOrgID).IsTrashed(), "a name that is taken leaves it in the trash")
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/trash/org/3/restore", &api.RestoreTrashOption{NewName: "org3-renamed"}).AddTokenAuth(adminTrashToken(t)), http.StatusNoContent)
	org := trashedAccount(t, trashOrgID)
	assert.False(t, org.IsTrashed())
	assert.Equal(t, "org3-renamed", org.Name)
	assert.Equal(t, "org3-renamed", trashRepoByID(t, 3).OwnerName)
	assert.DirExists(t, repo_model.RepoPath("org3-renamed", "repo3"))
	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org3-renamed/repo3"), http.StatusOK)
}

// the user with repositories, no organizations and no packages that the AC16 tests delete
const trashUserID = 27

var trashUserRepoIDs = []int64{44, 45, 49}

func deleteUser27(t *testing.T) {
	t.Helper()
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/users/user27?purge=true").AddTokenAuth(adminTrashToken(t)), http.StatusNoContent)
}

// AC16: deleting a user with purge sends their repositories to the trash as separate items and leaves an inert,
// hidden tombstone that keeps the name.
func TestTrashUserDelete(t *testing.T) {
	defer prepareTrash(t)()
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: trashUserID})
	require.NoError(t, db.Insert(t.Context(), &auth_model.TwoFactor{UID: trashUserID, Secret: []byte("s"), ScratchSalt: "a", ScratchHash: "b"}))
	require.NoError(t, db.Insert(t.Context(), &auth_model.WebAuthnCredential{UserID: trashUserID, Name: "key", LowerName: "key", CredentialID: []byte("abc")}))

	// without purge the user is still refused, as before
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/users/user27").AddTokenAuth(adminTrashToken(t)), http.StatusUnprocessableEntity)
	assert.False(t, trashedAccount(t, trashUserID).IsTrashed())

	deleteUser27(t)

	tombstone := trashedAccount(t, trashUserID)
	assert.True(t, tombstone.IsTrashed())
	assert.Equal(t, "user27", tombstone.Name)
	for _, id := range trashUserRepoIDs {
		repo := trashRepoByID(t, id)
		assert.True(t, repo.IsTrashed(), id)
		assert.False(t, repo.TrashedWithOwner, "separate items: %d", id)
		assert.Equal(t, "user27", repo.TrashedByName)
	}
	assert.DirExists(t, repo_model.RepoPath("user27", "repo49"))

	t.Run("no personal data and no credentials", func(t *testing.T) {
		assert.False(t, tombstone.IsActive)
		assert.True(t, tombstone.ProhibitLogin)
		assert.False(t, tombstone.IsAdmin)
		assert.Empty(t, tombstone.Passwd)
		assert.Empty(t, tombstone.Salt)
		assert.Empty(t, tombstone.FullName)
		assert.Empty(t, tombstone.Description)
		assert.Empty(t, tombstone.Location)
		assert.Empty(t, tombstone.Website)
		assert.Empty(t, tombstone.Avatar)
		assert.Empty(t, tombstone.LoginName)
		assert.NotEqual(t, user.Email, tombstone.Email)
		assert.Equal(t, "deleted-27@"+setting.Service.NoReplyAddress, tombstone.Email)
		for _, bean := range []any{
			&user_model.EmailAddress{UID: trashUserID}, &auth_model.AccessToken{UID: trashUserID}, &asymkey.PublicKey{OwnerID: trashUserID},
			&asymkey.GPGKey{OwnerID: trashUserID}, &auth_model.TwoFactor{UID: trashUserID}, &auth_model.WebAuthnCredential{UserID: trashUserID},
			&auth_model.OAuth2Grant{UserID: trashUserID}, &auth_model.OAuth2Application{UID: trashUserID}, &user_model.UserOpenID{UID: trashUserID},
			&user_model.Follow{UserID: trashUserID}, &user_model.Setting{UserID: trashUserID},
		} {
			unittest.AssertNotExistsBean(t, bean)
		}
		count, err := db.GetEngine(t.Context()).Table("external_login_user").Where("user_id = ?", trashUserID).Count()
		require.NoError(t, err)
		assert.Zero(t, count)
	})

	t.Run("invisible and inert", func(t *testing.T) {
		adminToken := adminTrashToken(t)
		MakeRequest(t, NewRequest(t, "GET", "/user27"), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/user27/repo49"), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/user27.png"), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/users/user27").AddTokenAuth(adminToken), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/users/user27/repos").AddTokenAuth(adminToken), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user27/repo49").AddTokenAuth(adminToken), http.StatusNotFound)
		for _, path := range []string{"/api/v1/users/search?q=user27", "/api/v1/admin/users?q=user27"} {
			assert.NotContains(t, MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(adminToken), http.StatusOK).Body.String(), `"login":"user27"`, path)
		}
		for _, path := range []string{"/explore/users?q=user27", "/admin/users?q=user27"} {
			assert.NotContains(t, loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK).Body.String(), `href="/user27"`, path)
		}
		_, err := user_model.GetUserByName(t.Context(), "user27")
		require.True(t, user_model.IsErrUserNotExist(err))
		found, err := user_model.GetUser(t.Context(), &user_model.User{LowerName: "user27"}) // sign-in, OAuth and auto-link look users up this way
		require.NoError(t, err)
		assert.False(t, found)
		_, err = user_model.GetUserByEmail(t.Context(), "user27@example.com")
		require.Error(t, err)
		_, err = user_model.GetUserByEmail(t.Context(), tombstone.Email)
		require.Error(t, err, "the placeholder doesn't find the tombstone")
		mailable, err := user_model.GetMaileableUsersByIDs(t.Context(), []int64{trashUserID}, false)
		require.NoError(t, err)
		assert.Empty(t, mailable)
		mailable, err = user_model.GetMaileableUsersByIDs(t.Context(), []int64{trashUserID}, true)
		require.NoError(t, err)
		assert.Empty(t, mailable)
		inactive, err := user_model.GetInactiveUsers(t.Context(), 0)
		require.NoError(t, err)
		for _, u := range inactive {
			assert.NotEqual(t, int64(trashUserID), u.ID)
		}
	})

	t.Run("nobody signs in", func(t *testing.T) {
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddBasicAuth("user27"), http.StatusUnauthorized)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth("0123456789012345678901234567890123456789"), http.StatusUnauthorized)
		resp := MakeRequest(t, NewRequestWithValues(t, "POST", "/user/login", map[string]string{"user_name": "user27", "password": "password"}), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "flash-error")
		MakeRequest(t, NewRequestWithValues(t, "POST", "/user/forgot_password", map[string]string{"email": "user27@example.com"}), NoExpectedStatus)
		assert.False(t, tombstone.ValidatePassword(t.Context(), ""))
		assert.False(t, tombstone.ValidatePassword(t.Context(), "password"))
		assert.False(t, tombstone.IsAccessAllowed(t.Context()))
	})

	t.Run("the name is reserved", func(t *testing.T) {
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/users", &api.CreateUserOption{
			Username: "user27", Email: "user27-again@example.com", Password: "password1234",
		}).AddTokenAuth(adminTrashToken(t)), http.StatusUnprocessableEntity)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "user27"}).AddTokenAuth(adminTrashToken(t)), http.StatusUnprocessableEntity)
	})

	t.Run("the cron job for inactive users leaves it alone", func(t *testing.T) {
		require.NoError(t, user_service.DeleteInactiveUsers(t.Context(), 0))
		assert.True(t, trashedAccount(t, trashUserID).IsTrashed())
	})

	t.Run("listed as separate repository items, not as an item itself", func(t *testing.T) {
		var list []*api.TrashItem
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/trash?q=user27").AddTokenAuth(adminTrashToken(t)), http.StatusOK), &list)
		assert.Len(t, list, 3)
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/trash?type=org&q=user27").AddTokenAuth(adminTrashToken(t)), http.StatusOK), &list)
		assert.Empty(t, list)
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/admin/trash/org/27/restore").AddTokenAuth(adminTrashToken(t)), http.StatusNotFound)
	})
}

// AC16: the tombstone goes with its last repository, exactly once: by purge, or by restoring it under a new owner.
func TestTrashUserTombstoneCleanup(t *testing.T) {
	defer prepareTrash(t)()
	missingRepoDirs(t)
	admin := trashAdminUser(t)
	ctx := t.Context()
	deleteUser27(t)

	require.NoError(t, trash_service.Purge(ctx, admin, 45))
	assert.True(t, trashedAccount(t, trashUserID).IsTrashed(), "still owns two repositories in the trash")

	require.ErrorIs(t, trash_service.RestoreRepo(ctx, admin, 44, trash_service.RestoreOptions{}), trash_service.ErrNeedNewOwner)
	require.NoError(t, trash_service.RestoreRepo(ctx, admin, 44, trash_service.RestoreOptions{NewOwner: "user4"}))
	assert.True(t, trashedAccount(t, trashUserID).IsTrashed())
	assert.Equal(t, int64(4), trashRepoByID(t, 44).OwnerID)

	require.NoError(t, trash_service.Purge(ctx, admin, 49))
	unittest.AssertNotExistsBean(t, &user_model.User{ID: trashUserID})
	assert.NoDirExists(t, user_model.UserPath("user27"))
	assert.DirExists(t, repo_model.RepoPath("user4", "template1"))

	// the name is free again
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/users", &api.CreateUserOption{
		Username: "user27", Email: "user27-again@example.com", Password: "password1234", MustChangePassword: new(false),
	}).AddTokenAuth(adminTrashToken(t)), http.StatusCreated)
}

// AC16: restoring the last repository to a new owner removes the tombstone; a leftover one is swept by the cron job.
func TestTrashUserTombstoneRestoreAndSweep(t *testing.T) {
	defer prepareTrash(t)()
	missingRepoDirs(t)
	admin := trashAdminUser(t)
	ctx := t.Context()
	deleteUser27(t)

	for _, id := range []int64{44, 49} {
		require.NoError(t, trash_service.RestoreRepo(ctx, admin, id, trash_service.RestoreOptions{NewOwner: "user4", NewName: "moved-" + trashRepoByID(t, id).Name}))
	}
	assert.True(t, trashedAccount(t, trashUserID).IsTrashed())
	// the crash case: the last repository went away without the tombstone being removed
	require.NoError(t, repo_service.DeleteRepositoryDirectly(ctx, 45, repo_service.DeleteRepositoryOpts{}))
	assert.True(t, trashedAccount(t, trashUserID).IsTrashed())
	require.NoError(t, trash_service.PurgeExpired(ctx, admin))
	unittest.AssertNotExistsBean(t, &user_model.User{ID: trashUserID})
	require.NoError(t, trash_service.PurgeExpired(ctx, admin), "idempotent")
}

// AC16: a user who owns nothing is deleted for good, and so is everything when the setting or the trash is off;
// the guards stay.
func TestTrashUserDeleteVariants(t *testing.T) {
	defer prepareTrash(t)()
	ctx := t.Context()

	t.Run("nothing owned: hard delete", func(t *testing.T) {
		user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8})
		require.NoError(t, user_service.DeleteUser(ctx, user, true))
		unittest.AssertNotExistsBean(t, &user_model.User{ID: 8})
	})

	t.Run("setting off: repositories are deleted too", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Trash.TrashUserRepos, false)()
		deleteUser27(t)
		unittest.AssertNotExistsBean(t, &user_model.User{ID: trashUserID})
		for _, id := range trashUserRepoIDs {
			unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: id})
		}
	})

	t.Run("trash off: repositories are deleted too", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Trash.RetentionDays, 0)()
		MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/users/user30?purge=true").AddTokenAuth(adminTrashToken(t)), http.StatusNoContent)
		unittest.AssertNotExistsBean(t, &user_model.User{ID: 30})
		unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: 50})
	})

	t.Run("the last admin stays", func(t *testing.T) {
		require.Error(t, user_service.DeleteUser(ctx, trashAdminUser(t), true))
		assert.False(t, trashedAccount(t, 1).IsTrashed())
	})

	t.Run("a member of an organization in the trash: no purge, no deletion; with purge the membership goes", func(t *testing.T) {
		deleteOrg3(t)
		user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}) // member of org3 only
		require.Error(t, user_service.DeleteUser(ctx, user, false))
		unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
		members := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: trashOrgID}).NumMembers
		require.NoError(t, user_service.DeleteUser(ctx, user, true))
		unittest.AssertNotExistsBean(t, &user_model.User{ID: 4})
		unittest.AssertNotExistsBean(t, &organization.OrgUser{UID: 4})
		unittest.AssertNotExistsBean(t, &organization.TeamUser{UID: 4})
		assert.Equal(t, members-1, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: trashOrgID}).NumMembers)
	})

	t.Run("moderation deletes for good", func(t *testing.T) {
		require.NoError(t, user_service.DeleteUserPermanently(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 21}), true))
		unittest.AssertNotExistsBean(t, &user_model.User{ID: 21})
		for _, id := range []int64{34, 35} {
			unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: id})
		}
	})
}

// AC15/AC16: purging the last owner of an organization sends the organization with its repositories to the trash as
// one item (retention > 0); a user who owns no repository directly is deleted for good.
func TestTrashUserSoleOrgOwner(t *testing.T) {
	defer prepareTrash(t)()
	token := getUserToken(t, "user8", auth_model.AccessTokenScopeAll)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "soleorg"}).AddTokenAuth(token), http.StatusCreated)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/soleorg/repos", &api.CreateRepoOption{Name: "solerepo"}).AddTokenAuth(token), http.StatusCreated)
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{LowerName: "soleorg"})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: org.ID, Name: "solerepo"})

	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/users/user8?purge=true").AddTokenAuth(adminTrashToken(t)), http.StatusNoContent)

	unittest.AssertNotExistsBean(t, &user_model.User{ID: 8})
	assert.True(t, trashedAccount(t, org.ID).IsTrashed())
	assert.True(t, trashRepoByID(t, repo.ID).TrashedWithOwner)
	assert.DirExists(t, repo_model.RepoPath("soleorg", "solerepo"))
	var list []*api.TrashItem
	DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/trash?type=org&q=soleorg").AddTokenAuth(adminTrashToken(t)), http.StatusOK), &list)
	require.Len(t, list, 1)
	assert.EqualValues(t, 1, list[0].RepoCount)
}

// N4: purging the last owner of an organization in the trash leaves it ownerless; restored, an admin can still use it and
// add an owner, and no page breaks.
func TestTrashOrgOwnerlessRestore(t *testing.T) {
	defer prepareTrash(t)()
	ctx := t.Context()
	token := getUserToken(t, "user8", auth_model.AccessTokenScopeAll)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "ownerless"}).AddTokenAuth(token), http.StatusCreated)
	org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{LowerName: "ownerless"})
	require.NoError(t, org_service.TrashOrganization(ctx, trashAdminUser(t), org))
	other := unittest.GetCount(t, &organization.OrgUser{}, "uid != 8")

	require.Error(t, user_service.DeleteUser(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8}), false), "without purge the membership keeps the user")
	require.NoError(t, user_service.DeleteUser(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8}), true))
	unittest.AssertNotExistsBean(t, &user_model.User{ID: 8})
	assert.Equal(t, other, unittest.GetCount(t, &organization.OrgUser{}, "uid != 8"), "only the deleted user's rows went")
	assert.Zero(t, unittest.GetCount(t, &organization.TeamUser{OrgID: org.ID}))

	require.NoError(t, trash_service.RestoreOrg(ctx, trashAdminUser(t), org.ID, trash_service.RestoreOptions{}))
	admin := loginUser(t, "user1")
	admin.MakeRequest(t, NewRequest(t, "GET", "/ownerless"), http.StatusOK)
	admin.MakeRequest(t, NewRequest(t, "GET", "/org/ownerless/teams"), http.StatusOK)
	admin.MakeRequest(t, NewRequest(t, "GET", "/org/ownerless/members"), http.StatusOK)
	admin.MakeRequest(t, NewRequest(t, "GET", "/org/ownerless/settings"), http.StatusOK)
	ownerTeam, err := org.GetOwnerTeam(ctx)
	require.NoError(t, err)
	admin.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org/ownerless/teams/%s", ownerTeam.LowerName)), http.StatusOK)
	adminToken := adminTrashToken(t)
	MakeRequest(t, NewRequest(t, "PUT", fmt.Sprintf("/api/v1/teams/%d/members/user2", ownerTeam.ID)).AddTokenAuth(adminToken), http.StatusNoContent)
	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org/ownerless/settings"), http.StatusOK)
}

// S1: restoring to a new owner leaves no access through the old organization's teams.
func TestTrashRestoreNoStaleAccess(t *testing.T) {
	defer prepareTrash(t)()
	admin := trashAdminUser(t)
	ctx := t.Context()
	require.NoError(t, repo_service.DeleteRepository(ctx, admin, trashRepoByID(t, 5), false))
	deleteOrg3(t)

	var members []string
	require.NoError(t, db.GetEngine(ctx).Table("team_user").Select("DISTINCT `user`.name").
		Join("INNER", "team_repo", "team_repo.team_id = team_user.team_id").
		Join("INNER", "`user`", "`user`.id = team_user.uid").
		Where("team_repo.repo_id = 5 AND `user`.id NOT IN (1, 8)").Find(&members))
	require.NotEmpty(t, members)

	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/trash/repo/5/restore", &api.RestoreTrashOption{NewOwner: "user8", NewName: "secretmoved"}).AddTokenAuth(adminTrashToken(t)), http.StatusNoContent)
	assert.Zero(t, unittest.GetCount(t, &organization.TeamRepo{RepoID: 5}))
	for _, name := range members {
		token := getUserToken(t, name, auth_model.AccessTokenScopeAll)
		body := MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/search?q=secretmoved&private=true").AddTokenAuth(token), http.StatusOK).Body.String()
		assert.NotContains(t, body, "secretmoved", name)
		body = loginUser(t, name).MakeRequest(t, NewRequest(t, "GET", "/explore/repos?q=secretmoved"), http.StatusOK).Body.String()
		assert.NotContains(t, body, `href="/user8/secretmoved"`, name)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user8/secretmoved").AddTokenAuth(token), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/issues/search?state=all").AddTokenAuth(token), http.StatusOK)
	}
}

// AC14: restore with a new owner or name and a purge meeting each other: the one that claims the repository first
// wins, and no files end up where the database doesn't point.
func TestTrashRestoreMoveConflict(t *testing.T) {
	defer prepareTrash(t)()
	admin := trashAdminUser(t)
	ctx := t.Context()
	require.NoError(t, repo_service.DeleteRepository(ctx, admin, trashRepoByID(t, 5), false))

	t.Run("purge claimed first", func(t *testing.T) {
		_, err := db.GetEngine(ctx).Exec("UPDATE `repository` SET trashed_unix = ? WHERE id = 5", -int64(timeutil.TimeStampNow()))
		require.NoError(t, err)
		require.ErrorIs(t, trash_service.RestoreRepo(ctx, admin, 5, trash_service.RestoreOptions{NewOwner: "user4", NewName: "moved"}), trash_service.ErrTrashConflict)
		repo := trashRepoByID(t, 5)
		assert.Equal(t, int64(trashOrgID), repo.OwnerID)
		assert.Equal(t, "repo5", repo.Name)
		assert.DirExists(t, repo_model.RepoPath("org3", "repo5"))
		assert.NoDirExists(t, repo_model.RepoPath("user4", "moved"))
		assert.NoDirExists(t, repo_model.RepoPath("user4", "repo5"))
		_, err = db.GetEngine(ctx).Exec("UPDATE `repository` SET trashed_unix = ? WHERE id = 5", int64(timeutil.TimeStampNow()))
		require.NoError(t, err)
	})

	t.Run("the move itself checks the claim before moving a file", func(t *testing.T) {
		stale := trashRepoByID(t, 5)
		stale.TrashedUnix++ // what the caller saw is not what is in the database
		user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
		require.ErrorIs(t, repo_service.MoveTrashedRepository(ctx, admin, user4, stale, "moved"), repo_service.ErrTrashConflict)
		assert.DirExists(t, repo_model.RepoPath("org3", "repo5"))
		assert.NoDirExists(t, repo_model.RepoPath("user4", "repo5"))
	})

	t.Run("restore won: the purge refuses and nothing is deleted", func(t *testing.T) {
		require.NoError(t, trash_service.RestoreRepo(ctx, admin, 5, trash_service.RestoreOptions{NewOwner: "user4", NewName: "moved"}))
		require.ErrorIs(t, trash_service.Purge(ctx, admin, 5), trash_service.ErrTrashConflict)
		assert.DirExists(t, repo_model.RepoPath("user4", "moved"))
		assert.NoDirExists(t, repo_model.RepoPath("org3", "repo5"))
		repo := trashRepoByID(t, 5)
		assert.Equal(t, "user4", repo.OwnerName)
		assert.False(t, repo.IsTrashed())
	})

	t.Run("purge after a rename deletes the directory the database names", func(t *testing.T) {
		require.NoError(t, repo_service.DeleteRepository(ctx, admin, trashRepoByID(t, 5), false))
		require.NoError(t, trash_service.Purge(ctx, admin, 5))
		assert.NoDirExists(t, repo_model.RepoPath("user4", "moved"))
		assert.NoDirExists(t, repo_model.RepoPath("org3", "repo5"))
	})
}

// AC16: the service path every deletion goes through (settings, admin UI, API and CLI call user_service.DeleteUser).
func TestTrashUserDeleteService(t *testing.T) {
	defer prepareTrash(t)()
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: trashUserID})
	require.NoError(t, user_service.DeleteUser(t.Context(), user, true))
	assert.True(t, trashedAccount(t, trashUserID).IsTrashed())
	for _, id := range trashUserRepoIDs {
		assert.True(t, trashRepoByID(t, id).IsTrashed())
	}
	// deleting the tombstone again changes nothing
	require.Error(t, user_service.DeleteUser(t.Context(), trashedAccount(t, trashUserID), false))
}
