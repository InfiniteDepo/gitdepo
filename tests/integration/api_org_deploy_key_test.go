// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"forgejo.org/models"
	asymkey_model "forgejo.org/models/asymkey"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The /orgs/{org}/keys API. org3 is owned by user2 and has repo3, repo5 and repo21; org17 owns big_test_private_4.
func TestAPIOrgDeployKey(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := t.Context()
	const keysURL = "/api/v1/orgs/org3/keys"
	writeScope := []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteOrganization}
	owner := getUserToken(t, "user2", writeScope...)

	create := func(t *testing.T, token string, opt api.CreateOrgDeployKeyOption, status int) *api.OrgDeployKey {
		t.Helper()
		if opt.Key == "" {
			opt.Key = newOrgDeployKeyContent(t)
		}
		resp := MakeRequest(t, NewRequestWithJSON(t, "POST", keysURL, opt).AddTokenAuth(token), status)
		if status != http.StatusCreated {
			return nil
		}
		var key api.OrgDeployKey
		DecodeJSON(t, resp, &key)
		return &key
	}
	count := func() int { return unittest.GetCount(t, &asymkey_model.OrgDeployKey{OrgID: 3}) }
	selection := func(t *testing.T, id int64) []int64 {
		t.Helper()
		ids, err := asymkey_model.GetOrgDeployKeyRepoIDs(ctx, []int64{id})
		require.NoError(t, err)
		return ids[id]
	}

	t.Run("create, get, list", func(t *testing.T) {
		all := create(t, owner, api.CreateOrgDeployKeyOption{Title: " all ", AllRepositories: true}, http.StatusCreated)
		assert.Equal(t, "all", all.Title)
		assert.True(t, all.AllRepositories)
		assert.False(t, all.ReadOnly)
		assert.Equal(t, fmt.Sprintf("%sapi/v1/orgs/org3/keys/%d", setting.AppURL, all.ID), all.URL)
		assert.Nil(t, all.LastUsed)
		assert.NotEmpty(t, all.Key)

		expires := time.Now().AddDate(0, 1, 0)
		selected := create(t, owner, api.CreateOrgDeployKeyOption{Title: "selected", ReadOnly: true, Repositories: []string{"repo3", "repo21"}, ExpiresAt: &expires}, http.StatusCreated)
		assert.False(t, selected.AllRepositories)
		assert.True(t, selected.ReadOnly)
		assert.NotNil(t, selected.Expires)
		assert.ElementsMatch(t, []int64{3, 32}, selection(t, selected.ID))

		resp := MakeRequest(t, NewRequest(t, "GET", keysURL).AddTokenAuth(owner), http.StatusOK)
		var keys []*api.OrgDeployKey
		DecodeJSON(t, resp, &keys)
		assert.Len(t, keys, 2)
		assert.Equal(t, "2", resp.Header().Get("X-Total-Count"))

		resp = MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/%d", keysURL, selected.ID)).AddTokenAuth(owner), http.StatusOK)
		var key api.OrgDeployKey
		DecodeJSON(t, resp, &key)
		assert.Equal(t, selected.Fingerprint, key.Fingerprint)

		resp = MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/%d/repos", keysURL, selected.ID)).AddTokenAuth(owner), http.StatusOK)
		var repos []*api.Repository
		DecodeJSON(t, resp, &repos)
		require.Len(t, repos, 2)
		assert.Equal(t, "repo21", repos[0].Name)
		assert.Equal(t, "repo3", repos[1].Name)
	})

	t.Run("create refused", func(t *testing.T) {
		before := count()
		past := time.Now().AddDate(0, 0, -2)
		userKey := unittest.AssertExistsAndLoadBean(t, &asymkey_model.PublicKey{ID: 1})
		for name, opt := range map[string]api.CreateOrgDeployKeyOption{
			"no repositories":         {Title: "none"},
			"another org's repo":      {Title: "other", Repositories: []string{"big_test_private_4"}},
			"unknown repo":            {Title: "unknown", Repositories: []string{"nope"}},
			"all and repositories":    {Title: "both", AllRepositories: true, Repositories: []string{"repo3"}},
			"expiry in the past":      {Title: "past", AllRepositories: true, ExpiresAt: &past},
			"name used":               {Title: "all", AllRepositories: true},
			"user key":                {Title: "user", AllRepositories: true, Key: userKey.Content},
			"not a key":               {Title: "garbage", AllRepositories: true, Key: "ssh-ed25519 garbage"},
			"title too long":          {Title: fmt.Sprintf("%051d", 0), AllRepositories: true},
			"another org's repo also": {Title: "mixed", Repositories: []string{"repo3", "big_test_private_4"}},
		} {
			create(t, owner, opt, http.StatusUnprocessableEntity)
			assert.Equal(t, before, count(), name)
		}
		// a trashed repository is not a repository of the organization any more
		trashed := createOrgDeployKeyRepo(t, "api-dk-trashed")
		require.NoError(t, repo_service.TrashRepository(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), trashed))
		create(t, owner, api.CreateOrgDeployKeyOption{Title: "trashed", Repositories: []string{"api-dk-trashed"}}, http.StatusUnprocessableEntity)
		// at most 1000 distinct names
		create(t, owner, api.CreateOrgDeployKeyOption{Title: "many", Repositories: orgDeployKeyRepoNames(1001)}, http.StatusUnprocessableEntity)
		assert.Equal(t, before, count())
	})

	all := unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{OrgID: 3, Name: "all"})
	selected := unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{OrgID: 3, Name: "selected"})
	other, err := asymkey_model.AddOrgDeployKey(ctx, 17, 0, "org17", newOrgDeployKeyContent(t), true, false, []int64{24}, 0)
	require.NoError(t, err)

	t.Run("permissions", func(t *testing.T) {
		// a team with administrator access that isn't the owners team
		adminTeam := &organization.Team{OrgID: 3, LowerName: "dk-admins", Name: "dk-admins", AccessMode: perm.AccessModeAdmin, IncludesAllRepositories: true}
		require.NoError(t, models.NewTeam(ctx, adminTeam))
		require.NoError(t, models.AddTeamMemberByCooptation(ctx, adminTeam, 5, 2))

		keyURL := fmt.Sprintf("%s/%d", keysURL, all.ID)
		requests := func(token string) map[string]*RequestWrapper {
			return map[string]*RequestWrapper{
				"list":   NewRequest(t, "GET", keysURL).AddTokenAuth(token),
				"get":    NewRequest(t, "GET", keyURL).AddTokenAuth(token),
				"create": NewRequestWithJSON(t, "POST", keysURL, api.CreateOrgDeployKeyOption{Title: "intruder", Key: newOrgDeployKeyContent(t), AllRepositories: true}).AddTokenAuth(token),
				"edit":   NewRequestWithJSON(t, "PATCH", fmt.Sprintf("%s/%d", keysURL, selected.ID), api.EditOrgDeployKeyOption{AllRepositories: orgDeployKeyTrue()}).AddTokenAuth(token),
				"delete": NewRequest(t, "DELETE", keyURL).AddTokenAuth(token),
				"repos":  NewRequest(t, "GET", keyURL+"/repos").AddTokenAuth(token),
				"add":    NewRequest(t, "PUT", fmt.Sprintf("%s/%d/repos/repo5", keysURL, selected.ID)).AddTokenAuth(token),
				"remove": NewRequest(t, "DELETE", fmt.Sprintf("%s/%d/repos/repo3", keysURL, selected.ID)).AddTokenAuth(token),
			}
		}
		check := func(t *testing.T, who, token string, status int) {
			t.Helper()
			for name, req := range requests(token) {
				resp := MakeRequest(t, req, NoExpectedStatus)
				assert.Equal(t, status, resp.Code, "%s %s", who, name)
			}
		}
		for user, status := range map[string]int{
			"user4": http.StatusForbidden, // member of team1
			"user5": http.StatusForbidden, // team with administrator access
			"user8": http.StatusForbidden, // outsider of a public organization
		} {
			check(t, user, getUserToken(t, user, writeScope...), status)
		}
		check(t, "anonymous", "", http.StatusUnauthorized)

		// a token with the read scope reads, never writes
		read := getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization)
		MakeRequest(t, NewRequest(t, "GET", keysURL).AddTokenAuth(read), http.StatusOK)
		MakeRequest(t, NewRequestWithJSON(t, "POST", keysURL, api.CreateOrgDeployKeyOption{Title: "read", Key: newOrgDeployKeyContent(t), AllRepositories: true}).AddTokenAuth(read), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", keysURL, all.ID)).AddTokenAuth(read), http.StatusForbidden)
		// a token without the organization scope, a public-only token
		MakeRequest(t, NewRequest(t, "GET", keysURL).AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "GET", keysURL).AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopePublicOnly)), http.StatusForbidden)

		// a site admin can, through the API like on the web
		admin := getUserToken(t, "user1", writeScope...)
		MakeRequest(t, NewRequest(t, "GET", keysURL).AddTokenAuth(admin), http.StatusOK)
		byAdmin := create(t, admin, api.CreateOrgDeployKeyOption{Title: "admin", Repositories: []string{"repo3"}}, http.StatusCreated)
		adminURL := fmt.Sprintf("%s/%d", keysURL, byAdmin.ID)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", adminURL, api.EditOrgDeployKeyOption{Repositories: &[]string{"repo5"}}).AddTokenAuth(admin), http.StatusOK)
		assert.Equal(t, []int64{5}, selection(t, byAdmin.ID))
		MakeRequest(t, NewRequest(t, "DELETE", adminURL).AddTokenAuth(admin), http.StatusNoContent)

		// a token limited to specific repositories, even one of the organization's
		repoOnly := createFineGrainedRepoAccessToken(t, "user2", writeScope, []int64{3})
		check(t, "repo-only token", repoOnly, http.StatusForbidden)

		// an outsider of a private organization doesn't learn it exists
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/privated_org/keys").AddTokenAuth(getUserToken(t, "user8", writeScope...)), http.StatusNotFound)

		assert.Equal(t, 2, count())
		assert.ElementsMatch(t, []int64{3, 32}, selection(t, selected.ID))
	})

	t.Run("keys and repositories of another organization", func(t *testing.T) {
		otherURL := fmt.Sprintf("%s/%d", keysURL, other.ID)
		MakeRequest(t, NewRequest(t, "GET", otherURL).AddTokenAuth(owner), http.StatusNotFound)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", otherURL, api.EditOrgDeployKeyOption{AllRepositories: orgDeployKeyTrue()}).AddTokenAuth(owner), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", otherURL+"/repos").AddTokenAuth(owner), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "PUT", otherURL+"/repos/repo3").AddTokenAuth(owner), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "DELETE", otherURL+"/repos/big_test_private_4").AddTokenAuth(owner), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "DELETE", otherURL).AddTokenAuth(owner), http.StatusNotFound)
		key := unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: other.ID})
		assert.False(t, key.IncludesAllRepos)
		assert.Equal(t, []int64{24}, selection(t, other.ID))

		// a repository of another organization can't be named under this one
		MakeRequest(t, NewRequest(t, "PUT", fmt.Sprintf("%s/%d/repos/big_test_private_4", keysURL, selected.ID)).AddTokenAuth(owner), http.StatusNotFound)
		assert.ElementsMatch(t, []int64{3, 32}, selection(t, selected.ID))
	})

	t.Run("edit", func(t *testing.T) {
		keyURL := fmt.Sprintf("%s/%d", keysURL, selected.ID)
		patch := func(t *testing.T, opt any, status int) {
			t.Helper()
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", keyURL, opt).AddTokenAuth(owner), status)
		}
		patch(t, map[string]any{}, http.StatusUnprocessableEntity)
		patch(t, api.EditOrgDeployKeyOption{AllRepositories: orgDeployKeyTrue(), Repositories: &[]string{"repo3"}}, http.StatusUnprocessableEntity)
		patch(t, api.EditOrgDeployKeyOption{Repositories: &[]string{}}, http.StatusUnprocessableEntity)
		patch(t, api.EditOrgDeployKeyOption{Repositories: &[]string{"big_test_private_4"}}, http.StatusUnprocessableEntity)
		assert.ElementsMatch(t, []int64{3, 32}, selection(t, selected.ID))

		patch(t, api.EditOrgDeployKeyOption{Repositories: &[]string{"repo5"}}, http.StatusOK)
		assert.Equal(t, []int64{5}, selection(t, selected.ID))
		// names are deduplicated, case-insensitively, before the cap
		patch(t, api.EditOrgDeployKeyOption{Repositories: &[]string{"repo5", "Repo5", "REPO5"}}, http.StatusOK)
		assert.Equal(t, []int64{5}, selection(t, selected.ID))
		many := append(orgDeployKeyRepoNames(1000), "repo5")
		patch(t, api.EditOrgDeployKeyOption{Repositories: &many}, http.StatusUnprocessableEntity)
		assert.Equal(t, []int64{5}, selection(t, selected.ID))
		_, extra := private.ServCommand(ctx, selected.KeyID, "org3", "repo3", perm.AccessModeRead, "127.0.0.1", "git-upload-pack", "")
		assert.Equal(t, http.StatusNotFound, extra.StatusCode, "repo3 is no longer covered")

		// switch to all repositories and back to the kept selection
		patch(t, api.EditOrgDeployKeyOption{AllRepositories: orgDeployKeyTrue()}, http.StatusOK)
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: selected.ID}).IncludesAllRepos)
		f := false
		patch(t, api.EditOrgDeployKeyOption{AllRepositories: &f}, http.StatusOK)
		assert.False(t, unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: selected.ID}).IncludesAllRepos)
		assert.Equal(t, []int64{5}, selection(t, selected.ID))

		// a key without a selection can't go back to "selected"
		patch2 := NewRequestWithJSON(t, "PATCH", fmt.Sprintf("%s/%d", keysURL, all.ID), api.EditOrgDeployKeyOption{AllRepositories: &f}).AddTokenAuth(owner)
		MakeRequest(t, patch2, http.StatusUnprocessableEntity)
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: all.ID}).IncludesAllRepos)
	})

	t.Run("repository sub-routes", func(t *testing.T) {
		reposURL := fmt.Sprintf("%s/%d/repos", keysURL, selected.ID)
		MakeRequest(t, NewRequest(t, "PUT", reposURL+"/repo3").AddTokenAuth(owner), http.StatusNoContent)
		MakeRequest(t, NewRequest(t, "PUT", reposURL+"/repo3").AddTokenAuth(owner), http.StatusNoContent) // already selected
		assert.ElementsMatch(t, []int64{3, 5}, selection(t, selected.ID))

		// one row at a time: removing repo3, then adding repo21 doesn't bring repo3 back
		MakeRequest(t, NewRequest(t, "DELETE", reposURL+"/repo3").AddTokenAuth(owner), http.StatusNoContent)
		MakeRequest(t, NewRequest(t, "PUT", reposURL+"/repo21").AddTokenAuth(owner), http.StatusNoContent)
		assert.ElementsMatch(t, []int64{5, 32}, selection(t, selected.ID))

		MakeRequest(t, NewRequest(t, "DELETE", reposURL+"/repo3").AddTokenAuth(owner), http.StatusNotFound) // not selected
		MakeRequest(t, NewRequest(t, "DELETE", reposURL+"/nope").AddTokenAuth(owner), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "DELETE", reposURL+"/repo21").AddTokenAuth(owner), http.StatusNoContent)
		MakeRequest(t, NewRequest(t, "DELETE", reposURL+"/repo5").AddTokenAuth(owner), http.StatusUnprocessableEntity) // the last one
		assert.Equal(t, []int64{5}, selection(t, selected.ID))

		// a key for all repositories has no selection to change
		allRepos := fmt.Sprintf("%s/%d/repos", keysURL, all.ID)
		MakeRequest(t, NewRequest(t, "PUT", allRepos+"/repo3").AddTokenAuth(owner), http.StatusUnprocessableEntity)
		MakeRequest(t, NewRequest(t, "DELETE", allRepos+"/repo3").AddTokenAuth(owner), http.StatusUnprocessableEntity)
		resp := MakeRequest(t, NewRequest(t, "GET", allRepos).AddTokenAuth(owner), http.StatusOK)
		assert.JSONEq(t, "[]", resp.Body.String())

		// a trashed repository is left out of the list
		trashed := createOrgDeployKeyRepo(t, "api-dk-listed")
		MakeRequest(t, NewRequest(t, "PUT", reposURL+"/api-dk-listed").AddTokenAuth(owner), http.StatusNoContent)
		require.NoError(t, repo_service.TrashRepository(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), trashed))
		resp = MakeRequest(t, NewRequest(t, "GET", reposURL+"?page=0&limit=10").AddTokenAuth(owner), http.StatusOK)
		var repos []*api.Repository
		DecodeJSON(t, resp, &repos)
		require.Len(t, repos, 1)
		assert.Equal(t, "repo5", repos[0].Name)
	})

	t.Run("removing a repository drops the key from its rules", func(t *testing.T) {
		writeKey := create(t, owner, api.CreateOrgDeployKeyOption{Title: "write", Repositories: []string{"repo3", "repo5"}}, http.StatusCreated)
		repo3 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
		require.NoError(t, git_model.UpdateProtectBranch(ctx, repo3, &git_model.ProtectedBranch{RepoID: 3, RuleName: "api-dk"},
			git_model.WhitelistOptions{DeployKeyIDs: []int64{writeKey.KeyID}}))
		rule := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{RepoID: 3, RuleName: "api-dk"})
		require.Equal(t, []int64{writeKey.KeyID}, rule.WhitelistDeployKeyIDs)

		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d/repos/repo3", keysURL, writeKey.ID)).AddTokenAuth(owner), http.StatusNoContent)
		assert.Empty(t, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: rule.ID}).WhitelistDeployKeyIDs)

		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", keysURL, writeKey.ID)).AddTokenAuth(owner), http.StatusNoContent)
		unittest.AssertNotExistsBean(t, &asymkey_model.OrgDeployKey{ID: writeKey.ID})
		unittest.AssertNotExistsBean(t, &asymkey_model.OrgDeployKeyRepo{OrgDeployKeyID: writeKey.ID})
		unittest.AssertNotExistsBean(t, &asymkey_model.PublicKey{ID: writeKey.KeyID})
	})

	t.Run("expiry policy", func(t *testing.T) {
		defer test.MockVariableValue(&setting.DeployKeyExpiry, setting.CredentialExpiryPolicy{Required: true, MaxLifetimeDays: 365})()
		admin := getUserToken(t, "user1", writeScope...)
		before := count()
		past := time.Now().AddDate(0, 0, -1)
		tooLate := time.Now().AddDate(0, 0, 366)
		// site admins aren't exempt: a "keys as code" job calls the API with a site admin token
		for who, token := range map[string]string{"owner": owner, "site admin": admin} {
			for name, expires := range map[string]*time.Time{"missing": nil, "past": &past, "beyond the maximum lifetime": &tooLate} {
				create(t, token, api.CreateOrgDeployKeyOption{Title: "expiry", AllRepositories: true, ExpiresAt: expires}, http.StatusUnprocessableEntity)
				assert.Equal(t, before, count(), "%s: %s", who, name)
			}
		}
		inPolicy := time.Now().AddDate(0, 0, 364)
		key := create(t, admin, api.CreateOrgDeployKeyOption{Title: "expiry", Repositories: []string{"repo3"}, ExpiresAt: &inPolicy}, http.StatusCreated)
		stored := unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: key.ID}).ExpiresUnix
		assert.Equal(t, inPolicy.Unix(), int64(stored))

		// PATCH can't extend or remove the expiry: the field isn't editable
		keyURL := fmt.Sprintf("%s/%d", keysURL, key.ID)
		for _, token := range []string{owner, admin} {
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", keyURL, map[string]any{"expires_at": tooLate}).AddTokenAuth(token), http.StatusUnprocessableEntity)
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", keyURL, map[string]any{"expires_at": nil}).AddTokenAuth(token), http.StatusUnprocessableEntity)
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", keyURL, map[string]any{"expires_at": tooLate, "repositories": []string{"repo5"}}).AddTokenAuth(token), http.StatusOK)
			assert.Equal(t, stored, unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: key.ID}).ExpiresUnix)
		}
		MakeRequest(t, NewRequest(t, "DELETE", keyURL).AddTokenAuth(owner), http.StatusNoContent)
	})

	t.Run("read-only maintenance", func(t *testing.T) {
		before := count()
		defer setMaintenance(t, setting.MaintenanceReadOnly, time.Now().Add(time.Hour))()
		MakeRequest(t, NewRequest(t, "GET", keysURL).AddTokenAuth(owner), http.StatusOK)
		create(t, owner, api.CreateOrgDeployKeyOption{Title: "maintenance", AllRepositories: true}, http.StatusServiceUnavailable)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", keysURL, all.ID)).AddTokenAuth(owner), http.StatusServiceUnavailable)
		assert.Equal(t, before, count())
	})

	t.Run("archived organization", func(t *testing.T) {
		org := &organization.Organization{Name: "api-dk-archived"}
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		require.NoError(t, organization.CreateOrganization(ctx, org, user2))
		repo, err := repo_service.CreateRepositoryDirectly(ctx, user2, org.AsUser(), repo_service.CreateRepoOptions{Name: "kept"})
		require.NoError(t, err)
		_, err = repo_service.CreateRepositoryDirectly(ctx, user2, org.AsUser(), repo_service.CreateRepoOptions{Name: "other"})
		require.NoError(t, err)
		key, err := asymkey_model.AddOrgDeployKey(ctx, org.ID, 0, "archived", newOrgDeployKeyContent(t), true, false, []int64{repo.ID}, 0)
		require.NoError(t, err)
		require.NoError(t, org_service.ArchiveOrganization(ctx, org, user2, false))

		base := "/api/v1/orgs/api-dk-archived/keys"
		keyURL := fmt.Sprintf("%s/%d", base, key.ID)
		MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(owner), http.StatusOK)
		for _, req := range []*RequestWrapper{
			NewRequestWithJSON(t, "POST", base, api.CreateOrgDeployKeyOption{Title: "new", Key: newOrgDeployKeyContent(t), AllRepositories: true}),
			NewRequestWithJSON(t, "PATCH", keyURL, api.EditOrgDeployKeyOption{AllRepositories: orgDeployKeyTrue()}),
			NewRequest(t, "PUT", keyURL+"/repos/other"),
			NewRequest(t, "DELETE", keyURL+"/repos/kept"),
			NewRequest(t, "DELETE", keyURL),
		} {
			MakeRequest(t, req.AddTokenAuth(owner), http.StatusForbidden)
		}
		assert.Equal(t, []int64{repo.ID}, selection(t, key.ID))
		assert.False(t, unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: key.ID}).IncludesAllRepos)
	})

	t.Run("an owner blocked by the two-factor requirement", func(t *testing.T) {
		_, err := db.Exec(ctx, "UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
		require.NoError(t, err)
		defer func() {
			_, err := db.Exec(ctx, "UPDATE `user` SET require_two_factor = ? WHERE id = 3", false)
			require.NoError(t, err)
		}()
		before := count()
		MakeRequest(t, NewRequest(t, "GET", keysURL).AddTokenAuth(owner), http.StatusForbidden)
		create(t, owner, api.CreateOrgDeployKeyOption{Title: "blocked", AllRepositories: true}, http.StatusForbidden)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("%s/%d", keysURL, selected.ID), api.EditOrgDeployKeyOption{AllRepositories: orgDeployKeyTrue()}).AddTokenAuth(owner), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", keysURL, all.ID)).AddTokenAuth(owner), http.StatusForbidden)
		unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: all.ID})
		assert.False(t, unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: selected.ID}).IncludesAllRepos)
		assert.Equal(t, before, count())
	})
}

// orgDeployKeyRepoNames returns n distinct repository names.
func orgDeployKeyRepoNames(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("repo-%d", i)
	}
	return names
}

func orgDeployKeyTrue() *bool {
	b := true
	return &b
}
