// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	asymkey_model "forgejo.org/models/asymkey"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createProjectForKeys(t *testing.T, orgID int64, name string) *repo_model.RepoGroup {
	t.Helper()
	group, err := repo_model.CreateRepoGroup(db.DefaultContext, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: orgID}), name, "")
	require.NoError(t, err)
	return group
}

func addProjectDeployKey(t *testing.T, orgID, groupID int64, name string, readOnly bool, expires timeutil.TimeStamp) *asymkey_model.OrgDeployKey {
	t.Helper()
	key, err := asymkey_model.AddOrgDeployKey(db.DefaultContext, orgID, groupID, name, newOrgDeployKeyContent(t), readOnly, false, nil, expires)
	require.NoError(t, err)
	return key
}

func moveRepoForKeys(t *testing.T, repoID, groupID int64) {
	t.Helper()
	// repo3 has a pending transfer in the fixtures, which refuses a move
	_, err := db.Exec(db.DefaultContext, "DELETE FROM repo_transfer WHERE repo_id = ?", repoID)
	require.NoError(t, err)
	_, err = db.Exec(db.DefaultContext, "UPDATE repository SET status = ? WHERE id = ?", repo_model.RepositoryReady, repoID)
	require.NoError(t, err)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID})
	require.NoError(t, repo_service.MoveRepository(db.DefaultContext, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}), repo, groupID))
}

// The /orgs/{org}/projects/{id}/keys API. org3 is owned by user2.
func TestAPIProjectDeployKey(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := t.Context()
	pay, web := createProjectForKeys(t, 3, "pay"), createProjectForKeys(t, 3, "web")
	foreign := createProjectForKeys(t, 17, "foreign")
	keysURL := fmt.Sprintf("/api/v1/orgs/org3/projects/%d/keys", pay.ID)
	writeScope := []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteOrganization}
	owner := getUserToken(t, "user2", writeScope...)
	admin := getUserToken(t, "user1", writeScope...)

	create := func(t *testing.T, token, url string, opt api.CreateKeyOption, status int) *api.OrgDeployKey {
		t.Helper()
		if opt.Key == "" {
			opt.Key = newOrgDeployKeyContent(t)
		}
		resp := MakeRequest(t, NewRequestWithJSON(t, "POST", url, opt).AddTokenAuth(token), status)
		if status != http.StatusCreated {
			return nil
		}
		var key api.OrgDeployKey
		DecodeJSON(t, resp, &key)
		return &key
	}
	count := func() int { return unittest.GetCount(t, &asymkey_model.OrgDeployKey{OrgID: 3}) }
	orgKey := addOrgDeployKey(t, 3, "org", newOrgDeployKeyContent(t), true)
	webKey := addProjectDeployKey(t, 3, web.ID, "web", true, 0)

	key := create(t, owner, keysURL, api.CreateKeyOption{Title: " ci ", ReadOnly: true}, http.StatusCreated)
	t.Run("create, get, list", func(t *testing.T) {
		assert.Equal(t, "ci", key.Title)
		assert.Equal(t, pay.ID, key.ProjectID)
		assert.False(t, key.AllRepositories)
		assert.True(t, key.ReadOnly)
		assert.Equal(t, fmt.Sprintf("%sapi/v1/orgs/org3/projects/%d/keys/%d", setting.AppURL, pay.ID, key.ID), key.URL)
		stored := unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: key.ID})
		assert.Equal(t, pay.ID, stored.GroupID)
		assert.False(t, stored.IncludesAllRepos)

		resp := MakeRequest(t, NewRequest(t, "GET", keysURL).AddTokenAuth(owner), http.StatusOK)
		var keys []*api.OrgDeployKey
		DecodeJSON(t, resp, &keys)
		require.Len(t, keys, 1, "the project's keys only")
		assert.Equal(t, key.ID, keys[0].ID)

		resp = MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/%d", keysURL, key.ID)).AddTokenAuth(owner), http.StatusOK)
		var got api.OrgDeployKey
		DecodeJSON(t, resp, &got)
		assert.Equal(t, key.Fingerprint, got.Fingerprint)

		// the organization's list doesn't show project keys
		resp = MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/keys").AddTokenAuth(owner), http.StatusOK)
		keys = nil
		DecodeJSON(t, resp, &keys)
		require.Len(t, keys, 1)
		assert.Equal(t, orgKey.ID, keys[0].ID)
		assert.Zero(t, keys[0].ProjectID)
	})

	t.Run("keys of other levels are not found", func(t *testing.T) {
		before := count()
		// the organization's and another project's keys through this project
		for _, id := range []int64{orgKey.ID, webKey.ID} {
			MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/%d", keysURL, id)).AddTokenAuth(owner), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", keysURL, id)).AddTokenAuth(owner), http.StatusNotFound)
		}
		// a project key through every organization endpoint
		orgURL := fmt.Sprintf("/api/v1/orgs/org3/keys/%d", key.ID)
		for _, req := range []*RequestWrapper{
			NewRequest(t, "GET", orgURL),
			NewRequestWithJSON(t, "PATCH", orgURL, api.EditOrgDeployKeyOption{AllRepositories: orgDeployKeyTrue()}),
			NewRequestWithJSON(t, "PATCH", orgURL, api.EditOrgDeployKeyOption{Repositories: &[]string{"repo3"}}),
			NewRequest(t, "GET", orgURL+"/repos"),
			NewRequest(t, "PUT", orgURL+"/repos/repo3"),
			NewRequest(t, "DELETE", orgURL+"/repos/repo3"),
			NewRequest(t, "DELETE", orgURL),
		} {
			MakeRequest(t, req.AddTokenAuth(owner), http.StatusNotFound)
		}
		stored := unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: key.ID})
		assert.False(t, stored.IncludesAllRepos)
		assert.Equal(t, pay.ID, stored.GroupID)
		unittest.AssertNotExistsBean(t, &asymkey_model.OrgDeployKeyRepo{OrgDeployKeyID: key.ID})
		// another organization's project, an unknown one
		for _, id := range []int64{foreign.ID, 999999} {
			url := fmt.Sprintf("/api/v1/orgs/org3/projects/%d/keys", id)
			MakeRequest(t, NewRequest(t, "GET", url).AddTokenAuth(owner), http.StatusNotFound)
			create(t, owner, url, api.CreateKeyOption{Title: "x"}, http.StatusNotFound)
		}
		assert.Equal(t, before, count())
	})

	t.Run("permissions", func(t *testing.T) {
		before := count()
		keyURL := fmt.Sprintf("%s/%d", keysURL, key.ID)
		requests := func(token string) map[string]*RequestWrapper {
			return map[string]*RequestWrapper{
				"list":   NewRequest(t, "GET", keysURL).AddTokenAuth(token),
				"get":    NewRequest(t, "GET", keyURL).AddTokenAuth(token),
				"create": NewRequestWithJSON(t, "POST", keysURL, api.CreateKeyOption{Title: "intruder", Key: newOrgDeployKeyContent(t)}).AddTokenAuth(token),
				"delete": NewRequest(t, "DELETE", keyURL).AddTokenAuth(token),
			}
		}
		check := func(t *testing.T, who, token string, status int) {
			t.Helper()
			for name, req := range requests(token) {
				resp := MakeRequest(t, req, NoExpectedStatus)
				assert.Equal(t, status, resp.Code, "%s %s", who, name)
			}
		}
		check(t, "member", getUserToken(t, "user4", writeScope...), http.StatusForbidden)
		check(t, "outsider", getUserToken(t, "user8", writeScope...), http.StatusForbidden)
		check(t, "anonymous", "", http.StatusUnauthorized)
		check(t, "repo-only token", createFineGrainedRepoAccessToken(t, "user2", writeScope, []int64{3}), http.StatusForbidden)
		check(t, "public-only token", getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopePublicOnly), http.StatusForbidden)
		check(t, "no organization scope", getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository), http.StatusForbidden)

		read := getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization)
		MakeRequest(t, NewRequest(t, "GET", keysURL).AddTokenAuth(read), http.StatusOK)
		create(t, read, keysURL, api.CreateKeyOption{Title: "read"}, http.StatusForbidden)
		assert.Equal(t, before, count())

		byAdmin := create(t, admin, keysURL, api.CreateKeyOption{Title: "admin"}, http.StatusCreated)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", keysURL, byAdmin.ID)).AddTokenAuth(admin), http.StatusNoContent)
		assert.Equal(t, before, count())
	})

	t.Run("expiry policy", func(t *testing.T) {
		defer test.MockVariableValue(&setting.DeployKeyExpiry, setting.CredentialExpiryPolicy{Required: true, MaxLifetimeDays: 365})()
		before := count()
		past := time.Now().AddDate(0, 0, -1)
		tooLate := time.Now().AddDate(0, 0, 366)
		for who, token := range map[string]string{"owner": owner, "site admin": admin} {
			for name, expires := range map[string]*time.Time{"missing": nil, "past": &past, "beyond the maximum lifetime": &tooLate} {
				create(t, token, keysURL, api.CreateKeyOption{Title: "expiry", ExpiresAt: expires}, http.StatusUnprocessableEntity)
				assert.Equal(t, before, count(), "%s: %s", who, name)
			}
		}
		inPolicy := time.Now().AddDate(0, 0, 364)
		k := create(t, admin, keysURL, api.CreateKeyOption{Title: "expiry", ExpiresAt: &inPolicy}, http.StatusCreated)
		assert.Equal(t, inPolicy.Unix(), int64(unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: k.ID}).ExpiresUnix))
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", keysURL, k.ID)).AddTokenAuth(owner), http.StatusNoContent)
	})

	t.Run("read-only maintenance", func(t *testing.T) {
		before := count()
		defer setMaintenance(t, setting.MaintenanceReadOnly, time.Now().Add(time.Hour))()
		MakeRequest(t, NewRequest(t, "GET", keysURL).AddTokenAuth(owner), http.StatusOK)
		create(t, owner, keysURL, api.CreateKeyOption{Title: "maintenance"}, http.StatusServiceUnavailable)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", keysURL, key.ID)).AddTokenAuth(owner), http.StatusServiceUnavailable)
		assert.Equal(t, before, count())
	})

	t.Run("archived organization", func(t *testing.T) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		org := &organization.Organization{Name: "api-pdk-archived"}
		require.NoError(t, organization.CreateOrganization(ctx, org, user2))
		group := createProjectForKeys(t, org.ID, "kept")
		k := addProjectDeployKey(t, org.ID, group.ID, "archived", true, 0)
		require.NoError(t, org_service.ArchiveOrganization(ctx, org, user2, false))

		base := fmt.Sprintf("/api/v1/orgs/api-pdk-archived/projects/%d/keys", group.ID)
		MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(owner), http.StatusOK)
		create(t, owner, base, api.CreateKeyOption{Title: "new"}, http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", base, k.ID)).AddTokenAuth(owner), http.StatusForbidden)
		unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: k.ID})
	})

	t.Run("delete", func(t *testing.T) {
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", keysURL, key.ID)).AddTokenAuth(owner), http.StatusNoContent)
		unittest.AssertNotExistsBean(t, &asymkey_model.OrgDeployKey{ID: key.ID})
		unittest.AssertNotExistsBean(t, &asymkey_model.PublicKey{ID: key.KeyID})
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", keysURL, key.ID)).AddTokenAuth(owner), http.StatusNotFound)
	})
}

// A site-admin token creates repository deploy keys through every mount of the repository routes, under the expiry
// policy: the "keys as code" path for repositories in projects.
func TestAPIRepoDeployKeySiteAdminExpiry(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.DeployKeyExpiry, setting.CredentialExpiryPolicy{Required: true, MaxLifetimeDays: 365})()
	pay := createProjectForKeys(t, 3, "pay")
	moveRepoForKeys(t, 3, pay.ID)
	admin := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteRepository)
	past := time.Now().AddDate(0, 0, -1)
	tooLate := time.Now().AddDate(0, 0, 366)
	inPolicy := time.Now().AddDate(0, 0, 364)

	for repoID, url := range map[int64]string{
		32: "/api/v1/repos/org3/repo21/keys",
		3:  "/api/v1/repos/org3/pay/repo3/-/keys",
	} {
		for _, u := range []string{url, fmt.Sprintf("/api/v1/repositories/%d/keys", repoID)} {
			before := unittest.GetCount(t, &asymkey_model.DeployKey{RepoID: repoID})
			for name, expires := range map[string]*time.Time{"missing": nil, "past": &past, "beyond the maximum lifetime": &tooLate} {
				req := NewRequestWithJSON(t, "POST", u, api.CreateKeyOption{Title: "ci", Key: newOrgDeployKeyContent(t), ExpiresAt: expires}).AddTokenAuth(admin)
				MakeRequest(t, req, http.StatusUnprocessableEntity)
				assert.Equal(t, before, unittest.GetCount(t, &asymkey_model.DeployKey{RepoID: repoID}), "%s: %s", u, name)
			}
			req := NewRequestWithJSON(t, "POST", u, api.CreateKeyOption{Title: "ci " + u, Key: newOrgDeployKeyContent(t), ExpiresAt: &inPolicy}).AddTokenAuth(admin)
			var created api.DeployKey
			DecodeJSON(t, MakeRequest(t, req, http.StatusCreated), &created)
			assert.Equal(t, before+1, unittest.GetCount(t, &asymkey_model.DeployKey{RepoID: repoID}), u)

			// list, get and delete through the same mount
			var keys []*api.DeployKey
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", u).AddTokenAuth(admin), http.StatusOK), &keys)
			assert.True(t, slices.ContainsFunc(keys, func(k *api.DeployKey) bool { return k.ID == created.ID }), u)
			keyURL := fmt.Sprintf("%s/%d", u, created.ID)
			MakeRequest(t, NewRequest(t, "GET", keyURL).AddTokenAuth(admin), http.StatusOK)
			MakeRequest(t, NewRequest(t, "DELETE", keyURL).AddTokenAuth(admin), http.StatusNoContent)
			assert.Equal(t, before, unittest.GetCount(t, &asymkey_model.DeployKey{RepoID: repoID}), u)
		}
	}
}

// Project deploy keys through the serv command and the pre-receive hook, called the way the SSH command calls them.
// org3's repo3 is moved into the project "pay"; repo21 stays at the root.
func TestProjectDeployKeyPush(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := t.Context()
	pay, web := createProjectForKeys(t, 3, "pay"), createProjectForKeys(t, 3, "web")
	moveRepoForKeys(t, 3, pay.ID)
	writeKey := addProjectDeployKey(t, 3, pay.ID, "pay write", false, 0)
	readKey := addProjectDeployKey(t, 3, pay.ID, "pay read", true, 0)
	expired := addProjectDeployKey(t, 3, pay.ID, "pay expired", false, timeutil.TimeStampNow()-10)
	webKey := addProjectDeployKey(t, 3, web.ID, "web write", false, 0)
	foreign := createProjectForKeys(t, 17, "foreign")
	foreignKey := addProjectDeployKey(t, 17, foreign.ID, "foreign write", false, 0)

	serv := func(keyID int64, owner, repo string, mode perm.AccessMode) private.ResponseExtra {
		verb := "git-upload-pack"
		if mode == perm.AccessModeWrite {
			verb = "git-receive-pack"
		}
		_, extra := private.ServCommand(ctx, keyID, owner, repo, mode, "127.0.0.1", verb, "")
		return extra
	}

	t.Run("serv", func(t *testing.T) {
		require.NoError(t, serv(writeKey.KeyID, "org3", "pay/repo3", perm.AccessModeWrite).Error)
		require.NoError(t, serv(readKey.KeyID, "org3", "pay/repo3", perm.AccessModeRead).Error)
		assert.Equal(t, http.StatusUnauthorized, serv(readKey.KeyID, "org3", "pay/repo3", perm.AccessModeWrite).StatusCode, "a read key can't push")
		assert.Equal(t, http.StatusUnauthorized, serv(expired.KeyID, "org3", "pay/repo3", perm.AccessModeRead).StatusCode, "an expired key never authenticates")
		// a root repository, another project's key, another organization's key with any group_id
		assert.Equal(t, http.StatusNotFound, serv(writeKey.KeyID, "org3", "repo21", perm.AccessModeRead).StatusCode)
		assert.Equal(t, http.StatusNotFound, serv(webKey.KeyID, "org3", "pay/repo3", perm.AccessModeRead).StatusCode)
		assert.Equal(t, http.StatusNotFound, serv(foreignKey.KeyID, "org3", "pay/repo3", perm.AccessModeRead).StatusCode)
		assert.Equal(t, http.StatusNotFound, serv(writeKey.KeyID, "org17", "big_test_private_4", perm.AccessModeRead).StatusCode)
	})

	emptyID := git.Sha1ObjectFormat.EmptyObjectID().String()
	const initCommit = "2a47ca4b614a9f5a43abbd5ad851a54a616ffee6"
	hook := func(opts private.HookOptions, ref git.RefName) private.ResponseExtra {
		opts.OldCommitIDs = []string{emptyID}
		opts.NewCommitIDs = []string{initCommit}
		opts.RefFullNames = []git.RefName{ref}
		opts.UserID = 3 // the owner, as serv sets it: never what decides
		return private.HookPreReceive(ctx, 3, opts)
	}

	t.Run("hook", func(t *testing.T) {
		require.NoError(t, hook(private.HookOptions{DeployKeyKeyID: writeKey.KeyID}, git.RefNameFromBranch("free")).Error)
		for name, keyID := range map[string]int64{"read": readKey.KeyID, "expired": expired.KeyID, "other project": webKey.KeyID, "other org": foreignKey.KeyID} {
			assert.Equal(t, http.StatusForbidden, hook(private.HookOptions{DeployKeyKeyID: keyID}, git.RefNameFromBranch("free")).StatusCode, name)
		}
		// no user permissions: the key can't change settings by push option
		extra := hook(private.HookOptions{DeployKeyKeyID: writeKey.KeyID, GitPushOptions: map[string]string{"repo.private": "false"}}, git.RefNameFromBranch("free"))
		assert.Equal(t, http.StatusForbidden, extra.StatusCode)
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}).IsPrivate)
	})

	t.Run("last used", func(t *testing.T) {
		_, err := db.Exec(ctx, "UPDATE org_deploy_key SET updated_unix = 1 WHERE id = ?", writeKey.ID)
		require.NoError(t, err)
		require.NoError(t, private.UpdatePublicKeyInRepo(ctx, writeKey.KeyID, 3))
		assert.Greater(t, unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: writeKey.ID}).UpdatedUnix, timeutil.TimeStamp(1))
	})

	t.Run("protection lists and moves", func(t *testing.T) {
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
		require.NoError(t, git_model.UpdateProtectBranch(ctx, repo, &git_model.ProtectedBranch{RepoID: 3, RuleName: "keys"},
			git_model.WhitelistOptions{DeployKeyIDs: []int64{writeKey.KeyID, readKey.KeyID, webKey.KeyID}}))
		rule := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{RepoID: 3, RuleName: "keys"})
		assert.Equal(t, []int64{writeKey.KeyID}, rule.WhitelistDeployKeyIDs, "only the project's write keys")

		moveRepoForKeys(t, 3, web.ID)
		assert.Empty(t, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: rule.ID}).WhitelistDeployKeyIDs)
		assert.Equal(t, http.StatusNotFound, serv(writeKey.KeyID, "org3", "web/repo3", perm.AccessModeRead).StatusCode)
		require.NoError(t, serv(webKey.KeyID, "org3", "web/repo3", perm.AccessModeWrite).Error)

		moveRepoForKeys(t, 3, 0)
		assert.Equal(t, http.StatusNotFound, serv(webKey.KeyID, "org3", "repo3", perm.AccessModeRead).StatusCode)
	})
}

// Project settings > Deploy keys: acting owners only, adding a key for the project, deleting it, the organization's
// page and the project's page never showing each other's keys, and the protection pickers of a repository in it.
func TestProjectDeployKeyWeb(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	pay, web := createProjectForKeys(t, 3, "pay"), createProjectForKeys(t, 3, "web")
	moveRepoForKeys(t, 3, pay.ID)
	owner := loginUser(t, "user2")
	keysURL := fmt.Sprintf("/org/org3/groups/%d/settings/keys", pay.ID)
	orgKey := addOrgDeployKey(t, 3, "org only key", newOrgDeployKeyContent(t), false)
	webKey := addProjectDeployKey(t, 3, web.ID, "web key", false, 0)

	t.Run("only acting owners", func(t *testing.T) {
		owner.MakeRequest(t, NewRequest(t, "GET", keysURL), http.StatusOK)
		loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", keysURL), http.StatusOK) // site admin
		for _, name := range []string{"user4", "user5"} {                                  // member of a team, outsider
			session := loginUser(t, name)
			session.MakeRequest(t, NewRequest(t, "GET", keysURL), http.StatusNotFound)
			session.MakeRequest(t, NewRequestWithValues(t, "POST", keysURL, map[string]string{"title": "intruder", "content": newOrgDeployKeyContent(t)}), http.StatusNotFound)
		}
		owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/groups/999999/settings/keys"), http.StatusNotFound)
		assert.Zero(t, unittest.GetCount(t, &asymkey_model.OrgDeployKey{OrgID: 3, GroupID: pay.ID}))
	})

	owner.MakeRequest(t, NewRequestWithValues(t, "POST", keysURL, map[string]string{"title": "pay write", "content": newOrgDeployKeyContent(t), "is_writable": "1", "scope": "all"}), http.StatusSeeOther)
	key := unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{OrgID: 3, GroupID: pay.ID, Name: "pay write"})

	t.Run("add", func(t *testing.T) {
		assert.False(t, key.IncludesAllRepos, "a scope field is ignored")
		assert.Equal(t, perm.AccessModeWrite, key.Mode)
		unittest.AssertNotExistsBean(t, &asymkey_model.OrgDeployKeyRepo{OrgDeployKeyID: key.ID})

		page := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", keysURL), http.StatusOK).Body)
		text := page.Find(".org-setting-content").Text()
		assert.Contains(t, text, "pay write")
		assert.NotContains(t, text, "org only key")
		assert.NotContains(t, text, "web key")
		assert.Zero(t, page.Find(`input[name="scope"]`).Length())

		page = NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/keys"), http.StatusOK).Body)
		assert.NotContains(t, page.Find(".org-setting-content").Text(), "pay write")
	})

	t.Run("pickers and repository page", func(t *testing.T) {
		for _, url := range []string{"/org3/pay/repo3/-/settings/branches/edit", "/org3/pay/repo3/-/settings/tags"} {
			page := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK).Body)
			assert.NotZero(t, page.Find(fmt.Sprintf(`.item[data-value="%d"]`, key.KeyID)).Length(), url)
			assert.Zero(t, page.Find(fmt.Sprintf(`.item[data-value="%d"]`, webKey.KeyID)).Length(), url)
		}
		page := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org3/pay/repo3/-/settings/keys"), http.StatusOK).Body)
		assert.Contains(t, page.Find("#org-deploy-keys").Text(), "pay write")
		assert.Equal(t, 1, page.Find(`#org-deploy-keys a[href$="/org3/pay/-/settings/keys"]`).Length(), "the project key links to the project's page")
	})

	add := func(t *testing.T, url string, values map[string]string, status int) {
		t.Helper()
		values["content"] = newOrgDeployKeyContent(t)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", url, values), status)
	}
	count := func() int { return unittest.GetCount(t, &asymkey_model.OrgDeployKey{OrgID: 3, GroupID: pay.ID}) }

	t.Run("expiry policy", func(t *testing.T) {
		defer test.MockVariableValue(&setting.DeployKeyExpiry, setting.CredentialExpiryPolicy{Required: true, MaxLifetimeDays: 365})()
		before := count()
		for name, date := range map[string]string{"missing": "", "past": "2020-01-01", "beyond the maximum lifetime": time.Now().AddDate(0, 0, 367).Format("2006-01-02")} {
			add(t, keysURL, map[string]string{"title": "expiry", "expires_at": date}, http.StatusOK)
			assert.Equal(t, before, count(), name)
		}
		add(t, keysURL, map[string]string{"title": "expiry", "expires_at": time.Now().AddDate(0, 0, 300).Format("2006-01-02")}, http.StatusSeeOther)
		k := unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{OrgID: 3, GroupID: pay.ID, Name: "expiry"})
		assert.NotZero(t, k.ExpiresUnix)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", keysURL+"/delete", map[string]string{"id": fmt.Sprint(k.ID)}), http.StatusOK)
	})

	t.Run("read-only maintenance", func(t *testing.T) {
		before := count()
		defer setMaintenance(t, setting.MaintenanceReadOnly, time.Now().Add(time.Hour))()
		owner.MakeRequest(t, NewRequest(t, "GET", keysURL), http.StatusOK)
		add(t, keysURL, map[string]string{"title": "maintenance"}, http.StatusSeeOther)
		assertMaintenanceFlash(t, owner)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", keysURL+"/delete", map[string]string{"id": fmt.Sprint(key.ID)}), http.StatusSeeOther)
		assert.Equal(t, before, count())
	})

	t.Run("archived organization", func(t *testing.T) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		org := &organization.Organization{Name: "pdk-archived"}
		require.NoError(t, organization.CreateOrganization(t.Context(), org, user2))
		group := createProjectForKeys(t, org.ID, "kept")
		k := addProjectDeployKey(t, org.ID, group.ID, "archived", true, 0)
		require.NoError(t, org_service.ArchiveOrganization(t.Context(), org, user2, false))

		base := fmt.Sprintf("/org/pdk-archived/groups/%d/settings/keys", group.ID)
		owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK)
		add(t, base, map[string]string{"title": "new"}, http.StatusForbidden)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/delete", map[string]string{"id": fmt.Sprint(k.ID)}), http.StatusForbidden)
		assert.Equal(t, 1, unittest.GetCount(t, &asymkey_model.OrgDeployKey{OrgID: org.ID}))
	})

	t.Run("organization in the trash", func(t *testing.T) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		org := &organization.Organization{Name: "pdk-trashed"}
		require.NoError(t, organization.CreateOrganization(t.Context(), org, user2))
		group := createProjectForKeys(t, org.ID, "kept")
		k := addProjectDeployKey(t, org.ID, group.ID, "trashed", true, 0)
		_, err := db.Exec(t.Context(), "UPDATE `user` SET trashed_unix = 1 WHERE id = ?", org.ID)
		require.NoError(t, err)

		base := fmt.Sprintf("/org/pdk-trashed/groups/%d/settings/keys", group.ID)
		owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusNotFound)
		add(t, base, map[string]string{"title": "new"}, http.StatusNotFound)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/delete", map[string]string{"id": fmt.Sprint(k.ID)}), http.StatusNotFound)

		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization)
		apiBase := fmt.Sprintf("/api/v1/orgs/pdk-trashed/projects/%d/keys", group.ID)
		MakeRequest(t, NewRequest(t, "GET", apiBase).AddTokenAuth(token), http.StatusNotFound)
		MakeRequest(t, NewRequestWithJSON(t, "POST", apiBase, api.CreateKeyOption{Title: "new", Key: newOrgDeployKeyContent(t)}).AddTokenAuth(token), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", apiBase, k.ID)).AddTokenAuth(token), http.StatusNotFound)
		assert.Equal(t, 1, unittest.GetCount(t, &asymkey_model.OrgDeployKey{OrgID: org.ID}))
	})

	t.Run("keys of other levels are not deleted here", func(t *testing.T) {
		for _, id := range []int64{orgKey.ID, webKey.ID} {
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", keysURL+"/delete", map[string]string{"id": fmt.Sprint(id)}), http.StatusNotFound)
			unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: id})
		}
		// nor a project key on the organization's page
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/keys/delete", map[string]string{"id": fmt.Sprint(key.ID)}), http.StatusNotFound)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/org/org3/settings/keys/%d/repos", key.ID), map[string]string{"scope": "all"}), http.StatusNotFound)
		assert.False(t, unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: key.ID}).IncludesAllRepos)
	})

	t.Run("delete", func(t *testing.T) {
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", keysURL+"/delete", map[string]string{"id": fmt.Sprint(key.ID)}), http.StatusOK)
		unittest.AssertNotExistsBean(t, &asymkey_model.OrgDeployKey{ID: key.ID})
		unittest.AssertNotExistsBean(t, &asymkey_model.PublicKey{ID: key.KeyID})
	})
}
