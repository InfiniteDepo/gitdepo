// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"strings"
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
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"
	trash_service "forgejo.org/services/trash"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Org Settings > Deploy keys: who may use it, adding, changing the selection, deleting, and the read-only list on
// the repository page. org3 is owned by user2 and has repo3, repo5 and repo21 (ID 32); org17 owns repo 23.
func TestOrgDeployKeyWeb(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := t.Context()
	owner := loginUser(t, "user2")
	const keysURL = "/org/org3/settings/keys"

	add := func(t *testing.T, session *TestSession, values map[string]string, status int) {
		t.Helper()
		session.MakeRequest(t, NewRequestWithValues(t, "POST", keysURL, values), status)
	}
	keyForm := func(name, scope, repoIDs string) map[string]string {
		return map[string]string{"title": name, "content": newOrgDeployKeyContent(t), "is_writable": "1", "scope": scope, "repo_ids": repoIDs}
	}
	count := func() int { return unittest.GetCount(t, &asymkey_model.OrgDeployKey{OrgID: 3}) }

	t.Run("only acting owners", func(t *testing.T) {
		owner.MakeRequest(t, NewRequest(t, "GET", keysURL), http.StatusOK)
		loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", keysURL), http.StatusOK) // site admin
		for _, name := range []string{"user4", "user5"} {                                  // member of a team, outsider
			session := loginUser(t, name)
			session.MakeRequest(t, NewRequest(t, "GET", keysURL), http.StatusNotFound)
			add(t, session, keyForm("intruder", "all", ""), http.StatusNotFound)
		}
		MakeRequest(t, NewRequest(t, "GET", keysURL), http.StatusSeeOther) // sign in first
		assert.Zero(t, count())
	})

	t.Run("add", func(t *testing.T) {
		add(t, owner, keyForm("all write", "all", ""), http.StatusSeeOther)
		add(t, owner, keyForm("repo5 read", "selected", "5"), http.StatusSeeOther)
		all := unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{OrgID: 3, Name: "all write"})
		assert.True(t, all.IncludesAllRepos)
		assert.Equal(t, perm.AccessModeWrite, all.Mode)
		selected := unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{OrgID: 3, Name: "repo5 read"})
		assert.False(t, selected.IncludesAllRepos)
		unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKeyRepo{OrgDeployKeyID: selected.ID, RepoID: 5})

		page := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", keysURL), http.StatusOK).Body)
		assert.Contains(t, page.Find(".flex-list").Text(), "all write")
		assert.Contains(t, page.Find(".flex-list").Text(), "repo5")
	})

	t.Run("add refused", func(t *testing.T) {
		before := count()
		userKey := unittest.AssertExistsAndLoadBean(t, &asymkey_model.PublicKey{ID: 1})
		for name, values := range map[string]map[string]string{
			"no repositories":       keyForm("none", "selected", ""),
			"another org's repo":    keyForm("org17", "selected", "23"),
			"a user's repo":         keyForm("user2", "selected", "1"),
			"name used":             keyForm("all write", "all", ""),
			"user key":              {"title": "user", "content": userKey.Content, "scope": "all"},
			"expiry in the past":    {"title": "past", "content": newOrgDeployKeyContent(t), "scope": "all", "expires_at": time.Now().AddDate(0, 0, -2).Format("2006-01-02")},
			"name too long":         keyForm(strings.Repeat("n", 51), "all", ""),
			"not a public key":      {"title": "bad", "content": "ssh-ed25519 garbage", "scope": "all"},
			"unparsable repository": keyForm("garbage", "selected", "5,x"),
		} {
			req := NewRequestWithValues(t, "POST", keysURL, values)
			resp := owner.MakeRequest(t, req, NoExpectedStatus)
			assert.Contains(t, []int{http.StatusOK, http.StatusSeeOther}, resp.Code, name)
			assert.Equal(t, before, count(), name)
		}
		// the refused form is shown again, open, with what was entered
		page := NewHTMLParser(t, owner.MakeRequest(t, NewRequestWithValues(t, "POST", keysURL, keyForm("kept input", "selected", "")), http.StatusOK).Body)
		assert.False(t, page.Find("#add-deploy-key-panel").HasClass("tw-hidden"))
		assert.Equal(t, "kept input", page.Find(`#add-deploy-key-panel input[name="title"]`).AttrOr("value", ""))
		assert.Equal(t, 1, page.Find(`#add-deploy-key-panel input[name="scope"][value="selected"][checked]`).Length())

		// a trashed repository can't be selected either
		trashed := createOrgDeployKeyRepo(t, "dk-trashed")
		require.NoError(t, repo_service.TrashRepository(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), trashed))
		add(t, owner, keyForm("trashed", "selected", fmt.Sprint(trashed.ID)), http.StatusOK)
		assert.Equal(t, before, count())
	})

	allWrite := unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{OrgID: 3, Name: "all write"})
	other, err := asymkey_model.AddOrgDeployKey(ctx, 17, 0, "org17 key", newOrgDeployKeyContent(t), true, true, nil, 0)
	require.NoError(t, err)

	t.Run("change the selection", func(t *testing.T) {
		reposURL := fmt.Sprintf("%s/%d/repos", keysURL, allWrite.ID)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", reposURL, map[string]string{"scope": "selected", "repo_ids": "5"}), http.StatusSeeOther)
		_, extra := private.ServCommand(ctx, allWrite.KeyID, "org3", "repo3", perm.AccessModeRead, "127.0.0.1", "git-upload-pack", "")
		assert.Equal(t, http.StatusNotFound, extra.StatusCode, "repo3 is no longer covered")
		_, extra = private.ServCommand(ctx, allWrite.KeyID, "org3", "repo5", perm.AccessModeRead, "127.0.0.1", "git-upload-pack", "")
		require.NoError(t, extra.Error)

		// refused: nothing selected, another org's repository
		for _, values := range []map[string]string{{"scope": "selected"}, {"scope": "selected", "repo_ids": "23"}} {
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", reposURL, values), http.StatusSeeOther)
			ids, err := asymkey_model.GetOrgDeployKeyRepoIDs(ctx, []int64{allWrite.ID})
			require.NoError(t, err)
			assert.Equal(t, []int64{5}, ids[allWrite.ID])
		}
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", reposURL, map[string]string{"scope": "all"}), http.StatusSeeOther)
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: allWrite.ID}).IncludesAllRepos)
	})

	t.Run("keys of another organization", func(t *testing.T) {
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("%s/%d/repos", keysURL, other.ID), map[string]string{"scope": "selected", "repo_ids": "3"}), http.StatusNotFound)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", keysURL+"/delete", map[string]string{"id": fmt.Sprint(other.ID)}), http.StatusNotFound)
		key := unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: other.ID})
		assert.True(t, key.IncludesAllRepos)
		unittest.AssertNotExistsBean(t, &asymkey_model.OrgDeployKeyRepo{OrgDeployKeyID: other.ID})
	})

	t.Run("repository page", func(t *testing.T) {
		// a repository admin who isn't an owner of the organization
		token, adminPerm := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository), "admin"
		MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/repo3/collaborators/user5", api.AddCollaboratorOption{Permission: &adminPerm}).AddTokenAuth(token), http.StatusNoContent)

		for name, session := range map[string]*TestSession{"owner": owner, "repo admin": loginUser(t, "user5")} {
			page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/settings/keys"), http.StatusOK).Body)
			list := page.Find("#org-deploy-keys").Text()
			assert.Contains(t, list, "all write", name)
			assert.Contains(t, list, allWrite.Fingerprint, name)
			assert.NotContains(t, list, "repo5 read", name)
			assert.NotContains(t, list, "org17 key", name)
			assert.NotContains(t, page.Find(".repo-setting-content").Text(), "ssh-ed25519", name) // no key content
			assert.Equal(t, name == "owner", page.Find(`a[href$="/org/org3/settings/keys"]`).Length() == 1, name)
		}
	})

	t.Run("protection pickers offer write org keys", func(t *testing.T) {
		readKey, err := asymkey_model.AddOrgDeployKey(ctx, 3, 0, "all read", newOrgDeployKeyContent(t), true, true, nil, 0)
		require.NoError(t, err)
		for _, url := range []string{"/org3/repo3/settings/branches/edit", "/org3/repo3/settings/tags"} {
			page := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK).Body)
			assert.NotZero(t, page.Find(fmt.Sprintf(`.item[data-value="%d"]`, allWrite.KeyID)).Length(), url)
			assert.Zero(t, page.Find(fmt.Sprintf(`.item[data-value="%d"]`, readKey.KeyID)).Length(), url)
		}
	})

	t.Run("protection rules lose a deleted key, also in trashed repositories", func(t *testing.T) {
		kept := createOrgDeployKeyRepo(t, "dk-kept")
		trashed := createOrgDeployKeyRepo(t, "dk-protected")
		for _, repo := range []*repo_model.Repository{kept, trashed} {
			require.NoError(t, git_model.UpdateProtectBranch(ctx, repo, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "main"},
				git_model.WhitelistOptions{DeployKeyIDs: []int64{allWrite.KeyID}}))
		}
		// the same public key is also a write deploy key of dk-kept
		pkey := unittest.AssertExistsAndLoadBean(t, &asymkey_model.PublicKey{ID: allWrite.KeyID})
		_, err := asymkey_model.AddDeployKey(ctx, kept.ID, "own", pkey.Content, false, 0)
		require.NoError(t, err)
		require.NoError(t, repo_service.TrashRepository(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), trashed))

		owner.MakeRequest(t, NewRequestWithValues(t, "POST", keysURL+"/delete", map[string]string{"id": fmt.Sprint(allWrite.ID)}), http.StatusOK)
		unittest.AssertNotExistsBean(t, &asymkey_model.OrgDeployKey{ID: allWrite.ID})
		unittest.AssertExistsAndLoadBean(t, &asymkey_model.PublicKey{ID: allWrite.KeyID}) // still the deploy key of dk-kept

		require.NoError(t, trash_service.RestoreRepo(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}), trashed.ID, trash_service.RestoreOptions{}))
		assert.Empty(t, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{RepoID: trashed.ID, RuleName: "main"}).WhitelistDeployKeyIDs)
		assert.Equal(t, []int64{allWrite.KeyID}, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{RepoID: kept.ID, RuleName: "main"}).WhitelistDeployKeyIDs)

		selected := unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{OrgID: 3, Name: "repo5 read"})
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", keysURL+"/delete", map[string]string{"id": fmt.Sprint(selected.ID)}), http.StatusOK)
		unittest.AssertNotExistsBean(t, &asymkey_model.OrgDeployKey{ID: selected.ID})
		unittest.AssertNotExistsBean(t, &asymkey_model.OrgDeployKeyRepo{OrgDeployKeyID: selected.ID})
		unittest.AssertNotExistsBean(t, &asymkey_model.PublicKey{ID: selected.KeyID})
	})

	t.Run("dropping a repository from the selection drops the key from its rules", func(t *testing.T) {
		key, err := asymkey_model.AddOrgDeployKey(ctx, 3, 0, "narrowed", newOrgDeployKeyContent(t), false, true, nil, 0)
		require.NoError(t, err)
		repo := createOrgDeployKeyRepo(t, "dk-narrowed")
		require.NoError(t, git_model.UpdateProtectBranch(ctx, repo, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "main"},
			git_model.WhitelistOptions{DeployKeyIDs: []int64{key.KeyID}}))
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("%s/%d/repos", keysURL, key.ID), map[string]string{"scope": "selected", "repo_ids": "3"}), http.StatusSeeOther)
		assert.Empty(t, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "main"}).WhitelistDeployKeyIDs)
	})

	t.Run("read-only maintenance", func(t *testing.T) {
		before := count()
		defer setMaintenance(t, setting.MaintenanceReadOnly, time.Now().Add(time.Hour))()
		owner.MakeRequest(t, NewRequest(t, "GET", keysURL), http.StatusOK)
		add(t, owner, keyForm("maintenance", "all", ""), http.StatusSeeOther)
		assertMaintenanceFlash(t, owner)
		assert.Equal(t, before, count())
	})

	t.Run("archived organization", func(t *testing.T) {
		org := &organization.Organization{Name: "dk-archived"}
		require.NoError(t, organization.CreateOrganization(ctx, org, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})))
		key, err := asymkey_model.AddOrgDeployKey(ctx, org.ID, 0, "archived", newOrgDeployKeyContent(t), true, true, nil, 0)
		require.NoError(t, err)
		require.NoError(t, org_service.ArchiveOrganization(ctx, org, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), false))

		base := "/org/dk-archived/settings/keys"
		owner.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", base, keyForm("new", "all", "")), http.StatusForbidden)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/delete", map[string]string{"id": fmt.Sprint(key.ID)}), http.StatusForbidden)
		unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: key.ID})
		assert.Equal(t, 1, unittest.GetCount(t, &asymkey_model.OrgDeployKey{OrgID: org.ID}))
	})

	t.Run("an owner blocked by the two-factor requirement", func(t *testing.T) {
		_, err := db.Exec(ctx, "UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
		require.NoError(t, err)
		defer func() {
			_, err := db.Exec(ctx, "UPDATE `user` SET require_two_factor = ? WHERE id = 3", false)
			require.NoError(t, err)
		}()
		// user2 has no second factor
		assert.NotEqual(t, http.StatusOK, owner.MakeRequest(t, NewRequest(t, "GET", keysURL), NoExpectedStatus).Code)
		before := count()
		resp := owner.MakeRequest(t, NewRequestWithValues(t, "POST", keysURL, keyForm("blocked", "all", "")), NoExpectedStatus)
		assert.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, resp.Code)
		assert.Equal(t, before, count())
	})
}

func createOrgDeployKeyRepo(t *testing.T, name string) *repo_model.Repository {
	t.Helper()
	repo, err := repo_service.CreateRepositoryDirectly(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}),
		unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}), repo_service.CreateRepoOptions{Name: name})
	require.NoError(t, err)
	return repo
}
