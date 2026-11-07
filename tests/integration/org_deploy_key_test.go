// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"

	asymkey_model "forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
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
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func newOrgDeployKeyContent(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

func addOrgDeployKey(t *testing.T, orgID int64, name, content string, readOnly bool, repoIDs ...int64) *asymkey_model.OrgDeployKey {
	t.Helper()
	key, err := asymkey_model.AddOrgDeployKey(db.DefaultContext, orgID, 0, name, content, readOnly, len(repoIDs) == 0, repoIDs, 0)
	require.NoError(t, err)
	return key
}

// Org deploy keys through the serv command and the pre-receive hook, called the way the SSH command calls them,
// so this runs without an ssh client. org3 owns repo3 (private), repo5 (private mirror) and repo21 (ID 32, public).
func TestOrgDeployKey(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := t.Context()

	readContent := newOrgDeployKeyContent(t)
	readKey := addOrgDeployKey(t, 3, "org read", readContent, true)                     // all repositories
	writeKey := addOrgDeployKey(t, 3, "org write", newOrgDeployKeyContent(t), false, 3) // repo3 only

	serv := func(keyID int64, owner, repo string, mode perm.AccessMode, verb string) (*private.ServCommandResults, private.ResponseExtra) {
		return private.ServCommand(ctx, keyID, owner, repo, mode, "127.0.0.1", verb, "")
	}
	upload := func(keyID int64, owner, repo string) (*private.ServCommandResults, private.ResponseExtra) {
		return serv(keyID, owner, repo, perm.AccessModeRead, "git-upload-pack")
	}
	receive := func(keyID int64, owner, repo string) (*private.ServCommandResults, private.ResponseExtra) {
		return serv(keyID, owner, repo, perm.AccessModeWrite, "git-receive-pack")
	}

	t.Run("serv", func(t *testing.T) {
		results, extra := upload(readKey.KeyID, "org3", "repo3")
		require.NoError(t, extra.Error)
		assert.Equal(t, int64(3), results.UserID) // recorded as the owner
		assert.Equal(t, readKey.KeyID, results.DeployKeyKeyID)
		assert.Equal(t, "org read", results.KeyName)

		_, extra = receive(readKey.KeyID, "org3", "repo3")
		assert.Equal(t, http.StatusUnauthorized, extra.StatusCode, "a read key can't push")

		results, extra = receive(writeKey.KeyID, "org3", "repo3")
		require.NoError(t, extra.Error)
		assert.Equal(t, writeKey.KeyID, results.DeployKeyKeyID)

		// not selected, another org's repository, a user's repository
		_, extra = upload(writeKey.KeyID, "org3", "repo5")
		assert.Equal(t, http.StatusNotFound, extra.StatusCode)
		_, extra = upload(readKey.KeyID, "org17", "big_test_private_4")
		assert.Equal(t, http.StatusNotFound, extra.StatusCode)
		_, extra = upload(readKey.KeyID, "user2", "repo2")
		assert.Equal(t, http.StatusNotFound, extra.StatusCode)
	})

	t.Run("higher mode wins", func(t *testing.T) {
		// the read org key is also a write deploy key of repo3
		_, err := asymkey_model.AddDeployKey(ctx, 3, "repo write", readContent, false, 0)
		require.NoError(t, err)
		results, extra := receive(readKey.KeyID, "org3", "repo3")
		require.NoError(t, extra.Error)
		assert.Equal(t, "repo write", results.KeyName)
		_, extra = receive(readKey.KeyID, "org3", "repo21")
		assert.Equal(t, http.StatusUnauthorized, extra.StatusCode)
	})

	t.Run("archived repository is read-only", func(t *testing.T) {
		_, err := db.Exec(ctx, "UPDATE repository SET is_archived = ? WHERE id = 3", true)
		require.NoError(t, err)
		_, extra := receive(writeKey.KeyID, "org3", "repo3")
		assert.Equal(t, http.StatusUnauthorized, extra.StatusCode)
		assert.Contains(t, extra.UserMsg, "is archived")
		_, extra = upload(writeKey.KeyID, "org3", "repo3")
		require.NoError(t, extra.Error)
		_, err = db.Exec(ctx, "UPDATE repository SET is_archived = ? WHERE id = 3", false)
		require.NoError(t, err)
	})

	t.Run("last used", func(t *testing.T) {
		_, err := db.Exec(ctx, "UPDATE org_deploy_key SET updated_unix = 1 WHERE id = ?", writeKey.ID)
		require.NoError(t, err)
		require.NoError(t, private.UpdatePublicKeyInRepo(ctx, writeKey.KeyID, 3))
		key := unittest.AssertExistsAndLoadBean(t, &asymkey_model.OrgDeployKey{ID: writeKey.ID})
		assert.Greater(t, key.UpdatedUnix, timeutil.TimeStamp(1))
	})

	emptyID := git.Sha1ObjectFormat.EmptyObjectID().String()
	const master, initCommit = "d22b4d4daa5be07329fcef6ed458f00cf3392da0", "2a47ca4b614a9f5a43abbd5ad851a54a616ffee6"
	hook := func(opts private.HookOptions, oldCommitID, newCommitID string, ref git.RefName) private.ResponseExtra {
		opts.OldCommitIDs = []string{oldCommitID}
		opts.NewCommitIDs = []string{newCommitID}
		opts.RefFullNames = []git.RefName{ref}
		opts.UserID = 3 // the owner, as serv sets it: never what decides
		return private.HookPreReceive(ctx, repoIDByName(t, "org3", "repo3"), opts)
	}
	keyHook := func(keyID int64, oldCommitID, newCommitID string, ref git.RefName) private.ResponseExtra {
		return hook(private.HookOptions{DeployKeyKeyID: keyID}, oldCommitID, newCommitID, ref)
	}

	// readKey is also a write deploy key of repo3 since "higher mode wins": the hook tests use their own read key
	hookRead := addOrgDeployKey(t, 3, "hook read", newOrgDeployKeyContent(t), true)

	t.Run("hook refuses keys without write access", func(t *testing.T) {
		// a read org key, a read repo key, an expired write org key: the owner's permission never counts
		repoRead, err := asymkey_model.AddDeployKey(ctx, 3, "repo read", newOrgDeployKeyContent(t), true, 0)
		require.NoError(t, err)
		expired, err := asymkey_model.AddOrgDeployKey(ctx, 3, 0, "expired", newOrgDeployKeyContent(t), false, true, nil, timeutil.TimeStampNow()-10)
		require.NoError(t, err)
		for name, keyID := range map[string]int64{"org read": hookRead.KeyID, "repo read": repoRead.KeyID, "expired": expired.KeyID, "unknown": 999999} {
			extra := keyHook(keyID, emptyID, initCommit, git.RefNameFromBranch("free"))
			assert.Equal(t, http.StatusForbidden, extra.StatusCode, name)
		}
		// the same for a tag, and when the key would change settings
		extra := keyHook(hookRead.KeyID, emptyID, initCommit, git.RefNameFromTag("free"))
		assert.Equal(t, http.StatusForbidden, extra.StatusCode)
		extra = hook(private.HookOptions{DeployKeyKeyID: expired.KeyID, GitPushOptions: map[string]string{"repo.private": "false"}}, emptyID, initCommit, git.RefNameFromBranch("free"))
		assert.Equal(t, http.StatusForbidden, extra.StatusCode)

		// a key of org3 that no longer covers the repository at push time
		other := addOrgDeployKey(t, 3, "repo5 only", newOrgDeployKeyContent(t), false, 5)
		extra = keyHook(other.KeyID, emptyID, initCommit, git.RefNameFromBranch("free"))
		assert.Equal(t, http.StatusForbidden, extra.StatusCode)
	})

	t.Run("hook allows a write org key on an unprotected branch", func(t *testing.T) {
		require.NoError(t, keyHook(writeKey.KeyID, emptyID, initCommit, git.RefNameFromBranch("free")).Error)
	})

	t.Run("branch protection", func(t *testing.T) {
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
		rule := &git_model.ProtectedBranch{RepoID: 3, RuleName: "org-key*", CanPush: true, EnableWhitelist: true}
		require.NoError(t, git_model.UpdateProtectBranch(ctx, repo, rule, git_model.WhitelistOptions{}))

		extra := keyHook(writeKey.KeyID, emptyID, initCommit, git.RefNameFromBranch("org-key-1"))
		assert.Equal(t, http.StatusForbidden, extra.StatusCode)
		assert.Contains(t, extra.UserMsg, "Not allowed to push to protected branch")

		// the read key isn't accepted in a list, the write key is
		require.NoError(t, git_model.UpdateProtectBranch(ctx, repo, rule, git_model.WhitelistOptions{
			DeployKeyIDs:          []int64{writeKey.KeyID, hookRead.KeyID},
			DeleteDeployKeyIDs:    []int64{writeKey.KeyID},
			ForcePushDeployKeyIDs: []int64{writeKey.KeyID},
		}))
		rule = unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: rule.ID})
		assert.Equal(t, []int64{writeKey.KeyID}, rule.WhitelistDeployKeyIDs)
		require.NoError(t, keyHook(writeKey.KeyID, emptyID, initCommit, git.RefNameFromBranch("org-key-1")).Error)
		require.NoError(t, keyHook(writeKey.KeyID, master, initCommit, git.RefNameFromBranch("org-key-1")).Error) // force push
		require.NoError(t, keyHook(writeKey.KeyID, master, emptyID, git.RefNameFromBranch("org-key-1")).Error)    // delete

		// another write key: refused by each list
		all := addOrgDeployKey(t, 3, "all write", newOrgDeployKeyContent(t), false)
		extra = keyHook(all.KeyID, emptyID, initCommit, git.RefNameFromBranch("org-key-1"))
		assert.Contains(t, extra.UserMsg, "Not allowed to push to protected branch")
		extra = keyHook(all.KeyID, master, initCommit, git.RefNameFromBranch("org-key-1"))
		assert.Contains(t, extra.UserMsg, "protected from force push")
		extra = keyHook(all.KeyID, master, emptyID, git.RefNameFromBranch("org-key-1"))
		assert.Contains(t, extra.UserMsg, "protected from deletion")

		// "all deploy keys with write access" covers org keys too
		rule.WhitelistDeployKeys = true
		require.NoError(t, git_model.UpdateProtectBranch(ctx, repo, rule, git_model.WhitelistOptions{DeployKeyIDs: rule.WhitelistDeployKeyIDs}))
		require.NoError(t, keyHook(all.KeyID, emptyID, initCommit, git.RefNameFromBranch("org-key-1")).Error)
	})

	t.Run("tag protection", func(t *testing.T) {
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
		ids, err := git_model.FilterWriteDeployKeyIDs(ctx, repo, []int64{writeKey.KeyID, hookRead.KeyID})
		require.NoError(t, err)
		require.NoError(t, git_model.InsertProtectedTag(ctx, &git_model.ProtectedTag{RepoID: 3, NamePattern: "v*", AllowlistDeployKeyIDs: ids}))

		require.NoError(t, keyHook(writeKey.KeyID, emptyID, initCommit, git.RefNameFromTag("v1")).Error)
		other := addOrgDeployKey(t, 3, "tag write", newOrgDeployKeyContent(t), false, 3)
		extra := keyHook(other.KeyID, emptyID, initCommit, git.RefNameFromTag("v1"))
		assert.Equal(t, http.StatusForbidden, extra.StatusCode)
	})

	t.Run("repository moved to another owner", func(t *testing.T) {
		admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		org17 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 17})
		repo, err := repo_service.CreateRepositoryDirectly(ctx, admin, org3, repo_service.CreateRepoOptions{Name: "moving"})
		require.NoError(t, err)
		// created after readKey (all repositories): covered at once
		_, extra := upload(readKey.KeyID, "org3", "moving")
		require.NoError(t, extra.Error)
		movingKey := addOrgDeployKey(t, 3, "moving", newOrgDeployKeyContent(t), false, repo.ID)
		require.NoError(t, git_model.UpdateProtectBranch(ctx, repo, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "main"},
			git_model.WhitelistOptions{DeployKeyIDs: []int64{movingKey.KeyID, readKey.KeyID}}))
		rule := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "main"})
		require.Equal(t, []int64{movingKey.KeyID}, rule.WhitelistDeployKeyIDs)
		_, extra = receive(movingKey.KeyID, "org3", "moving")
		require.NoError(t, extra.Error)

		require.NoError(t, repo_service.TransferOwnership(audit_model.WithSystem(ctx, "test"), admin, org17, repo, nil))

		_, extra = upload(movingKey.KeyID, "org17", "moving")
		assert.Equal(t, http.StatusNotFound, extra.StatusCode)
		_, extra = upload(readKey.KeyID, "org17", "moving")
		assert.Equal(t, http.StatusNotFound, extra.StatusCode)
		unittest.AssertNotExistsBean(t, &asymkey_model.OrgDeployKeyRepo{RepoID: repo.ID})
		assert.Empty(t, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: rule.ID}).WhitelistDeployKeyIDs)

		// moving it back doesn't restore the selection
		repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
		require.NoError(t, repo.LoadOwner(ctx))
		require.NoError(t, repo_service.TransferOwnership(audit_model.WithSystem(ctx, "test"), admin, org3, repo, nil))
		_, extra = upload(movingKey.KeyID, "org3", "moving")
		assert.Equal(t, http.StatusNotFound, extra.StatusCode)
		_, extra = upload(readKey.KeyID, "org3", "moving") // all repositories: covered again
		require.NoError(t, extra.Error)
	})

	t.Run("deleting the organization deletes its keys", func(t *testing.T) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		org := &organization.Organization{Name: "deploy-key-org"}
		require.NoError(t, organization.CreateOrganization(ctx, org, user2))
		repo, err := repo_service.CreateRepositoryDirectly(ctx, user2, org.AsUser(), repo_service.CreateRepoOptions{Name: "selected"})
		require.NoError(t, err)

		onlyOrg := addOrgDeployKey(t, org.ID, "only org", newOrgDeployKeyContent(t), true, repo.ID)
		sharedContent := newOrgDeployKeyContent(t)
		shared := addOrgDeployKey(t, org.ID, "shared", sharedContent, true)
		_, err = asymkey_model.AddDeployKey(ctx, 1, "shared", sharedContent, true, 0)
		require.NoError(t, err)

		// deleting the repository deletes its selections
		require.NoError(t, repo_service.DeleteRepositoryDirectly(ctx, repo.ID, repo_service.DeleteRepositoryOpts{}))
		unittest.AssertNotExistsBean(t, &asymkey_model.OrgDeployKeyRepo{RepoID: repo.ID})

		require.NoError(t, org_service.DeleteOrganization(ctx, org, false))
		unittest.AssertNotExistsBean(t, &asymkey_model.OrgDeployKey{OrgID: org.ID})
		unittest.AssertNotExistsBean(t, &asymkey_model.PublicKey{ID: onlyOrg.KeyID})
		unittest.AssertExistsAndLoadBean(t, &asymkey_model.PublicKey{ID: shared.KeyID}) // still a deploy key of repo1
	})
}

// Clone and push over SSH with organization deploy keys. Needs an ssh client, so it only runs in CI.
func TestOrgDeployKeySSH(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		req := NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", api.CreateRepoOption{Name: "org-deploy-key-ssh", AutoInit: true, Private: true}).AddTokenAuth(token)
		MakeRequest(t, req, http.StatusCreated)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: 3, LowerName: "org-deploy-key-ssh"})

		keys := map[string]*protectionTestDeployKey{}
		for _, name := range []string{"read", "write"} {
			withKeyFile(t, "org-"+name, func(keyFile string) {
				pubKey, err := os.ReadFile(keyFile + ".pub")
				require.NoError(t, err)
				key := addOrgDeployKey(t, 3, "ssh "+name, string(pubKey), name == "read", repo.ID)
				keys[name] = &protectionTestDeployKey{file: keyFile, keyID: key.KeyID}
			})
		}

		dstPath := t.TempDir()
		useDeployKey(t, keys["read"])
		t.Run("Clone", doGitClone(dstPath, createSSHUrl(fmt.Sprintf("org3/%s.git", repo.Name), u)))
		doAddChangesToCheckout(dstPath, "org-key.md")(t)

		_, err := doGitPushWithDeployKey(t, keys["read"], dstPath, "origin", repo.DefaultBranch)
		require.Error(t, err, "a read key can't push")
		_, err = doGitPushWithDeployKey(t, keys["write"], dstPath, "origin", repo.DefaultBranch)
		require.NoError(t, err)
	})
}
