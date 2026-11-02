// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/perm"
	"forgejo.org/modules/git"
	"forgejo.org/modules/private"
	api "forgejo.org/modules/structs"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// branchPusher pushes to the test repository as one user or deploy key, over HTTP or SSH.
type branchPusher struct {
	remote  *url.URL
	keyFile string // SSH key, empty for HTTP
}

func (p branchPusher) push(t *testing.T, dstPath string, args ...string) (stderr string, err error) {
	t.Helper()
	if p.keyFile != "" {
		useDeployKey(t, &protectionTestDeployKey{file: p.keyFile})
	}
	_, stderr, err = git.NewCommand(git.DefaultContext, "push").AddDynamicArguments(p.remote.String()).
		AddArguments(git.ToTrustedCmdArgs(args)...).RunStdString(&git.RunOpts{Dir: dstPath})
	return stderr, err
}

func gitHead(t *testing.T, dstPath string) string {
	t.Helper()
	out, _, err := git.NewCommand(git.DefaultContext, "rev-parse", "HEAD").RunStdString(&git.RunOpts{Dir: dstPath})
	require.NoError(t, err)
	return strings.TrimSpace(out)
}

// commitOnBranch resets the local branch to start and adds a commit for each file.
func commitOnBranch(t *testing.T, dstPath, branch, start string, files ...string) {
	t.Helper()
	doGitCheckoutBranch(dstPath, "-B", branch, start)(t)
	for _, file := range files {
		doAddChangesToCheckout(dstPath, file)(t)
	}
}

// deleteForcePushRepo creates the repository user2/<reponame> with user4 as a write collaborator,
// the branch protection rules "master" and "release*", and three deploy keys. Both rules let
// user2 and the "listed" deploy key delete and force-push, and "release*" protects secret.txt.
func deleteForcePushRepo(t *testing.T, reponame string) (APITestContext, map[string]*protectionTestDeployKey) {
	t.Helper()
	owner := NewAPITestContext(t, "user2", reponame, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
	t.Run("CreateRepository", doAPICreateRepository(owner, nil, git.Sha1ObjectFormat))
	t.Run("AddCollaborator", doAPIAddCollaborator(owner, "user4", perm.AccessModeWrite))
	keys := createProtectionTestDeployKeys(t, owner)

	for _, rule := range []string{"master", "release*"} {
		req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/%s/%s/branch_protections", owner.Username, owner.Reponame), api.CreateBranchProtectionOption{
			RuleName:                       rule,
			EnablePush:                     true,
			ProtectedFilePatterns:          "secret.txt",
			DeleteAllowlistUsernames:       []string{"user2", "user5"}, // user5 can't write and is dropped
			DeleteAllowlistDeployKeyIDs:    []int64{keys["listed"].keyID, keys["readonly"].keyID, 999999},
			ForcePushAllowlistUsernames:    []string{"user2"},
			ForcePushAllowlistDeployKeyIDs: []int64{keys["listed"].keyID},
		}).AddTokenAuth(owner.Token)
		resp := MakeRequest(t, req, http.StatusCreated)
		var bp api.BranchProtection
		DecodeJSON(t, resp, &bp)
		assert.Equal(t, []string{"user2"}, bp.DeleteAllowlistUsernames)
		assert.Equal(t, []int64{keys["listed"].keyID}, bp.DeleteAllowlistDeployKeyIDs)
		assert.Equal(t, []string{"user2"}, bp.ForcePushAllowlistUsernames)
		assert.Equal(t, []int64{keys["listed"].keyID}, bp.ForcePushAllowlistDeployKeyIDs)
	}
	return owner, keys
}

func editReleaseProtection(t *testing.T, owner APITestContext, opts api.EditBranchProtectionOption) api.BranchProtection {
	t.Helper()
	req := NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/%s/%s/branch_protections/release*", owner.Username, owner.Reponame), opts).AddTokenAuth(owner.Token)
	resp := MakeRequest(t, req, http.StatusOK)
	var bp api.BranchProtection
	DecodeJSON(t, resp, &bp)
	return bp
}

// testDeleteForcePush checks that allowed may delete and force-push the protected branch,
// that refused may not, and that the other checks of the rule still apply.
func testDeleteForcePush(t *testing.T, owner APITestContext, dstPath, branch string, allowed, refused branchPusher) {
	commitOnBranch(t, dstPath, branch, "master", branch+"-1.txt")
	first := gitHead(t, dstPath)
	doAddChangesToCheckout(dstPath, branch+"-2.txt")(t)
	_, err := allowed.push(t, dstPath, branch)
	require.NoError(t, err)

	t.Run("ForcePushRefused", func(t *testing.T) {
		stderr, err := refused.push(t, dstPath, "--force", first+":refs/heads/"+branch)
		require.Error(t, err)
		assert.Contains(t, stderr, "protected from force push")
	})

	t.Run("ForcePushAllowed", func(t *testing.T) {
		_, err := allowed.push(t, dstPath, "--force", first+":refs/heads/"+branch)
		require.NoError(t, err)
	})

	t.Run("ForcePushStillChecksProtectedFiles", func(t *testing.T) {
		commitOnBranch(t, dstPath, branch, "master", "secret.txt")
		stderr, err := allowed.push(t, dstPath, "--force", branch)
		require.Error(t, err)
		assert.Contains(t, stderr, "protected from changing file secret.txt")
	})

	t.Run("ForcePushStillChecksPushAllowlist", func(t *testing.T) {
		enabled, disabled := true, false
		editReleaseProtection(t, owner, api.EditBranchProtectionOption{EnablePush: &enabled, EnablePushWhitelist: &enabled, PushWhitelistUsernames: []string{"user4"}})
		defer editReleaseProtection(t, owner, api.EditBranchProtectionOption{EnablePush: &enabled, EnablePushWhitelist: &disabled})

		commitOnBranch(t, dstPath, branch, "master", branch+"-3.txt")
		stderr, err := allowed.push(t, dstPath, "--force", branch)
		require.Error(t, err)
		assert.Contains(t, stderr, "Not allowed to push to protected branch "+branch)
	})

	t.Run("DeleteRefused", func(t *testing.T) {
		stderr, err := refused.push(t, dstPath, "--delete", branch)
		require.Error(t, err)
		assert.Contains(t, stderr, "protected from deletion")
	})

	t.Run("DeleteAllowed", func(t *testing.T) {
		_, err := allowed.push(t, dstPath, "--delete", branch)
		require.NoError(t, err)
	})

	t.Run("DefaultBranchCannotBeDeleted", func(t *testing.T) {
		stderr, err := allowed.push(t, dstPath, "--delete", "master")
		require.Error(t, err)
		assert.Contains(t, stderr, "default branch and cannot be deleted")
	})
}

func TestProtectedBranchDeleteForcePush(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		owner, keys := deleteForcePushRepo(t, "delete-force-push")
		repoURL := fmt.Sprintf("/api/v1/repos/%s/%s", owner.Username, owner.Reponame)

		httpURL := func(username string) *url.URL {
			userURL := *u
			userURL.Path = owner.GitPath()
			userURL.User = url.UserPassword(username, userPassword)
			return &userURL
		}
		user2, user4 := branchPusher{remote: httpURL("user2")}, branchPusher{remote: httpURL("user4")}

		dstPath := t.TempDir()
		t.Run("Clone", doGitClone(dstPath, httpURL("user2")))

		t.Run("HTTP", func(t *testing.T) {
			testDeleteForcePush(t, owner, dstPath, "release-http", user2, user4)
		})

		t.Run("APIEdit", func(t *testing.T) {
			approvals := int64(0)
			bp := editReleaseProtection(t, owner, api.EditBranchProtectionOption{RequiredApprovals: &approvals})
			assert.Equal(t, []string{"user2"}, bp.DeleteAllowlistUsernames)
			assert.Equal(t, []int64{keys["listed"].keyID}, bp.ForcePushAllowlistDeployKeyIDs)

			bp = editReleaseProtection(t, owner, api.EditBranchProtectionOption{
				DeleteAllowlistUsernames:       []string{"user4"},
				ForcePushAllowlistDeployKeyIDs: []int64{keys["unlisted"].keyID},
			})
			assert.Equal(t, []string{"user4"}, bp.DeleteAllowlistUsernames)
			assert.Equal(t, []string{"user2"}, bp.ForcePushAllowlistUsernames)
			assert.Equal(t, []int64{keys["unlisted"].keyID}, bp.ForcePushAllowlistDeployKeyIDs)

			req := NewRequest(t, "GET", repoURL+"/branch_protections/release*").AddTokenAuth(owner.Token)
			resp := MakeRequest(t, req, http.StatusOK)
			DecodeJSON(t, resp, &bp)
			assert.Equal(t, []string{"user4"}, bp.DeleteAllowlistUsernames)

			bp = editReleaseProtection(t, owner, api.EditBranchProtectionOption{
				DeleteAllowlistUsernames:       []string{"user2"},
				ForcePushAllowlistDeployKeyIDs: []int64{keys["listed"].keyID},
			})
			assert.Equal(t, []string{"user2"}, bp.DeleteAllowlistUsernames)
		})

		branchExists := func(t *testing.T, branch string) bool {
			t.Helper()
			resp := MakeRequest(t, NewRequest(t, "GET", repoURL+"/branches/"+branch).AddTokenAuth(owner.Token), NoExpectedStatus)
			return resp.Code == http.StatusOK
		}

		t.Run("WebDelete", func(t *testing.T) {
			commitOnBranch(t, dstPath, "release-web", "master", "release-web.txt")
			_, err := user2.push(t, dstPath, "release-web")
			require.NoError(t, err)

			hasDeleteButton := func(t *testing.T, username string) bool {
				t.Helper()
				resp := loginUser(t, username).MakeRequest(t, NewRequest(t, "GET", "/user2/delete-force-push/branches"), http.StatusOK)
				doc := NewHTMLParser(t, resp.Body)
				return doc.Find(".delete-branch-button").FilterFunction(func(_ int, s *goquery.Selection) bool {
					return s.AttrOr("data-name", "") == "release-web"
				}).Length() == 1
			}
			assert.False(t, hasDeleteButton(t, "user4"))
			assert.True(t, hasDeleteButton(t, "user2"))

			deleteURL := "/user2/delete-force-push/branches/delete?name=release-web"
			loginUser(t, "user4").MakeRequest(t, NewRequest(t, "POST", deleteURL), http.StatusOK)
			assert.True(t, branchExists(t, "release-web"))
			loginUser(t, "user2").MakeRequest(t, NewRequest(t, "POST", deleteURL), http.StatusOK)
			assert.False(t, branchExists(t, "release-web"))
		})

		t.Run("APIDelete", func(t *testing.T) {
			commitOnBranch(t, dstPath, "release-api", "master", "release-api.txt")
			_, err := user2.push(t, dstPath, "release-api")
			require.NoError(t, err)

			user4Token := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeWriteRepository)
			MakeRequest(t, NewRequest(t, "DELETE", repoURL+"/branches/release-api").AddTokenAuth(user4Token), http.StatusForbidden)
			assert.True(t, branchExists(t, "release-api"))
			MakeRequest(t, NewRequest(t, "DELETE", repoURL+"/branches/release-api").AddTokenAuth(owner.Token), http.StatusNoContent)
			assert.False(t, branchExists(t, "release-api"))
			MakeRequest(t, NewRequest(t, "DELETE", repoURL+"/branches/master").AddTokenAuth(owner.Token), http.StatusForbidden)
		})

		// Calls the pre-receive hook the way the SSH command does for a deploy key, so this runs without an ssh client.
		t.Run("DeployKeyHook", func(t *testing.T) {
			commitOnBranch(t, dstPath, "release-key", "master", "release-key-1.txt")
			first := gitHead(t, dstPath)
			doAddChangesToCheckout(dstPath, "release-key-2.txt")(t)
			second := gitHead(t, dstPath)
			_, err := user2.push(t, dstPath, "release-key")
			require.NoError(t, err)

			preReceive := func(key *protectionTestDeployKey, oldCommitID, newCommitID string) private.ResponseExtra {
				return private.HookPreReceive(t.Context(), repoIDByName(t, owner.Username, owner.Reponame), private.HookOptions{
					OldCommitIDs:   []string{oldCommitID},
					NewCommitIDs:   []string{newCommitID},
					RefFullNames:   []git.RefName{git.RefNameFromBranch("release-key")},
					UserID:         2,
					UserName:       "user2",
					DeployKeyKeyID: key.keyID,
				})
			}
			emptyID := git.Sha1ObjectFormat.EmptyObjectID().String()

			extra := preReceive(keys["unlisted"], second, first)
			assert.Equal(t, http.StatusForbidden, extra.StatusCode)
			assert.Contains(t, extra.UserMsg, "protected from force push")
			extra = preReceive(keys["unlisted"], second, emptyID)
			assert.Equal(t, http.StatusForbidden, extra.StatusCode)
			assert.Contains(t, extra.UserMsg, "protected from deletion")

			require.NoError(t, preReceive(keys["listed"], second, first).Error)
			require.NoError(t, preReceive(keys["listed"], second, emptyID).Error)

			// a deploy key isn't allowed through the lists of the user it pushes as
			editReleaseProtection(t, owner, api.EditBranchProtectionOption{DeleteAllowlistDeployKeyIDs: []int64{}})
			extra = preReceive(keys["listed"], second, emptyID)
			assert.Equal(t, http.StatusForbidden, extra.StatusCode)
		})
	})
}

func TestProtectedBranchDeleteForcePushSSH(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		owner, keys := deleteForcePushRepo(t, "delete-force-push-ssh")
		sshURL := createSSHUrl(owner.GitPath(), u)

		withKeyFile(t, "user2", func(user2Key string) {
			withKeyFile(t, "user4", func(user4Key string) {
				t.Run("CreateUser2Key", doAPICreateUserKey(owner, "user2-key", user2Key))
				user4 := NewAPITestContext(t, "user4", owner.Reponame, auth_model.AccessTokenScopeWriteUser)
				t.Run("CreateUser4Key", doAPICreateUserKey(user4, "user4-key", user4Key))

				dstPath := t.TempDir()
				useDeployKey(t, &protectionTestDeployKey{file: user2Key})
				t.Run("Clone", doGitClone(dstPath, sshURL))

				t.Run("Users", func(t *testing.T) {
					testDeleteForcePush(t, owner, dstPath, "release-ssh", branchPusher{sshURL, user2Key}, branchPusher{sshURL, user4Key})
				})

				t.Run("DeployKeys", func(t *testing.T) {
					testDeleteForcePush(t, owner, dstPath, "release-key", branchPusher{sshURL, keys["listed"].file}, branchPusher{sshURL, keys["unlisted"].file})
				})
			})
		})
	})
}
