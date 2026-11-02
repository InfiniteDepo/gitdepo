// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/modules/git"
	api "forgejo.org/modules/structs"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type protectionTestDeployKey struct {
	file  string
	id    int64 // deploy key ID
	keyID int64 // public key ID, used by the protection rules
}

// createProtectionTestDeployKeys creates a write deploy key "listed", a write deploy key "unlisted"
// and a read-only deploy key "readonly" for the repository of ctx.
func createProtectionTestDeployKeys(t *testing.T, ctx APITestContext) map[string]*protectionTestDeployKey {
	t.Helper()
	keys := map[string]*protectionTestDeployKey{}
	for _, name := range []string{"listed", "unlisted", "readonly"} {
		withKeyFile(t, name, func(keyFile string) {
			pubKey, err := os.ReadFile(keyFile + ".pub")
			require.NoError(t, err)
			req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/%s/%s/keys", ctx.Username, ctx.Reponame), api.CreateKeyOption{
				Title:    name,
				Key:      string(pubKey),
				ReadOnly: name == "readonly",
			}).AddTokenAuth(ctx.Token)
			resp := MakeRequest(t, req, http.StatusCreated)
			var key api.DeployKey
			DecodeJSON(t, resp, &key)
			keys[name] = &protectionTestDeployKey{file: keyFile, id: key.ID, keyID: key.KeyID}
		})
	}
	return keys
}

// useDeployKey makes the git commands of the current test use the given SSH key.
func useDeployKey(t *testing.T, key *protectionTestDeployKey) {
	t.Setenv("GIT_SSH_COMMAND", "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i \""+key.file+"\"")
}

func doGitPushWithDeployKey(t *testing.T, key *protectionTestDeployKey, dstPath string, args ...string) (stderr string, err error) {
	t.Helper()
	useDeployKey(t, key)
	_, stderr, err = git.NewCommand(git.DefaultContext, "push").AddArguments(git.ToTrustedCmdArgs(args)...).RunStdString(&git.RunOpts{Dir: dstPath})
	return stderr, err
}

func TestDeployKeyBranchProtection(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		ctx := NewAPITestContext(t, "user2", "deploy-key-branch-protection", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
		t.Run("CreateRepository", doAPICreateRepository(ctx, nil, git.Sha1ObjectFormat))
		keys := createProtectionTestDeployKeys(t, ctx)

		dstPath := t.TempDir()
		useDeployKey(t, keys["listed"])
		t.Run("Clone", doGitClone(dstPath, createSSHUrl(ctx.GitPath(), u)))

		protectionURL := fmt.Sprintf("/api/v1/repos/%s/%s/branch_protections", ctx.Username, ctx.Reponame)
		editProtection := func(t *testing.T, opts api.EditBranchProtectionOption) api.BranchProtection {
			t.Helper()
			req := NewRequestWithJSON(t, "PATCH", protectionURL+"/master", opts).AddTokenAuth(ctx.Token)
			resp := MakeRequest(t, req, http.StatusOK)
			var bp api.BranchProtection
			DecodeJSON(t, resp, &bp)
			return bp
		}
		getProtection := func(t *testing.T) api.BranchProtection {
			t.Helper()
			req := NewRequest(t, "GET", protectionURL+"/master").AddTokenAuth(ctx.Token)
			resp := MakeRequest(t, req, http.StatusOK)
			var bp api.BranchProtection
			DecodeJSON(t, resp, &bp)
			return bp
		}

		t.Run("APICreate", func(t *testing.T) {
			req := NewRequestWithJSON(t, "POST", protectionURL, api.CreateBranchProtectionOption{
				RuleName:                  "master",
				EnablePush:                true,
				EnablePushWhitelist:       true,
				PushWhitelistDeployKeyIDs: []int64{keys["listed"].keyID, keys["readonly"].keyID, 999999},
			}).AddTokenAuth(ctx.Token)
			resp := MakeRequest(t, req, http.StatusCreated)
			var bp api.BranchProtection
			DecodeJSON(t, resp, &bp)
			// read-only and unknown keys are dropped
			assert.Equal(t, []int64{keys["listed"].keyID}, bp.PushWhitelistDeployKeyIDs)
			assert.False(t, bp.PushWhitelistDeployKeys)
			assert.Equal(t, []int64{keys["listed"].keyID}, getProtection(t).PushWhitelistDeployKeyIDs)
		})

		t.Run("ListedKeyCanPush", func(t *testing.T) {
			doAddChangesToCheckout(dstPath, "listed.md")(t)
			_, err := doGitPushWithDeployKey(t, keys["listed"], dstPath, "origin", "master")
			require.NoError(t, err)
		})

		t.Run("UnlistedKeyIsRefused", func(t *testing.T) {
			doAddChangesToCheckout(dstPath, "unlisted.md")(t)
			stderr, err := doGitPushWithDeployKey(t, keys["unlisted"], dstPath, "origin", "master")
			require.Error(t, err)
			assert.Contains(t, stderr, "Not allowed to push to protected branch master")
		})

		t.Run("ReadOnlyKeyIsRefused", func(t *testing.T) {
			_, err := doGitPushWithDeployKey(t, keys["readonly"], dstPath, "origin", "master")
			require.Error(t, err)
		})

		t.Run("LegacyAllDeployKeys", func(t *testing.T) {
			enabled, allKeys := true, true
			bp := editProtection(t, api.EditBranchProtectionOption{
				EnablePush:                &enabled,
				EnablePushWhitelist:       &enabled,
				PushWhitelistDeployKeys:   &allKeys,
				PushWhitelistDeployKeyIDs: []int64{},
			})
			assert.True(t, bp.PushWhitelistDeployKeys)
			assert.Empty(t, bp.PushWhitelistDeployKeyIDs)

			_, err := doGitPushWithDeployKey(t, keys["unlisted"], dstPath, "origin", "master")
			require.NoError(t, err)
		})

		t.Run("APIEditKeepsKeysWhenOmitted", func(t *testing.T) {
			enabled, allKeys := true, false
			bp := editProtection(t, api.EditBranchProtectionOption{
				EnablePush:                &enabled,
				EnablePushWhitelist:       &enabled,
				PushWhitelistDeployKeys:   &allKeys,
				PushWhitelistDeployKeyIDs: []int64{keys["unlisted"].keyID},
			})
			assert.Equal(t, []int64{keys["unlisted"].keyID}, bp.PushWhitelistDeployKeyIDs)

			approvals := int64(0)
			bp = editProtection(t, api.EditBranchProtectionOption{RequiredApprovals: &approvals})
			assert.Equal(t, []int64{keys["unlisted"].keyID}, bp.PushWhitelistDeployKeyIDs)
		})

		t.Run("DeletedKeyIsRemovedFromRules", func(t *testing.T) {
			req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/%s/%s/tag_protections", ctx.Username, ctx.Reponame), api.CreateTagProtectionOption{
				NamePattern:           "v*",
				AllowlistDeployKeyIDs: []int64{keys["unlisted"].keyID, keys["listed"].keyID},
			}).AddTokenAuth(ctx.Token)
			resp := MakeRequest(t, req, http.StatusCreated)
			var tp api.TagProtection
			DecodeJSON(t, resp, &tp)
			assert.ElementsMatch(t, []int64{keys["unlisted"].keyID, keys["listed"].keyID}, tp.AllowlistDeployKeyIDs)

			req = NewRequestf(t, "DELETE", "/api/v1/repos/%s/%s/keys/%d", ctx.Username, ctx.Reponame, keys["unlisted"].id).AddTokenAuth(ctx.Token)
			MakeRequest(t, req, http.StatusNoContent)

			assert.Empty(t, getProtection(t).PushWhitelistDeployKeyIDs)

			req = NewRequestf(t, "GET", "/api/v1/repos/%s/%s/tag_protections/%d", ctx.Username, ctx.Reponame, tp.ID).AddTokenAuth(ctx.Token)
			resp = MakeRequest(t, req, http.StatusOK)
			DecodeJSON(t, resp, &tp)
			assert.Equal(t, []int64{keys["listed"].keyID}, tp.AllowlistDeployKeyIDs)
		})
	})
}

func TestDeployKeyTagProtection(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		for _, owner := range []string{"user2", "org3"} {
			t.Run(owner, func(t *testing.T) {
				ctx := NewAPITestContext(t, "user2", "deploy-key-tag-protection", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser, auth_model.AccessTokenScopeWriteOrganization)
				if owner == "user2" {
					t.Run("CreateRepository", doAPICreateRepository(ctx, nil, git.Sha1ObjectFormat))
				} else {
					req := NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", api.CreateRepoOption{
						Name:     ctx.Reponame,
						AutoInit: true,
						Readme:   "Default",
					}).AddTokenAuth(ctx.Token)
					MakeRequest(t, req, http.StatusCreated)
					ctx.Username = owner
				}
				keys := createProtectionTestDeployKeys(t, ctx)

				dstPath := t.TempDir()
				useDeployKey(t, keys["listed"])
				t.Run("Clone", doGitClone(dstPath, createSSHUrl(ctx.GitPath(), u)))

				// The repository owner is on the allow-list: this used to let every deploy key
				// of a user-owned repository through.
				t.Run("APICreate", func(t *testing.T) {
					req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/%s/%s/tag_protections", ctx.Username, ctx.Reponame), api.CreateTagProtectionOption{
						NamePattern:           "v*",
						WhitelistUsernames:    []string{"user2"},
						AllowlistDeployKeyIDs: []int64{keys["listed"].keyID, keys["readonly"].keyID},
					}).AddTokenAuth(ctx.Token)
					resp := MakeRequest(t, req, http.StatusCreated)
					var tp api.TagProtection
					DecodeJSON(t, resp, &tp)
					assert.Equal(t, []int64{keys["listed"].keyID}, tp.AllowlistDeployKeyIDs)
				})

				for _, tag := range []string{"v1", "v2", "v3"} {
					_, _, err := git.NewCommand(git.DefaultContext, "tag").AddDynamicArguments(tag).RunStdString(&git.RunOpts{Dir: dstPath})
					require.NoError(t, err)
				}

				t.Run("ListedKeyCanCreateAndDelete", func(t *testing.T) {
					_, err := doGitPushWithDeployKey(t, keys["listed"], dstPath, "origin", "v1")
					require.NoError(t, err)
					_, err = doGitPushWithDeployKey(t, keys["listed"], dstPath, "origin", ":refs/tags/v1")
					require.NoError(t, err)
				})

				t.Run("UnlistedKeyIsRefused", func(t *testing.T) {
					stderr, err := doGitPushWithDeployKey(t, keys["unlisted"], dstPath, "origin", "v2")
					require.Error(t, err)
					assert.Contains(t, stderr, "Tag v2 is protected")
				})

				t.Run("ReadOnlyKeyIsRefused", func(t *testing.T) {
					_, err := doGitPushWithDeployKey(t, keys["readonly"], dstPath, "origin", "v3")
					require.Error(t, err)
				})

				t.Run("UnprotectedTag", func(t *testing.T) {
					_, _, runErr := git.NewCommand(git.DefaultContext, "tag", "release-1").RunStdString(&git.RunOpts{Dir: dstPath})
					require.NoError(t, runErr)
					_, err := doGitPushWithDeployKey(t, keys["unlisted"], dstPath, "origin", "release-1")
					require.NoError(t, err)
				})
			})
		}
	})
}
