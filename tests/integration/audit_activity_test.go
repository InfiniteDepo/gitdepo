// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	actions_model "forgejo.org/models/actions"
	asymkey_model "forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	packages_model "forgejo.org/models/packages"
	"forgejo.org/models/perm"
	quota_model "forgejo.org/models/quota"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	lfs_module "forgejo.org/modules/lfs"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/storage"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	"forgejo.org/routers/common"
	packages_service "forgejo.org/services/packages"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// auditActivity returns the one entry of action written after since.
func auditActivity(t *testing.T, since int64, action string) *audit_model.Entry {
	t.Helper()
	entries := auditActions(t, since, action)
	require.Len(t, entries, 1, action)
	return entries[0]
}

func TestAuditAPIWrite(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteIssue, auth_model.AccessTokenScopeWriteRepository)
	tok, err := auth_model.GetAccessTokenBySHA(t.Context(), token)
	require.NoError(t, err)

	t.Run("repository write", func(t *testing.T) {
		since := auditMaxID(t)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/issues?secret=q", &api.CreateIssueOption{Title: "audit"}).AddTokenAuth(token), http.StatusCreated)
		e := auditActivity(t, since, "activity.api.write")
		assert.Equal(t, audit_model.CategoryActivity, e.Category)
		assert.Equal(t, audit_model.ResultSuccess, e.Result)
		assert.Equal(t, audit_model.CredentialAccessToken, e.CredentialType)
		assert.Equal(t, tok.ID, e.CredentialID)
		assert.EqualValues(t, 2, e.ActorID)
		assert.EqualValues(t, 1, e.RepoID)
		assert.EqualValues(t, 2, e.OwnerID)
		assert.Equal(t, "user2/repo1", e.TargetName)
		data := auditData(t, e)
		assert.Equal(t, "POST", data["method"])
		assert.Equal(t, "/api/v1/repos/{username}/{reponame}/issues", data["route"])
		assert.EqualValues(t, http.StatusCreated, data["status"])
		assert.Equal(t, "repo", data["target"])
		assertNoSecrets(t, since, token, "secret=q")
	})

	t.Run("missing repository targets the user", func(t *testing.T) {
		since := auditMaxID(t)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/no-such-repo/issues", &api.CreateIssueOption{Title: "audit"}).AddTokenAuth(token), http.StatusNotFound)
		e := auditActivity(t, since, "activity.api.write")
		assert.Equal(t, audit_model.ResultFailure, e.Result)
		assert.Zero(t, e.RepoID)
		assert.EqualValues(t, 2, e.OwnerID)
		assert.Equal(t, "user2", e.TargetName)
		assert.Equal(t, "user", auditData(t, e)["target"])
		assert.EqualValues(t, http.StatusNotFound, auditData(t, e)["status"])
	})

	t.Run("failures keep their status", func(t *testing.T) {
		since := auditMaxID(t)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/issues", &api.CreateIssueOption{Title: ""}).AddTokenAuth(token), http.StatusUnprocessableEntity)
		assert.EqualValues(t, http.StatusUnprocessableEntity, auditData(t, auditActivity(t, since, "activity.api.write"))["status"])

		since = auditMaxID(t)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "no-scope"}).AddTokenAuth(token), http.StatusForbidden)
		assert.EqualValues(t, http.StatusForbidden, auditData(t, auditActivity(t, since, "activity.api.write"))["status"])
	})

	t.Run("identical failures are aggregated", func(t *testing.T) {
		audit_model.ResetActivity()
		since := auditMaxID(t)
		for range 5 {
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/issues", &api.CreateIssueOption{Title: ""}).AddTokenAuth(token), http.StatusUnprocessableEntity)
		}
		assert.Len(t, auditActions(t, since, "activity.api.write"), 1) // the first of the window is written at once
		audit_model.FlushAggregated(t.Context(), true)
		agg := auditActivity(t, since, "activity.api.write.aggregated")
		assert.EqualValues(t, 4, auditData(t, agg)["count"])
		assert.EqualValues(t, http.StatusUnprocessableEntity, auditData(t, agg)["status"])
	})

	t.Run("anonymous and reads are not recorded", func(t *testing.T) {
		since := auditMaxID(t)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/issues", &api.CreateIssueOption{Title: "x"}), http.StatusUnauthorized)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/issues").AddTokenAuth(token), http.StatusOK)
		assert.Empty(t, auditActions(t, since, "activity.api.write"))
		assert.Empty(t, auditActions(t, since, "activity.api.sudo"))
	})

	t.Run("sudo read", func(t *testing.T) {
		adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeReadRepository)
		since := auditMaxID(t)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1?sudo=user2").AddTokenAuth(adminToken), http.StatusOK)
		e := auditActivity(t, since, "activity.api.sudo")
		assert.EqualValues(t, 2, e.ActorID)
		assert.EqualValues(t, 1, e.SudoByID)
		assert.EqualValues(t, 1, e.RepoID)
		assert.Equal(t, "GET", auditData(t, e)["method"])

		audit_model.ResetActivity()
		since = auditMaxID(t)
		for range 3 {
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/no-such-repo?sudo=user2").AddTokenAuth(adminToken), http.StatusNotFound)
		}
		audit_model.FlushAggregated(t.Context(), true)
		assert.EqualValues(t, 2, auditData(t, auditActivity(t, since, "activity.api.sudo.aggregated"))["count"])
	})

	t.Run("a change and its request share the request ID", func(t *testing.T) {
		since := auditMaxID(t)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/hooks", &api.CreateHookOption{
			Type: "gitea", Config: api.CreateHookOptionConfig{"content_type": "json", "url": "http://example.com/"},
		}).AddTokenAuth(token), http.StatusCreated)
		change := auditActivity(t, since, "repo.webhook.created")
		write := auditActivity(t, since, "activity.api.write")
		assert.NotEmpty(t, write.RequestID)
		assert.Equal(t, change.RequestID, write.RequestID)
	})

	t.Run("job token", func(t *testing.T) {
		task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
		task.RepoID, task.OwnerID = 1, 2
		task.GenerateToken()
		require.NoError(t, actions_model.UpdateTask(t.Context(), task, "repo_id", "owner_id", "token", "token_salt", "token_hash", "token_last_eight"))
		since := auditMaxID(t)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/issues", &api.CreateIssueOption{Title: "job"}).AddTokenAuth(task.Token), http.StatusCreated)
		e := auditActivity(t, since, "activity.api.write")
		assert.Equal(t, audit_model.ActorActions, e.ActorType)
		assert.Equal(t, audit_model.CredentialActionsTask, e.CredentialType)
		assert.Equal(t, task.ID, e.CredentialID)
	})

	t.Run("generic package", func(t *testing.T) {
		since := auditMaxID(t)
		MakeRequest(t, NewRequestWithBody(t, "PUT", "/api/packages/user2/generic/audit-pkg/1.0/file.bin", strings.NewReader("data")).AddBasicAuth("user2"), http.StatusCreated)
		e := auditActivity(t, since, "activity.api.write")
		assert.EqualValues(t, 2, e.OwnerID)
		assert.Zero(t, e.RepoID)
		assert.Equal(t, audit_model.CredentialPassword, e.CredentialType)
		assert.Equal(t, "PUT", auditData(t, e)["method"])
		assert.NotContains(t, auditData(t, e)["route"], "audit-pkg")
	})

	t.Run("container chunks", func(t *testing.T) {
		resp := MakeRequest(t, NewRequest(t, "GET", setting.AppURL+"v2/token").AddBasicAuth("user2"), http.StatusOK)
		tr := &struct {
			Token string `json:"token"`
		}{}
		DecodeJSON(t, resp, tr)
		bearer := "Bearer " + tr.Token
		blob := []byte("audit blob")
		sum := sha256.Sum256(blob)
		digest := "sha256:" + hex.EncodeToString(sum[:])

		since := auditMaxID(t)
		resp = MakeRequest(t, NewRequest(t, "POST", setting.AppURL+"v2/user2/audit-img/blobs/uploads").AddTokenAuth(bearer), http.StatusAccepted)
		uploadURL := resp.Header().Get("Location")
		resp = MakeRequest(t, NewRequestWithBody(t, "PATCH", setting.AppURL+uploadURL[1:], bytes.NewReader(blob)).AddTokenAuth(bearer).
			SetHeader("Content-Range", fmt.Sprintf("0-%d", len(blob)-1)), http.StatusAccepted)
		uploadURL = resp.Header().Get("Location")
		MakeRequest(t, NewRequest(t, "PUT", fmt.Sprintf("%s?digest=%s", setting.AppURL+uploadURL[1:], digest)).AddTokenAuth(bearer), http.StatusCreated)
		var methods []any
		for _, e := range auditActions(t, since, "activity.api.write") {
			methods = append(methods, auditData(t, e)["method"])
		}
		assert.Contains(t, methods, "PUT")
		assert.NotContains(t, methods, "PATCH")
	})

	t.Run("fail open", func(t *testing.T) {
		defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error { return errors.New("down") })()
		before := audit_model.WriteErrors.Load()
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/issues", &api.CreateIssueOption{Title: "fail open"}).AddTokenAuth(token), http.StatusCreated)
		assert.Greater(t, audit_model.WriteErrors.Load(), before)
	})
}

// gitURL is u with path and basic auth as user with password (a token or a password).
func gitURL(u *url.URL, path, user, password string) *url.URL {
	c := *u
	c.Path = path
	c.User = url.UserPassword(user, password)
	return &c
}

func TestAuditGitPush(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		auditFresh(t)
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		tok, err := auth_model.GetAccessTokenBySHA(t.Context(), token)
		require.NoError(t, err)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "audit-push", AutoInit: true, DefaultBranch: "main", Readme: "Default"}).AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeAll)), http.StatusCreated)
		repo, err := repo_model.GetRepositoryByOwnerAndName(t.Context(), "user2", "audit-push")
		require.NoError(t, err)

		dir := t.TempDir()
		doGitClone(dir, gitURL(u, "/user2/audit-push.git", "user2", token))(t)
		doGitCheckoutBranch(dir, "-b", "feature")(t)
		commitFile(t, dir, "a.txt", 10)

		t.Run("push", func(t *testing.T) {
			since := auditMaxID(t)
			doGitPushTestRepository(dir, "origin", "feature")(t)
			e := auditActivity(t, since, "activity.git.push")
			assert.Equal(t, audit_model.CredentialAccessToken, e.CredentialType)
			assert.Equal(t, tok.ID, e.CredentialID)
			assert.EqualValues(t, 2, e.ActorID)
			assert.Equal(t, repo.ID, e.RepoID)
			assert.Equal(t, "127.0.0.1", e.IP)
			assert.NotEmpty(t, e.RequestID)
			data := auditData(t, e)
			refs := data["refs"].([]any)
			require.Len(t, refs, 1)
			ref := refs[0].(map[string]any)
			assert.Equal(t, "refs/heads/feature", ref["ref"])
			assert.Equal(t, git.Sha1ObjectFormat.EmptyObjectID().String(), ref["old"])
			assert.Equal(t, false, ref["forced"])
			assert.EqualValues(t, 0, data["forced_count"])
			assert.EqualValues(t, 0, data["deleted_count"])
			assert.Nil(t, data["trigger"])
			assertNoSecrets(t, since, token)
		})

		t.Run("inherited sudo key does not survive", func(t *testing.T) {
			t.Setenv("GITEA_AUDIT_SUDO_BY", "1") // the git process inherits the server's environment
			commitFile(t, dir, "inherited.txt", 10)
			since := auditMaxID(t)
			doGitPushTestRepository(dir, "origin", "feature")(t)
			e := auditActivity(t, since, "activity.git.push")
			assert.Zero(t, e.SudoByID)
			assert.Equal(t, tok.ID, e.CredentialID)
			assert.EqualValues(t, 2, e.ActorID)
		})

		t.Run("force push", func(t *testing.T) {
			_, _, err := git.NewCommand(git.DefaultContext, "commit", "--amend", "-m", "amended").RunStdString(&git.RunOpts{Dir: dir})
			require.NoError(t, err)
			since := auditMaxID(t)
			doGitPushTestRepository(dir, "-f", "origin", "feature")(t)
			data := auditData(t, auditActivity(t, since, "activity.git.push"))
			assert.EqualValues(t, 1, data["forced_count"])
			assert.Equal(t, true, data["refs"].([]any)[0].(map[string]any)["forced"])
		})

		t.Run("delete", func(t *testing.T) {
			since := auditMaxID(t)
			doGitPushTestRepository(dir, "origin", ":feature")(t)
			assert.EqualValues(t, 1, auditData(t, auditActivity(t, since, "activity.git.push"))["deleted_count"])
		})

		t.Run("AGit is not a push entry", func(t *testing.T) {
			since := auditMaxID(t)
			doGitPushTestRepository(dir, "origin", "HEAD:refs/for/main/audit-topic", "-o", "title=audit")(t)
			assert.Empty(t, auditActions(t, since, "activity.git.push"))
		})

		t.Run("wiki", func(t *testing.T) {
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/audit-push/wiki/new", &api.CreateWikiPageOptions{Title: "Home", ContentBase64: "aG9tZQ=="}).AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)), http.StatusCreated)
			wikiDir := t.TempDir()
			cloneWiki(t, wikiDir, gitURL(u, "/user2/audit-push.wiki.git", "user2", token))
			commitFile(t, wikiDir, "Page.md", 10)
			since := auditMaxID(t)
			doGitPushTestRepository(wikiDir, "origin", "HEAD")(t)
			e := auditActivity(t, since, "activity.git.push")
			assert.Equal(t, true, auditData(t, e)["wiki"])
			assert.Equal(t, repo.ID, e.RepoID)
		})

		t.Run("web editor", func(t *testing.T) {
			session := loginUser(t, "user2")
			since := auditMaxID(t)
			testEditFile(t, session, "user2", "audit-push", "main", "README.md", "edited")
			e := auditActivity(t, since, "activity.git.push")
			assert.Equal(t, audit_model.CredentialSession, e.CredentialType)
			assert.EqualValues(t, 2, e.ActorID)
			assert.NotEmpty(t, e.RequestID)
			assert.Equal(t, "web", auditData(t, e)["trigger"])
		})

		t.Run("deploy key at hook level", func(t *testing.T) {
			key, err := asymkey_model.AddDeployKey(audit_model.WithCLI(t.Context()), repo.ID, "audit-deploy", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFeRC8GfFyXtiy0f1E7hLv77BXW7e68tFvIcs8/29YqH nocomment", false, 0)
			require.NoError(t, err)
			gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
			require.NoError(t, err)
			defer gitRepo.Close()
			main, err := gitRepo.GetBranchCommitID("main")
			require.NoError(t, err)
			since := auditMaxID(t)
			extra := private.HookPushAudit(t.Context(), repo.ID, private.HookOptions{
				OldCommitIDs: []string{git.Sha1ObjectFormat.EmptyObjectID().String()}, NewCommitIDs: []string{main},
				RefFullNames: []git.RefName{git.RefNameFromBranch("deploy")}, UserID: repo.OwnerID, UserName: "user2",
				DeployKeyKeyID: key.KeyID, AuditIP: "192.0.2.7",
			})
			require.NoError(t, extra.Error)
			e := auditActivity(t, since, "activity.git.push")
			assert.Equal(t, audit_model.ActorDeployKey, e.ActorType)
			assert.Equal(t, audit_model.CredentialDeployKey, e.CredentialType)
			assert.Equal(t, key.ID, e.CredentialID)
			assert.Equal(t, "192.0.2.7", e.IP)
		})

		t.Run("unknown forced", func(t *testing.T) {
			gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
			require.NoError(t, err)
			defer gitRepo.Close()
			main, err := gitRepo.GetBranchCommitID("main")
			require.NoError(t, err)
			since := auditMaxID(t)
			extra := private.HookPushAudit(t.Context(), repo.ID, private.HookOptions{
				OldCommitIDs: []string{strings.Repeat("a", 40)}, NewCommitIDs: []string{main}, // an old commit that doesn't exist: merge-base fails
				RefFullNames: []git.RefName{git.RefNameFromBranch("unknown-forced")}, UserID: 2, UserName: "user2", AuditCredential: "session:0",
			})
			require.NoError(t, extra.Error)
			data := auditData(t, auditActivity(t, since, "activity.git.push"))
			assert.EqualValues(t, 1, data["forced_unknown"])
			assert.Zero(t, data["forced_count"])
			ref := data["refs"].([]any)[0].(map[string]any)
			assert.Nil(t, ref["forced"])
			assert.Contains(t, ref, "forced")
		})
	})
}

func TestAuditGitPushRefused(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		auditFresh(t)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
		require.NoError(t, err)
		defer gitRepo.Close()
		master, err := gitRepo.GetBranchCommitID("master")
		require.NoError(t, err)
		branch2, err := gitRepo.GetBranchCommitID("branch2")
		require.NoError(t, err)
		zero := git.Sha1ObjectFormat.EmptyObjectID().String()

		refused := func(t *testing.T, reason string, opts private.HookOptions) {
			t.Helper()
			if opts.UserID == 0 {
				opts.UserID, opts.UserName = 2, "user2"
			}
			opts.AuditCredential = "session:0"
			audit_model.ResetActivity() // an identical refusal in the same minute would only be counted
			since := auditMaxID(t)
			extra := private.HookPreReceive(t.Context(), repo.ID, opts)
			require.Error(t, extra.Error)
			e := auditActivity(t, since, "activity.git.push.refused")
			assert.Equal(t, audit_model.ResultRefused, e.Result)
			assert.Equal(t, reason, auditData(t, e)["reason"])
			assert.Equal(t, repo.ID, e.RepoID)
		}
		push := func(old, new string, ref git.RefName) private.HookOptions {
			return private.HookOptions{OldCommitIDs: []string{old}, NewCommitIDs: []string{new}, RefFullNames: []git.RefName{ref}}
		}

		t.Run("protected_branch", func(t *testing.T) {
			refused(t, "protected_branch", push(master, zero, git.RefNameFromBranch("master")))
		})
		t.Run("identical refusals are aggregated", func(t *testing.T) {
			audit_model.ResetActivity()
			since := auditMaxID(t)
			for range 3 {
				extra := private.HookPreReceive(t.Context(), repo.ID, private.HookOptions{
					OldCommitIDs: []string{master}, NewCommitIDs: []string{zero}, RefFullNames: []git.RefName{git.RefNameFromBranch("master")},
					UserID: 2, UserName: "user2", AuditCredential: "session:0",
				})
				require.Error(t, extra.Error)
			}
			assert.Len(t, auditActions(t, since, "activity.git.push.refused"), 1)
			audit_model.FlushAggregated(t.Context(), true)
			assert.EqualValues(t, 2, auditData(t, auditActivity(t, since, "activity.git.push.refused.aggregated"))["count"])
		})
		t.Run("force_push", func(t *testing.T) {
			require.NoError(t, git_model.UpdateProtectBranch(audit_model.WithCLI(t.Context()), repo, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "branch2", CanPush: true}, git_model.WhitelistOptions{}))
			defer func() {
				require.NoError(t, git_model.DeleteProtectedBranch(audit_model.WithCLI(t.Context()), repo, protectedBranchID(t, repo.ID, "branch2")))
			}()
			refused(t, "force_push", push(branch2, master, git.RefNameFromBranch("branch2")))
		})
		t.Run("push_rule", func(t *testing.T) {
			setPRTitleRule(t, repo.ID, git_model.PushRule{BranchNameRegex: "^ok-"})
			defer setPRTitleRule(t, repo.ID, git_model.PushRule{})
			refused(t, "push_rule", push(zero, master, git.RefNameFromBranch("bad")))
		})
		t.Run("push_rule AGit title", func(t *testing.T) {
			setPRTitleRule(t, repo.ID, git_model.PushRule{PRTitleRegex: `^ABC-\d+ `})
			defer setPRTitleRule(t, repo.ID, git_model.PushRule{})
			audit_model.ResetActivity()
			since := auditMaxID(t)
			_, extra := private.HookProcReceive(t.Context(), repo.ID, private.HookOptions{
				OldCommitIDs: []string{zero}, NewCommitIDs: []string{branch2}, RefFullNames: []git.RefName{"refs/for/master/audit-title"},
				UserID: 2, UserName: "user2", GitPushOptions: map[string]string{"title": "no key"},
			})
			require.Error(t, extra.Error)
			assert.Equal(t, "push_rule", auditData(t, auditActivity(t, since, "activity.git.push.refused"))["reason"])
		})
		t.Run("org_policy", func(t *testing.T) {
			defer setPersonalRepoMode(t, setting.PersonalReposPrivateOnly)()
			private2 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
			since := auditMaxID(t)
			extra := private.HookPreReceive(t.Context(), private2.ID, private.HookOptions{
				OldCommitIDs: []string{zero}, NewCommitIDs: []string{zero}, RefFullNames: []git.RefName{git.RefNameFromBranch("x")},
				UserID: 2, UserName: "user2", GitPushOptions: map[string]string{"repo.private": "false"},
			})
			require.Error(t, extra.Error)
			assert.Equal(t, "org_policy", auditData(t, auditActivity(t, since, "activity.git.push.refused"))["reason"])
		})
		t.Run("deploy_key", func(t *testing.T) {
			key, err := asymkey_model.AddDeployKey(audit_model.WithCLI(t.Context()), 2, "audit-other-repo", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINDRDoephkaFELacrNNe2fqAwedhRB1MKOpLEHlPuczO nocomment", false, 0)
			require.NoError(t, err)
			opts := push(master, branch2, git.RefNameFromBranch("branch2"))
			opts.DeployKeyKeyID = key.KeyID
			refused(t, "deploy_key", opts)
		})
		t.Run("permission", func(t *testing.T) {
			opts := push(master, branch2, git.RefNameFromBranch("branch2"))
			opts.UserID, opts.UserName = 4, "user4"
			refused(t, "permission", opts)
		})
		t.Run("protected_tag", func(t *testing.T) {
			require.NoError(t, git_model.InsertProtectedTag(t.Context(), &git_model.ProtectedTag{RepoID: repo.ID, NamePattern: "audit-v*"}))
			refused(t, "protected_tag", push(zero, master, git.RefNameFromTag("audit-v1")))
		})
		t.Run("size_lock", func(t *testing.T) {
			defer test.MockVariableValue(&setting.Quota.Enabled, true)()
			group, err := quota_model.CreateGroup(t.Context(), "audit-block")
			require.NoError(t, err)
			rule, err := quota_model.CreateRule(t.Context(), "audit-block", 0, quota_model.LimitSubjects{quota_model.LimitSubjectSizeAll})
			require.NoError(t, err)
			require.NoError(t, group.AddRuleByName(t.Context(), rule.Name))
			require.NoError(t, group.AddUserByID(t.Context(), 2))
			defer func() { require.NoError(t, group.RemoveUserByID(t.Context(), 2)) }()
			refused(t, "size_lock", push(zero, master, git.RefNameFromBranch("audit-quota")))
		})

		t.Run("HTTP", func(t *testing.T) {
			readToken := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
			dir := t.TempDir()
			doGitClone(dir, gitURL(u, "/user2/repo1.git", "user2", readToken))(t)
			doGitCheckoutBranch(dir, "-b", "audit-read")(t)
			commitFile(t, dir, "r.txt", 10)

			since := auditMaxID(t)
			_, err := gitPushResult(dir, "origin", "audit-read")
			require.Error(t, err)
			e := auditActivity(t, since, "activity.git.push.refused") // none for git's first, anonymous round trip
			assert.Equal(t, "permission", auditData(t, e)["reason"])
			assert.Equal(t, audit_model.CredentialAccessToken, e.CredentialType)

			t.Run("size_lock", func(t *testing.T) {
				defer resetPersonalRepoMode(t)
				lockPersonalRepos(t, 2, true)
				writeToken := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
				doGitSetRemoteURL(dir, "origin", gitURL(u, "/user2/repo1.git", "user2", writeToken))(t)
				since := auditMaxID(t)
				_, err := gitPushResult(dir, "origin", "audit-read")
				require.Error(t, err)
				assert.Equal(t, "size_lock", auditData(t, auditActivity(t, since, "activity.git.push.refused"))["reason"])
			})

			t.Run("expired token", func(t *testing.T) {
				expiredToken := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
				expired, err := auth_model.GetAccessTokenBySHA(t.Context(), expiredToken)
				require.NoError(t, err)
				_, err = db.GetEngine(t.Context()).Exec("UPDATE access_token SET expires_unix = 1 WHERE id = ?", expired.ID)
				require.NoError(t, err)
				doGitSetRemoteURL(dir, "origin", gitURL(u, "/user2/repo1.git", "user2", expiredToken))(t)
				since := auditMaxID(t)
				_, err = gitPushResult(dir, "origin", "audit-read")
				require.Error(t, err)
				assert.Empty(t, auditActions(t, since, "activity.git.push.refused"))
			})
		})
	})
}

func protectedBranchID(t *testing.T, repoID int64, name string) int64 {
	t.Helper()
	pb, err := git_model.GetProtectedBranchRuleByName(t.Context(), repoID, name)
	require.NoError(t, err)
	return pb.ID
}

// TestAuditServRefused covers the refusals of the SSH entry point at its internal API, without an SSH client.
func TestAuditServRefused(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		auditFresh(t)
		const verb = "git-receive-pack"
		serv := func(t *testing.T, reason string, keyID int64, owner, repo string, repoID int64) {
			t.Helper()
			audit_model.ResetActivity()
			since := auditMaxID(t)
			_, extra := private.ServCommand(t.Context(), keyID, owner, repo, perm.AccessModeWrite, "127.0.0.1", verb, "")
			require.Error(t, extra.Error)
			e := auditActivity(t, since, "activity.git.push.refused")
			assert.Equal(t, audit_model.ResultRefused, e.Result)
			assert.Equal(t, reason, auditData(t, e)["reason"])
			assert.Equal(t, repoID, e.RepoID)
		}

		t.Run("permission", func(t *testing.T) {
			serv(t, "permission", 1, "user15", "big_test_private_1", unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user15", Name: "big_test_private_1"}).ID)
		})
		t.Run("read_only_key", func(t *testing.T) {
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			sshPub, err := ssh.NewPublicKey(pub)
			require.NoError(t, err)
			key, err := asymkey_model.AddDeployKey(audit_model.WithCLI(t.Context()), 1, "audit-read-only", string(ssh.MarshalAuthorizedKey(sshPub)), true, 0)
			require.NoError(t, err)
			serv(t, "read_only_key", key.KeyID, "user2", "repo1", 1)
		})
		t.Run("size_lock", func(t *testing.T) {
			defer resetPersonalRepoMode(t)
			lockPersonalRepos(t, 2, true)
			serv(t, "size_lock", 1, "user2", "repo1", 1)
		})
	})
}

func TestAuditDownloads(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	saveTestAttachments(t)
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeReadIssue)
	tok, err := auth_model.GetAccessTokenBySHA(t.Context(), token)
	require.NoError(t, err)

	download := func(t *testing.T, req *RequestWrapper, kind, object string) *audit_model.Entry {
		t.Helper()
		since := auditMaxID(t)
		MakeRequest(t, req, http.StatusOK)
		e := auditActivity(t, since, "activity.download")
		assert.Equal(t, audit_model.CredentialAccessToken, e.CredentialType)
		assert.Equal(t, tok.ID, e.CredentialID)
		assert.EqualValues(t, 2, e.ActorID)
		assert.EqualValues(t, 1, e.RepoID)
		data := auditData(t, e)
		assert.Equal(t, kind, data["kind"])
		assert.Equal(t, object, data["object"])
		assert.Positive(t, data["bytes"])
		assertNoSecrets(t, since, token, "secret=q")
		assert.Empty(t, auditActions(t, since, "activity.api.read"))
		return e
	}

	t.Run("raw and media", func(t *testing.T) {
		download(t, NewRequest(t, "GET", "/user2/repo1/raw/branch/master/README.md?secret=q").AddTokenAuth(token), "raw", "README.md")
		download(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/raw/README.md?ref=master").AddTokenAuth(token), "raw", "README.md")
		download(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/media/README.md?ref=master").AddTokenAuth(token), "raw", "README.md")
	})

	t.Run("archive", func(t *testing.T) {
		download(t, NewRequest(t, "GET", "/user2/repo1/archive/master.zip").AddTokenAuth(token), "archive", "master.zip")
		download(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/archive/master.zip").AddTokenAuth(token), "archive", "master.zip")
	})

	t.Run("attachment", func(t *testing.T) {
		download(t, NewRequest(t, "GET", "/attachments/a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11").AddTokenAuth(token), "attachment", "1")
	})

	t.Run("release asset", func(t *testing.T) {
		att, err := repo_model.GetAttachmentByUUID(t.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a19")
		require.NoError(t, err)
		_, err = storage.Attachments.Save(att.RelativePath(), strings.NewReader("release asset"), -1)
		require.NoError(t, err)
		e := download(t, NewRequest(t, "GET", "/user2/repo1/releases/download/v1.1/"+att.Name).AddTokenAuth(token), "release_asset", strconv.FormatInt(att.ID, 10))
		assert.EqualValues(t, 13, auditData(t, e)["bytes"])
	})

	t.Run("lfs", func(t *testing.T) {
		content := []byte("audit lfs content")
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		oid := storeObjectInRepo(t, repo.ID, &content)
		req := NewRequest(t, "GET", "/user2/repo1.git/info/lfs/objects/"+oid+"/x")
		req.SetBasicAuth("user2", token)
		e := download(t, req, "lfs", oid)
		assert.EqualValues(t, len(content), auditData(t, e)["bytes"])
	})

	t.Run("not recorded", func(t *testing.T) {
		since := auditMaxID(t)
		MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/raw/branch/master/README.md"), http.StatusOK) // anonymous
		session := loginUser(t, "user2")
		MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/raw/branch/master/README.md"), http.StatusOK)
		session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/raw/branch/master/README.md"), http.StatusOK) // session, LOG_READS off
		req := NewRequest(t, "GET", "/user2/repo1/raw/branch/master/README.md").AddTokenAuth(token)
		resp := MakeRequest(t, req, http.StatusOK)
		since2 := auditMaxID(t)
		req = NewRequest(t, "GET", "/user2/repo1/raw/branch/master/README.md").AddTokenAuth(token)
		req.Header.Set("If-None-Match", resp.Header().Get("ETag"))
		MakeRequest(t, req, http.StatusNotModified)
		assert.Empty(t, auditActions(t, since2, "activity.download"))
		assert.Len(t, auditActions(t, since, "activity.download"), 1) // only the first token request
	})

	t.Run("session with LOG_READS", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Audit.LogReads, true)()
		session := loginUser(t, "user2")
		since := auditMaxID(t)
		session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/raw/branch/master/README.md"), http.StatusOK)
		e := auditActivity(t, since, "activity.download")
		assert.Equal(t, audit_model.CredentialSession, e.CredentialType)
	})
}

func TestAuditAPIReads(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
	count := func(path string) int {
		since := auditMaxID(t)
		MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusOK)
		return len(auditActions(t, since, "activity.api.read"))
	}

	assert.Zero(t, count("/api/v1/repos/user2/repo2")) // LOG_READS off

	defer test.MockVariableValue(&setting.Audit.LogReads, true)()
	since := auditMaxID(t)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo2?secret=q").AddTokenAuth(token), http.StatusOK)
	e := auditActivity(t, since, "activity.api.read")
	assert.Equal(t, "user2/repo2", e.TargetName)
	assert.Equal(t, "GET", auditData(t, e)["method"])
	assertNoSecrets(t, since, token, "secret=q")
	assert.Zero(t, count("/api/v1/repos/user2/repo1")) // public

	// a public repository of a private organization counts as private
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	require.NoError(t, user_model.UpdateUserCols(t.Context(), &user_model.User{ID: org.ID, Visibility: api.VisibleTypePrivate}, "visibility"))
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: org.ID, IsPrivate: false})
	orgToken := getUserToken(t, "user1", auth_model.AccessTokenScopeAll)
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/"+org.Name+"/"+repo.Name).AddTokenAuth(orgToken), http.StatusOK)
	assert.Len(t, auditActions(t, since, "activity.api.read"), 1)

	// a failed read is aggregated
	audit_model.ResetActivity()
	since = auditMaxID(t)
	for range 3 {
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo2/branches/no-such-branch").AddTokenAuth(token), http.StatusNotFound)
	}
	assert.Len(t, auditActions(t, since, "activity.api.read"), 1)
	audit_model.FlushAggregated(t.Context(), true)
	assert.EqualValues(t, 2, auditData(t, auditActivity(t, since, "activity.api.read.aggregated"))["count"])

	// a download is not recorded twice
	since = auditMaxID(t)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo2/raw/Home.md?ref=master").AddTokenAuth(token), http.StatusOK)
	assert.Len(t, auditActions(t, since, "activity.download"), 1)
	assert.Empty(t, auditActions(t, since, "activity.api.read"))
}

func TestAuditUploads(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWritePackage)
	tok, err := auth_model.GetAccessTokenBySHA(t.Context(), token)
	require.NoError(t, err)

	t.Run("lfs", func(t *testing.T) {
		content := []byte("audit lfs upload")
		sum := sha256.Sum256(content)
		oid := hex.EncodeToString(sum[:])
		since := auditMaxID(t)
		req := NewRequestWithBody(t, "PUT", fmt.Sprintf("/user2/repo1.git/info/lfs/objects/%s/%d", oid, len(content)), bytes.NewReader(content))
		req.SetBasicAuth("user2", token)
		MakeRequest(t, req, http.StatusOK)
		e := auditActivity(t, since, "activity.upload")
		data := auditData(t, e)
		assert.Equal(t, "lfs", data["kind"])
		assert.Equal(t, "create", data["op"])
		assert.Equal(t, oid, data["object"])
		assert.EqualValues(t, len(content), data["bytes"])
		assert.Equal(t, tok.ID, e.CredentialID)
		assert.EqualValues(t, 1, e.RepoID)
	})

	t.Run("generic package and release asset: only the API entry", func(t *testing.T) {
		since := auditMaxID(t)
		MakeRequest(t, NewRequestWithBody(t, "PUT", "/api/packages/user2/generic/audit/1.0/a.bin", strings.NewReader("12345")).AddBasicAuth("user2").SetHeader("Authorization", "token "+token), http.StatusCreated)
		e := auditActivity(t, since, "activity.api.write")
		assert.EqualValues(t, 5, auditData(t, e)["bytes"])
		assert.Empty(t, auditActions(t, since, "activity.upload"))
	})

	t.Run("web attachment", func(t *testing.T) {
		session := loginUser(t, "user2")
		since := auditMaxID(t)
		createAttachment(t, session, "user2/repo1", "image.png", generateImg(), http.StatusOK)
		e := auditActivity(t, since, "activity.upload")
		data := auditData(t, e)
		assert.Equal(t, "attachment", data["kind"])
		assert.Equal(t, "create", data["op"])
		assert.Positive(t, data["bytes"])
		assert.Equal(t, audit_model.CredentialSession, e.CredentialType)
		assert.EqualValues(t, 1, e.RepoID)
	})

	t.Run("web package delete targets the owner", func(t *testing.T) {
		session := loginUser(t, "user2")
		pv, err := packages_model.GetVersionByNameAndVersion(t.Context(), 2, packages_model.TypeGeneric, "audit", "1.0")
		require.NoError(t, err)
		since := auditMaxID(t)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/-/packages/generic/audit/1.0/settings", map[string]string{"action": "delete"}), http.StatusSeeOther)
		e := auditActivity(t, since, "activity.upload")
		assert.Equal(t, "package", auditData(t, e)["kind"])
		assert.Equal(t, "delete", auditData(t, e)["op"])
		assert.EqualValues(t, 2, e.OwnerID)
		assert.Equal(t, "user2", e.TargetName)
		assert.Equal(t, strconv.FormatInt(pv.ID, 10), auditData(t, e)["object"])
	})

	t.Run("web release", func(t *testing.T) {
		session := loginUser(t, "user2")
		since := auditMaxID(t)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/releases/new", map[string]string{
			"tag_name": "audit-v1", "tag_target": "master", "title": "audit",
		}), http.StatusSeeOther)
		e := auditActivity(t, since, "activity.upload")
		assert.Equal(t, "release", auditData(t, e)["kind"])
		assert.Equal(t, "create", auditData(t, e)["op"])
		assert.Equal(t, audit_model.CredentialSession, e.CredentialType)

		since = auditMaxID(t)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/releases/edit/audit-v1", map[string]string{"title": "audit 2"}), http.StatusSeeOther)
		assert.Equal(t, "update", auditData(t, auditActivity(t, since, "activity.upload"))["op"])

		rel, err := repo_model.GetRelease(t.Context(), 1, "audit-v1")
		require.NoError(t, err)
		since = auditMaxID(t)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/user2/repo1/releases/delete?id=%d", rel.ID), nil), http.StatusOK)
		assert.Equal(t, "delete", auditData(t, auditActivity(t, since, "activity.upload"))["op"])
	})
}

func TestAuditGitReadHTTP(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		auditFresh(t)
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
		tok, err := auth_model.GetAccessTokenBySHA(t.Context(), token)
		require.NoError(t, err)

		since := auditMaxID(t)
		require.NoError(t, git.CloneWithArgs(t.Context(), git.AllowLFSFiltersArgs(), gitURL(u, "/user2/repo2.git", "user2", token).String(), t.TempDir(), git.CloneRepoOptions{})) // private: git only sends credentials when asked
		entries := auditActions(t, since, "activity.git.read")
		require.NotEmpty(t, entries) // protocol v2 sends more than one POST
		for _, e := range entries {
			assert.Equal(t, tok.ID, e.CredentialID)
			assert.EqualValues(t, 2, e.RepoID)
			assert.Equal(t, "http", auditData(t, e)["protocol"])
			assert.Equal(t, "upload-pack", auditData(t, e)["service"])
		}
		assert.Positive(t, auditData(t, entries[len(entries)-1])["bytes"])
		assertNoSecrets(t, since, token)

		// a failed read is aggregated
		audit_model.ResetActivity()
		since = auditMaxID(t)
		actor := &audit_model.Actor{Type: audit_model.ActorUser, ID: 2, Name: "user2", IP: "127.0.0.1", Credential: audit_model.Credential{Type: audit_model.CredentialAccessToken, ID: tok.ID}}
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
		for range 3 {
			common.RecordGitRead(audit_model.WithActor(t.Context(), actor), repo, "upload-pack", "http", 0, false, true)
		}
		audit_model.FlushAggregated(t.Context(), true)
		assert.EqualValues(t, 2, auditData(t, auditActivity(t, since, "activity.git.read.aggregated"))["count"])

		// git over HTTP takes no session, so a password clone is a credential read: recorded without LOG_READS
		req := NewRequestWithBody(t, "POST", "/user2/repo1.git/git-upload-pack", strings.NewReader("0000"))
		req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
		req.SetBasicAuth("user2", userPassword)
		since = auditMaxID(t)
		MakeRequest(t, req, http.StatusOK)
		assert.Equal(t, audit_model.CredentialPassword, auditActivity(t, since, "activity.git.read").CredentialType)

		// anonymous clone of a public repository: nothing
		since = auditMaxID(t)
		doGitClone(t.TempDir(), gitURL(u, "/user2/repo1.git", "", ""))(t)
		assert.Empty(t, auditActions(t, since, "activity.git.read"))
	})
}

func TestAuditJWTCredential(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	content := []byte("jwt lfs content")
	oid := storeObjectInRepo(t, 1, &content)

	get := func(t *testing.T, cred string) *audit_model.Entry {
		t.Helper()
		jwtToken, err := setting.LFS.SigningKey.JWT(lfs_module.Claims{RepoID: 1, Op: "download", UserID: 2, Cred: cred})
		require.NoError(t, err)
		since := auditMaxID(t)
		MakeRequest(t, NewRequest(t, "GET", "/user2/repo1.git/info/lfs/objects/"+oid+"/x").SetHeader("Authorization", "Bearer "+jwtToken), http.StatusOK)
		return auditActivity(t, since, "activity.download")
	}

	e := get(t, "ssh_key:1")
	assert.Equal(t, audit_model.CredentialSSHKey, e.CredentialType)
	assert.EqualValues(t, 1, e.CredentialID)
	assert.EqualValues(t, 2, e.ActorID)

	e = get(t, "deploy_key:7")
	assert.Equal(t, audit_model.ActorDeployKey, e.ActorType)
	assert.Zero(t, e.ActorID)
	assert.EqualValues(t, 1, e.RepoID)

	for _, cred := range []string{"", "session:1", "bogus:1", "ssh_key:0"} {
		assert.Equal(t, audit_model.CredentialUnknown, get(t, cred).CredentialType, cred)
	}
}

func TestAuditSudoPush(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeAll)
	tok, err := auth_model.GetAccessTokenBySHA(t.Context(), token)
	require.NoError(t, err)

	since := auditMaxID(t)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/sudo-audit.txt?sudo=user2", &api.CreateFileOptions{
		FileOptions: api.FileOptions{Message: "sudo"}, ContentBase64: "aGVsbG8=",
	}).AddTokenAuth(token), http.StatusCreated)
	e := auditActivity(t, since, "activity.git.push")
	assert.EqualValues(t, 2, e.ActorID)
	assert.EqualValues(t, 1, e.SudoByID)
	assert.Equal(t, audit_model.CredentialAccessToken, e.CredentialType)
	assert.Equal(t, tok.ID, e.CredentialID)
}

func TestAuditContainerJWTCredential(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	auditFresh(t)
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeWritePackage)
	tok, err := auth_model.GetAccessTokenBySHA(t.Context(), token)
	require.NoError(t, err)

	req := NewRequest(t, "GET", setting.AppURL+"v2/token")
	req.SetBasicAuth("user2", token)
	var tokenResponse struct {
		Token string `json:"token"`
	}
	DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &tokenResponse)

	push := func(t *testing.T, jwt string) *audit_model.Entry {
		t.Helper()
		since := auditMaxID(t)
		MakeRequest(t, NewRequestWithBody(t, "POST", setting.AppURL+"v2/user2/audit/blobs/uploads?digest=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", bytes.NewReader(nil)).AddTokenAuth("Bearer "+jwt), http.StatusCreated)
		return auditActivity(t, since, "activity.api.write")
	}

	e := push(t, tokenResponse.Token)
	assert.Equal(t, audit_model.CredentialAccessToken, e.CredentialType)
	assert.Equal(t, tok.ID, e.CredentialID)
	assert.EqualValues(t, 2, e.ActorID)

	// a JWT minted from a JWT keeps the original credential
	req = NewRequest(t, "GET", setting.AppURL+"v2/token").AddTokenAuth("Bearer " + tokenResponse.Token)
	DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &tokenResponse)
	assert.Equal(t, tok.ID, push(t, tokenResponse.Token).CredentialID)

	// a JWT without the claim
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	old, err := packages_service.CreateAuthorizationToken(user, auth_model.AccessTokenScopeAll, optional.None[timeutil.TimeStamp](), audit_model.Credential{})
	require.NoError(t, err)
	assert.Equal(t, audit_model.CredentialUnknown, push(t, old).CredentialType)
}

// TestAuditServRead covers the SSH reads at the internal API of the SSH entry point, without an SSH client.
func TestAuditServRead(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		auditFresh(t)
		serv := func(verb string) []*audit_model.Entry {
			since := auditMaxID(t)
			_, extra := private.ServCommand(t.Context(), 1, "user2", "repo1", perm.AccessModeRead, "127.0.0.1", verb, "")
			require.NoError(t, extra.Error)
			return auditActions(t, since, "activity.git.read")
		}
		for _, service := range []string{"upload-pack", "upload-archive"} {
			entries := serv("git-" + service)
			require.Len(t, entries, 1, service)
			e := entries[0]
			assert.Equal(t, audit_model.CredentialSSHKey, e.CredentialType)
			assert.EqualValues(t, 1, e.CredentialID)
			assert.EqualValues(t, 1, e.RepoID)
			data := auditData(t, e)
			assert.Equal(t, service, data["service"])
			assert.Equal(t, "ssh", data["protocol"])
			assert.Nil(t, data["bytes"])
		}
		assert.Empty(t, serv("git-lfs-authenticate"))
	})
}
