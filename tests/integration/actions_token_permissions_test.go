// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/lfs"
	"forgejo.org/modules/private"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/stretchr/testify/require"
)

func TestActionsTokenPermissions(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		// private, so that nothing is readable without the token
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
		require.True(t, repo.IsPrivate)
		otherRepo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 4})
		require.False(t, otherRepo.IsPrivate)
		original := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
		t.Cleanup(func() {
			require.NoError(t, actions_model.UpdateTask(context.Background(), original, "repo_id", "owner_id", "is_fork_pull_request", "token_permissions", "token_salt", "token_hash", "token_last_eight"))
		})

		taskToken := func(t *testing.T, tokenPermissions string, isFork bool) string {
			t.Helper()
			task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
			task.RepoID = repo.ID
			task.OwnerID = repo.OwnerID
			task.IsForkPullRequest = isFork
			task.TokenPermissions = tokenPermissions
			task.GenerateToken()
			require.NoError(t, actions_model.UpdateTask(t.Context(), task, "repo_id", "owner_id", "is_fork_pull_request", "token_permissions", "token", "token_salt", "token_hash", "token_last_eight"))
			return task.Token
		}

		t.Run("read-all can't open a pull request", func(t *testing.T) {
			// repo1 has pull requests: the task is bound to it for this test only
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
			task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
			createPull := func(tokenPermissions string, status int) {
				t.Helper()
				changed := *task
				changed.RepoID = repo.ID
				changed.OwnerID = repo.OwnerID
				changed.TokenPermissions = tokenPermissions
				changed.GenerateToken()
				require.NoError(t, actions_model.UpdateTask(t.Context(), &changed, "repo_id", "owner_id", "token_permissions", "token", "token_salt", "token_hash", "token_last_eight"))
				MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/%s/%s/pulls", repo.OwnerName, repo.Name),
					&api.CreatePullRequestOption{Head: "master", Base: "master", Title: "from a job"}).AddTokenAuth(changed.Token), status)
			}
			// as today: the request reaches the handler, which refuses the same head and base
			createPull("", http.StatusUnprocessableEntity)
			readAll := actions_model.TokenPermissions{}
			for _, t := range unit.AllRepoUnitTypes {
				readAll[t] = perm.AccessModeRead
			}
			createPull(readAll.Encode(), http.StatusNotFound)
		})

		t.Run("pre-receive decides from the task", func(t *testing.T) {
			hook := func(taskID int64) error {
				return private.HookPreReceive(t.Context(), repoIDByName(t, repo.OwnerName, repo.Name), private.HookOptions{
					OldCommitIDs: []string{git.Sha1ObjectFormat.EmptyObjectID().String()},
					NewCommitIDs: []string{"2a47ca4b614a9f5a43abbd5ad851a54a616ffee6"},
					RefFullNames: []git.RefName{git.RefNameFromBranch("job-token-hook")},
					UserID:       user_model.ActionsUserID,
					ActionTaskID: taskID,
				}).Error
			}
			// a push by the server as the Actions user, without a task
			require.ErrorContains(t, hook(0), "status=403")
			require.ErrorContains(t, hook(99999999), "status=500")
			taskToken(t, actions_model.TokenPermissions{unit.TypeCode: perm.AccessModeRead}.Encode(), false)
			require.ErrorContains(t, hook(47), "status=403")
			taskToken(t, actions_model.TokenPermissions{unit.TypeCode: perm.AccessModeWrite}.Encode(), true)
			require.ErrorContains(t, hook(47), "status=403")
		})

		read, write := perm.AccessModeRead, perm.AccessModeWrite
		contents := func(mode perm.AccessMode) actions_model.TokenPermissions {
			return actions_model.TokenPermissions{unit.TypeCode: mode, unit.TypeReleases: mode, unit.TypeWiki: mode}
		}
		all := func(mode perm.AccessMode) string {
			p := actions_model.TokenPermissions{}
			for _, t := range unit.AllRepoUnitTypes {
				p[t] = mode
			}
			return p.Encode()
		}

		for _, tc := range []struct {
			name             string
			tokenPermissions string
			isFork           bool
			readIssues       int
			createIssue      int
			comment          int
			clone            bool
			push             bool
			lfsDownload      int
			lfsUpload        int
		}{
			{name: "legacy", readIssues: http.StatusOK, createIssue: http.StatusCreated, comment: http.StatusCreated, clone: true, push: true, lfsDownload: http.StatusOK, lfsUpload: http.StatusOK},
			{name: "legacy fork", isFork: true, readIssues: http.StatusOK, createIssue: http.StatusCreated, comment: http.StatusCreated, clone: true, lfsDownload: http.StatusOK, lfsUpload: http.StatusUnauthorized},
			{name: "write-all", tokenPermissions: all(write), readIssues: http.StatusOK, createIssue: http.StatusCreated, comment: http.StatusCreated, clone: true, push: true, lfsDownload: http.StatusOK, lfsUpload: http.StatusOK},
			{name: "fork write-all", tokenPermissions: all(write), isFork: true, readIssues: http.StatusOK, createIssue: http.StatusNotFound, comment: http.StatusNotFound, clone: true, lfsDownload: http.StatusOK, lfsUpload: http.StatusUnauthorized},
			{name: "read-all", tokenPermissions: all(read), readIssues: http.StatusOK, createIssue: http.StatusNotFound, comment: http.StatusNotFound, clone: true, lfsDownload: http.StatusOK, lfsUpload: http.StatusUnauthorized},
			{name: "contents read", tokenPermissions: contents(read).Encode(), readIssues: http.StatusNotFound, createIssue: http.StatusNotFound, comment: http.StatusNotFound, clone: true, lfsDownload: http.StatusOK, lfsUpload: http.StatusUnauthorized},
			{
				name:             "contents write issues read",
				tokenPermissions: actions_model.TokenPermissions{unit.TypeCode: write, unit.TypeIssues: read}.Encode(),
				readIssues:       http.StatusOK, createIssue: http.StatusNotFound, comment: http.StatusNotFound, clone: true, push: true, lfsDownload: http.StatusOK, lfsUpload: http.StatusOK,
			},
			{
				name:             "issues write",
				tokenPermissions: actions_model.TokenPermissions{unit.TypeIssues: write}.Encode(),
				readIssues:       http.StatusOK, createIssue: http.StatusCreated, comment: http.StatusCreated, lfsDownload: http.StatusUnauthorized, lfsUpload: http.StatusUnauthorized,
			},
			{name: "nothing", tokenPermissions: "{}", readIssues: http.StatusNotFound, createIssue: http.StatusNotFound, comment: http.StatusNotFound, lfsDownload: http.StatusUnauthorized, lfsUpload: http.StatusUnauthorized},
		} {
			t.Run(tc.name, func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()
				token := taskToken(t, tc.tokenPermissions, tc.isFork)
				apiRepo := fmt.Sprintf("/api/v1/repos/%s/%s", repo.OwnerName, repo.Name)

				MakeRequest(t, NewRequest(t, "GET", apiRepo+"/issues").AddTokenAuth(token), tc.readIssues)
				MakeRequest(t, NewRequestWithJSON(t, "POST", apiRepo+"/issues", &api.CreateIssueOption{Title: "from a job"}).AddTokenAuth(token), tc.createIssue)
				MakeRequest(t, NewRequestWithJSON(t, "POST", apiRepo+"/issues/1/comments", &api.CreateIssueCommentOption{Body: "from a job"}).AddTokenAuth(token), tc.comment)
				// another repository, even a public one, stays out of reach
				MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/%s/%s", otherRepo.OwnerName, otherRepo.Name)).AddTokenAuth(token), http.StatusNotFound)

				lfsRequest := func(operation string) *RequestWrapper {
					req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/%s/%s.git/info/lfs/objects/batch", repo.OwnerName, repo.Name), &lfs.BatchRequest{
						Operation: operation,
						Objects:   []lfs.Pointer{{Oid: "83de2e488b89a0aa1c97496b888120a28b0c1e15463a4adb8405578c540f36d4", Size: 6}},
					}).SetHeader("Accept", lfs.AcceptHeader).SetHeader("Content-Type", lfs.MediaType)
					req.Request.SetBasicAuth("token", token)
					return req
				}
				MakeRequest(t, lfsRequest("download"), tc.lfsDownload)
				MakeRequest(t, lfsRequest("upload"), tc.lfsUpload)

				gitURL := *u
				gitURL.Path = fmt.Sprintf("/%s/%s.git", repo.OwnerName, repo.Name)
				gitURL.User = url.UserPassword("token", token)
				if !tc.clone {
					doGitCloneFail(&gitURL)(t)
					return
				}
				dstPath := t.TempDir()
				require.NoError(t, git.Clone(t.Context(), gitURL.String(), dstPath, git.CloneRepoOptions{}))
				doGitSetRemoteURL(dstPath, "origin", &gitURL)(t)
				branch := "job-token-" + strings.ReplaceAll(tc.name, " ", "-")
				doGitCreateBranch(dstPath, branch)(t)
				doGitAddSomeCommits(dstPath, branch)(t)
				if tc.push {
					doGitPushTestRepository(dstPath, "origin", branch)(t)
				} else {
					doGitPushTestRepositoryFail(t, dstPath, "origin", branch)
				}
			})
		}
	})
}
