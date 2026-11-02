// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/services/forms"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An AGit PR's head branch "<user>/<topic>" is not a real branch. Merging it with "delete branch" must not delete an
// unrelated real branch of that name (here: user "release", topic "2.0" and the branch release/2.0).
func TestPullAgitMergeKeepsSameNamedBranch(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer tests.PrintCurrentTest(t)()
		require.NoError(t, user_model.CreateUser(db.DefaultContext, &user_model.User{
			Name: "release", Email: "release@example.com", Passwd: userPassword, MustChangePassword: false,
		}))
		maintainer := loginUser(t, "user2")
		baseRepo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user2", Name: "repo1"})

		dst := t.TempDir()
		remote := *u
		remote.Path = "/user2/repo1.git"
		remote.User = url.UserPassword("release", userPassword)
		t.Run("Clone", doGitClone(dst, &remote))

		agitPR := func(t *testing.T, topic string) *issues_model.PullRequest {
			testEditFileToNewBranch(t, maintainer, "user2", "repo1", "master", "release/"+topic, "README.md", "unrelated branch "+topic+"\n")
			require.NoError(t, os.WriteFile(path.Join(dst, "agit-"+topic), []byte(topic), 0o666))
			require.NoError(t, git.AddChanges(dst, true))
			sig := &git.Signature{Email: "release@example.com", Name: "release", When: time.Now()}
			require.NoError(t, git.CommitChanges(dst, git.CommitChangesOptions{Committer: sig, Author: sig, Message: "agit " + topic}))
			require.NoError(t, git.NewCommand(git.DefaultContext, "push", "origin", "HEAD:refs/for/master", "-o").
				AddDynamicArguments("topic="+topic).AddArguments("-o").AddDynamicArguments("title=agit "+topic).
				Run(&git.RunOpts{Dir: dst}))
			return unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{
				Flow: issues_model.PullRequestFlowAGit, BaseRepoID: baseRepo.ID, HeadBranch: "release/" + topic,
			})
		}

		t.Run("web", func(t *testing.T) {
			pr := agitPR(t, "2.0")
			testPullMerge(t, maintainer, "user2", "repo1", strconv.FormatInt(pr.Index, 10), repo_model.MergeStyleMerge, true)
			assert.True(t, bwBranchExists("user2", "repo1", "release/2.0"), "unrelated branch release/2.0 was deleted")

			// the cleanup button must not delete it either
			maintainer.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/user2/repo1/pulls/%d/cleanup", pr.Index)), http.StatusNotFound)
			assert.True(t, bwBranchExists("user2", "repo1", "release/2.0"), "cleanup deleted unrelated branch release/2.0")
		})

		t.Run("api", func(t *testing.T) {
			pr := agitPR(t, "3.0")
			ctx := NewAPITestContext(t, "user2", "repo1", auth_model.AccessTokenScopeWriteRepository)
			doAPIMergePullRequestForm(t, ctx, "user2", "repo1", pr.Index, &forms.MergePullRequestForm{Do: "merge", DeleteBranchAfterMerge: true})
			assert.True(t, bwBranchExists("user2", "repo1", "release/3.0"), "unrelated branch release/3.0 was deleted")
		})
	})
}

func bwBranchExists(owner, repo, branch string) bool {
	return git.IsBranchExist(db.DefaultContext, repo_model.RepoPath(owner, repo), branch)
}
