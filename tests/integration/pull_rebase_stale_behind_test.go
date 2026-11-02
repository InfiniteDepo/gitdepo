// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/url"
	"strings"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/services/forms"
	repo_service "forgejo.org/services/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The base branch moves after the pull request was opened, and the asynchronous refresh of the
// stored commits_behind has not run yet: a rebase merge must still rebase.
func TestPullRebaseMergeStaleCommitsBehind(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		ctx := NewAPITestContext(t, "user2", "", auth_model.AccessTokenScopeWriteRepository)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		repo, err := repo_service.CreateRepository(db.DefaultContext, user2, user2, repo_service.CreateRepoOptions{
			Name: "rebase-stale-behind", AutoInit: true, Readme: "Default", DefaultBranch: "main",
		})
		require.NoError(t, err)
		revertTestCommit(t, repo, "main", "feature", "create", "a.txt", "a\n")
		_, err = doAPICreatePullRequest(ctx, "user2", repo.Name, "main", "feature")(t)
		require.NoError(t, err)
		revertTestCommit(t, repo, "main", "main", "create", "before.txt", "before\n")

		// Let the refresh of the push finish, then put back the value it would have replaced.
		assert.Eventually(t, func() bool {
			pr, err := issues_model.GetPullRequestByIndex(db.DefaultContext, repo.ID, 1)
			return err == nil && pr.CommitsBehind == 1
		}, 10*time.Second, 50*time.Millisecond)
		_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE pull_request SET commits_behind = 0 WHERE base_repo_id = ?", repo.ID)
		require.NoError(t, err)
		premerge, err := gitrepo.GetBranchCommitID(db.DefaultContext, repo, "main")
		require.NoError(t, err)
		doAPIMergePullRequestForm(t, ctx, "user2", repo.Name, 1, &forms.MergePullRequestForm{Do: string(repo_model.MergeStyleRebase)})

		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, Index: 1})
		assert.True(t, pr.HasMerged)
		// The PR's commit was rebased on the moved base: it sits directly on top of it.
		tip, err := gitrepo.GetBranchCommitID(db.DefaultContext, repo, "main")
		require.NoError(t, err)
		parent, _, err := git.NewCommand(t.Context(), "rev-parse").AddDynamicArguments(tip + "^").RunStdString(&git.RunOpts{Dir: repo.RepoPath()})
		require.NoError(t, err)
		assert.Equal(t, premerge, strings.TrimSpace(parent))
	})
}
