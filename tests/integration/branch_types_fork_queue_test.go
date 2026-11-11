// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/git"
	"forgejo.org/modules/private"
	api "forgejo.org/modules/structs"
	"forgejo.org/services/forms"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A pull request that the merge queue merges, from a release branch, under "Always": the merge is done, the branch is
// kept and the timeline says why.
func TestBranchTypesMergeQueueKept(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-queue")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{DevelopmentBranch: "develop", ReleasePrefixes: []string{"release/"}}, http.StatusOK)
		bwRepoPost(t, owner, "org3", repo, "always", http.StatusSeeOther)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", path.Join("org3", repo, "settings/branches/edit"), map[string]string{
			"rule_name": "master", "enable_push": "all", "enable_status_check": "true", "status_check_contexts": "ci", "require_merge_queue": "true",
		}), http.StatusSeeOther)
		r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})

		testNewFileToNewBranch(t, owner, "org3", repo, "master", "release/1.0", "rel.txt", "rel\n")
		var pull api.PullRequest
		DecodeJSON(t, ctx.Session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/"+repo+"/pulls", &api.CreatePullRequestOption{Head: "release/1.0", Base: "master", Title: "rel"}).AddTokenAuth(ctx.Token), http.StatusCreated), &pull)
		ctx.Username, ctx.Reponame = "org3", repo
		setStatus(t, ctx, pull.Head.Sha, api.CommitStatusSuccess)

		var e api.MergeQueueEntry
		req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/org3/%s/pulls/%d/merge-queue", repo, pull.Index), &forms.MergePullRequestForm{Do: "merge"}).AddTokenAuth(ctx.Token)
		DecodeJSON(t, ctx.Session.MakeRequest(t, req, http.StatusCreated), &e)
		require.NotEmpty(t, e.TestSHA)
		setStatus(t, ctx, e.TestSHA, api.CommitStatusSuccess)

		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: r.ID, Index: pull.Index})
		require.True(t, pr.HasMerged)
		assert.True(t, bwBranchExists("org3", repo, "release/1.0"))
		body := owner.MakeRequest(t, NewRequest(t, "GET", path.Join("org3", repo, "pulls", fmt.Sprint(pull.Index))), http.StatusOK).Body.String()
		assert.Contains(t, body, "did not delete the head branch")
		assert.Contains(t, body, "it is a release branch")
	})
}

// The merged pull request of a fork whose head branch the model of the fork keeps: somebody who can't write the fork
// learns nothing of its model (permission code, plain flash), and a reader of the base repository who can't read the
// fork sees only that the branch was kept.
func TestBranchTypesForkKeptGenericText(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-fork")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		forker := loginUser(t, "user4")
		forkCtx := NewAPITestContext(t, "user4", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		bwRepoPost(t, owner, "org3", repo, "always", http.StatusSeeOther)
		testRepoFork(t, forker, "org3", repo, "user4", repo)
		_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET is_private = ? WHERE owner_name = ? AND name = ?", true, "user4", repo)
		require.NoError(t, err)
		req := NewRequestWithJSON(t, "PUT", "/api/v1/repos/user4/"+repo+"/branching-model", &api.EditRepoBranchingModelOption{ReleasePrefixes: []string{"release/"}}).AddTokenAuth(forkCtx.Token)
		forkCtx.Session.MakeRequest(t, req, http.StatusOK)
		base := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})
		require.True(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user4", Name: repo}).IsPrivate, "the fork is private")

		newPR := func(branch string) (string, int64) {
			testNewFileToNewBranch(t, forker, "user4", repo, "master", branch, strings.ReplaceAll(branch, "/", "-")+".txt", "from fork "+branch+"\n")
			testPullCreateDirectly(t, forker, "org3", repo, "master", "user4", repo, branch, "PR "+branch)
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: base.ID, HeadBranch: branch})
			return fmt.Sprint(pr.Index), pr.Index
		}

		// the merger can't write the fork: refused with the permission code, nothing about the model
		idx, n := newPR("release/9.0")
		ctx.ExpectedCode = http.StatusForbidden
		resp := doAPIMergePullRequestForm(t, ctx, "org3", repo, n, &forms.MergePullRequestForm{Do: "merge", DeleteBranchAfterMerge: true})
		ctx.ExpectedCode = 0
		assert.Equal(t, "permission", resp.Header().Get("X-Branch-Kept"))
		assert.NotContains(t, resp.Body.String(), "release")
		_ = idx

		// web, under Always: a plain flash
		idx, _ = newPR("release/9.1")
		testPullMerge(t, owner, "org3", repo, idx, repo_model.MergeStyleMerge, false)
		assert.NotContains(t, bwFlash(owner), "release branch")
		assert.True(t, git.IsBranchExist(t.Context(), repo_model.RepoPath("user4", repo), "release/9.1"))

		// the merger may write the fork now: the reason is the merger's to read, the other reader gets the short text
		forkCtx.Session.MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user4/"+repo+"/collaborators/user2", map[string]string{"permission": "write"}).AddTokenAuth(forkCtx.Token), http.StatusNoContent)
		idx, _ = newPR("release/9.2")
		testPullMerge(t, owner, "org3", repo, idx, repo_model.MergeStyleMerge, false)
		assert.True(t, git.IsBranchExist(t.Context(), repo_model.RepoPath("user4", repo), "release/9.2"))
		page := path.Join("org3", repo, "pulls", idx)
		assert.Contains(t, owner.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body.String(), "it is a release branch")
		other := loginUser(t, "user8")
		body := other.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body.String()
		assert.Contains(t, body, "The branch was kept.")
		assert.NotContains(t, body, "it is a release branch")
	})
}

// The link after a push to a fork names the base the base repository's model chooses only for a pusher who can read
// that repository; anybody else gets the default branch.
func TestBranchTypesPostPushLinkNoRead(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-nolink")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		testAPICreateBranch(t, owner, "org3", repo, "master", "develop", http.StatusCreated)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{
			DevelopmentBranch: "develop", ReleasePrefixes: []string{"release/"},
			Types: []api.BranchType{{Name: "Feature", Prefix: "feature/", Base: "development"}},
		}, http.StatusOK)
		forker := loginUser(t, "user4")
		testRepoFork(t, forker, "org3", repo, "user4", repo)
		testEditFileToNewBranch(t, forker, "user4", repo, "master", "feature/x", "README.md", "x\n")
		fork := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user4", Name: repo})
		tip := func() string {
			g, err := git.OpenRepository(t.Context(), fork.RepoPath())
			require.NoError(t, err)
			defer g.Close()
			id, err := g.GetBranchCommitID("feature/x")
			require.NoError(t, err)
			return id
		}()
		link := func() string {
			res, extra := private.HookPostReceive(t.Context(), fork.ID, private.HookOptions{
				UserID: 4, OldCommitIDs: []string{git.Sha1ObjectFormat.EmptyObjectID().String()}, NewCommitIDs: []string{tip},
				RefFullNames: []git.RefName{git.RefNameFromBranch("feature/x")},
			})
			require.NoError(t, extra.Error)
			require.NotEmpty(t, res.Results)
			return res.Results[0].CreateURL
		}
		assert.Contains(t, link(), "/compare/develop...user4:feature/x")

		// the base repository becomes private: the forker no longer reads it, so its model must not choose the target
		ctx.Session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/"+repo, map[string]any{"private": true}).AddTokenAuth(ctx.Token), http.StatusOK)
		got := link()
		assert.Contains(t, got, "/compare/master...", got)
		assert.NotContains(t, got, "develop")
	})
}
