// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	api "forgejo.org/modules/structs"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"
	"forgejo.org/tests/forgery"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// R2-2: DeleteBranch called with the commit the caller checked, after the branch moved: refused, nothing deleted,
// nothing recorded.
func TestBranchTypesDeleteStaleExpected(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-stale")
		owner := loginUser(t, "user2")
		testNewFileToNewBranch(t, owner, "org3", repo, "master", "moving", "m.txt", "one\n")
		stale := btTip(t, repo, "moving")
		testEditFileToNewBranch(t, owner, "org3", repo, "moving", "moving", "m.txt", "two\n")
		moved := btTip(t, repo, "moving")
		require.NotEqual(t, stale, moved)

		r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})
		doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		gitRepo, err := git.OpenRepository(t.Context(), r.RepoPath())
		require.NoError(t, err)
		defer gitRepo.Close()
		since := auditMaxID(t)
		err = repo_service.DeleteBranch(t.Context(), doer, r, gitRepo, "moving", stale)
		require.True(t, errors.Is(err, repo_service.ErrBranchHasNewCommits), "%v", err)
		assert.Equal(t, moved, btTip(t, repo, "moving"))
		if b, err := git_model.GetBranch(t.Context(), r.ID, "moving"); err == nil {
			assert.False(t, b.IsDeleted)
		}
		assert.Zero(t, btDeletedAudits(t, since))
		// the commit that was checked deletes it
		require.NoError(t, repo_service.DeleteBranch(t.Context(), doer, r, gitRepo, "moving", moved))
		assert.False(t, bwBranchExists("org3", repo, "moving"))
	})
}

// R2-1: the largest valid model, every value full of characters that JSON escapes, saves (the audit entry shrinks).
func TestBranchTypesMaximalModelSaves(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-max")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		types := make([]api.BranchType, 20)
		for i := range types {
			types[i] = api.BranchType{
				Name:   strings.Repeat("&", 40) + string(rune('A'+i)),
				Prefix: strings.Repeat("<", 49) + string(rune('a'+i)) + strings.Repeat(">", 49) + "/",
				Base:   "branch", BaseBranch: strings.Repeat("&", 250) + string(rune('a'+i)),
			}
		}
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{ReleasePrefixes: []string{"release/"}, Types: types}, http.StatusOK)
		btOrgModel(t, ctx, &api.OrgBranchingModel{ReleasePrefixes: []string{"release/"}, Types: types}, http.StatusOK)
		btOrgModel(t, ctx, &api.OrgBranchingModel{}, http.StatusOK)
	})
}

// R2-3, R2-4, R2-5: "Delete branch" is not offered for a kept head on a closed or merged pull request and the page says
// why; only a pull request that carries a branch forward loses the merge box note.
func TestBranchTypesKeptNotes(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-notes")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		testAPICreateBranch(t, owner, "org3", repo, "master", "develop", http.StatusCreated)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{DevelopmentBranch: "develop", ReleasePrefixes: []string{"release/"}, MergeForward: true}, http.StatusOK)
		bwRepoPost(t, owner, "org3", repo, "never", http.StatusSeeOther)
		page := func(idx string) string {
			return owner.MakeRequest(t, NewRequest(t, "GET", path.Join("org3", repo, "pulls", idx)), http.StatusOK).Body.String()
		}

		// open, an ordinary pull request from a release branch into master (not carried forward): the note stays
		idx := bwPR(t, owner, "org3", repo, "master", "release/2.0")
		assert.Contains(t, page(idx), "release/2.0 will be kept")

		// closed, unmerged: no button, a note
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", path.Join("org3", repo, "issues", idx, "comments"), map[string]string{"status": "close"}), http.StatusOK)
		body := page(idx)
		assert.NotContains(t, body, `data-modal-id="delete-branch"`)
		assert.Contains(t, body, "release/2.0 is kept")

		// a pull request that carries release/1.0 forward to develop: no note, no box
		idx = bwPR(t, owner, "org3", repo, "develop", "release/1.0")
		assert.NotContains(t, page(idx), "release/1.0 will be kept")
		// and forward to a later release branch; backwards is no merge forward, so the note stays
		idx = bwPR(t, owner, "org3", repo, "release/2.0", "release/1.0")
		assert.NotContains(t, page(idx), "release/1.0 will be kept")
		idx = bwPR(t, owner, "org3", repo, "release/1.0", "release/2.0")
		assert.Contains(t, page(idx), "release/2.0 will be kept")

		// merged: no button, a note
		idx = bwPR(t, owner, "org3", repo, "master", "release/3.0")
		testPullMerge(t, owner, "org3", repo, idx, repo_model.MergeStyleMerge, false)
		body = page(idx)
		assert.NotContains(t, body, `data-modal-id="delete-branch"`)
		assert.Contains(t, body, "release/3.0 is kept")
	})
}

// A fork's pull request created through the API without a base uses the base repository's model.
func TestBranchTypesAPIForkNoBase(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-forknobase")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		testAPICreateBranch(t, owner, "org3", repo, "master", "develop", http.StatusCreated)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{
			DevelopmentBranch: "develop", ReleasePrefixes: []string{"release/"},
			Types: []api.BranchType{{Name: "Feature", Prefix: "feature/", Base: "development"}},
		}, http.StatusOK)
		forker := loginUser(t, "user4")
		forkCtx := NewAPITestContext(t, "user4", repo, auth_model.AccessTokenScopeWriteRepository)
		testRepoFork(t, forker, "org3", repo, "user4", repo)
		testNewFileToNewBranch(t, forker, "user4", repo, "master", "feature/fork", "f.txt", "f\n")
		req := NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/"+repo+"/pulls", &api.CreatePullRequestOption{Head: "user4:feature/fork", Title: "from the fork"}).AddTokenAuth(forkCtx.Token)
		var pr api.PullRequest
		DecodeJSON(t, forkCtx.Session.MakeRequest(t, req, http.StatusCreated), &pr)
		assert.Equal(t, "develop", pr.Base.Ref)
	})
}

// U4: the stack merge dialog counts only the branches it can delete, and the merge deletes through the shared kept
// check: a release branch in the chain survives the "delete branches" box.
func TestBranchTypesStackMergeKept(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		owner := loginUser(t, "user2")
		repo := forgery.CreateRepository(t, user2, &forgery.CreateRepositoryOptions{
			Files: forgery.MapFS{"README.md": forgery.MapFile("stack")},
		})
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		owner.MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/"+repo.Name+"/branching-model", &api.EditRepoBranchingModelOption{ReleasePrefixes: []string{"release/"}}).AddTokenAuth(token), http.StatusOK)

		stackCommit(t, user2, repo, "main", "a", "create", "a.txt", "a")
		a := stackPull(t, user2, repo, "main", "a")
		stackCommit(t, user2, repo, "a", "release/2.0", "create", "r.txt", "r")
		r := stackPull(t, user2, repo, "a", "release/2.0")
		stackCommit(t, user2, repo, "release/2.0", "c", "create", "c.txt", "c")
		c := stackPull(t, user2, repo, "release/2.0", "c")

		// the dialog: the box is ticked for the two deletable branches only and says that one is kept
		doc := stackPage(t, owner, repo, c)
		label := strings.Join(strings.Fields(doc.Find(`label[for="merge-stack-delete"]`).Text()), " ")
		assert.Equal(t, "Delete the 2 merged branches", label)
		assert.Contains(t, strings.Join(strings.Fields(doc.Find("#merge-stack-kept").Text()), " "), "kept")

		flash := postMergeStack(t, owner, repo, c, stackValues(stackFormHeads(doc), true))
		assert.Contains(t, flash, "The head branch was kept because it is a release branch")
		assert.Contains(t, flash, "Merged 3 pull requests into main.")
		assertMerged(t, true, a, r, c)
		assert.False(t, git.IsBranchExist(t.Context(), repo.RepoPath(), "a"))
		assert.True(t, git.IsBranchExist(t.Context(), repo.RepoPath(), "release/2.0"), "the release branch is kept")
		assert.False(t, git.IsBranchExist(t.Context(), repo.RepoPath(), "c"))
	})
}

// RT1: the kept reason in the timeline of a merged pull request is shown only to those who can read the code of the
// repository, not to a reader who has the pull requests unit only.
func TestBranchTypesKeptReasonNeedsCodeRead(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-leak")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		ctx.Session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/"+repo, map[string]any{"private": true}).AddTokenAuth(ctx.Token), http.StatusOK)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{ReleasePrefixes: []string{"rel/"}}, http.StatusOK)
		bwRepoPost(t, owner, "org3", repo, "always", http.StatusSeeOther)

		var team api.Team
		DecodeJSON(t, ctx.Session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/teams", &api.CreateTeamOption{
			Name: "bt-pulls-only", Permission: "read", UnitsMap: map[string]string{"repo.pulls": "read", "repo.issues": "read"},
		}).AddTokenAuth(ctx.Token), http.StatusCreated), &team)
		ctx.Session.MakeRequest(t, NewRequest(t, "PUT", fmt.Sprintf("/api/v1/teams/%d/members/user8", team.ID)).AddTokenAuth(ctx.Token), http.StatusNoContent)
		ctx.Session.MakeRequest(t, NewRequest(t, "PUT", fmt.Sprintf("/api/v1/teams/%d/repos/org3/%s", team.ID, repo)).AddTokenAuth(ctx.Token), http.StatusNoContent)

		idx := bwPR(t, owner, "org3", repo, "master", "rel/5.0")
		testPullMerge(t, owner, "org3", repo, idx, repo_model.MergeStyleMerge, false)
		require.True(t, bwBranchExists("org3", repo, "rel/5.0"))

		link := path.Join("org3", repo, "pulls", idx)
		assert.Contains(t, owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body.String(), "it is a release branch")
		reader := loginUser(t, "user8")
		body := reader.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body.String()
		assert.NotContains(t, body, "it is a release branch")
		assert.Contains(t, body, "The branch was kept.")
	})
}
