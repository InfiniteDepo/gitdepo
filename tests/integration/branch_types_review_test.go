// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/private"
	api "forgejo.org/modules/structs"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/forms"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"
	"forgejo.org/tests/forgery"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func btTip(t *testing.T, repo, branch string) string {
	t.Helper()
	gitRepo, err := git.OpenRepository(t.Context(), repo_model.RepoPath("org3", repo))
	require.NoError(t, err)
	defer gitRepo.Close()
	id, err := gitRepo.GetBranchCommitID(branch)
	require.NoError(t, err)
	return id
}

func btDeletedAudits(t *testing.T, since int64) int64 {
	t.Helper()
	n, err := db.GetEngine(t.Context()).Table("audit_event").Where("id > ? AND action = ?", since, "repo.branch.deleted").Count()
	require.NoError(t, err)
	return n
}

// W1: a push that lands between the check of the caller and the deletion is never deleted with its commits: the
// deletion is a compare-and-swap on the commit that was checked, and nothing is recorded.
func TestBranchTypesDeleteSwap(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-swap")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		bwRepoPost(t, owner, "org3", repo, "always", http.StatusSeeOther)
		testNewFileToNewBranch(t, owner, "org3", repo, "master", "pushed", "pushed.txt", "the late push\n")
		pushed := btTip(t, repo, "pushed")
		r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})

		// the hook is where the other push lands: it moves the branch to the commit of "pushed"
		arm := func(target string) {
			repo_service.DeleteBranchTestHook = func(hr *repo_model.Repository, branch string) {
				if hr.ID == r.ID && branch == target {
					_, _, err := git.NewCommand(t.Context(), "update-ref").AddDynamicArguments("refs/heads/"+branch, pushed).RunStdString(&git.RunOpts{Dir: hr.RepoPath()})
					assert.NoError(t, err)
				}
			}
		}
		defer func() { repo_service.DeleteBranchTestHook = nil }()
		survived := func(branch string) {
			t.Helper()
			assert.True(t, bwBranchExists("org3", repo, branch), branch)
			assert.Equal(t, pushed, btTip(t, repo, branch), "the pushed commit survives")
			b, err := git_model.GetBranch(t.Context(), r.ID, branch)
			if err == nil {
				assert.False(t, b.IsDeleted, "no deleted_branch row")
			}
		}

		// web merge: the merge is done, the branch stays, the flash says why
		since := auditMaxID(t)
		idx := bwPR(t, owner, "org3", repo, "master", "feature/web")
		arm("feature/web")
		testPullMerge(t, owner, "org3", repo, idx, repo_model.MergeStyleMerge, false)
		survived("feature/web")
		assert.Contains(t, bwFlash(owner), "new commits")
		assert.Zero(t, btDeletedAudits(t, since), "no audit row")

		// API merge that asked for the deletion: 403 and the code in the header
		idx = bwPR(t, owner, "org3", repo, "master", "feature/api")
		n, err := strconv.ParseInt(idx, 10, 64)
		require.NoError(t, err)
		arm("feature/api")
		ctx.ExpectedCode = http.StatusForbidden
		resp := doAPIMergePullRequestForm(t, ctx, "org3", repo, n, &forms.MergePullRequestForm{Do: "merge", DeleteBranchAfterMerge: true})
		ctx.ExpectedCode = 0
		assert.Equal(t, "new_commits", resp.Header().Get("X-Branch-Kept"))
		survived("feature/api")
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: r.ID, HeadBranch: "feature/api"})
		assert.True(t, pr.HasMerged)

		// API merge where the setting forced the deletion: 200, still the header
		idx = bwPR(t, owner, "org3", repo, "master", "feature/forced")
		n, _ = strconv.ParseInt(idx, 10, 64)
		arm("feature/forced")
		resp = doAPIMergePullRequestForm(t, ctx, "org3", repo, n, &forms.MergePullRequestForm{Do: "merge"})
		assert.Equal(t, "new_commits", resp.Header().Get("X-Branch-Kept"))
		survived("feature/forced")

		// the Branches page and the API delete: 409 and a flash, nothing deleted
		testNewFileToNewBranch(t, owner, "org3", repo, "master", "manual", "manual.txt", "x\n")
		arm("manual")
		req := NewRequest(t, "DELETE", "/api/v1/repos/org3/"+repo+"/branches/manual").AddTokenAuth(ctx.Token)
		ctx.Session.MakeRequest(t, req, http.StatusConflict)
		survived("manual")
		testNewFileToNewBranch(t, owner, "org3", repo, "master", "manual2", "manual2.txt", "x\n")
		arm("manual2")
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", path.Join("org3", repo, "branches/delete")+"?name=manual2", nil), http.StatusOK)
		survived("manual2")
		assert.Zero(t, btDeletedAudits(t, since), "no audit row")

		// a branch that doesn't exist is a 404, not a server error
		ctx.Session.MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/org3/"+repo+"/branches/not-there").AddTokenAuth(ctx.Token), http.StatusNotFound)

		// without the other push the same requests delete
		repo_service.DeleteBranchTestHook = nil
		testNewFileToNewBranch(t, owner, "org3", repo, "master", "plain", "plain.txt", "x\n")
		ctx.Session.MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/org3/"+repo+"/branches/plain").AddTokenAuth(ctx.Token), http.StatusNoContent)
		assert.False(t, bwBranchExists("org3", repo, "plain"))
		assert.EqualValues(t, 1, btDeletedAudits(t, since))
	})
}

// The "Delete branch" button of a merged pull request follows the kept rules of delete-after-merge, including the
// base of a type and the default pull request target; the Branches page stays governed by the protection rules only.
// A child pull request whose head is the new base doesn't turn the merge into a server error.
func TestBranchTypesCleanupKept(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-cleanup")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{
			DevelopmentBranch: "develop", ReleasePrefixes: []string{"release/"}, DefaultPRTarget: "staging",
			Types: []api.BranchType{{Name: "Docs", Prefix: "docs/", Base: "branch", BaseBranch: "docs-base"}},
		}, http.StatusOK)
		bwRepoPost(t, owner, "org3", repo, "never", http.StatusSeeOther)
		r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})
		page := func(idx string) *HTMLDoc {
			return NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", path.Join("org3", repo, "pulls", idx)), http.StatusOK).Body)
		}

		for head, reason := range map[string]string{"develop": "development branch", "staging": "base of a branch type or the default", "docs-base": "base of a branch type or the default", "release/1": "release branch"} {
			idx := bwPR(t, owner, "org3", repo, "master", head)
			testPullMerge(t, owner, "org3", repo, idx, repo_model.MergeStyleMerge, false)
			page(idx).AssertElement(t, `button[data-modal-id="delete-branch"]`, false)
			owner.MakeRequest(t, NewRequest(t, "POST", path.Join("org3", repo, "pulls", idx, "cleanup")), http.StatusOK)
			assert.True(t, bwBranchExists("org3", repo, head), head)
			assert.Contains(t, bwFlash(owner), reason)
		}

		// a plain branch is offered and deleted
		idx := bwPR(t, owner, "org3", repo, "master", "feature/plain")
		testPullMerge(t, owner, "org3", repo, idx, repo_model.MergeStyleMerge, false)
		page(idx).AssertElement(t, `button[data-modal-id="delete-branch"]`, true)
		owner.MakeRequest(t, NewRequest(t, "POST", path.Join("org3", repo, "pulls", idx, "cleanup")), http.StatusOK)
		assert.False(t, bwBranchExists("org3", repo, "feature/plain"))

		// the Branches page deletes a type's base all the same: only protection rules govern it
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", path.Join("org3", repo, "branches/delete")+"?name=docs-base", nil), http.StatusOK)
		assert.False(t, bwBranchExists("org3", repo, "docs-base"))

		// a child pull request whose head is already part of the base the parent's children move to: the merge is a success, the
		// parent's branch is kept (it cannot be retargeted away)
		bwRepoPost(t, owner, "org3", repo, "always", http.StatusSeeOther)
		testNewFileToNewBranch(t, owner, "org3", repo, "master", "parent", "parent.txt", "p\n")
		testEditFile(t, owner, "org3", repo, "master", "README.md", "master moved on\n")
		testAPICreateBranch(t, owner, "org3", repo, "master", "kid", http.StatusCreated)
		ctx.Session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/"+repo+"/pulls", &api.CreatePullRequestOption{Head: "kid", Base: "parent", Title: "child"}).AddTokenAuth(ctx.Token), http.StatusCreated)
		idx = bwPR(t, owner, "org3", repo, "master", "parent")
		testPullMerge(t, owner, "org3", repo, idx, repo_model.MergeStyleMerge, false)
		parent := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: r.ID, HeadBranch: "parent", BaseBranch: "master"})
		assert.True(t, parent.HasMerged)
		assert.True(t, bwBranchExists("org3", repo, "parent"))
	})
}

// Auto merge really merges, and the kept branch is explained in the timeline.
func TestBranchTypesAutoMergeKept(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-auto")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{DevelopmentBranch: "develop", ReleasePrefixes: []string{"release/"}}, http.StatusOK)
		bwRepoPost(t, owner, "org3", repo, "always", http.StatusSeeOther)
		bwProtect(t, ctx, repo, "master", parameterProtectBranch{"enable_push": "true", "enable_status_check": "true", "status_check_contexts": "gitea/actions"})
		r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})

		idx := bwPR(t, owner, "org3", repo, "master", "release/3.0")
		testPullMergeForm(t, owner, http.StatusOK, "org3", repo, idx, optionsPullMerge{"do": "merge", "merge_when_checks_succeed": "true", "delete_branch_after_merge": "true"})
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: r.ID, HeadBranch: "release/3.0"})
		require.False(t, pr.HasMerged)
		ctx.Username, ctx.Reponame = "org3", repo
		doAPICreateCommitStatus(ctx, btTip(t, repo, "release/3.0"), api.CreateStatusOption{State: api.CommitStatusSuccess, Context: "gitea/actions"})(t)
		pr = unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
		assert.True(t, pr.HasMerged)
		assert.True(t, bwBranchExists("org3", repo, "release/3.0"))
		resp := owner.MakeRequest(t, NewRequest(t, "GET", path.Join("org3", repo, "pulls", idx)), http.StatusOK)
		body := resp.Body.String()
		assert.Contains(t, body, "did not delete the head branch")
		assert.Contains(t, body, "release/3.0")
		assert.Contains(t, body, "it is a release branch")
	})
}

// A pull request whose head and base are the same branch of the same repository is refused (422), also when the
// base was left out and the branch is the one it resolves to.
func TestBranchTypesSameBranchPR(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-same")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		for _, o := range []*api.CreatePullRequestOption{
			{Head: "master", Base: "master", Title: "same"},
			{Head: "org3:master", Base: "master", Title: "same, owner-qualified"},
			{Head: "master", Title: "no base: the default branch is the head"},
		} {
			ctx.Session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/"+repo+"/pulls", o).AddTokenAuth(ctx.Token), http.StatusUnprocessableEntity)
		}
	})
}

// The web entry points name only the head branch, so the compare page chooses the base by the branching model; the
// link after a push does the same for the pusher who can read the repository, and never exposes the model otherwise.
func TestBranchTypesLinks(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-links")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		testAPICreateBranch(t, owner, "org3", repo, "master", "develop", http.StatusCreated)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{
			DevelopmentBranch: "develop", ReleasePrefixes: []string{"release/"},
			Types: []api.BranchType{{Name: "Feature", Prefix: "feature/", Base: "development"}},
		}, http.StatusOK)
		testNewFileToNewBranch(t, owner, "org3", repo, "master", "feature/x", "x.txt", "x\n")

		compareLinks := func(p string) []string {
			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", p), http.StatusOK).Body)
			var links []string
			doc.doc.Find(`a[href*="/compare/"]`).Each(func(_ int, s *goquery.Selection) {
				links = append(links, s.AttrOr("href", ""))
			})
			return links
		}
		for _, p := range []string{path.Join("org3", repo, "branches"), path.Join("org3", repo)} {
			links := compareLinks(p)
			require.NotEmpty(t, links, p)
			for _, l := range links {
				assert.NotContains(t, l, "master...", p)
			}
			assert.Contains(t, strings.Join(links, " "), "/compare/feature/x", p)
		}
		resp := owner.MakeRequest(t, NewRequest(t, "GET", path.Join("org3", repo, "compare", "feature%2Fx")), http.StatusOK)
		assert.Contains(t, NewHTMLParser(t, resp.Body).doc.Find("#base-target-text").Text(), "develop")

		// the link after a push
		r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})
		push := func(userID int64, branch string) string {
			res, extra := private.HookPostReceive(t.Context(), r.ID, private.HookOptions{
				UserID: userID, OldCommitIDs: []string{git.Sha1ObjectFormat.EmptyObjectID().String()}, NewCommitIDs: []string{btTip(t, repo, branch)},
				RefFullNames: []git.RefName{git.RefNameFromBranch(branch)},
			})
			require.NoError(t, extra.Error)
			if len(res.Results) == 0 || !res.Results[0].Message {
				return ""
			}
			return res.Results[0].CreateURL
		}
		assert.Equal(t, r.HTMLURL()+"/compare/develop...feature/x", push(2, "feature/x"))
		assert.Empty(t, push(2, "master"), "the default branch gets no link to itself")
	})
}

// The organization's branch workflow and branching model endpoints are owner-only and need an all-access token,
// like the other owner-only organization endpoints.
func TestBranchTypesOrgTokens(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		full := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization)
		publicOnly := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopePublicOnly)
		// a token restricted to one repository (the API only issues such tokens with repository scopes)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		other := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user2", Name: "repo1"})
		tok := forgery.CreateAccessToken(t, user2, &forgery.CreateAccessTokenOptions{Scope: "write:organization"})
		tok.ResourceAllRepos = false
		_, err := db.GetEngine(t.Context()).ID(tok.ID).Cols("resource_all_repos").Update(tok)
		require.NoError(t, err)
		resource := &auth_model.AccessTokenResourceRepo{TokenID: tok.ID, RepoID: other.ID}
		require.NoError(t, db.Insert(t.Context(), resource))
		t.Cleanup(func() { unittest.AssertSuccessfulDelete(t, resource) })
		restricted := tok.Token
		for _, p := range []string{"/api/v1/orgs/org3/branch-workflow", "/api/v1/orgs/org3/branching-model"} {
			MakeRequest(t, NewRequest(t, "GET", p).AddTokenAuth(full), http.StatusOK)
			MakeRequest(t, NewRequest(t, "GET", p).AddTokenAuth(publicOnly), http.StatusForbidden)
			MakeRequest(t, NewRequest(t, "GET", p).AddTokenAuth(restricted), http.StatusForbidden)
		}
		MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/branch-workflow", map[string]string{"delete_branch_after_merge": "always"}).AddTokenAuth(restricted), http.StatusForbidden)
		MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/branching-model", &api.OrgBranchingModel{ReleasePrefixes: []string{"release/"}}).AddTokenAuth(restricted), http.StatusForbidden)
		MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/branch-workflow", map[string]string{"delete_branch_after_merge": "always"}).AddTokenAuth(publicOnly), http.StatusForbidden)
		MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/branching-model", &api.OrgBranchingModel{ReleasePrefixes: []string{"release/"}}).AddTokenAuth(publicOnly), http.StatusForbidden)
	})
}

// W3: the repository's delete-after-merge setting is recorded with the stored value as "before", and an unchanged
// save records nothing.
func TestBranchTypesAuditDeleteAfterMerge(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-audit")
		owner := loginUser(t, "user2")
		since := auditMaxID(t)
		bwRepoPost(t, owner, "org3", repo, "always", http.StatusSeeOther)
		data := auditData(t, auditOne(t, since, "repo.branch_workflow.changed"))
		before, _ := data["before"].(map[string]any)
		after, _ := data["after"].(map[string]any)
		assert.Equal(t, "always", after["mode"])
		assert.NotEqual(t, "always", before["mode"])

		since = auditMaxID(t)
		bwRepoPost(t, owner, "org3", repo, "always", http.StatusSeeOther)
		n, err := db.GetEngine(t.Context()).Table("audit_event").Where("id > ? AND action = ?", since, "repo.branch_workflow.changed").Count()
		require.NoError(t, err)
		assert.Zero(t, n)
	})
}

// A repository inside a project inherits the organization's model: kept branches and the pull request target.
func TestBranchTypesInProject(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		ctx := audit_model.WithSystem(t.Context(), "test")
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		group, err := repo_model.CreateRepoGroup(ctx, org, "bt", "")
		require.NoError(t, err)
		repo, err := repo_service.CreateRepository(ctx, user2, org, repo_service.CreateRepoOptions{Name: "inproj", Readme: "Default", AutoInit: true, DefaultBranch: "main", GroupID: group.ID})
		require.NoError(t, err)
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/branching-model", &api.OrgBranchingModel{
			DevelopmentBranch: "dev", ProductionBranch: "prod", ReleasePrefixes: []string{"rel/"}, DefaultPRTarget: "staging",
			Types: []api.BranchType{{Name: "Feature", Prefix: "feature/", Base: "development"}},
		}).AddTokenAuth(token), http.StatusOK)
		defer MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/branching-model", &api.OrgBranchingModel{}).AddTokenAuth(token), http.StatusOK)

		var got api.RepoBranchingModel
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/bt/inproj/-/branching-model").AddTokenAuth(token), http.StatusOK), &got)
		assert.Equal(t, "org", got.Source)
		assert.Equal(t, "dev", got.Effective.DevelopmentBranch)

		repo, err = repo_model.GetRepositoryByID(ctx, repo.ID)
		require.NoError(t, err)
		for branch, want := range map[string]string{
			"main": branchworkflow.KeptDefault, "dev": branchworkflow.KeptDevelopment, "prod": branchworkflow.KeptProduction,
			"rel/1": branchworkflow.KeptRelease, "staging": branchworkflow.KeptBase, "feature/a": "",
			"merge-queue/main/1": branchworkflow.KeptMergeQueue,
		} {
			reason, err := branchworkflow.KeptReason(ctx, repo, branch, false)
			require.NoError(t, err)
			assert.Equal(t, want, reason, branch)
		}
		for _, b := range []string{"dev", "feature/a"} {
			testAPICreateBranch(t, session, "org3", "bt/inproj/-", "main", b, http.StatusCreated)
		}
		target, err := branchworkflow.ResolveTarget(ctx, repo, "feature/a")
		require.NoError(t, err)
		assert.Equal(t, "dev", target.Branch)
	})
}
