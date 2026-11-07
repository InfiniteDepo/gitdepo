// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	api "forgejo.org/modules/structs"
	"forgejo.org/services/forms"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func btModel(t *testing.T, ctx APITestContext, repo string, o *api.EditRepoBranchingModelOption, expected int) {
	t.Helper()
	req := NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/"+repo+"/branching-model", o).AddTokenAuth(ctx.Token)
	ctx.Session.MakeRequest(t, req, expected)
}

func btOrgModel(t *testing.T, ctx APITestContext, o *api.OrgBranchingModel, expected int) {
	t.Helper()
	req := NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/branching-model", o).AddTokenAuth(ctx.Token)
	ctx.Session.MakeRequest(t, req, expected)
}

// R1: branch types and the default pull request target are stored through the web form and the API, by org owners
// and repository admins only, validated as a whole, locked by the organization, and recorded in the audit log.
func TestBranchTypesSettings(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-settings")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		types := []api.BranchType{
			{Name: "Feature", Prefix: "feature/", Base: "development"},
			{Name: "Hotfix", Prefix: "hotfix/", Base: "production"},
			{Name: "Docs", Prefix: "docs/", Base: "branch", BaseBranch: "docs-base"},
		}

		// the organization's model through the API
		since := auditMaxID(t)
		btOrgModel(t, ctx, &api.OrgBranchingModel{ReleasePrefixes: []string{"release/"}, ProductionBranch: "prod", Types: types, DefaultPRTarget: "develop"}, http.StatusOK)
		entry := auditOne(t, since, "org.branch_workflow.changed")
		after, _ := auditData(t, entry)["after"].(map[string]any)
		assert.Equal(t, []any{
			map[string]any{"name": "Feature", "prefix": "feature/", "base": "development", "base_branch": "", "on": true},
			map[string]any{"name": "Hotfix", "prefix": "hotfix/", "base": "production", "base_branch": "", "on": true},
			map[string]any{"name": "Docs", "prefix": "docs/", "base": "branch", "base_branch": "docs-base", "on": true},
		}, after["types"])
		assert.Equal(t, "develop", after["default_pr_target"])
		var org api.OrgBranchingModel
		req := NewRequest(t, "GET", "/api/v1/orgs/org3/branching-model").AddTokenAuth(ctx.Token)
		DecodeJSON(t, ctx.Session.MakeRequest(t, req, http.StatusOK), &org)
		assert.Equal(t, types, org.Types)
		assert.Equal(t, "develop", org.DefaultPRTarget)

		// a repository inside the organization inherits it
		req = NewRequest(t, "GET", "/api/v1/repos/org3/"+repo+"/branching-model").AddTokenAuth(ctx.Token)
		var got api.RepoBranchingModel
		DecodeJSON(t, ctx.Session.MakeRequest(t, req, http.StatusOK), &got)
		assert.Equal(t, "org", got.Source)
		assert.Equal(t, types, got.Effective.Types)
		assert.Equal(t, "develop", got.Effective.DefaultPRTarget)

		// the organization's web form
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/branch_workflow/branching_model", map[string]string{
			"release_prefixes": "release/", "default_pr_target": "main",
			"type_name": "Chore", "type_prefix": "chore/", "type_base": "development", "type_on": "0",
		}), http.StatusSeeOther)
		DecodeJSON(t, ctx.Session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/branching-model").AddTokenAuth(ctx.Token), http.StatusOK), &org)
		assert.Equal(t, []api.BranchType{{Name: "Chore", Prefix: "chore/", Base: "development"}}, org.Types)
		assert.Equal(t, "main", org.DefaultPRTarget)

		// a repository admin overrides it
		since = auditMaxID(t)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{ReleasePrefixes: []string{"release/"}, Types: types[:1], DefaultPRTarget: "develop"}, http.StatusOK)
		auditOne(t, since, "repo.branch_workflow.changed")
		DecodeJSON(t, ctx.Session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/"+repo+"/branching-model").AddTokenAuth(ctx.Token), http.StatusOK), &got)
		assert.Equal(t, "repo", got.Source)
		assert.Equal(t, types[:1], got.Own.Types)

		// invalid values answer 422 and store nothing
		many := make([]api.BranchType, 21)
		for i := range many {
			many[i] = api.BranchType{Name: "T" + strconv.Itoa(i), Prefix: fmt.Sprintf("t%d/", i), Base: "development"}
		}
		for _, bad := range map[string][]api.BranchType{
			"bad prefix":        {{Name: "A", Prefix: "a b/", Base: "development"}},
			"comma":             {{Name: "A", Prefix: "a,b/", Base: "development"}},
			"duplicate":         {types[0], types[0]},
			"release prefix":    {{Name: "A", Prefix: "release/", Base: "development"}},
			"merge queue":       {{Name: "A", Prefix: "merge-queue/", Base: "development"}},
			"unknown base":      {{Name: "A", Prefix: "a/", Base: "tag"}},
			"named base empty":  {{Name: "A", Prefix: "a/", Base: "branch"}},
			"named base bad":    {{Name: "A", Prefix: "a/", Base: "branch", BaseBranch: "bad..name"}},
			"empty name":        {{Name: "", Prefix: "a/", Base: "development"}},
			"too many (21)":     many,
			"long prefix":       {{Name: "A", Prefix: strings.Repeat("p", 101), Base: "development"}},
			"name too long":     {{Name: strings.Repeat("n", 51), Prefix: "a/", Base: "development"}},
			"prefix of the dev": {{Name: "A", Prefix: "develop", Base: "development"}},
		} {
			btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{DevelopmentBranch: "develop", ReleasePrefixes: []string{"release/"}, Types: bad}, http.StatusUnprocessableEntity)
		}
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{ReleasePrefixes: []string{"release/"}, DefaultPRTarget: "bad..name"}, http.StatusUnprocessableEntity)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", path.Join("org3", repo, "settings/branch_workflow/branching_model"), map[string]string{
			"release_prefixes": "release/", "type_name": "A", "type_prefix": "a b/", "type_base": "development", "type_on": "0",
		}), http.StatusSeeOther)
		DecodeJSON(t, ctx.Session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/"+repo+"/branching-model").AddTokenAuth(ctx.Token), http.StatusOK), &got)
		assert.Equal(t, types[:1], got.Own.Types, "nothing was stored")
		assert.Equal(t, "develop", got.Own.DefaultPRTarget)

		// the organization's lock refuses the repository's change, in the web form and the API
		btOrgModel(t, ctx, &api.OrgBranchingModel{ReleasePrefixes: []string{"release/"}, ProductionBranch: "prod", Types: types, Enforce: true}, http.StatusOK)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{ReleasePrefixes: []string{"release/"}, ProductionBranch: "prod", Types: types[1:2]}, http.StatusForbidden)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", path.Join("org3", repo, "settings/branch_workflow/branching_model"), map[string]string{
			"release_prefixes": "release/", "type_name": "A", "type_prefix": "a/", "type_base": "development", "type_on": "0",
		}), http.StatusForbidden)
		DecodeJSON(t, ctx.Session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/"+repo+"/branching-model").AddTokenAuth(ctx.Token), http.StatusOK), &got)
		assert.True(t, got.Locked)
		assert.Equal(t, types, got.Effective.Types)

		// somebody who is neither an owner nor an admin
		other := loginUser(t, "user4")
		other.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/branch_workflow/branching_model", map[string]string{"release_prefixes": "x/"}), http.StatusNotFound)
		otherCtx := NewAPITestContext(t, "user4", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		req = NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/branching-model", &api.OrgBranchingModel{ReleasePrefixes: []string{"x/"}, Types: types}).AddTokenAuth(otherCtx.Token)
		otherCtx.Session.MakeRequest(t, req, http.StatusForbidden)
		btOrgModel(t, ctx, &api.OrgBranchingModel{}, http.StatusOK)
	})
}

// R3/R4: the base of a new pull request, when none is given, comes from the head's type, then the default pull request
// target, then the default branch; an explicit base always wins.
func TestBranchTypesPRTarget(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-target")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		for _, b := range []string{"develop", "prod"} {
			testAPICreateBranch(t, owner, "org3", repo, "master", b, http.StatusCreated)
		}
		for _, b := range []string{"feature/a", "hotfix/h", "docs/d", "plain", "plain2"} {
			testNewFileToNewBranch(t, owner, "org3", repo, "master", b, strings.ReplaceAll(b, "/", "-")+".txt", b+"\n")
		}
		set := func(target string) {
			btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{
				DevelopmentBranch: "develop", ProductionBranch: "prod", ReleasePrefixes: []string{"release/"}, DefaultPRTarget: target,
				Types: []api.BranchType{
					{Name: "Feature", Prefix: "feature/", Base: "development"},
					{Name: "Hotfix", Prefix: "hotfix/", Base: "production"},
					{Name: "Docs", Prefix: "docs/", Base: "branch", BaseBranch: "docs-base"},
				},
			}, http.StatusOK)
		}
		compare := func(s *TestSession, repoPath, head string) string {
			resp := s.MakeRequest(t, NewRequest(t, "GET", path.Join(repoPath, "compare", head)), http.StatusOK)
			return strings.TrimSpace(NewHTMLParser(t, resp.Body).doc.Find("#base-target-text").Text())
		}
		apiPR := func(head, base string) string {
			req := NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/"+repo+"/pulls", &api.CreatePullRequestOption{Head: head, Base: base, Title: "PR " + head}).AddTokenAuth(ctx.Token)
			var pr api.PullRequest
			DecodeJSON(t, ctx.Session.MakeRequest(t, req, http.StatusCreated), &pr)
			return pr.Base.Ref
		}

		set("")
		assert.Contains(t, compare(owner, "org3/"+repo, "feature/a"), "The base is develop, where Feature branches go")
		assert.Contains(t, compare(owner, "org3/"+repo, "hotfix/h"), "The base is prod, where Hotfix branches go")
		assert.Contains(t, compare(owner, "org3/"+repo, "docs/d"), "docs-base, which doesn't exist, so the base is develop")
		assert.Contains(t, compare(owner, "org3/"+repo, "plain"), "the default branch")
		assert.Equal(t, "develop", apiPR("feature/a", ""))
		assert.Equal(t, "prod", apiPR("hotfix/h", ""))
		assert.Equal(t, "develop", apiPR("docs/d", ""))
		assert.Equal(t, "master", apiPR("plain", ""))
		// an explicit base wins, in the API and in the address
		assert.Equal(t, "prod", apiPR("feature/a", "prod"))
		assert.NotContains(t, compare(owner, "org3/"+repo, "master...feature/a"), "branching model")

		set("develop")
		assert.Contains(t, compare(owner, "org3/"+repo, "plain2"), "The base is develop, the default pull request target")
		assert.Equal(t, "develop", apiPR("plain2", ""))

		// a missing default target falls back to the development branch
		set("not-there")
		assert.Contains(t, compare(owner, "org3/"+repo, "plain2"), "not-there, which doesn't exist, so the base is develop")

		// a fork's pull request uses the base repository's model
		other := loginUser(t, "user4")
		testRepoFork(t, other, "org3", repo, "user4", repo)
		testEditFileToNewBranch(t, other, "user4", repo, "master", "feature/fork", "README.md", "from fork\n")
		assert.Contains(t, compare(other, "org3/"+repo, "user4:feature/fork"), "The base is develop, where Feature branches go")
	})
}

// R2: a development, production or release branch is never deleted after its pull request was merged; the reason is
// shown, the merge succeeds, and a normal branch is still deleted. Web, API and auto merge.
func TestBranchTypesKeptAfterMerge(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-kept")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{DevelopmentBranch: "develop", ProductionBranch: "prod", ReleasePrefixes: []string{"release/"}}, http.StatusOK)
		bwRepoPost(t, owner, "org3", repo, "always", http.StatusSeeOther)

		for head, reason := range map[string]string{"develop": "development branch", "prod": "production branch", "release/1.0": "release branch"} {
			idx := bwPR(t, owner, "org3", repo, "master", head)
			testPullMerge(t, owner, "org3", repo, idx, repo_model.MergeStyleMerge, false)
			assert.True(t, bwBranchExists("org3", repo, head), head)
			assert.Contains(t, bwFlash(owner), reason)
			// Always: a timeline entry says so
			resp := owner.MakeRequest(t, NewRequest(t, "GET", path.Join("org3", repo, "pulls", idx)), http.StatusOK)
			assert.Contains(t, resp.Body.String(), reason)
		}

		// a normal branch is deleted
		idx := bwPR(t, owner, "org3", repo, "master", "feature/ok")
		testPullMerge(t, owner, "org3", repo, idx, repo_model.MergeStyleMerge, false)
		assert.False(t, bwBranchExists("org3", repo, "feature/ok"))

		// API: asked for, the reason is the answer and the code is in the header; the merge itself is done
		idx = bwPR(t, owner, "org3", repo, "master", "release/2.0")
		n, err := strconv.ParseInt(idx, 10, 64)
		require.NoError(t, err)
		ctx.ExpectedCode = http.StatusForbidden
		doAPIMergePullRequestForm(t, ctx, "org3", repo, n, &forms.MergePullRequestForm{Do: "merge", DeleteBranchAfterMerge: true})
		ctx.ExpectedCode = 0
		assert.True(t, bwBranchExists("org3", repo, "release/2.0"))
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo}).ID, HeadBranch: "release/2.0"})
		assert.True(t, pr.HasMerged)

		// auto merge
		bwProtect(t, ctx, repo, "master", parameterProtectBranch{"enable_push": "true", "enable_status_check": "true", "status_check_contexts": "gitea/actions"})
		idx = bwPR(t, owner, "org3", repo, "master", "release/3.0")
		testPullMergeForm(t, owner, http.StatusOK, "org3", repo, idx, optionsPullMerge{"do": "merge", "merge_when_checks_succeed": "true", "delete_branch_after_merge": "true"})
		assert.True(t, bwBranchExists("org3", repo, "release/3.0"))
	})
}

// W2: the "Delete merged branches" tool neither offers nor deletes the development, production and release branches.
func TestBranchTypesDeleteMergedTool(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bt-merged")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		for _, b := range []string{"old-dev", "old-prod", "old-rel/1.0", "old-plain"} {
			testAPICreateBranch(t, owner, "org3", repo, "master", b, http.StatusCreated)
		}
		testEditFile(t, owner, "org3", repo, "master", "README.md", "newer\n") // the branches are now behind: merged
		btModel(t, ctx, repo, &api.EditRepoBranchingModelOption{DevelopmentBranch: "old-dev", ProductionBranch: "old-prod", ReleasePrefixes: []string{"old-rel/"}}, http.StatusOK)

		page := path.Join("org3", repo, "settings/branch_workflow/delete_merged")
		resp := owner.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK)
		var offered []string
		NewHTMLParser(t, resp.Body).doc.Find(`input[name="branch"]`).Each(func(_ int, s *goquery.Selection) {
			offered = append(offered, s.AttrOr("value", ""))
		})
		r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})
		prefix := strconv.FormatInt(r.ID, 10) + ":"
		assert.Equal(t, []string{prefix + "old-plain"}, offered)

		// a hand-made request naming the kept branches deletes none of them
		form := url.Values{"branch": {prefix + "old-dev", prefix + "old-prod", prefix + "old-rel/1.0", prefix + "old-plain"}}
		req := NewRequestWithBody(t, "POST", page, strings.NewReader(form.Encode())).SetHeader("Content-Type", "application/x-www-form-urlencoded")
		owner.MakeRequest(t, req, http.StatusSeeOther)
		for _, b := range []string{"old-dev", "old-prod", "old-rel/1.0"} {
			assert.True(t, bwBranchExists("org3", repo, b), b)
		}
		assert.False(t, bwBranchExists("org3", repo, "old-plain"))
	})
}
