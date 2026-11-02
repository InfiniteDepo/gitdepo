// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	app_context "forgejo.org/services/context"
	"forgejo.org/services/forms"
	repo_service "forgejo.org/services/repository"
	commitstatus_service "forgejo.org/services/repository/commitstatus"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bwRepo creates an organization repository owned by org3 (whose owner is user2) and returns its name.
func bwRepo(t *testing.T, name string) string {
	t.Helper()
	ctx := NewAPITestContext(t, "user2", name, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
	req := NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{
		Name: name, AutoInit: true, Readme: "Default", DefaultBranch: "master",
	}).AddTokenAuth(ctx.Token)
	ctx.Session.MakeRequest(t, req, http.StatusCreated)
	return name
}

func bwProtect(t *testing.T, ctx APITestContext, repo, rule string, params parameterProtectBranch) {
	t.Helper()
	ctx.Username, ctx.Reponame = "org3", repo
	doProtectBranch(ctx, rule, params)(t)
}

func bwOrgPost(t *testing.T, s *TestSession, mode string, enforce bool, expected int) {
	t.Helper()
	values := map[string]string{"delete_after_merge": mode}
	if enforce {
		values["enforce"] = "on"
	}
	s.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/branch_workflow", values), expected)
}

func bwRepoPost(t *testing.T, s *TestSession, owner, repo, mode string, expected int) {
	t.Helper()
	s.MakeRequest(t, NewRequestWithValues(t, "POST", path.Join(owner, repo, "settings/branch_workflow"), map[string]string{"delete_after_merge": mode}), expected)
}

// bwGetRepoAPI returns the GET /repos/{owner}/{repo}/branch-workflow response.
func bwGetRepoAPI(t *testing.T, ctx APITestContext, owner, repo string) map[string]any {
	t.Helper()
	req := NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/%s/%s/branch-workflow", owner, repo)).AddTokenAuth(ctx.Token)
	resp := ctx.Session.MakeRequest(t, req, http.StatusOK)
	var got map[string]any
	DecodeJSON(t, resp, &got)
	return got
}

func bwPutRepoAPI(t *testing.T, ctx APITestContext, owner, repo, mode string, expected int) {
	t.Helper()
	req := NewRequestWithJSON(t, "PUT", fmt.Sprintf("/api/v1/repos/%s/%s/branch-workflow", owner, repo), map[string]string{"delete_branch_after_merge": mode}).AddTokenAuth(ctx.Token)
	ctx.Session.MakeRequest(t, req, expected)
}

// bwPR creates a branch with an own commit in owner/repo and opens a PR from it to master. It returns the PR index.
func bwPR(t *testing.T, s *TestSession, owner, repo, base, head string) string {
	t.Helper()
	if !git.IsBranchExist(t.Context(), repo_model.RepoPath(owner, repo), head) {
		testNewFileToNewBranch(t, s, owner, repo, base, head, head+".txt", "edited on "+head+"\n")
	}
	resp := testPullCreate(t, s, owner, repo, true, base, head, "PR from "+head)
	return strings.Split(test.RedirectURL(resp), "/")[4]
}

// bwFlag matches `'key':  value ,` as rendered into the page's script.
func bwFlag(body, key string, value bool) bool {
	return regexp.MustCompile(`'` + key + `':\s+` + strconv.FormatBool(value) + `\b`).MatchString(body)
}

func bwFlash(s *TestSession) string {
	c := s.GetCookie(app_context.CookieNameFlash)
	if c == nil {
		return ""
	}
	v, _ := url.QueryUnescape(c.Value)
	v, _ = url.QueryUnescape(v)
	return strings.ReplaceAll(v, "+", " ")
}

// AC1 + AC12: pages exist, default to "Inherit", and are limited to org owners / repo admins.
func TestBranchWorkflowSettingsPages(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bw-pages")
		owner := loginUser(t, "user2")

		resp := owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/branch_workflow"), http.StatusOK)
		doc := NewHTMLParser(t, resp.Body)
		values := map[string]bool{}
		doc.doc.Find(`select[name="delete_after_merge"] option`).Each(func(_ int, s *goquery.Selection) {
			v, _ := s.Attr("value")
			values[v] = true
		})
		assert.Equal(t, map[string]bool{"inherit": true, "off": true, "default-on": true, "always": true}, values)
		assert.Equal(t, 1, doc.doc.Find(`input[name="enforce"]`).Length())

		resp = owner.MakeRequest(t, NewRequest(t, "GET", path.Join("org3", repo, "settings/branch_workflow")), http.StatusOK)
		doc = NewHTMLParser(t, resp.Body)
		selected, _ := doc.doc.Find(`select[name="delete_after_merge"] option[selected]`).Attr("value")
		assert.Equal(t, "inherit", selected)

		// AC12: user4 is neither an org owner nor a repo admin of org3/<repo>
		other := loginUser(t, "user4")
		other.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/branch_workflow"), http.StatusNotFound)
		bwOrgPost(t, other, "always", true, http.StatusNotFound)
		other.MakeRequest(t, NewRequest(t, "GET", path.Join("org3", repo, "settings/branch_workflow")), http.StatusNotFound)
		bwRepoPost(t, other, "org3", repo, "always", http.StatusNotFound)

		// API: same limits
		ownerCtx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		otherCtx := NewAPITestContext(t, "user4", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		bwPutRepoAPI(t, otherCtx, "org3", repo, "always", http.StatusForbidden)
		bwPutRepoAPI(t, ownerCtx, "org3", repo, "always", http.StatusOK)
		req := NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/branch-workflow", map[string]any{"delete_branch_after_merge": "always"}).AddTokenAuth(otherCtx.Token)
		otherCtx.Session.MakeRequest(t, req, http.StatusForbidden)
	})
}

// AC2 + AC3 + AC4: inheritance chain instance -> org -> repo, lock, legacy field.
func TestBranchWorkflowInheritance(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bw-inherit")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)

		// instance default from app.ini
		restore := test.MockVariableValue(&setting.Repository.BranchWorkflow.DeleteSourceBranchAfterMerge, "default-on")
		got := bwGetRepoAPI(t, ctx, "org3", repo)
		assert.Equal(t, "default-on", got["effective_delete_branch_after_merge"])
		assert.Equal(t, "instance", got["source"])
		assert.Equal(t, "inherit", got["delete_branch_after_merge"])
		restore()

		// org value, not enforced: applies to the existing repo and to a repo created later
		bwOrgPost(t, owner, "default-on", false, http.StatusSeeOther)
		got = bwGetRepoAPI(t, ctx, "org3", repo)
		assert.Equal(t, "default-on", got["effective_delete_branch_after_merge"])
		assert.Equal(t, "org", got["source"])
		assert.Equal(t, false, got["locked"])
		later := bwRepo(t, "bw-inherit-later")
		assert.Equal(t, "default-on", bwGetRepoAPI(t, ctx, "org3", later)["effective_delete_branch_after_merge"])

		// legacy field maps to Default on
		req := NewRequest(t, "GET", "/api/v1/repos/org3/"+repo).AddTokenAuth(ctx.Token)
		var legacy api.Repository
		DecodeJSON(t, ctx.Session.MakeRequest(t, req, http.StatusOK), &legacy)
		assert.True(t, legacy.DefaultDeleteBranchAfterMerge)

		// an unknown value changes nothing
		bwOrgPost(t, owner, "bogus", true, http.StatusSeeOther)
		bwRepoPost(t, owner, "org3", repo, "bogus", http.StatusSeeOther)
		got = bwGetRepoAPI(t, ctx, "org3", repo)
		assert.Equal(t, "default-on", got["effective_delete_branch_after_merge"])
		assert.Equal(t, "inherit", got["delete_branch_after_merge"])
		assert.Equal(t, false, got["locked"])

		// unlocked: the repo can override, via web and API
		bwRepoPost(t, owner, "org3", repo, "off", http.StatusSeeOther)
		got = bwGetRepoAPI(t, ctx, "org3", repo)
		assert.Equal(t, "off", got["effective_delete_branch_after_merge"])
		assert.Equal(t, "repo", got["source"])
		bwPutRepoAPI(t, ctx, "org3", repo, "always", http.StatusOK)
		assert.Equal(t, "always", bwGetRepoAPI(t, ctx, "org3", repo)["effective_delete_branch_after_merge"])
		patch := func(v bool, expected int) {
			req := NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/"+repo, map[string]any{"default_delete_branch_after_merge": v}).AddTokenAuth(ctx.Token)
			ctx.Session.MakeRequest(t, req, expected)
		}
		patch(false, http.StatusOK) // legacy field writes Off
		assert.Equal(t, "off", bwGetRepoAPI(t, ctx, "org3", repo)["effective_delete_branch_after_merge"])

		// locked: value is forced, web and API changes (also through the legacy field) are refused
		bwOrgPost(t, owner, "always", true, http.StatusSeeOther)
		got = bwGetRepoAPI(t, ctx, "org3", repo)
		assert.Equal(t, "always", got["effective_delete_branch_after_merge"])
		assert.Equal(t, "org", got["source"])
		assert.Equal(t, true, got["locked"])
		assert.Equal(t, "org3", got["locked_by"])
		bwRepoPost(t, owner, "org3", repo, "off", http.StatusForbidden)
		bwPutRepoAPI(t, ctx, "org3", repo, "off", http.StatusForbidden)
		patch(false, http.StatusForbidden)
		patch(true, http.StatusOK) // same as the mapped current value: no change, not refused
		assert.Equal(t, "always", bwGetRepoAPI(t, ctx, "org3", repo)["effective_delete_branch_after_merge"])

		resp := owner.MakeRequest(t, NewRequest(t, "GET", path.Join("org3", repo, "settings/branch_workflow")), http.StatusOK)
		body := resp.Body.String()
		assert.Contains(t, body, "Set by organization")
		assert.Contains(t, body, "org3")
		doc := NewHTMLParser(t, bytes.NewBufferString(body))
		_, disabled := doc.doc.Find(`select[name="delete_after_merge"]`).Attr("disabled")
		assert.True(t, disabled)

		// org API
		put := func(body map[string]any, expected int) {
			req := NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/branch-workflow", body).AddTokenAuth(ctx.Token)
			ctx.Session.MakeRequest(t, req, expected)
		}
		put(map[string]any{"delete_branch_after_merge": "inherit", "enforce_delete_branch_after_merge": true}, http.StatusUnprocessableEntity) // lock needs a value
		put(map[string]any{"delete_branch_after_merge": "off", "enforce_delete_branch_after_merge": false}, http.StatusOK)
		req = NewRequest(t, "GET", "/api/v1/orgs/org3/branch-workflow").AddTokenAuth(ctx.Token)
		var org map[string]any
		DecodeJSON(t, ctx.Session.MakeRequest(t, req, http.StatusOK), &org)
		assert.Equal(t, "off", org["delete_branch_after_merge"])
		assert.Equal(t, false, org["enforce_delete_branch_after_merge"])
		// unlocked again: the repo's own value (off, written through the legacy field above) is back
		assert.Equal(t, "off", bwGetRepoAPI(t, ctx, "org3", repo)["effective_delete_branch_after_merge"])
	})
}

// AC4/OL 7a: a repo that only has the legacy bool shows "Default on" everywhere.
func TestBranchWorkflowLegacyBool(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user2", Name: "repo1"})
		u, err := repo.GetUnit(db.DefaultContext, unit.TypePullRequests)
		require.NoError(t, err)
		u.PullRequestsConfig().DefaultDeleteBranchAfterMerge = true
		require.NoError(t, repo_model.UpdateRepoUnit(db.DefaultContext, u))

		ctx := NewAPITestContext(t, "user2", "repo1", auth_model.AccessTokenScopeWriteRepository)
		got := bwGetRepoAPI(t, ctx, "user2", "repo1")
		assert.Equal(t, "default-on", got["effective_delete_branch_after_merge"])
		assert.Equal(t, "repo", got["source"])

		s := loginUser(t, "user2")
		resp := s.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/branch_workflow"), http.StatusOK)
		selected, _ := NewHTMLParser(t, resp.Body).doc.Find(`select[name="delete_after_merge"] option[selected]`).Attr("value")
		assert.Equal(t, "default-on", selected)

		// saving the units page must not reset the setting (the form has no such field any more)
		s.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/units", map[string]string{
			"enable_pulls": "on", "pulls_allow_merge": "on", "pulls_default_merge_style": "merge",
		}), http.StatusSeeOther)
		repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "user2", Name: "repo1"})
		u, err = repo.GetUnit(db.DefaultContext, unit.TypePullRequests)
		require.NoError(t, err)
		assert.Equal(t, repo_model.DeleteBranchDefaultOn, u.PullRequestsConfig().GetDeleteBranchAfterMerge())
	})
}

// AC5 + AC6 + AC13: merge box data. The Vue checkbox state is covered by PullRequestMergeForm.test.js.
func TestBranchWorkflowMergeBox(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bw-box")
		owner := loginUser(t, "user2")
		idx := bwPR(t, owner, "org3", repo, "master", "box")
		page := func() string {
			return owner.MakeRequest(t, NewRequest(t, "GET", path.Join("org3", repo, "pulls", idx)), http.StatusOK).Body.String()
		}

		body := page()
		assert.True(t, bwFlag(body, "defaultDeleteBranchAfterMerge", false))
		assert.True(t, bwFlag(body, "deleteBranchForced", false))

		bwRepoPost(t, owner, "org3", repo, "default-on", http.StatusSeeOther)
		body = page()
		assert.True(t, bwFlag(body, "defaultDeleteBranchAfterMerge", true))
		assert.True(t, bwFlag(body, "deleteBranchForced", false))

		bwOrgPost(t, owner, "always", true, http.StatusSeeOther)
		body = page()
		assert.True(t, bwFlag(body, "defaultDeleteBranchAfterMerge", true))
		assert.True(t, bwFlag(body, "deleteBranchForced", true))
		assert.Contains(t, body, "Set by organization org3")
	})
}

// AC6 + AC8 + AC11: Always deletes for web, API (even with false) and auto-merge; the branch can be restored.
func TestBranchWorkflowAlwaysDeletes(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bw-always")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		bwOrgPost(t, owner, "always", true, http.StatusSeeOther)

		// web, checkbox not ticked
		idx := bwPR(t, owner, "org3", repo, "master", "web-pr")
		testPullMerge(t, owner, "org3", repo, idx, repo_model.MergeStyleMerge, false)
		assert.False(t, bwBranchExists("org3", repo, "web-pr"))

		// AC8: the deleted branch is still restorable (existing restore button on the branches page)
		resp := owner.MakeRequest(t, NewRequest(t, "GET", path.Join("org3", repo, "branches")), http.StatusOK)
		restore, ok := NewHTMLParser(t, resp.Body).doc.Find(`.restore-branch-button[data-url*="name=web-pr"]`).First().Attr("data-url")
		if assert.True(t, ok, "restore button not found") {
			owner.MakeRequest(t, NewRequest(t, "POST", restore), http.StatusOK)
			assert.True(t, bwBranchExists("org3", repo, "web-pr"))
		}

		// API with delete_branch_after_merge=false
		idx = bwPR(t, owner, "org3", repo, "master", "api-pr")
		n, err := strconv.ParseInt(idx, 10, 64)
		require.NoError(t, err)
		doAPIMergePullRequestForm(t, ctx, "org3", repo, n, &forms.MergePullRequestForm{Do: "merge", DeleteBranchAfterMerge: false})
		assert.False(t, bwBranchExists("org3", repo, "api-pr"))

		// auto-merge scheduled with delete=false
		bwProtect(t, ctx, repo, "master", parameterProtectBranch{"enable_push": "true", "enable_status_check": "true", "status_check_contexts": "gitea/actions"})
		idx = bwPR(t, owner, "org3", repo, "master", "auto-pr")
		testPullMergeForm(t, owner, http.StatusOK, "org3", repo, idx, optionsPullMerge{"do": "merge", "merge_when_checks_succeed": "true", "delete_branch_after_merge": "false"})
		assert.True(t, bwBranchExists("org3", repo, "auto-pr"))
		r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})
		gitRepo, err := gitrepo.OpenRepository(db.DefaultContext, r)
		require.NoError(t, err)
		defer gitRepo.Close()
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: r.ID, HeadBranch: "auto-pr"})
		sha, err := gitRepo.GetRefCommitID(pr.GetGitRefName())
		require.NoError(t, err)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		require.NoError(t, commitstatus_service.CreateCommitStatus(db.DefaultContext, r, user2, sha, &git_model.CommitStatus{State: api.CommitStatusSuccess, Context: "gitea/actions"}))
		pr = unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
		assert.True(t, pr.HasMerged)
		assert.False(t, bwBranchExists("org3", repo, "auto-pr"))
	})
}

// AC7 + AC11: exceptions keep the branch and give a reason; a kept branch never fails the merge when Always forced it.
func TestBranchWorkflowKeptBranches(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bw-kept")
		owner := loginUser(t, "user2")
		ctx := NewAPITestContext(t, "user2", repo, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		bwOrgPost(t, owner, "always", true, http.StatusSeeOther)

		// protected branch: kept with reason. Forced: merge succeeds (200). Requested: web flashes the reason, API 403.
		forcedIdx := bwPR(t, owner, "org3", repo, "master", "prot-forced")
		apiIdx := bwPR(t, owner, "org3", repo, "master", "prot-api")
		api2Idx := bwPR(t, owner, "org3", repo, "master", "prot-api2")
		for _, b := range []string{"prot-forced", "prot-api", "prot-api2"} {
			bwProtect(t, ctx, repo, b, parameterProtectBranch{"enable_push": "true"})
		}
		testPullMerge(t, owner, "org3", repo, forcedIdx, repo_model.MergeStyleMerge, false)
		assert.True(t, bwBranchExists("org3", repo, "prot-forced"))
		assert.Contains(t, bwFlash(owner), "protected branch")

		n, _ := strconv.ParseInt(apiIdx, 10, 64)
		doAPIMergePullRequestForm(t, ctx, "org3", repo, n, &forms.MergePullRequestForm{Do: "merge"}) // forced: 200
		assert.True(t, bwBranchExists("org3", repo, "prot-api"))
		n, _ = strconv.ParseInt(api2Idx, 10, 64)
		ctx.ExpectedCode = http.StatusForbidden
		doAPIMergePullRequestForm(t, ctx, "org3", repo, n, &forms.MergePullRequestForm{Do: "merge", DeleteBranchAfterMerge: true})
		ctx.ExpectedCode = 0
		assert.True(t, bwBranchExists("org3", repo, "prot-api2"))

		// another open PR with the same head
		testNewFileToNewBranch(t, owner, "org3", repo, "master", "dev", "dev.txt", "dev\n")
		testNewFileToNewBranch(t, owner, "org3", repo, "master", "shared", "shared.txt", "shared\n")
		first := bwPR(t, owner, "org3", repo, "master", "shared")
		testPullCreate(t, owner, "org3", repo, true, "dev", "shared", "second PR from shared")
		testPullMerge(t, owner, "org3", repo, first, repo_model.MergeStyleMerge, false)
		assert.True(t, bwBranchExists("org3", repo, "shared"))
		assert.Contains(t, bwFlash(owner), "another open pull request")

		// a fork without write access to the head repo: kept
		other := loginUser(t, "user4")
		testRepoFork(t, other, "org3", repo, "user4", repo)
		testEditFileToNewBranch(t, other, "user4", repo, "master", "fork-head", "README.md", "from fork\n")
		resp := testPullCreateDirectly(t, other, "org3", repo, "master", "user4", repo, "fork-head", "PR from fork")
		forkIdx := strings.Split(test.RedirectURL(resp), "/")[4]
		testPullMerge(t, owner, "org3", repo, forkIdx, repo_model.MergeStyleMerge, false)
		assert.True(t, bwBranchExists("user4", repo, "fork-head"))
	})
}

// AC7 + OL 7c: a head branch that is the base of another open PR.
func TestBranchWorkflowBaseOfOpenPR(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bw-stack")
		owner := loginUser(t, "user2")
		bwOrgPost(t, owner, "always", true, http.StatusSeeOther)

		for _, retarget := range []bool{false, true} {
			t.Run(fmt.Sprintf("retarget=%v", retarget), func(t *testing.T) {
				defer test.MockVariableValue(&setting.Repository.PullRequest.RetargetChildrenOnMerge, retarget)()
				base, child := fmt.Sprintf("stack-base-%v", retarget), fmt.Sprintf("stack-child-%v", retarget)
				baseIdx := bwPR(t, owner, "org3", repo, "master", base)
				testEditFileToNewBranch(t, owner, "org3", repo, base, child, "README.md", "child "+child+"\n")
				childIdx := strings.Split(test.RedirectURL(testPullCreate(t, owner, "org3", repo, true, base, child, "child")), "/")[4]

				testPullMerge(t, owner, "org3", repo, baseIdx, repo_model.MergeStyleMerge, false)

				r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})
				n, _ := strconv.ParseInt(childIdx, 10, 64)
				childPR := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: r.ID, Index: n})
				if retarget {
					assert.Equal(t, "master", childPR.BaseBranch)
					assert.False(t, bwBranchExists("org3", repo, base))
				} else {
					assert.Equal(t, base, childPR.BaseBranch)
					assert.True(t, bwBranchExists("org3", repo, base))
					assert.Contains(t, bwFlash(owner), "another open pull request")
				}
			})
		}
	})
}

// MF1: AGit PRs are skipped; a real branch with the same name survives.
func TestBranchWorkflowAgitSkipped(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bw-agit")
		owner := loginUser(t, "user2")
		bwOrgPost(t, owner, "always", true, http.StatusSeeOther)
		testEditFileToNewBranch(t, owner, "org3", repo, "master", "user2/topic1", "README.md", "same name as the agit head\n")

		dst := t.TempDir()
		u.Path = "/org3/" + repo + ".git"
		u.User = url.UserPassword("user2", userPassword)
		t.Run("Clone", doGitClone(dst, u))
		require.NoError(t, os.WriteFile(path.Join(dst, "agit_file"), []byte("agit"), 0o666))
		require.NoError(t, git.AddChanges(dst, true))
		sig := &git.Signature{Email: "user2@example.com", Name: "user2", When: time.Now()}
		require.NoError(t, git.CommitChanges(dst, git.CommitChangesOptions{Committer: sig, Author: sig, Message: "agit commit"}))
		stderr := &bytes.Buffer{}
		require.NoError(t, git.NewCommand(git.DefaultContext, "push", "origin", "HEAD:refs/for/master", "-o").
			AddDynamicArguments("topic=topic1").AddArguments("-o").AddDynamicArguments(`title="agit pr"`).
			Run(&git.RunOpts{Dir: dst, Stderr: stderr}))

		r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{Flow: issues_model.PullRequestFlowAGit, BaseRepoID: r.ID})
		testPullMerge(t, owner, "org3", repo, strconv.FormatInt(pr.Index, 10), repo_model.MergeStyleMerge, false)
		assert.True(t, bwBranchExists("org3", repo, "user2/topic1"))
	})
}

// MF6: only delete when the branch still points at the PR head.
func TestBranchWorkflowNewCommitsKept(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		repo := bwRepo(t, "bw-newcommits")
		owner := loginUser(t, "user2")
		idx := bwPR(t, owner, "org3", repo, "master", "moved")
		testPullMerge(t, owner, "org3", repo, idx, repo_model.MergeStyleMerge, false)
		testEditFile(t, owner, "org3", repo, "moved", "README.md", "pushed after the merge\n")

		r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: repo})
		n, _ := strconv.ParseInt(idx, 10, 64)
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: r.ID, Index: n})
		require.NoError(t, pr.LoadAttributes(db.DefaultContext))
		require.NoError(t, pr.LoadBaseRepo(db.DefaultContext))
		require.NoError(t, pr.LoadHeadRepo(db.DefaultContext))
		gitRepo, err := gitrepo.OpenRepository(db.DefaultContext, r)
		require.NoError(t, err)
		defer gitRepo.Close()
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		err = repo_service.DeleteBranchAfterMerge(db.DefaultContext, user2, pr, gitRepo)
		require.ErrorIs(t, err, repo_service.ErrBranchHasNewCommits)
		assert.True(t, bwBranchExists("org3", repo, "moved"))
	})
}
