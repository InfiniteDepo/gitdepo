// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/log"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/services/forms"
	issue_service "forgejo.org/services/issue"
	pull_service "forgejo.org/services/pull"
	files_service "forgejo.org/services/repository/files"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const prTitleRuleMessage = "<b>Start with ABC-1</b>"

func setPRTitleRule(t *testing.T, repoID int64, rule git_model.PushRule) {
	t.Helper()
	rule.RepoID = repoID
	require.NoError(t, git_model.UpsertPushRule(t.Context(), &rule))
}

// prTitleRuleBranch creates a branch of repo1 with one new commit.
func prTitleRuleBranch(t *testing.T, repo *repo_model.Repository, owner *user_model.User, branch string) {
	t.Helper()
	_, err := files_service.ChangeRepoFiles(git.DefaultContext, repo, owner, &files_service.ChangeRepoFilesOptions{
		Files:     []*files_service.ChangeRepoFile{{Operation: "create", TreePath: branch + ".txt", ContentReader: strings.NewReader(branch)}},
		OldBranch: "master",
		NewBranch: branch,
	})
	require.NoError(t, err)
}

func countPulls(t *testing.T) int64 {
	t.Helper()
	n, err := db.GetEngine(t.Context()).Count(new(issues_model.PullRequest))
	require.NoError(t, err)
	return n
}

func TestPRTitleRuleSettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	settingsURL := "/user2/repo1/settings/push_rules"

	loginUser(t, "user4").MakeRequest(t, NewRequestWithValues(t, "POST", settingsURL, map[string]string{"pr_title_regex": "^x"}), http.StatusNotFound)

	session := loginUser(t, "user2")
	for _, values := range []map[string]string{
		{"pr_title_regex": "("},
		{"pr_title_banned_regex": strings.Repeat("a", 1025)},
		{"pr_title_branches": "main;[a"},
		{"pr_title_message": strings.Repeat("a", 256)},
	} {
		resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", settingsURL, values), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "Invalid push rule")
	}
	rule, err := git_model.GetPushRule(t.Context(), repo.ID)
	require.NoError(t, err)
	assert.Nil(t, rule)

	session.MakeRequest(t, NewRequestWithValues(t, "POST", settingsURL, map[string]string{
		"pr_title_regex": "^ABC-", "pr_title_banned_regex": "^WIP", "pr_title_message": "msg",
		"pr_title_branches": "main;release/*", "pr_title_block_merge": "on",
	}), http.StatusSeeOther)
	rule, err = git_model.GetPushRule(t.Context(), repo.ID)
	require.NoError(t, err)
	assert.Equal(t, "^ABC-", rule.PRTitleRegex)
	assert.Equal(t, "^WIP", rule.PRTitleBannedRegex)
	assert.Equal(t, "msg", rule.PRTitleMessage)
	assert.Equal(t, "main;release/*", rule.PRTitleBranches)
	assert.True(t, rule.PRTitleBlockMerge)
	resp := session.MakeRequest(t, NewRequest(t, "GET", settingsURL), http.StatusOK)
	assert.Contains(t, resp.Body.String(), `value="main;release/*"`)
}

func TestPRTitleRuleRefuse(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: repo.OwnerID})
	session := loginUser(t, owner.Name)
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteIssue)
	for _, b := range []string{"t-api-bad", "t-api-ok", "t-web-bad", "t-web-ok", "t-agit", "t-filter", "t-retarget"} {
		prTitleRuleBranch(t, repo, owner, b)
	}
	setPRTitleRule(t, repo.ID, git_model.PushRule{PRTitleRegex: `^ABC-\d+ `, PRTitleBannedRegex: `^BAN`, PRTitleMessage: prTitleRuleMessage})

	createAPI := func(head, title string, status int) *api.PullRequest {
		resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls", &api.CreatePullRequestOption{
			Head: head, Base: "master", Title: title,
		}).AddTokenAuth(token), status)
		if status != http.StatusCreated {
			var e api.APIError
			DecodeJSON(t, resp, &e)
			assert.Equal(t, prTitleRuleMessage, e.Message) // plain text in the API
			return nil
		}
		var pr api.PullRequest
		DecodeJSON(t, resp, &pr)
		return &pr
	}

	t.Run("Create", func(t *testing.T) {
		before := countPulls(t)
		createAPI("t-api-bad", "no key", http.StatusUnprocessableEntity)
		createAPI("t-api-bad", "ABC-1 BAN", http.StatusCreated) // the banned regex is anchored
		assert.Equal(t, before+1, countPulls(t))

		// web: refused with the message as plain text, accepted when matching
		compare := func(branch string) string {
			resp := session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/compare/master..."+branch), http.StatusOK)
			action, ok := NewHTMLParser(t, resp.Body).doc.Find("#new-issue").Attr("action")
			require.True(t, ok)
			return action
		}
		before = countPulls(t)
		resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", compare("t-web-bad"), map[string]string{"title": "no key"}), http.StatusBadRequest)
		var e map[string]string
		DecodeJSON(t, resp, &e)
		assert.Equal(t, map[string]string{"errorMessage": prTitleRuleMessage, "renderFormat": "text"}, e)
		assert.Equal(t, before, countPulls(t))
		session.MakeRequest(t, NewRequestWithValues(t, "POST", compare("t-web-ok"), map[string]string{"title": "ABC-2 fine"}), http.StatusOK)
		assert.Equal(t, before+1, countPulls(t))
	})

	t.Run("Edit", func(t *testing.T) {
		pr := createAPI("t-api-ok", "ABC-3 start", http.StatusCreated)
		patch := func(status int, path, title string) {
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/user2/repo1/%s/%d", path, pr.Index), map[string]string{"title": title}).AddTokenAuth(token), status)
		}
		patch(http.StatusUnprocessableEntity, "pulls", "nokey")
		patch(http.StatusUnprocessableEntity, "issues", "nokey")
		patch(http.StatusCreated, "pulls", "ABC-4 renamed")
		patch(http.StatusCreated, "issues", "ABC-5 renamed")
		patch(http.StatusUnprocessableEntity, "pulls", "BAN: ABC-6 x")

		webTitle := func(title string, status int) {
			session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/user2/repo1/pulls/%d/title", pr.Index), map[string]string{"title": title}), status)
		}
		webTitle("nokey", http.StatusBadRequest)
		webTitle("ABC-7 web", http.StatusOK)
		// drafts skip must-match, never must-not-match
		webTitle("WIP: nokey", http.StatusOK)
		webTitle("ABC-7 web", http.StatusOK)
		setPRTitleRule(t, repo.ID, git_model.PushRule{PRTitleRegex: `^ABC-\d+ `, PRTitleBannedRegex: `^WIP`})
		webTitle("WIP: ABC-8 x", http.StatusBadRequest)
		// un-drafting is checked against the new title
		setPRTitleRule(t, repo.ID, git_model.PushRule{PRTitleRegex: `^ABC-\d+ `})
		webTitle("WIP: ABC-9 x", http.StatusOK)
		webTitle("ABC-9 x", http.StatusOK)
		webTitle("WIP: ABC-9 x", http.StatusOK)
		webTitle("not matching", http.StatusBadRequest) // the draft prefix removed: refused
		webTitle("  ABC-9 padded  ", http.StatusOK)     // trimmed before matching
	})

	t.Run("Retarget", func(t *testing.T) {
		setPRTitleRule(t, repo.ID, git_model.PushRule{})
		testAPICreateBranch(t, session, "user2", "repo1", "master", "release/1.0", http.StatusCreated)
		pr := createAPI("t-retarget", "no key", http.StatusCreated)
		setPRTitleRule(t, repo.ID, git_model.PushRule{PRTitleRegex: `^ABC-\d+ `, PRTitleBranches: "release/*", PRTitleMessage: prTitleRuleMessage})

		// a bad title on an unfiltered base branch cannot move onto a covered one
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d", pr.Index), map[string]string{"base": "release/1.0"}).AddTokenAuth(token), http.StatusUnprocessableEntity)
		retarget := fmt.Sprintf("/user2/repo1/pull/%d/target_branch", pr.Index)
		resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", retarget, map[string]string{"target_branch": "release/1.0"}), http.StatusBadRequest)
		var e map[string]string
		DecodeJSON(t, resp, &e)
		assert.Equal(t, prTitleRuleMessage, e["errorMessage"])
		assert.Equal(t, "master", unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).BaseBranch)

		// a refused retarget changes nothing else: the title stays as it was
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d", pr.Index), map[string]string{"title": "changed", "base": "release/1.0"}).AddTokenAuth(token), http.StatusUnprocessableEntity)
		stored := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
		require.NoError(t, stored.LoadIssue(t.Context()))
		assert.Equal(t, "no key", stored.Issue.Title)

		// a matching title can
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d", pr.Index), map[string]string{"title": "x"}).AddTokenAuth(token), http.StatusCreated)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d", pr.Index), map[string]string{"title": "ABC-1 x", "base": "release/1.0"}).AddTokenAuth(token), http.StatusCreated)
		assert.Equal(t, "release/1.0", unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).BaseBranch)
	})

	t.Run("BranchFilterAndAGit", func(t *testing.T) {
		setPRTitleRule(t, repo.ID, git_model.PushRule{PRTitleRegex: `^ABC-\d+ `, PRTitleBranches: "release/*"})
		createAPI("t-filter", "no key", http.StatusCreated) // base master is not covered
		setPRTitleRule(t, repo.ID, git_model.PushRule{PRTitleRegex: `^ABC-\d+ `, PRTitleBranches: "master"})

		// AGit and cherry-pick PRs go through NewPullRequest and are matched on the base branch
		before := countPulls(t)
		issue := &issues_model.Issue{RepoID: repo.ID, Repo: repo, Title: "no key", PosterID: owner.ID, Poster: owner, IsPull: true}
		pr := &issues_model.PullRequest{
			HeadRepoID: repo.ID, BaseRepoID: repo.ID, HeadBranch: "user2/topic", BaseBranch: "master",
			Flow: issues_model.PullRequestFlowAGit, Type: issues_model.PullRequestGitea,
		}
		err := pull_service.NewPullRequest(t.Context(), repo, issue, nil, nil, pr, nil)
		require.ErrorAs(t, err, new(*git_model.ErrPRTitleRule))
		assert.Equal(t, before, countPulls(t))
	})
}

func TestPRTitleRuleBlockMerge(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: repo.OwnerID})
	session := loginUser(t, owner.Name)
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteIssue)
	prTitleRuleBranch(t, repo, owner, "t-merge")
	resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls", &api.CreatePullRequestOption{
		Head: "t-merge", Base: "master", Title: "ABC-0 ok",
	}).AddTokenAuth(token), http.StatusCreated)
	var apiPR api.PullRequest
	DecodeJSON(t, resp, &apiPR)
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, Index: apiPR.Index})
	require.NoError(t, pr.LoadIssue(t.Context()))
	setPRTitleRule(t, repo.ID, git_model.PushRule{PRTitleRegex: `^ABC-\d+ `, PRTitleMessage: prTitleRuleMessage, PRTitleBlockMerge: true})

	// creation and edits are not refused in block-merge mode
	require.NoError(t, issue_service.ChangeTitle(t.Context(), pr.Issue, owner, "no key"))

	mergeURL := fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d/merge", pr.Index)
	mergeBody := &forms.MergePullRequestForm{Do: string(repo_model.MergeStyleMerge), MergeMessageField: "m"}

	// the merge box shows the failed check with the escaped message
	resp = session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/user2/repo1/pulls/%d", pr.Index)), http.StatusOK)
	box := NewHTMLParser(t, resp.Body).doc.Find(".merge.box .pr-title-rule-error")
	require.Equal(t, 1, box.Length())
	assert.Contains(t, box.Text(), prTitleRuleMessage)
	assert.Zero(t, box.Find("b").Length())

	// refused on the API, for force-merge and auto-merge too
	MakeRequest(t, NewRequestWithJSON(t, "POST", mergeURL, mergeBody).AddTokenAuth(token), http.StatusMethodNotAllowed)
	mergeBody.ForceMerge = true
	MakeRequest(t, NewRequestWithJSON(t, "POST", mergeURL, mergeBody).AddTokenAuth(token), http.StatusMethodNotAllowed)
	require.NoError(t, pr.LoadBaseRepo(t.Context()))
	perm, err := access_model.GetUserRepoPermission(t.Context(), repo, owner)
	require.NoError(t, err)
	err = pull_service.CheckPullMergeable(t.Context(), owner, &perm, pr, pull_service.MergeCheckTypeAuto, true, repo_model.MergeStyleMerge)
	require.ErrorAs(t, err, new(*git_model.ErrPRTitleRule))

	// the web merge answers with the message
	resp = session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/user2/repo1/pulls/%d/merge", pr.Index), map[string]string{"do": "merge"}), http.StatusBadRequest)
	var e map[string]string
	DecodeJSON(t, resp, &e)
	assert.Equal(t, prTitleRuleMessage, e["errorMessage"])

	// a user without merge rights gets "not allowed", not the rule message
	reader := loginUser(t, "user5")
	readerToken := getTokenForLoggedInUser(t, reader, auth_model.AccessTokenScopeWriteRepository)
	resp = MakeRequest(t, NewRequestWithJSON(t, "POST", mergeURL, mergeBody).AddTokenAuth(readerToken), http.StatusMethodNotAllowed)
	assert.NotContains(t, resp.Body.String(), "Start with ABC-1")

	// marking as merged manually skips the title rule by design: nothing is merged by gitdepo
	require.NoError(t, pull_service.CheckPullMergeable(t.Context(), owner, &perm, pr, pull_service.MergeCheckTypeManually, true, repo_model.MergeStyleMerge))

	// a WIP pull request keeps its own error first
	require.NoError(t, issue_service.ChangeTitle(t.Context(), pr.Issue, owner, "WIP: no key"))
	err = pull_service.CheckPullMergeable(t.Context(), owner, &perm, pr, pull_service.MergeCheckTypeGeneral, true, repo_model.MergeStyleMerge)
	require.ErrorIs(t, err, pull_service.ErrIsWorkInProgress)

	// fixing the title allows the merge
	require.NoError(t, issue_service.ChangeTitle(t.Context(), pr.Issue, owner, "ABC-1 fixed"))
	MakeRequest(t, NewRequestWithJSON(t, "POST", mergeURL, mergeBody).AddTokenAuth(token), http.StatusOK)
}

func TestPRTitleRuleInvalidStoredRule(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: repo.OwnerID})
	session := loginUser(t, owner.Name)
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteIssue)
	prTitleRuleBranch(t, repo, owner, "t-invalid")
	_, err := db.GetEngine(t.Context()).Insert(&git_model.PushRule{RepoID: repo.ID, PRTitleRegex: "("}) // bypasses the settings validation
	require.NoError(t, err)

	logChecker, cleanup := test.NewLogChecker(log.DEFAULT, log.ERROR)
	defer cleanup()
	logChecker.Filter("Invalid pull request title rule").StopMark("Invalid pull request title rule")
	before := countPulls(t)
	resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls", &api.CreatePullRequestOption{
		Head: "t-invalid", Base: "master", Title: "anything",
	}).AddTokenAuth(token), http.StatusUnprocessableEntity)
	assert.Contains(t, resp.Body.String(), "must fix it on the push rules settings page")
	assert.Equal(t, before, countPulls(t))
	logFiltered, _ := logChecker.Check(5 * time.Second)
	assert.True(t, logFiltered[0], "expected the invalid rule to be logged")

	// the repository UI still renders
	session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/pulls"), http.StatusOK)
	session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/push_rules"), http.StatusOK)
}

func TestPRTitleRuleSystemRetarget(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: repo.OwnerID})
	session := loginUser(t, owner.Name)
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)

	// child PR t-child -> t-parent
	prTitleRuleBranch(t, repo, owner, "t-parent")
	_, err := files_service.ChangeRepoFiles(git.DefaultContext, repo, owner, &files_service.ChangeRepoFilesOptions{
		Files:     []*files_service.ChangeRepoFile{{Operation: "create", TreePath: "child.txt", ContentReader: strings.NewReader("c")}},
		OldBranch: "t-parent",
		NewBranch: "t-child",
	})
	require.NoError(t, err)
	resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls", &api.CreatePullRequestOption{
		Head: "t-child", Base: "t-parent", Title: "child without key",
	}).AddTokenAuth(token), http.StatusCreated)
	var child api.PullRequest
	DecodeJSON(t, resp, &child)

	// refuse mode covering the new base: the automatic retarget is a system action and must not be refused
	setPRTitleRule(t, repo.ID, git_model.PushRule{PRTitleRegex: `^ABC-\d+ `, PRTitleBranches: "master"})
	require.NoError(t, pull_service.RetargetBranchPulls(t.Context(), owner, repo.ID, "t-parent", "master"))
	assert.Equal(t, "master", unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: child.ID}).BaseBranch)
}

func TestPRTitleRuleRevert(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		ctx := NewAPITestContext(t, "user2", "", auth_model.AccessTokenScopeWriteRepository)
		repo, _ := revertTestRepo(t, ctx, "revert-title-rule", repo_model.MergeStyleSquash)
		setPRTitleRule(t, repo.ID, git_model.PushRule{PRTitleRegex: `^ABC-\d+ `, PRTitleMessage: prTitleRuleMessage})
		before := countPulls(t)

		// API: 422 with the plain message, no pull request row and no revert branch left behind
		resp := ctx.Session.MakeRequest(t, NewRequest(t, "POST", revertTestURL("revert-title-rule", 1)).AddTokenAuth(ctx.Token), http.StatusUnprocessableEntity)
		var apiErr api.APIError
		DecodeJSON(t, resp, &apiErr)
		assert.Equal(t, prTitleRuleMessage, apiErr.Message)
		assert.Equal(t, before, countPulls(t))
		gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
		require.NoError(t, err)
		defer gitRepo.Close()
		assert.False(t, gitRepo.IsBranchExist("revert-1-feature"))
		// so a retry after fixing the rule works
		setPRTitleRule(t, repo.ID, git_model.PushRule{})
		ctx.Session.MakeRequest(t, NewRequest(t, "POST", revertTestURL("revert-title-rule", 1)).AddTokenAuth(ctx.Token), http.StatusCreated)

		// web (another repository): a flash on the original pull request, shown escaped
		webRepo, _ := revertTestRepo(t, ctx, "revert-title-rule-web", repo_model.MergeStyleSquash)
		const linkMessage = `<a href="https://evil.example/login">sign in again</a>`
		setPRTitleRule(t, webRepo.ID, git_model.PushRule{PRTitleRegex: `^ABC-\d+ `, PRTitleMessage: linkMessage})
		before = countPulls(t)
		resp = ctx.Session.MakeRequest(t, NewRequest(t, "POST", "/user2/revert-title-rule-web/pulls/1/revert"), http.StatusSeeOther)
		assert.Equal(t, "/user2/revert-title-rule-web/pulls/1", test.RedirectURL(resp))
		flash := NewHTMLParser(t, ctx.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/revert-title-rule-web/pulls/1"), http.StatusOK).Body).Find(".flash-error")
		assert.Contains(t, flash.Text(), linkMessage) // shown as text...
		assert.Zero(t, flash.Find("a").Length())      // ...not as a link or other markup
		assert.Equal(t, before, countPulls(t))
	})
}

func TestPRTitleRuleForkPull(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	session := loginUser(t, user4.Name)
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	forkName := "repo1-title-fork"
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/forks", &api.CreateForkOption{Name: &forkName}).AddTokenAuth(token), http.StatusAccepted)
	fork := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: user4.ID, Name: forkName})
	prTitleRuleBranch(t, fork, user4, "t-fork")

	// only the base repository's rule counts: the fork has none
	setPRTitleRule(t, repo.ID, git_model.PushRule{PRTitleRegex: `^ABC-\d+ `, PRTitleMessage: prTitleRuleMessage})
	before := countPulls(t)
	create := func(title string, status int) {
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls", &api.CreatePullRequestOption{
			Head: "user4:t-fork", Base: "master", Title: title,
		}).AddTokenAuth(token), status)
	}
	create("no key", http.StatusUnprocessableEntity)
	assert.Equal(t, before, countPulls(t))
	create("ABC-1 fork", http.StatusCreated)
}
