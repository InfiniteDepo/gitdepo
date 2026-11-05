// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	repo_service "forgejo.org/services/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// expensiveRules returns n rules of 100 path patterns that are slow to match against long paths of "ab/".
func expensiveRules(prefix string, n int, users ...string) []*api.ApprovalRule {
	var rules []*api.ApprovalRule
	for i := range n {
		var patterns []string
		for j := range 100 {
			patterns = append(patterns, fmt.Sprintf("**/a*b*c%d_%d/**", i, j))
		}
		rules = append(rules, &api.ApprovalRule{
			Name: fmt.Sprintf("%s%d", prefix, i), RequiredCount: 1, RequireCodeOwners: true, Usernames: users, PathPatterns: strings.Join(patterns, ";"),
		})
	}
	return rules
}

// workSetup is the worst case of approval-rule path matching: 20 rules of 100 patterns on each of the three levels
// (repository, project, organization), with code owners, and a pull request of 20 changed files with paths of about
// 4 KiB. codeowners, if set, is the CODEOWNERS file of the base branch.
func workSetup(t *testing.T, name, codeowners string) (owner APITestContext, repo *repo_model.Repository, e *drEnv, pull int64) {
	owner = NewAPITestContext(t, "user2", "", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
	bwRepo(t, name)
	repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: name})
	ctx := asActor(t, 2, "user2")
	group, err := repo_model.CreateRepoGroup(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}), name+"-project", "")
	require.NoError(t, err)
	require.NoError(t, repo_service.MoveRepository(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), repo, group.ID))
	repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
	e = newDREnv(t, repo.ID)
	e.branch(name)
	if codeowners != "" {
		e.change(name, "", create("CODEOWNERS", codeowners))
	}

	e.do("POST", "/branch_protections", &api.CreateBranchProtectionOption{RuleName: name, ApprovalRules: expensiveRules("R", 20, "user2")}, http.StatusCreated)
	for _, p := range []string{"/api/v1/orgs/org3/branch_protections", fmt.Sprintf("/api/v1/orgs/org3/projects/%d/branch_protections", group.ID)} {
		body := &api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: name, ApprovalRules: expensiveRules("O", 20, "user2")}}
		MakeRequest(t, NewRequestWithJSON(t, "POST", p, body).AddTokenAuth(owner.Token), http.StatusCreated)
	}

	// 20 files with paths of about 4 KiB: matching one rule takes a large part of the budget
	var paths []string
	for i := range 20 {
		paths = append(paths, strings.Repeat("ab/", 1360)+fmt.Sprintf("f%d", i))
	}
	commitFiles(t, repo, name, name+"-head", paths)
	return owner, repo, e, e.open(name, name+"-head", "long paths")
}

// commitFiles commits the files at paths (each holding "x") on top of base as branch head, without a work tree.
func commitFiles(t *testing.T, repo *repo_model.Repository, base, head string, paths []string) {
	t.Helper()
	index := filepath.Join(t.TempDir(), "index")
	git := func(stdin string, args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo.RepoPath()
		cmd.Stdin = strings.NewReader(stdin)
		cmd.Env = append(os.Environ(), "GIT_INDEX_FILE="+index, "GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@example.com", "GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@example.com")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return strings.TrimSpace(string(out))
	}
	git("", "read-tree", base)
	blob := git("x", "hash-object", "-w", "--stdin")
	var info strings.Builder
	for _, p := range paths {
		fmt.Fprintf(&info, "100644 %s\t%s\n", blob, p)
	}
	git(info.String(), "update-index", "--add", "--index-info")
	git("", "update-ref", "refs/heads/"+head, git("", "commit-tree", git("", "write-tree"), "-p", base, "-m", "files"))
}

// timed runs f and fails if it takes 4 s or more: it was about 13 s per request (0.2 s per rule), twice that with
// code owners, and about 37 s with a large CODEOWNERS file (74 s for the pull request page with the owner marks).
func timed(t *testing.T, what string, f func()) {
	t.Helper()
	start := time.Now()
	f()
	assert.Less(t, time.Since(start), 4*time.Second*slowdown, what)
}

// One evaluation of the approval rules of a pull request shares one work budget: every rule of the three levels,
// with code owners, costs about one budget, and the rules beyond it apply (fail closed).
func TestApprovalRulesWorkPerRequest(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		owner, repo, e, pull := workSetup(t, "ar-work", "")

		var rules []*api.PullApprovalRule
		timed(t, "approvals", func() { rules = e.approvals(pull) })
		// the first few rules are matched (no file matches them), the rest are beyond the budget and apply
		assert.Greater(t, len(rules), 50)
		assert.Less(t, len(rules), 60)
		for _, r := range rules {
			assert.False(t, r.Satisfied, r.Name)
		}
		timed(t, "pull request page", func() {
			owner.Session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/pulls/%d", repo.Link(), pull)), http.StatusOK)
		})
		timed(t, "merge check", func() { e.merge(pull, http.StatusMethodNotAllowed) })
	})
}

// CODEOWNERS lines are matched once per request, under the same budget: with a CODEOWNERS file of 500 lines that
// scan the whole path, naming owners who can't approve, the requests stay bounded. Past the budget, code owners
// can't be checked and block the merge.
func TestApprovalRulesWorkWithCodeOwners(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		var co strings.Builder
		for i := range 500 {
			fmt.Fprintf(&co, ".*\\.ext%d @user4 @user5 @user8 @org3/team1\n", i)
		}
		co.WriteString(".*f[0-9]+ @user4 @user5 @user8 @org3/team1\n")
		setUserCols(t, 4, func(u *user_model.User) { u.IsActive = false }, "is_active")
		setUserCols(t, 5, func(u *user_model.User) { u.ProhibitLogin = true }, "prohibit_login")
		owner, repo, e, pull := workSetup(t, "ar-work-co", co.String())

		timed(t, "approvals", func() { e.approvals(pull) })
		page := fmt.Sprintf("%s/pulls/%d", repo.Link(), pull)
		var body string
		timed(t, "pull request page (organization owner)", func() {
			body = owner.Session.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body.String()
		})
		admin := loginUser(t, "user1")
		timed(t, "pull request page (site admin)", func() { admin.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK) })
		timed(t, "pull request page (anonymous)", func() { MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK) })
		timed(t, "merge check", func() { e.merge(pull, http.StatusMethodNotAllowed) })
		// the rules that apply are checked against CODEOWNERS only while the budget lasts
		assert.Contains(t, body, "codeowners-unchecked")
	})
}

// A legitimate large pull request stays mergeable: a CODEOWNERS file of 1000 prefix lines and 1000 changed files
// (a mass vendoring) cost only the prefixes of the lines a path doesn't start with, so the code owner's approval
// counts and the pull request merges.
func TestApprovalRulesWorkLargePullRequest(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		name := "ar-work-mono"
		var co strings.Builder
		var paths []string
		for i := range 1000 {
			fmt.Fprintf(&co, "team%04d/.* @user1\n", i)
			paths = append(paths, fmt.Sprintf("team%04d/vendor/github.com/example/lib/file.go", i))
		}
		bwRepo(t, name)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: name})
		e := newDREnv(t, repo.ID)
		e.branch(name)
		e.change(name, "", create("CODEOWNERS", co.String()))
		e.do("POST", "/branch_protections", &api.CreateBranchProtectionOption{RuleName: name, ApprovalRules: []*api.ApprovalRule{
			{Name: "Owners", RequiredCount: 1, RequireCodeOwners: true},
		}}, http.StatusCreated)
		commitFiles(t, repo, name, name+"-head", paths)
		pull := e.open(name, name+"-head", "vendor")
		token := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeWriteRepository)
		MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/org3/%s/pulls/%d/reviews", name, pull), &api.CreatePullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(token), http.StatusOK)

		var rules []*api.PullApprovalRule
		timed(t, "approvals", func() { rules = e.approvals(pull) })
		require.Len(t, rules, 1)
		assert.True(t, rules[0].Satisfied)
		timed(t, "merge", func() { e.merge(pull, http.StatusOK) })
	})
}
