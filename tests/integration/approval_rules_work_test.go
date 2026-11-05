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

// One evaluation of the approval rules of a pull request shares one work budget: 20 rules of 100 patterns on each
// of the three levels (repository, project, organization), with code owners, against 20 changed files of about
// 4 KiB, cost about one rule's matching, and the rules beyond the budget apply (fail closed).
func TestApprovalRulesWorkPerRequest(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		owner := NewAPITestContext(t, "user2", "", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
		bwRepo(t, "ar-work")
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: "ar-work"})
		ctx := asActor(t, 2, "user2")
		group, err := repo_model.CreateRepoGroup(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}), "ar-work-project", "")
		require.NoError(t, err)
		require.NoError(t, repo_service.MoveRepository(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), repo, group.ID))
		repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
		e := newDREnv(t, repo.ID)
		e.branch("ar-work")

		e.do("POST", "/branch_protections", &api.CreateBranchProtectionOption{RuleName: "ar-work", ApprovalRules: expensiveRules("R", 20, "user2")}, http.StatusCreated)
		for _, p := range []string{"/api/v1/orgs/org3/branch_protections", fmt.Sprintf("/api/v1/orgs/org3/projects/%d/branch_protections", group.ID)} {
			body := &api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "ar-work", ApprovalRules: expensiveRules("O", 20, "user2")}}
			MakeRequest(t, NewRequestWithJSON(t, "POST", p, body).AddTokenAuth(owner.Token), http.StatusCreated)
		}

		// 20 files with paths of about 4 KiB: matching one rule takes nearly the whole budget
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
		git("", "read-tree", "ar-work")
		blob := git("x", "hash-object", "-w", "--stdin")
		for i := range 20 {
			git("", "update-index", "--add", "--cacheinfo", "100644,"+blob+","+strings.Repeat("ab/", 1360)+fmt.Sprintf("f%d", i))
		}
		commit := git("", "commit-tree", git("", "write-tree"), "-p", "ar-work", "-m", "long paths")
		git("", "update-ref", "refs/heads/ar-work-head", commit)
		pull := e.open("ar-work", "ar-work-head", "long paths")

		// it was about 13 s for each request (0.2 s per rule), twice that with code owners
		limit := 4 * time.Second
		start := time.Now()
		rules := e.approvals(pull)
		assert.Less(t, time.Since(start), limit, "approvals")
		// the first rule is matched (no file matches it), the 59 beyond the budget apply: they fail closed
		assert.Len(t, rules, 59)
		for _, r := range rules {
			assert.False(t, r.Satisfied, r.Name)
		}

		start = time.Now()
		owner.Session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/pulls/%d", repo.Link(), pull)), http.StatusOK)
		assert.Less(t, time.Since(start), limit, "pull request page")

		start = time.Now()
		e.merge(pull, http.StatusMethodNotAllowed)
		assert.Less(t, time.Since(start), limit, "merge check")
	})
}
