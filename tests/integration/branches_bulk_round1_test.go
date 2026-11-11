// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/ratelimit"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/services/branchworkflow"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func b1PullAPI(t *testing.T, s *TestSession, owner, repo, head, base string) {
	t.Helper()
	token := getTokenForLoggedInUser(t, s, auth_model.AccessTokenScopeWriteRepository)
	s.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/"+owner+"/"+repo+"/pulls", &api.CreatePullRequestOption{
		Head: head, Base: base, Title: "pr " + head + " into " + base,
	}).AddTokenAuth(token), http.StatusCreated)
}

// RT1: a pull request in a stranger's fork whose head is a branch of this repository keeps nothing; a pull request
// from this repository into its fork parent keeps its head, and a pull request into this repository keeps its base.
func TestBranchesBulkOpenPRRule(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		owner := loginUser(t, "user2")
		bwRepo(t, "rt-pin")
		testAPICreateBranch(t, owner, "org3", "rt-pin", "master", "victim", http.StatusCreated)
		testEditFile(t, owner, "org3", "rt-pin", "victim", "README.md", "victim work\n")
		testAPICreateBranch(t, owner, "org3", "rt-pin", "master", "other", http.StatusCreated)

		stranger := loginUser(t, "user4")
		testRepoFork(t, stranger, "org3", "rt-pin", "user4", "rt-fork")
		// the attack: the PR lives in the stranger's fork and its head is the upstream branch
		b1PullAPI(t, stranger, "user4", "rt-fork", "org3:victim", "master")

		parent := loadRepo(t, "org3", "rt-pin")
		fork := loadRepo(t, "user4", "rt-fork")
		reason, err := branchworkflow.KeptReason(t.Context(), parent, "victim", true)
		require.NoError(t, err)
		assert.Empty(t, reason, "a pull request in a stranger's fork must not keep the upstream branch")
		tok := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository)
		var res api.DeleteBranchesResult
		DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/rt-pin/branches/delete",
			&api.DeleteBranchesOption{Names: []string{"victim"}}).AddTokenAuth(tok), http.StatusOK), &res)
		assert.Equal(t, []string{"victim"}, res.Deleted)

		// the normal direction: the fork's branch into the parent keeps the fork's branch, the parent's base branch is kept
		testAPICreateBranch(t, stranger, "user4", "rt-fork", "master", "featx", http.StatusCreated)
		testEditFile(t, stranger, "user4", "rt-fork", "featx", "README.md", "x\n")
		b1PullAPI(t, stranger, "org3", "rt-pin", "user4:featx", "other")
		for _, c := range []struct {
			repo   *repo_model.Repository
			branch string
			want   string
		}{
			{fork, "featx", branchworkflow.KeptOpenPR},   // head in this repository, base is the fork parent
			{parent, "other", branchworkflow.KeptOpenPR}, // base of a pull request into this repository
			{parent, "featx", ""},                        // the head lives in the fork
			{fork, "other", ""},
		} {
			got, err := branchworkflow.KeptReason(t.Context(), c.repo, c.branch, true)
			require.NoError(t, err)
			assert.Equal(t, c.want, got, "%s %s", c.repo.FullName(), c.branch)
			k, err := branchworkflow.NewKeptChecker(t.Context(), c.repo, true)
			require.NoError(t, err)
			assert.Equal(t, c.want, k.Reason(c.branch), "checker: %s %s", c.repo.FullName(), c.branch)
		}
	})
}

// RT2: the merged filter pins the tip git walked: a push after the walk is not deleted as merged.
func TestBranchesBulkMergedPinsWalkedTip(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		s := loginUser(t, "user2")
		repo := dmRepo(t, s, "rt-merged")
		gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
		require.NoError(t, err)
		defer gitRepo.Close()
		model, err := branchworkflow.GetEffectiveModel(t.Context(), repo)
		require.NoError(t, err)
		walkedTip := bkTip(t, repo, "merged-old")

		q, err := repo_service.BranchFilter{State: repo_service.BranchMerged}.Query(t.Context(), repo, gitRepo, model)
		require.NoError(t, err)
		found, err := repo_service.FindDeletableBranches(t.Context(), repo, q, 100)
		require.NoError(t, err)
		assert.Contains(t, found.Branches, repo_service.SelectedBranch{Name: "merged-old", Commit: walkedTip})

		// a push between the walk and the row read: merged-old now carries unmerged work
		testEditFile(t, s, "org3", "rt-merged", "merged-old", "README.md", "unmerged work\n")
		found, err = repo_service.FindDeletableBranches(t.Context(), repo, q, 100)
		require.NoError(t, err)
		for _, b := range found.Branches {
			assert.NotEqual(t, "merged-old", b.Name)
		}
		doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "user2"})
		// and a delete pinned to the walked tip is refused by the compare-and-swap
		res, err := repo_service.DeleteSelectedBranches(t.Context(), doer, repo, gitRepo, []repo_service.SelectedBranch{{Name: "merged-old", Commit: walkedTip}})
		require.NoError(t, err)
		assert.Equal(t, []repo_service.BranchResult{{Name: "merged-old", Reason: repo_service.KeptNewCommits}}, res)
		assert.Contains(t, dmBranches(t, repo), "merged-old")
	})
}

// L4: a pull request opened while the run is going keeps its branch: the rule is read per branch, right before it.
func TestBranchesBulkKeptRuleReadPerBranch(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		s := loginUser(t, "user2")
		repo := bkRepo(t, s, "bk-race")
		doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "user2"})
		gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
		require.NoError(t, err)
		defer gitRepo.Close()
		opened := false
		repo_service.DeleteBranchTestHook = func(_ *repo_model.Repository, branch string) {
			if branch == "m-a" && !opened {
				opened = true
				b1PullAPI(t, s, "org3", repo.Name, "unmerged2", "master")
			}
		}
		defer func() { repo_service.DeleteBranchTestHook = nil }()
		res, err := repo_service.DeleteSelectedBranches(t.Context(), doer, repo, gitRepo, []repo_service.SelectedBranch{{Name: "m-a"}, {Name: "unmerged2"}})
		require.NoError(t, err)
		assert.Equal(t, []repo_service.BranchResult{{Name: "m-a"}, {Name: "unmerged2", Reason: branchworkflow.KeptOpenPR}}, res)
		assert.Contains(t, dmBranches(t, repo), "unmerged2")
	})
}

// RT3 and the audit notes: refused branches are listed in the summary with their codes, each deletion says "bulk", a
// failed summary entry fails the request, a restore is recorded, and the web refuses a mirror like the API.
func TestBranchesBulkAudit(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		s := loginUser(t, "user2")
		repo := bkRepo(t, s, "bk-audit")
		link := "/org3/" + repo.Name
		tok := getTokenForLoggedInUser(t, s, auth_model.AccessTokenScopeWriteRepository)
		endpoint := "/api/v1/repos/org3/" + repo.Name + "/branches/delete"
		audit_model.ResetActivity()

		since := auditMaxID(t)
		var res api.DeleteBranchesResult
		DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", endpoint,
			&api.DeleteBranchesOption{Names: []string{"m-a", "prot-merged", "pr-base", "master", "ghost"}}).AddTokenAuth(tok), http.StatusOK), &res)
		assert.Equal(t, []string{"m-a"}, res.Deleted)
		e := repoOne(t, since, "repo.branches.bulk_deleted", repo)
		assert.ElementsMatch(t, []any{"ghost: not_found", "master: default", "pr-base: open_pr", "prot-merged: protected"}, auditData(t, e)["refused"])
		one := auditActions(t, since, "repo.branch.deleted")
		require.Len(t, one, 1)
		assert.Equal(t, "bulk", auditData(t, one[0])["via"])

		// a failed summary entry fails the request (the deletions stand and are audited one by one)
		func() {
			insert := audit_model.InsertEntry
			defer test.MockVariableValue(&audit_model.InsertEntry, func(ctx context.Context, e *audit_model.Entry) error {
				if e.Action == "repo.branches.bulk_deleted" {
					return errors.New("audit down")
				}
				return insert(ctx, e)
			})()
			MakeRequest(t, NewRequestWithJSON(t, "POST", endpoint, &api.DeleteBranchesOption{Names: []string{"m-b"}}).AddTokenAuth(tok), http.StatusInternalServerError)
		}()

		// a restore is its own audit action
		row := unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: repo.ID, Name: "m-a", IsDeleted: true})
		since = auditMaxID(t)
		s.MakeRequest(t, NewRequestWithURLValues(t, "POST", link+"/branches/restore_selected", url.Values{"branch_id": {strconv.FormatInt(row.ID, 10)}}), http.StatusSeeOther)
		restored := auditActions(t, since, "repo.branch.restored")
		require.Len(t, restored, 1)
		assert.Equal(t, "m-a", restored[0].TargetName)

		// the web refuses a mirror
		setMirror := func(on bool) {
			_, err := db.GetEngine(t.Context()).ID(repo.ID).Cols("is_mirror").Update(&repo_model.Repository{IsMirror: on})
			require.NoError(t, err)
		}
		setMirror(true)
		defer setMirror(false)
		s.MakeRequest(t, NewRequestWithURLValues(t, "POST", link+"/branches/delete_selected", url.Values{"branch": {"m-keep"}}), http.StatusForbidden)
		assert.Contains(t, dmBranches(t, repo), "m-keep")
	})
}

// O2: restoring under a required branch type names that reason for the branch, not a generic failure.
func TestBranchesBulkRestoreTypeRequired(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		s := loginUser(t, "user2")
		repo := bkRepo(t, s, "bk-restore")
		link := "/org3/" + repo.Name
		bkPost(t, s, link, "", bkTip(t, repo, "m-a")+":m-a")
		row := unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: repo.ID, Name: "m-a", IsDeleted: true})
		// the model now requires a type, and "m-a" has none
		ctx := NewAPITestContext(t, "user2", repo.Name, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		btModel(t, ctx, repo.Name, bnOptions(api.BranchNaming{RequireBranchType: true}), http.StatusOK)
		s.MakeRequest(t, NewRequestWithURLValues(t, "POST", link+"/branches/restore_selected", url.Values{"branch_id": {strconv.FormatInt(row.ID, 10)}}), http.StatusSeeOther)
		flash := bwFlash(s)
		assert.Contains(t, flash, "m-a: the branching model requires a branch type this name lacks")
		assert.NotContains(t, dmBranches(t, repo), "m-a")
	})
}

// L3: the API filter delete walks the history and reads every branch row, so it takes a heavy token; naming
// branches does not.
func TestBranchesBulkAPIFilterHeavy(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		s := loginUser(t, "user2")
		repo := bkRepo(t, s, "bk-heavy")
		tok := getTokenForLoggedInUser(t, s, auth_model.AccessTokenScopeWriteRepository)
		endpoint := "/api/v1/repos/org3/" + repo.Name + "/branches/delete"
		mockRateLimit(t, map[string]setting.RateLimitClass{
			ratelimit.Heavy: {AuthenticatedRate: slow, AuthenticatedBurst: 1, AnonymousRate: slow, AnonymousBurst: 1},
		}, "")
		post := func(o *api.DeleteBranchesOption, status int) {
			t.Helper()
			MakeRequest(t, fromIP(NewRequestWithJSON(t, "POST", endpoint, o).AddTokenAuth(tok), "198.51.100.77"), status)
		}
		post(&api.DeleteBranchesOption{Names: []string{"ghost"}}, http.StatusOK) // naming is no heavy work
		post(&api.DeleteBranchesOption{Merged: "merged"}, http.StatusOK)
		post(&api.DeleteBranchesOption{Merged: "merged"}, http.StatusTooManyRequests)
	})
}
