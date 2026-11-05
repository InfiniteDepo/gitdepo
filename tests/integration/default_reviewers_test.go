// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/process"
	api "forgejo.org/modules/structs"
	"forgejo.org/services/forms"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// drEnv works on one repository through /api/v1/repositories/{id}, which also serves repositories in a project.
// user2 owns it and authors the pull requests.
type drEnv struct {
	t      *testing.T
	owner  APITestContext
	repoID int64
	api    string
	last   *api.PullRequest // the last pull request opened
}

func newDREnv(t *testing.T, repoID int64, user ...string) *drEnv {
	user = append(user, "user2")
	return &drEnv{
		t: t, repoID: repoID, api: fmt.Sprintf("/api/v1/repositories/%d", repoID),
		owner: NewAPITestContext(t, user[0], "", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteUser),
	}
}

func (e *drEnv) do(method, path string, body any, expected int) *httptest.ResponseRecorder {
	e.t.Helper()
	req := NewRequestWithJSON(e.t, method, e.api+path, body).AddTokenAuth(e.owner.Token)
	return e.owner.Session.MakeRequest(e.t, req, expected)
}

func (e *drEnv) collaborator(user, permission string) {
	e.t.Helper()
	e.do("PUT", "/collaborators/"+user, &api.AddCollaboratorOption{Permission: &permission}, http.StatusNoContent)
}

func (e *drEnv) change(branch, newBranch string, files ...*api.ChangeFileOperation) {
	e.t.Helper()
	e.do("POST", "/contents", &api.ChangeFilesOptions{FileOptions: api.FileOptions{BranchName: branch, NewBranchName: newBranch, Message: "change"}, Files: files}, http.StatusCreated)
}

func (e *drEnv) branch(name string) {
	e.t.Helper()
	e.do("POST", "/branches", &api.CreateBranchRepoOption{BranchName: name, OldRefName: "master"}, http.StatusCreated)
}

func (e *drEnv) protect(base string, rules ...*api.ApprovalRule) {
	e.t.Helper()
	e.do("POST", "/branch_protections", &api.CreateBranchProtectionOption{RuleName: base, ApplyToAdmins: true, ApprovalRules: rules}, http.StatusCreated)
}

// pr opens a pull request from a new branch head (made from base, with files) into base.
func (e *drEnv) pr(base, head, title string, files ...*api.ChangeFileOperation) int64 {
	e.t.Helper()
	e.change(base, head, files...)
	return e.open(base, head, title)
}

func (e *drEnv) open(base, head, title string) int64 {
	e.t.Helper()
	var pr api.PullRequest
	DecodeJSON(e.t, e.do("POST", "/pulls", &api.CreatePullRequestOption{Base: base, Head: head, Title: title}, http.StatusCreated), &pr)
	e.last = &pr
	return pr.Index
}

func (e *drEnv) issueID(index int64) int64 {
	pr, err := issues_model.GetPullRequestByIndex(e.t.Context(), e.repoID, index)
	require.NoError(e.t, err)
	return pr.IssueID
}

// requested returns the sorted names of the users and ("team:name") teams that hold a review request.
func (e *drEnv) requested(index int64) []string {
	e.t.Helper()
	var reviews []*issues_model.Review
	require.NoError(e.t, db.GetEngine(db.DefaultContext).Where("issue_id = ? AND type = ?", e.issueID(index), issues_model.ReviewTypeRequest).Find(&reviews))
	names := []string{}
	for _, r := range reviews {
		if r.ReviewerTeamID != 0 {
			team, err := organization.GetTeamByID(db.DefaultContext, r.ReviewerTeamID)
			require.NoError(e.t, err)
			names = append(names, "team:"+team.Name)
		} else {
			names = append(names, unittest.AssertExistsAndLoadBean(e.t, &user_model.User{ID: r.ReviewerID}).Name)
		}
	}
	slices.Sort(names)
	return names
}

func (e *drEnv) requestComments(index int64) int64 {
	n, err := db.GetEngine(db.DefaultContext).Where("issue_id = ? AND type = ?", e.issueID(index), issues_model.CommentTypeReviewRequest).Count(new(issues_model.Comment))
	require.NoError(e.t, err)
	return n
}

func (e *drEnv) pushComments(index int64) int64 {
	n, err := db.GetEngine(db.DefaultContext).Where("issue_id = ? AND type = ?", e.issueID(index), issues_model.CommentTypePullRequestPush).Count(new(issues_model.Comment))
	require.NoError(e.t, err)
	return n
}

func teamID(t *testing.T, name string) string {
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{OrgID: 3, Name: name})
	return fmt.Sprint(team.ID)
}

func (e *drEnv) merge(index int64, expected int) string {
	e.t.Helper()
	return e.do("POST", fmt.Sprintf("/pulls/%d/merge", index), &forms.MergePullRequestForm{Do: "merge"}, expected).Body.String()
}

func (e *drEnv) approvals(index int64) []*api.PullApprovalRule {
	var rules []*api.PullApprovalRule
	DecodeJSON(e.t, e.do("GET", fmt.Sprintf("/pulls/%d/approvals", index), nil, http.StatusOK), &rules)
	return rules
}

func pullTaskRunning() bool {
	processes, _ := process.GetManager().Processes(true, true)
	return slices.ContainsFunc(processes, func(p *process.Process) bool { return strings.HasPrefix(p.Description, "AddTestPullRequestTask") })
}

func requestRule(name string, count int64, source string, users ...string) *api.ApprovalRule {
	return &api.ApprovalRule{Name: name, RequiredCount: count, Usernames: users, RequestReviews: true, SourceBranchPattern: source}
}

func setUserCol(t *testing.T, id int64, col string, value, restore any) {
	t.Helper()
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET "+col+" = ? WHERE id = ?", value, id)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET "+col+" = ? WHERE id = ?", restore, id)
		assert.NoError(t, err)
	})
}

// A rule that requests reviews asks its reviewers when a pull request opens; the source branch only limits
// the requests, a rule with a count blocks whatever the source branch is, and a request-only rule requires nothing.
func TestDefaultReviewersOpenAndSource(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newDREnv(t, 1)
		e.collaborator("user4", "write")
		e.collaborator("user5", "write")

		e.branch("dr-open")
		e.protect("dr-open", requestRule("Docs", 0, "feature/*", "user4"), requestRule("Gate", 1, "release/*", "user5"))

		t.Run("SourceMatches", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			index := e.pr("dr-open", "feature/a", "a", create("a.txt", "a"))
			assert.Equal(t, []string{"user4"}, e.requested(index))
			assert.EqualValues(t, 1, e.requestComments(index))
		})

		t.Run("SourceMismatchStillBlocks", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			index := e.pr("dr-open", "other/b", "b", create("b.txt", "b"))
			assert.Empty(t, e.requested(index), "no source pattern matches")
			// Gate has a count, so it blocks although its source pattern doesn't match; Docs is request-only
			assert.Contains(t, e.merge(index, http.StatusMethodNotAllowed), "Gate")
			rules := e.approvals(index)
			require.Len(t, rules, 1)
			assert.Equal(t, "Gate", rules[0].Name)
		})

		t.Run("RequestOnlyRuleDoesNotBlock", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.branch("dr-only")
			e.protect("dr-only", requestRule("Docs", 0, "", "user4"))
			index := e.pr("dr-only", "head-only", "c", create("c.txt", "c"))
			assert.Equal(t, []string{"user4"}, e.requested(index))
			assert.Empty(t, e.approvals(index))
			e.merge(index, http.StatusOK)
		})

		t.Run("WorkInProgress", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.branch("dr-wip")
			e.protect("dr-wip", requestRule("Docs", 0, "", "user4"))
			index := e.pr("dr-wip", "head-wip", "WIP: d", create("d.txt", "d"))
			assert.Empty(t, e.requested(index))
			e.do("PATCH", fmt.Sprintf("/pulls/%d", index), &api.EditPullRequestOption{Title: "d"}, http.StatusCreated)
			assert.Equal(t, []string{"user4"}, e.requested(index), "requested when the WIP prefix goes, like code owners")
		})
	})
}

// A rule with path patterns asks when a push makes it match for the first time, and only then.
func TestDefaultReviewersPathsOnPush(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newDREnv(t, 1)
		e.collaborator("user4", "write")
		e.branch("dr-path")
		rule := requestRule("DB", 0, "", "user4")
		rule.PathPatterns = "db/**"
		e.protect("dr-path", rule)

		index := e.pr("dr-path", "head-path", "p", create("src/a.txt", "a"))
		assert.Empty(t, e.requested(index), "no file matches on open")

		e.change("head-path", "", create("db/x.txt", "x"))
		require.Eventually(t, func() bool { return len(e.requested(index)) == 1 }, 15*time.Second, 100*time.Millisecond)
		assert.Equal(t, []string{"user4"}, e.requested(index))

		// the author takes the request back; the rule matched before this push, so a second push doesn't ask again
		e.do("DELETE", fmt.Sprintf("/pulls/%d/requested_reviewers", index), &api.PullReviewRequestOptions{Reviewers: []string{"user4"}}, http.StatusNoContent)
		before := e.pushComments(index)
		e.change("head-path", "", create("db/y.txt", "y"))
		// the push comment is made by the task that sends the requests: wait until that task is over
		require.Eventually(t, func() bool { return e.pushComments(index) > before && !pullTaskRunning() }, 15*time.Second, 50*time.Millisecond)
		assert.Empty(t, e.requested(index))
	})
}

// A pull request that opens without commits asks its reviewers (also those of a rule without paths) with its first push.
func TestDefaultReviewersEmptyAtOpen(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newDREnv(t, 1)
		e.collaborator("user4", "write")
		e.branch("dr-empty")
		e.protect("dr-empty", requestRule("Ask", 0, "", "user4"))
		e.branch("head-empty")
		index := e.open("dr-empty", "head-empty", "empty")
		assert.Empty(t, e.requested(index))
		e.change("head-empty", "", create("e.txt", "e"))
		require.Eventually(t, func() bool { return len(e.requested(index)) == 1 }, 15*time.Second, 100*time.Millisecond)
	})
}

// Retargeting to a branch with a rule asks its reviewers, except those who already reviewed.
func TestDefaultReviewersRetarget(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newDREnv(t, 1)
		e.collaborator("user4", "write")
		e.collaborator("user10", "write")
		e.branch("dr-from")
		e.branch("dr-to")
		e.protect("dr-to", requestRule("Docs", 0, "", "user4", "user10"))

		index := e.pr("dr-from", "head-retarget", "r", create("r.txt", "r"))
		assert.Empty(t, e.requested(index))
		user10 := NewAPITestContext(t, "user10", "", auth_model.AccessTokenScopeWriteRepository)
		req := NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/pulls/%d/reviews", e.api, index), &api.CreatePullReviewOptions{Event: api.ReviewStateComment, Body: "looks fine"}).AddTokenAuth(user10.Token)
		user10.Session.MakeRequest(t, req, http.StatusOK)

		e.do("PATCH", fmt.Sprintf("/pulls/%d", index), &api.EditPullRequestOption{Base: "dr-to"}, http.StatusCreated)
		assert.Equal(t, []string{"user4"}, e.requested(index))
	})
}

// Nobody who must not be asked is asked: the author, an inactive or login-prohibited user, a user without access to
// the pull requests and a user blocked by the organization's two-factor requirement.
func TestDefaultReviewersNeverRequested(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newDREnv(t, 1)
		for _, name := range []string{"user4", "user5", "user8", "user10"} {
			e.collaborator(name, "write")
		}
		setUserCol(t, 5, "is_active", false, true)
		setUserCol(t, 8, "prohibit_login", true, false)
		e.branch("dr-never")
		e.protect("dr-never", requestRule("Everyone", 0, "", "user2", "user4", "user5", "user8"))
		index := e.pr("dr-never", "head-never", "n", create("n.txt", "n"))
		assert.Equal(t, []string{"user4"}, e.requested(index), "not the author (user2), inactive (user5) or login-prohibited (user8)")

		t.Run("NoPullRequestAccess", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			var repo api.Repository
			DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{
				Name: "dr-private", Private: true, AutoInit: true, Readme: "Default", DefaultBranch: "master",
			}).AddTokenAuth(e.owner.Token), http.StatusCreated), &repo)
			p := newDREnv(t, repo.ID)
			p.protect("master", requestRule("Docs", 0, "", "user2"))
			// saving a rule drops users without write access, so name user4 (no access at all) in the row
			_, err := db.GetEngine(t.Context()).Exec("UPDATE approval_rule SET user_i_ds = ? WHERE name = ? AND protected_branch_id IN (SELECT id FROM protected_branch WHERE repo_id = ?)", "[4]", "Docs", repo.ID)
			require.NoError(t, err)

			index := p.pr("master", "head-private", "x", create("x.txt", "x"))
			assert.Empty(t, p.requested(index))
		})
	})
}

// Organization and project rules ask users and teams of the organization, a team only with the repository, and the
// organization's two-factor requirement keeps blocked users out.
func TestDefaultReviewersOrgAndProject(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		owner := NewAPITestContext(t, "user2", "", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
		bwRepo(t, "dr-org")
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: "dr-org"})
		e := newDREnv(t, repo.ID)
		MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/2/repos/org3/dr-org").AddTokenAuth(owner.Token), http.StatusNoContent)

		orgRule := func(path, name string, rule *api.ApprovalRule) {
			rule.Teams = []string{"team1"}
			body := &api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: name, ApprovalRules: []*api.ApprovalRule{rule}}}
			MakeRequest(t, NewRequestWithJSON(t, "POST", path, body).AddTokenAuth(owner.Token), http.StatusCreated)
		}

		e.branch("dr-org-base")
		orgRule("/api/v1/orgs/org3/branch_protections", "dr-org-base", requestRule("Org", 0, "", "user4"))
		index := e.pr("dr-org-base", "head-org", "o", create("o.txt", "o"))
		assert.Equal(t, []string{"team:team1", "user4"}, e.requested(index))
		assert.Len(t, e.last.RequestedReviewersTeams, 1, "a team is listed once")

		t.Run("TeamWithoutPullRequestsOrRepo", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			team := func(name string, units []string) {
				MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/teams", &api.CreateTeamOption{Name: name, Permission: "read", Units: units}).AddTokenAuth(owner.Token), http.StatusCreated)
			}
			team("dr-nopulls", []string{"repo.code"})
			team("dr-norepo", []string{"repo.code", "repo.pulls"})
			MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/"+teamID(t, "dr-nopulls")+"/repos/org3/dr-org").AddTokenAuth(owner.Token), http.StatusNoContent)
			e.branch("dr-org-teams")
			body := &api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "dr-org-teams", ApprovalRules: []*api.ApprovalRule{{
				Name: "Teams", Teams: []string{"team1", "dr-nopulls", "dr-norepo"}, RequestReviews: true,
			}}}}
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/branch_protections", body).AddTokenAuth(owner.Token), http.StatusCreated)
			index := e.pr("dr-org-teams", "head-teams", "tm", create("tm.txt", "tm"))
			assert.Equal(t, []string{"team:team1"}, e.requested(index), "no team without the repository or its pull requests")
		})

		t.Run("TwoFactorBlocked", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			// user2 is no admin and would be blocked itself: the administrator user1 authors this one
			admin := newDREnv(t, repo.ID, "user1")
			e.branch("dr-org-2fa")
			orgRule("/api/v1/orgs/org3/branch_protections", "dr-org-2fa", requestRule("Org", 0, "", "user4"))
			setUserCol(t, 3, "require_two_factor", true, false)
			index := admin.pr("dr-org-2fa", "head-2fa", "t", create("t.txt", "t"))
			assert.Equal(t, []string{"team:team1"}, admin.requested(index), "user4 has no second factor")
		})

		t.Run("Project", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			group, err := repo_model.CreateRepoGroup(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}), "dr-project", "")
			require.NoError(t, err)
			require.NoError(t, repo_service.MoveRepository(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), repo, group.ID))
			e.branch("dr-proj-base")
			orgRule(fmt.Sprintf("/api/v1/orgs/org3/projects/%d/branch_protections", group.ID), "dr-proj-base", requestRule("Project", 0, "", "user4"))
			index := e.pr("dr-proj-base", "head-proj", "q", create("q.txt", "q"))
			assert.Equal(t, []string{"team:team1", "user4"}, e.requested(index))
		})
	})
}

// The new fields round-trip on repository, organization and project rules, and invalid ones are refused (API and web).
func TestDefaultReviewersFields(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newDREnv(t, 1)
		rule := requestRule("Docs", 0, "feature/*", "user2")

		t.Run("API", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.do("POST", "/branch_protections", &api.CreateBranchProtectionOption{RuleName: "df-bad-count", ApprovalRules: []*api.ApprovalRule{{Name: "Zero", RequiredCount: 0, Usernames: []string{"user2"}, SourceBranchPattern: "x/*"}}}, http.StatusUnprocessableEntity)
			e.do("POST", "/branch_protections", &api.CreateBranchProtectionOption{RuleName: "df-bad-glob", ApprovalRules: []*api.ApprovalRule{requestRule("Bad", 1, "[a", "user2")}}, http.StatusUnprocessableEntity)
			e.do("POST", "/branch_protections", &api.CreateBranchProtectionOption{RuleName: "df-bad-count", ApprovalRules: []*api.ApprovalRule{requestRule("Neg", -1, "", "user2")}}, http.StatusUnprocessableEntity)

			bad := func(rule *api.ApprovalRule) {
				t.Helper()
				e.do("POST", "/branch_protections", &api.CreateBranchProtectionOption{RuleName: "df-bad", ApprovalRules: []*api.ApprovalRule{rule}}, http.StatusUnprocessableEntity)
			}
			codeOwners := requestRule("Owners", 0, "", "user2")
			codeOwners.RequireCodeOwners = true
			bad(codeOwners) // a rule without a count can't enforce code owners
			bad(requestRule("Ctl", 1, "a\u0001b", "user2"))
			bad(requestRule("Bidi", 1, "a\u202eb", "user2"))
			bad(requestRule("Complex", 1, strings.Repeat("*aa", 16)+"*c", "user2"))
			path := requestRule("Paths", 1, "", "user2")
			path.PathPatterns = strings.Repeat("*a", 8) + "*"
			bad(path)
			path.PathPatterns = "src/**/*.go;{docs,api}/**"
			e.do("POST", "/branch_protections", &api.CreateBranchProtectionOption{RuleName: "df-paths", ApprovalRules: []*api.ApprovalRule{path}}, http.StatusCreated)

			// a source pattern is trimmed, and dropped without review requests
			trimmed := requestRule("Trim", 0, " release/** ", "user2")
			noRequest := &api.ApprovalRule{Name: "NoRequest", RequiredCount: 1, Usernames: []string{"user2"}, SourceBranchPattern: "x/*"}
			e.do("POST", "/branch_protections", &api.CreateBranchProtectionOption{RuleName: "df-trim", ApprovalRules: []*api.ApprovalRule{trimmed, noRequest}}, http.StatusCreated)
			var tbp api.BranchProtection
			DecodeJSON(t, e.do("GET", "/branch_protections/df-trim", nil, http.StatusOK), &tbp)
			require.Len(t, tbp.ApprovalRules, 2)
			assert.Equal(t, "release/**", tbp.ApprovalRules[0].SourceBranchPattern)
			assert.Empty(t, tbp.ApprovalRules[1].SourceBranchPattern)

			e.do("POST", "/branch_protections", &api.CreateBranchProtectionOption{RuleName: "df-repo", ApprovalRules: []*api.ApprovalRule{rule}}, http.StatusCreated)
			var bp api.BranchProtection
			DecodeJSON(t, e.do("GET", "/branch_protections/df-repo", nil, http.StatusOK), &bp)
			require.Len(t, bp.ApprovalRules, 1)
			assert.Equal(t, rule.Usernames, bp.ApprovalRules[0].Usernames)
			assert.True(t, bp.ApprovalRules[0].RequestReviews)
			assert.Zero(t, bp.ApprovalRules[0].RequiredCount)
			assert.Equal(t, "feature/*", bp.ApprovalRules[0].SourceBranchPattern)
		})

		t.Run("OrgAndProject", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			token := e.owner.Token
			org := &api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "df-org", ApprovalRules: []*api.ApprovalRule{requestRule("Docs", 0, "feature/*", "user4")}}}
			project := newAuditProject(t, token)
			for _, path := range []string{"/api/v1/orgs/org3/branch_protections", fmt.Sprintf("/api/v1/orgs/org3/projects/%d/branch_protections", project)} {
				MakeRequest(t, NewRequestWithJSON(t, "POST", path, &api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "df-bad", ApprovalRules: []*api.ApprovalRule{{Name: "Zero", Usernames: []string{"user4"}}}}}).AddTokenAuth(token), http.StatusUnprocessableEntity)
				MakeRequest(t, NewRequestWithJSON(t, "POST", path, org).AddTokenAuth(token), http.StatusCreated)
				var bp api.OrgBranchProtection
				DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", path+"/df-org").AddTokenAuth(token), http.StatusOK), &bp)
				require.Len(t, bp.ApprovalRules, 1)
				assert.True(t, bp.ApprovalRules[0].RequestReviews)
				assert.Equal(t, "feature/*", bp.ApprovalRules[0].SourceBranchPattern)
				assert.Zero(t, bp.ApprovalRules[0].RequiredCount)
			}
		})

		t.Run("Web", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			const edit = "/user2/repo1/settings/branches/edit"
			saved := func() []*api.ApprovalRule {
				resp := e.owner.Session.MakeRequest(t, NewRequest(t, "GET", e.api+"/branch_protections/df-web").AddTokenAuth(e.owner.Token), NoExpectedStatus)
				if resp.Code == http.StatusNotFound {
					return nil
				}
				var bp api.BranchProtection
				DecodeJSON(t, resp, &bp)
				return bp.ApprovalRules
			}
			form := func(count, request, source string) url.Values {
				return url.Values{"rule_name": {"df-web"}, "approval_rule_name": {"Web"}, "approval_rule_count": {count}, "approval_rule_users": {"user2"}, "approval_rule_request_reviews": {request}, "approval_rule_source_branch": {source}}
			}
			// refused: nothing is saved
			for _, count := range []string{"", "1x", "99999999999999999999"} {
				e.owner.Session.MakeRequest(t, NewRequestWithURLValues(t, "POST", edit, form(count, "true", "")), http.StatusSeeOther)
				assert.Empty(t, saved(), "count %q", count)
			}
			withOwners := form("0", "true", "")
			withOwners.Set("approval_rule_code_owners", "true")
			e.owner.Session.MakeRequest(t, NewRequestWithURLValues(t, "POST", edit, withOwners), http.StatusSeeOther)
			assert.Empty(t, saved())
			e.owner.Session.MakeRequest(t, NewRequestWithURLValues(t, "POST", edit, form("0", "false", "")), http.StatusSeeOther)
			assert.Empty(t, saved())
			e.owner.Session.MakeRequest(t, NewRequestWithURLValues(t, "POST", edit, form("1", "true", "[a")), http.StatusSeeOther)
			assert.Empty(t, saved())
			// accepted
			e.owner.Session.MakeRequest(t, NewRequestWithURLValues(t, "POST", edit, form("0", "true", "feature/*")), http.StatusSeeOther)
			rules := saved()
			require.Len(t, rules, 1)
			assert.True(t, rules[0].RequestReviews)
			assert.Equal(t, "feature/*", rules[0].SourceBranchPattern)
			// the editor shows the saved values
			resp := e.owner.Session.MakeRequest(t, NewRequest(t, "GET", edit+"?rule_name=df-web"), http.StatusOK)
			page := NewHTMLParser(t, resp.Body)
			assert.Equal(t, "true", page.Find(`select[name="approval_rule_request_reviews"] option[selected]`).AttrOr("value", ""))
			assert.Equal(t, "feature/*", page.Find(`input[name="approval_rule_source_branch"]`).AttrOr("value", ""))
		})
	})
}

// A request of a rule without a count is no official request and can't block a merge; one of a rule with a count is official.
func TestDefaultReviewersOfficial(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newDREnv(t, 1)
		e.collaborator("user4", "write")
		e.collaborator("user5", "write")
		official := func(index int64, user string) bool {
			var r issues_model.Review
			has, err := db.GetEngine(db.DefaultContext).Where("issue_id = ? AND type = ? AND reviewer_id = ?", e.issueID(index), issues_model.ReviewTypeRequest, unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: user}).ID).Get(&r)
			require.NoError(t, err)
			require.True(t, has)
			return r.Official
		}
		protect := func(base string, rule *api.ApprovalRule) {
			e.branch(base)
			e.do("POST", "/branch_protections", &api.CreateBranchProtectionOption{RuleName: base, RequiredApprovals: 1, BlockOnOfficialReviewRequests: true, ApprovalRules: []*api.ApprovalRule{rule}}, http.StatusCreated)
		}

		protect("dr-off0", requestRule("Ask", 0, "", "user4"))
		index := e.pr("dr-off0", "head-off0", "z", create("z.txt", "z"))
		assert.False(t, official(index, "user4"))
		user5 := NewAPITestContext(t, "user5", "", auth_model.AccessTokenScopeWriteRepository)
		MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/pulls/%d/reviews", e.api, index), &api.CreatePullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(user5.Token), http.StatusOK)
		e.merge(index, http.StatusOK) // the pending request of user4 doesn't block

		protect("dr-off1", requestRule("Gate", 1, "", "user4"))
		index = e.pr("dr-off1", "head-off1", "z1", create("z1.txt", "z1"))
		assert.True(t, official(index, "user4"))
	})
}

// A closed pull request gets no requests when its WIP prefix goes.
func TestDefaultReviewersClosed(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newDREnv(t, 1)
		e.collaborator("user4", "write")
		e.branch("dr-closed")
		e.protect("dr-closed", requestRule("Ask", 0, "", "user4"))
		index := e.pr("dr-closed", "head-closed", "WIP: c", create("c.txt", "c"))
		e.do("PATCH", fmt.Sprintf("/pulls/%d", index), &api.EditPullRequestOption{State: new("closed")}, http.StatusCreated)
		e.do("PATCH", fmt.Sprintf("/pulls/%d", index), &api.EditPullRequestOption{Title: "c"}, http.StatusCreated)
		assert.Empty(t, e.requested(index))
	})
}

// Pull requests from a fork and with AGit (whose source is "<pusher>/<topic>") are asked on a push too.
func TestDefaultReviewersForkAndAGit(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newDREnv(t, 1)
		e.collaborator("user4", "write")
		e.collaborator("user5", "write")
		docs := requestRule("Docs", 0, "", "user5")
		docs.PathPatterns = "docs/**"

		t.Run("Fork", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.branch("dr-fork")
			e.protect("dr-fork", docs)
			user4 := NewAPITestContext(t, "user4", "repo1", auth_model.AccessTokenScopeWriteRepository)
			req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/forks", &api.CreateForkOption{Name: new("dr-fork-repo")}).AddTokenAuth(user4.Token)
			var fork api.Repository
			DecodeJSON(t, user4.Session.MakeRequest(t, req, http.StatusAccepted), &fork)
			change := func(branch, newBranch, path string) {
				req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/user4/dr-fork-repo/contents"), &api.ChangeFilesOptions{
					FileOptions: api.FileOptions{BranchName: branch, NewBranchName: newBranch, Message: "change"}, Files: []*api.ChangeFileOperation{create(path, path)},
				}).AddTokenAuth(user4.Token)
				user4.Session.MakeRequest(t, req, http.StatusCreated)
			}
			change("master", "fork-head", "src/f.txt")
			req = NewRequestWithJSON(t, "POST", e.api+"/pulls", &api.CreatePullRequestOption{Base: "dr-fork", Head: "user4:fork-head", Title: "f"}).AddTokenAuth(user4.Token)
			var pr api.PullRequest
			DecodeJSON(t, user4.Session.MakeRequest(t, req, http.StatusCreated), &pr)
			assert.Empty(t, e.requested(pr.Index))
			change("fork-head", "", "docs/f.md")
			require.Eventually(t, func() bool { return len(e.requested(pr.Index)) == 1 }, 15*time.Second, 100*time.Millisecond)
			assert.Equal(t, []string{"user5"}, e.requested(pr.Index))
		})

		t.Run("AGit", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.branch("dr-agit")
			agit := requestRule("Docs", 0, "user4/*", "user5") // matched against the stored head "<pusher>/<topic>"
			agit.PathPatterns = "docs/**"
			e.protect("dr-agit", agit)
			dst := t.TempDir()
			remote := *u
			remote.Path = "/user2/repo1.git"
			remote.User = url.UserPassword("user4", userPassword)
			t.Run("Clone", doGitClone(dst, &remote))
			require.NoError(t, git.NewCommand(git.DefaultContext, "checkout", "-b", "agit-work", "origin/dr-agit").Run(&git.RunOpts{Dir: dst}))
			push := func(path string) {
				require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dst, path)), 0o777))
				require.NoError(t, os.WriteFile(filepath.Join(dst, path), []byte(path), 0o666))
				require.NoError(t, git.AddChanges(dst, true))
				sig := &git.Signature{Email: "user4@example.com", Name: "user4", When: time.Now()}
				require.NoError(t, git.CommitChanges(dst, git.CommitChangesOptions{Committer: sig, Author: sig, Message: "agit " + path}))
				require.NoError(t, git.NewCommand(git.DefaultContext, "push", "origin", "HEAD:refs/for/dr-agit", "-o", "topic=t1", "-o", "title=agit").Run(&git.RunOpts{Dir: dst}))
			}
			push("src/a.txt")
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{Flow: issues_model.PullRequestFlowAGit, BaseRepoID: 1, HeadBranch: "user4/t1"})
			assert.Empty(t, e.requested(pr.Index))
			push("docs/a.md")
			require.Eventually(t, func() bool { return len(e.requested(pr.Index)) == 1 }, 15*time.Second, 100*time.Millisecond)
			assert.Equal(t, []string{"user5"}, e.requested(pr.Index))
		})
	})
}

// Approval-rule patterns use linear-time matching: a path pattern within the limits against a long changed path and a
// source branch pattern against a long head branch name, both ending in the pattern's last character, stay fast.
func TestDefaultReviewersPatternLinearTime(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newDREnv(t, 1)
		e.collaborator("user4", "write")
		long := strings.Repeat("a/", 200) + "x"

		e.branch("dr-lin-path")
		rule := &api.ApprovalRule{Name: "Path", RequiredCount: 1, Usernames: []string{"user4"}, PathPatterns: "*/*/*/*/*/*x"}
		e.protect("dr-lin-path", rule)
		index := e.pr("dr-lin-path", "head-lin-path", "lp", create(long, "y"))
		start := time.Now()
		assert.Empty(t, e.approvals(index), "the path has more than six segments")
		assert.Less(t, time.Since(start), 5*time.Second)

		e.collaborator("user10", "write")
		e.branch("dr-lin-source")
		e.protect("dr-lin-source", requestRule("Source", 0, "*/*/*/*/*/*x", "user4"), requestRule("Deep", 0, "**/*/*/*/*x", "user10"))
		// the API caps branch names at 100 bytes, git doesn't
		e.change("dr-lin-source", "head-lin-source", create("ls.txt", "ls"))
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		_, _, err := git.NewCommand(t.Context(), "update-ref").AddDynamicArguments(git.BranchPrefix+long, "head-lin-source").RunStdString(&git.RunOpts{Dir: repo.RepoPath()})
		require.NoError(t, err)
		start = time.Now()
		index = e.open("dr-lin-source", long, "ls")
		assert.Less(t, time.Since(start), 5*time.Second)
		assert.Equal(t, []string{"user10"}, e.requested(index), "only the pattern with ** matches the branch")
	})
}

// A request of an approval rule that only requests reviews is advisory under organization and project rules too: it
// doesn't block with "Block on official review requests", while a request of a rule with a count does.
func TestDefaultReviewersAdvisoryOrgAndProject(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		owner := NewAPITestContext(t, "user2", "", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
		bwRepo(t, "dr-advisory")
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: "dr-advisory"})
		e := newDREnv(t, repo.ID)
		e.collaborator("user4", "write")
		e.collaborator("user28", "write")
		user28 := NewAPITestContext(t, "user28", "", auth_model.AccessTokenScopeWriteRepository)

		check := func(path, base string) {
			t.Helper()
			protect := func(base string, rule *api.ApprovalRule) {
				e.branch(base)
				body := &api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{
					RuleName: base, BlockOnOfficialReviewRequests: true, ApprovalRules: []*api.ApprovalRule{rule},
				}}
				MakeRequest(t, NewRequestWithJSON(t, "POST", path, body).AddTokenAuth(owner.Token), http.StatusCreated)
			}
			protect(base+"-0", requestRule("Ask", 0, "", "user4"))
			index := e.pr(base+"-0", "head-"+base+"-0", "a0", create(base+"0.txt", "a"))
			require.Equal(t, []string{"user4"}, e.requested(index))
			e.merge(index, http.StatusOK)

			protect(base+"-1", requestRule("Gate", 1, "", "user4", "user28"))
			index = e.pr(base+"-1", "head-"+base+"-1", "a1", create(base+"1.txt", "a"))
			require.Equal(t, []string{"user28", "user4"}, e.requested(index))
			MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/pulls/%d/reviews", e.api, index), &api.CreatePullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(user28.Token), http.StatusOK)
			assert.Contains(t, e.merge(index, http.StatusMethodNotAllowed), "There are official review requests")
		}

		check("/api/v1/orgs/org3/branch_protections", "dr-adv-org")
		t.Run("Project", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			group, err := repo_model.CreateRepoGroup(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}), "dr-adv-project", "")
			require.NoError(t, err)
			require.NoError(t, repo_service.MoveRepository(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), repo, group.ID))
			check(fmt.Sprintf("/api/v1/orgs/org3/projects/%d/branch_protections", group.ID), "dr-adv-proj")
		})
	})
}
