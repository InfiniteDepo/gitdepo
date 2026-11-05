// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
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

func (e *drEnv) merge(index int64, expected int) string {
	e.t.Helper()
	return e.do("POST", fmt.Sprintf("/pulls/%d/merge", index), &forms.MergePullRequestForm{Do: "merge"}, expected).Body.String()
}

func (e *drEnv) approvals(index int64) []*api.PullApprovalRule {
	var rules []*api.PullApprovalRule
	DecodeJSON(e.t, e.do("GET", fmt.Sprintf("/pulls/%d/approvals", index), nil, http.StatusOK), &rules)
	return rules
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
		require.Eventually(t, func() bool { return e.pushComments(index) > before }, 15*time.Second, 100*time.Millisecond)
		time.Sleep(time.Second) // the request, if it were sent, follows the push comment
		assert.Empty(t, e.requested(index))
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
