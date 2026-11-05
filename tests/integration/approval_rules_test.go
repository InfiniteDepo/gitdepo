// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	api "forgejo.org/modules/structs"
	"forgejo.org/services/forms"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// approvalRulesEnv is repo user2/repo1 with user4 and user5 as writers. user2 owns the repo and authors the PRs.
type approvalRulesEnv struct {
	t      *testing.T
	owner  APITestContext
	writer map[string]APITestContext
}

func newApprovalRulesEnv(t *testing.T) *approvalRulesEnv {
	e := &approvalRulesEnv{t: t, writer: map[string]APITestContext{}}
	e.owner = NewAPITestContext(t, "user2", "repo1", auth_model.AccessTokenScopeWriteRepository)
	for _, name := range []string{"user4", "user5"} {
		req := NewRequestWithJSON(t, "PUT", fmt.Sprintf("/api/v1/repos/user2/repo1/collaborators/%s", name), &api.AddCollaboratorOption{Permission: new("write")}).AddTokenAuth(e.owner.Token)
		e.owner.Session.MakeRequest(t, req, http.StatusNoContent)
		e.writer[name] = NewAPITestContext(t, name, "repo1", auth_model.AccessTokenScopeWriteRepository)
	}
	return e
}

func (e *approvalRulesEnv) changeFiles(branch, newBranch string, files ...*api.ChangeFileOperation) *api.FilesResponse {
	req := NewRequestWithJSON(e.t, "POST", "/api/v1/repos/user2/repo1/contents", &api.ChangeFilesOptions{
		FileOptions: api.FileOptions{BranchName: branch, NewBranchName: newBranch, Message: "change"},
		Files:       files,
	}).AddTokenAuth(e.owner.Token)
	resp := e.owner.Session.MakeRequest(e.t, req, http.StatusCreated)
	var fr api.FilesResponse
	DecodeJSON(e.t, resp, &fr)
	return &fr
}

func create(path, content string) *api.ChangeFileOperation {
	return &api.ChangeFileOperation{Operation: "create", Path: path, ContentBase64: base64.StdEncoding.EncodeToString([]byte(content))}
}

// base creates the protected target branch (from master) with the given files.
func (e *approvalRulesEnv) base(name string, files ...*api.ChangeFileOperation) *api.FilesResponse {
	req := NewRequestWithJSON(e.t, "POST", "/api/v1/repos/user2/repo1/branches", &api.CreateBranchRepoOption{BranchName: name, OldRefName: "master"}).AddTokenAuth(e.owner.Token)
	e.owner.Session.MakeRequest(e.t, req, http.StatusCreated)
	if len(files) == 0 {
		return nil
	}
	return e.changeFiles(name, "", files...)
}

// setFile creates or replaces a file on a branch (master may already have a CODEOWNERS the new branch inherits).
func (e *approvalRulesEnv) setFile(branch, path, content string) *api.FilesResponse {
	req := NewRequestf(e.t, "GET", "/api/v1/repos/user2/repo1/contents/%s?ref=%s", path, branch).AddTokenAuth(e.owner.Token)
	resp := e.owner.Session.MakeRequest(e.t, req, NoExpectedStatus)
	if resp.Code == http.StatusNotFound {
		return e.changeFiles(branch, "", create(path, content))
	}
	var existing api.ContentsResponse
	DecodeJSON(e.t, resp, &existing)
	return e.changeFiles(branch, "", &api.ChangeFileOperation{
		Operation: "update", Path: path, SHA: existing.SHA, ContentBase64: base64.StdEncoding.EncodeToString([]byte(content)),
	})
}

func (e *approvalRulesEnv) protect(base string, applyToAdmins bool, rules ...*api.ApprovalRule) {
	req := NewRequestWithJSON(e.t, "POST", "/api/v1/repos/user2/repo1/branch_protections", &api.CreateBranchProtectionOption{
		RuleName: base, ApplyToAdmins: applyToAdmins, ApprovalRules: rules,
	}).AddTokenAuth(e.owner.Token)
	e.owner.Session.MakeRequest(e.t, req, http.StatusCreated)
}

// pr opens a PR from a new head branch carrying files into base and returns its index.
func (e *approvalRulesEnv) pr(base string, files ...*api.ChangeFileOperation) int64 {
	head := "head-" + base
	e.changeFiles(base, head, files...)
	pr, err := doAPICreatePullRequest(e.owner, "user2", "repo1", base, head)(e.t)
	require.NoError(e.t, err)
	return pr.Index
}

func (e *approvalRulesEnv) approve(user string, index int64) {
	ctx := e.writer[user]
	req := NewRequestWithJSON(e.t, "POST", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d/reviews", index), &api.CreatePullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(ctx.Token)
	ctx.Session.MakeRequest(e.t, req, http.StatusOK)
}

// apiMerge merges the pull request once its conflict check has finished: a push starts that check in a goroutine, and
// the merge refuses a pull request that is still being checked ("Please try again later").
func (e *approvalRulesEnv) apiMerge(ctx APITestContext, index int64, force bool, expected int) string {
	require.Eventually(e.t, func() bool {
		pr := &issues_model.PullRequest{}
		has, err := db.GetEngine(db.DefaultContext).Where("base_repo_id = 1 AND `index` = ?", index).Get(pr)
		return err == nil && has && pr.Status != issues_model.PullRequestStatusChecking && !pullTaskRunning()
	}, 15*time.Second, 50*time.Millisecond)
	req := NewRequestWithJSON(e.t, "POST", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d/merge", index), &forms.MergePullRequestForm{Do: "merge", ForceMerge: force}).AddTokenAuth(ctx.Token)
	return ctx.Session.MakeRequest(e.t, req, expected).Body.String()
}

func (e *approvalRulesEnv) approvals(index int64) []*api.PullApprovalRule {
	req := NewRequestf(e.t, "GET", "/api/v1/repos/user2/repo1/pulls/%d/approvals", index).AddTokenAuth(e.owner.Token)
	resp := e.owner.Session.MakeRequest(e.t, req, http.StatusOK)
	var rules []*api.PullApprovalRule
	DecodeJSON(e.t, resp, &rules)
	return rules
}

func ruleOf(name string, count int64, users ...string) *api.ApprovalRule {
	return &api.ApprovalRule{Name: name, RequiredCount: count, Usernames: users}
}

func TestApprovalRulesMerge(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newApprovalRulesEnv(t)

		// AC2/AC5/AC12: blocked until every rule is satisfied, the refusal names the rule (API).
		t.Run("API", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("ar-api")
			e.protect("ar-api", true, ruleOf("Security", 1, "user4"), ruleOf("Backend", 1, "user5"))
			index := e.pr("ar-api", create("a.txt", "a"))

			assert.Contains(t, e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed), "Security")
			e.approve("user5", index)
			assert.Contains(t, e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed), "Security")
			e.approve("user4", index)
			e.apiMerge(e.owner, index, false, http.StatusOK)
		})

		// AC2: web merge.
		t.Run("Web", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("ar-web")
			e.protect("ar-web", true, ruleOf("Security", 1, "user4"))
			index := e.pr("ar-web", create("a.txt", "a"))
			opts := optionsPullMerge{"do": "merge"}

			testPullMergeForm(t, e.owner.Session, http.StatusBadRequest, "user2", "repo1", fmt.Sprint(index), opts)
			e.approve("user4", index)
			testPullMergeForm(t, e.owner.Session, http.StatusOK, "user2", "repo1", fmt.Sprint(index), opts)
		})

		// AC2: a scheduled auto merge waits for the rule, and the approval merges it.
		t.Run("AutoMerge", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("ar-auto")
			e.protect("ar-auto", true, ruleOf("Security", 1, "user4"))
			index := e.pr("ar-auto", create("a.txt", "a"))

			req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/%d/merge", index), &forms.MergePullRequestForm{Do: "merge", MergeWhenChecksSucceed: true}).AddTokenAuth(e.owner.Token)
			e.owner.Session.MakeRequest(t, req, http.StatusCreated)
			pr := doAPIGetPullRequest(e.owner, "user2", "repo1", index)(t)
			assert.False(t, pr.HasMerged)
			e.approve("user4", index)
			assert.Eventually(t, func() bool {
				return doAPIGetPullRequest(e.owner, "user2", "repo1", index)(t).HasMerged
			}, 10*time.Second, 200*time.Millisecond)
		})

		// AC10: admins bypass with force merge unless ApplyToAdmins.
		t.Run("AdminBypass", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("ar-admin-off")
			e.protect("ar-admin-off", false, ruleOf("Security", 1, "user4"))
			index := e.pr("ar-admin-off", create("a.txt", "a"))
			e.apiMerge(e.owner, index, true, http.StatusOK)

			e.base("ar-admin-on")
			e.protect("ar-admin-on", true, ruleOf("Security", 1, "user4"))
			index = e.pr("ar-admin-on", create("a.txt", "a"))
			e.apiMerge(e.owner, index, true, http.StatusMethodNotAllowed)
		})

		// AC4: rules with paths apply only to matching files, including both sides of a rename and non-ASCII names.
		t.Run("Paths", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			protected := &api.ApprovalRule{Name: "DBA", RequiredCount: 1, Usernames: []string{"user4"}, PathPatterns: "db/**"}

			e.base("ar-path-other")
			e.protect("ar-path-other", true, protected)
			index := e.pr("ar-path-other", create("src/a.txt", "a"))
			e.apiMerge(e.owner, index, false, http.StatusOK)

			e.base("ar-path-hit")
			e.protect("ar-path-hit", true, protected)
			index = e.pr("ar-path-hit", create("db/a.txt", "a"))
			e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed)

			e.base("ar-path-utf8")
			e.protect("ar-path-utf8", true, protected)
			index = e.pr("ar-path-utf8", create("db/ünï cödé.txt", "a"))
			e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed)

			fr := e.base("ar-path-rename", create("db/moved.txt", "moved"))
			e.protect("ar-path-rename", true, protected)
			index = e.pr("ar-path-rename", &api.ChangeFileOperation{Operation: "update", FromPath: "db/moved.txt", Path: "src/moved.txt", SHA: fr.Files[0].SHA, ContentBase64: base64.StdEncoding.EncodeToString([]byte("moved"))})
			e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed)
			e.approve("user4", index)
			e.apiMerge(e.owner, index, false, http.StatusOK)
		})

		// AC6: every owner of a changed file must approve; CODEOWNERS comes from the target branch.
		t.Run("CodeOwners", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			owners := &api.ApprovalRule{Name: "Code owners", RequiredCount: 1, RequireCodeOwners: true}

			// created before master gets a CODEOWNERS that must not matter
			e.base("ar-co-other")
			e.base("ar-co", create("CODEOWNERS", "docs/.* @user4\nsrc/.* @user5\n"))
			e.changeFiles("master", "", create("CODEOWNERS", "docs/.* @user5\n"))
			e.protect("ar-co", true, owners)
			index := e.pr("ar-co", create("docs/a.md", "a"), create("src/b.go", "b"))

			e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed)
			e.approve("user4", index)
			e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed)
			e.approve("user5", index)
			e.apiMerge(e.owner, index, false, http.StatusOK)

			e.protect("ar-co-other", true, owners)
			index = e.pr("ar-co-other", create("docs/a.md", "a"))
			e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed)
			e.approve("user4", index) // master's CODEOWNERS names user5, the target branch has none
			e.apiMerge(e.owner, index, false, http.StatusOK)
		})

		// the CODEOWNERS a PR itself edits doesn't count
		t.Run("CodeOwnersEditedByPR", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("ar-co-edit")
			fr := e.setFile("ar-co-edit", "CODEOWNERS", "docs/.* @user4\n")
			e.protect("ar-co-edit", true, &api.ApprovalRule{Name: "Code owners", RequiredCount: 1, RequireCodeOwners: true})
			index := e.pr("ar-co-edit", create("docs/a.md", "a"), &api.ChangeFileOperation{
				Operation: "update", Path: "CODEOWNERS", SHA: fr.Files[0].SHA,
				ContentBase64: base64.StdEncoding.EncodeToString([]byte("docs/.* @user5\n")),
			})
			e.approve("user5", index) // the owner the PR proposes
			e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed)
			e.approve("user4", index) // the owner of the target branch
			e.apiMerge(e.owner, index, false, http.StatusOK)
		})

		// every CODEOWNERS line matching a file must have an approving owner, a catch-all line doesn't cover the rest
		t.Run("CodeOwnersEveryLine", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("ar-co-lines")
			e.setFile("ar-co-lines", "CODEOWNERS", ".* @user5\nsrc/auth/.* @user4\n")
			e.protect("ar-co-lines", true, &api.ApprovalRule{Name: "Code owners", RequiredCount: 1, RequireCodeOwners: true})
			index := e.pr("ar-co-lines", create("src/auth/x.go", "x"))
			e.approve("user5", index)
			e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed)
			e.approve("user4", index)
			e.apiMerge(e.owner, index, false, http.StatusOK)
		})

		// AC7: legacy rules keep working, with and without approval rules.
		t.Run("Legacy", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("ar-legacy")
			req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branch_protections", &api.CreateBranchProtectionOption{RuleName: "ar-legacy", RequiredApprovals: 1, ApplyToAdmins: true}).AddTokenAuth(e.owner.Token)
			e.owner.Session.MakeRequest(t, req, http.StatusCreated)
			index := e.pr("ar-legacy", create("a.txt", "a"))
			e.apiMerge(e.owner, index, false, http.StatusMethodNotAllowed)
			e.approve("user4", index)
			e.apiMerge(e.owner, index, false, http.StatusOK)
		})

		// AC8/AC9: merge box and approvals endpoint list every applicable rule and expose no internals.
		t.Run("StatusAndEndpoint", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("ar-status")
			e.protect("ar-status", true,
				ruleOf("Security", 1, "user4"), ruleOf("Backend", 1, "user5"),
				&api.ApprovalRule{Name: "DBA", RequiredCount: 1, Usernames: []string{"user5"}, PathPatterns: "db/**"})
			index := e.pr("ar-status", create("a.txt", "a"))
			e.approve("user4", index)

			box := func(ctx APITestContext) string {
				resp := ctx.Session.MakeRequest(t, NewRequestf(t, "GET", "/user2/repo1/pulls/%d", index), http.StatusOK)
				return strings.Join(strings.Fields(NewHTMLParser(t, resp.Body).doc.Find(".merge-section").Text()), " ")
			}
			text := box(e.owner)
			assert.Contains(t, text, "Security: 1/1")
			assert.Contains(t, text, "Backend: 0/1")
			assert.NotContains(t, text, "DBA")
			assert.Contains(t, text, "Can approve: user5", "repo admins see who can approve")

			text = box(e.writer["user5"])
			assert.Contains(t, text, "Security: 1/1")
			assert.Contains(t, text, "Backend: 0/1")
			assert.NotContains(t, text, "Can approve", "writers only see the status")

			rules := e.approvals(index)
			require.Len(t, rules, 2, "DBA doesn't apply")
			assert.Equal(t, "Security", rules[0].Name)
			assert.True(t, rules[0].Satisfied)
			assert.Equal(t, int64(1), rules[0].Granted)
			assert.Equal(t, []string{"user4"}, rules[0].Approvers)
			assert.False(t, rules[1].Satisfied)

			req := NewRequestf(t, "GET", "/api/v1/repos/user2/repo1/pulls/%d/approvals", index).AddTokenAuth(e.owner.Token)
			body := e.owner.Session.MakeRequest(t, req, http.StatusOK).Body.String()
			for _, leaked := range []string{"user_i_ds", "team_i_ds", "user_ids", "team_ids", "path_patterns", "usernames", "teams", "\"id\""} {
				assert.NotContains(t, body, leaked)
			}
		})

		// AC1/AC13: rules round-trip through the API; only repo admins edit them.
		t.Run("EditAndPermissions", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			e.base("ar-edit")
			e.protect("ar-edit", false, ruleOf("Security", 2, "user4", "user5"))

			get := func(rule ...string) []*api.ApprovalRule {
				resp := e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/branch_protections/"+append(rule, "ar-edit")[0]).AddTokenAuth(e.owner.Token), http.StatusOK)
				var bp api.BranchProtection
				DecodeJSON(t, resp, &bp)
				return bp.ApprovalRules
			}
			rules := get()
			require.Len(t, rules, 1)
			assert.Equal(t, "Security", rules[0].Name)
			assert.Equal(t, int64(2), rules[0].RequiredCount)
			assert.ElementsMatch(t, []string{"user4", "user5"}, rules[0].Usernames)

			patch := func(ctx APITestContext, rules []*api.ApprovalRule, expected int) {
				req := NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/branch_protections/ar-edit", &api.EditBranchProtectionOption{ApprovalRules: rules}).AddTokenAuth(ctx.Token)
				ctx.Session.MakeRequest(t, req, expected)
			}
			patch(e.writer["user4"], []*api.ApprovalRule{}, http.StatusForbidden)
			require.Len(t, get(), 1)
			patch(e.owner, []*api.ApprovalRule{ruleOf("Zero", 0, "user4")}, http.StatusUnprocessableEntity)
			patch(e.owner, []*api.ApprovalRule{{Name: "Bad glob", RequiredCount: 1, Usernames: []string{"user4"}, PathPatterns: "[a"}}, http.StatusUnprocessableEntity)
			require.Len(t, get(), 1)
			patch(e.owner, nil, http.StatusOK) // nil keeps the rules
			require.Len(t, get(), 1)
			patch(e.owner, []*api.ApprovalRule{}, http.StatusOK)
			assert.Empty(t, get())

			// web form: a repo admin creates a rule, a writer can't
			form := map[string]string{"rule_name": "ar-edit-web", "approval_rule_name": "Web", "approval_rule_count": "1", "approval_rule_users": "user4"}
			e.writer["user4"].Session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/branches/edit", form), http.StatusNotFound)
			e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/branch_protections/ar-edit-web").AddTokenAuth(e.owner.Token), http.StatusNotFound)
			e.owner.Session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/branches/edit", form), http.StatusSeeOther)
			rules = get("ar-edit-web")
			require.Len(t, rules, 1)
			assert.Equal(t, []string{"user4"}, rules[0].Usernames)

			// no JS: the editor renders no blank rows, only the trailing empty approval_rule_name
			edit := func() *HTMLDoc {
				resp := e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/branches/edit?rule_name=ar-edit-web"), http.StatusOK)
				return NewHTMLParser(t, resp.Body)
			}
			page := edit()
			assert.Equal(t, 1, page.Find(`.approval-rule-cards input[name="approval_rule_name"]`).Length())
			assert.Equal(t, 1, page.Find(`fieldset.approval-rules > input[type="hidden"][name="approval_rule_name"]`).Length())
			ruleID, _ := page.Find(`input[name="rule_id"]`).Attr("value")
			// existing rows are saved, the trailing field is dropped as nameless
			values := url.Values{"rule_id": {ruleID}, "rule_name": {"ar-edit-web"}, "approval_rule_name": {"Web2", ""}, "approval_rule_count": {"2"}, "approval_rule_users": {"user5"}}
			e.owner.Session.MakeRequest(t, NewRequestWithURLValues(t, "POST", "/user2/repo1/settings/branches/edit", values), http.StatusSeeOther)
			rules = get("ar-edit-web")
			require.Len(t, rules, 1)
			assert.Equal(t, "Web2", rules[0].Name)
			// only the trailing empty field: the rules are cleared and the editor shows no card
			e.owner.Session.MakeRequest(t, NewRequestWithURLValues(t, "POST", "/user2/repo1/settings/branches/edit", url.Values{"rule_id": {ruleID}, "rule_name": {"ar-edit-web"}, "approval_rule_name": {""}}), http.StatusSeeOther)
			assert.Empty(t, get("ar-edit-web"))
			assert.Zero(t, edit().Find(`.approval-rule-cards input[name="approval_rule_name"]`).Length())
		})
	})
}
