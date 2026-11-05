// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setUserCols changes columns of a user and restores them when the test ends.
func setUserCols(t *testing.T, id int64, change func(*user_model.User), cols ...string) {
	t.Helper()
	u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: id})
	old := *u
	change(u)
	require.NoError(t, user_model.UpdateUserCols(t.Context(), u, cols...))
	t.Cleanup(func() {
		u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: id})
		u.IsActive, u.ProhibitLogin = old.IsActive, old.ProhibitLogin
		require.NoError(t, user_model.UpdateUserCols(db.DefaultContext, u, cols...))
	})
}

func text(doc *HTMLDoc, selector string) string {
	return strings.Join(strings.Fields(doc.Find(selector).Text()), " ")
}

// Owners who left keep blocking, and the CODEOWNERS file view, the merge box and the rule page say who and why.
func TestStaleOwners(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := &pusherEnv{newApprovalRulesEnv(t)}
		setUserCols(t, 4, func(u *user_model.User) { u.IsActive = false }, "is_active")
		setUserCols(t, 5, func(u *user_model.User) { u.ProhibitLogin = true }, "prohibit_login")
		owners := &api.ApprovalRule{Name: "Code owners", RequiredCount: 1, RequireCodeOwners: true}
		// user4 is inactive, user5 prohibited and user8 can't write
		codeowners := "docs/.* @user4 @user5 @user8\n[Core][2]\ncore/.* @user4\n"

		e.base("so-main", create("CODEOWNERS", codeowners))
		e.protect("so-main", true, owners)
		index := e.pr("so-main", create("docs/a.md", "a"))

		t.Run("file view", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			resp := e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/src/branch/so-main/CODEOWNERS"), http.StatusOK)
			marks := text(NewHTMLParser(t, resp.Body), ".codeowners-ineligible")
			assert.Contains(t, marks, "Line 1: user4 can't approve (inactive)")
			assert.Contains(t, marks, "user5 can't approve (login prohibited)")
			assert.Contains(t, marks, "user8 can't approve (no write access)")
			assert.Contains(t, marks, "Line 3: user4 can't approve (inactive)")
		})

		t.Run("merge box shows it to a code reader only", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			box := e.mergeBox(e.owner, index)
			assert.Contains(t, text(box, ".merge-section .codeowners-ineligible"), "user4 can't approve (inactive)")
			assert.Contains(t, text(box, ".merge-section .codeowners-ineligible"), "user8 can't approve (no write access)")

			// without read access to the code the owners stay hidden: the unit is off for everyone
			_, err := db.GetEngine(t.Context()).Exec("DELETE FROM repo_unit WHERE repo_id = 1 AND type = 1")
			require.NoError(t, err)
			defer func() {
				_, err := db.GetEngine(t.Context()).Exec("INSERT INTO repo_unit (repo_id, type, config, created_unix) VALUES (1, 1, '{}', 0)")
				require.NoError(t, err)
			}()
			resp := MakeRequest(t, NewRequestf(t, "GET", "/user2/repo1/pulls/%d", index), http.StatusOK)
			body := resp.Body.String()
			assert.NotContains(t, body, "can&#39;t approve (")
			assert.NotContains(t, body, "user4")
		})

		t.Run("rule page", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			// a rule listing only people who left, and a CODEOWNERS section nobody can meet
			e.base("so-rule", create("CODEOWNERS", "[Core][2]\ncore/.* @user4 @user5\ndocs/.* @user4\n"))
			e.protect("so-rule", true, owners, &api.ApprovalRule{Name: "Leads", RequiredCount: 2, Usernames: []string{"user4", "user5", "user2"}})
			resp := e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/branches/edit?rule_name=so-rule"), http.StatusOK)
			warn := text(NewHTMLParser(t, resp.Body), ".rule-warnings")
			assert.Contains(t, warn, "Approval rule Leads needs 2 approvals, but only 1 people can approve")
			assert.Contains(t, warn, "CODEOWNERS line 3 has no owner who can approve")
			assert.Contains(t, warn, "CODEOWNERS section Core needs 2 approvals, but only 0 owners can approve")

			e.base("so-none") // before the glob protects it
			// a glob has no one branch to read: the approval rule is checked, CODEOWNERS isn't
			e.protect("so-*", true, owners, &api.ApprovalRule{Name: "Leads", RequiredCount: 2, Usernames: []string{"user4", "user5", "user2"}})
			resp = e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/branches/edit?rule_name="+url.QueryEscape("so-*")), http.StatusOK)
			warn = text(NewHTMLParser(t, resp.Body), ".rule-warnings")
			assert.Contains(t, warn, "Approval rule Leads")
			assert.NotContains(t, warn, "CODEOWNERS")

			// no CODEOWNERS file on the branch, no CODEOWNERS warning
			e.protect("so-none", true, owners)
			resp = e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/branches/edit?rule_name=so-none"), http.StatusOK)
			assert.Empty(t, text(NewHTMLParser(t, resp.Body), ".rule-warnings"))
		})
	})
}

// The rule page of a repository inside a project.
func TestStaleOwnersProject(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		f, _ := prepareRepoGroupGit(t)
		group, err := repo_model.GetRepoGroupByName(db.DefaultContext, f.org.ID, "proj")
		require.NoError(t, err)
		priv, err := repo_model.GetRepositoryByPath(db.DefaultContext, f.org.ID, group.Name, "priv")
		require.NoError(t, err)
		setUserCols(t, 4, func(u *user_model.User) { u.IsActive = false }, "is_active")
		rule := &git_model.ProtectedBranch{RepoID: priv.ID, RuleName: "main"}
		require.NoError(t, git_model.UpdateProtectBranch(db.DefaultContext, priv, rule, git_model.WhitelistOptions{}))
		// inserted as it is: SetApprovalRules would drop user4, who can't write the repository
		require.NoError(t, db.Insert(db.DefaultContext, &git_model.ApprovalRule{ProtectedBranchID: rule.ID, Name: "Leads", RequiredCount: 1, UserIDs: []int64{4}}))

		session := loginUser(t, "user2")
		resp := session.MakeRequest(t, NewRequest(t, "GET", priv.Link()+"/settings/branches/edit?rule_name=main"), http.StatusOK)
		assert.Contains(t, text(NewHTMLParser(t, resp.Body), ".rule-warnings"), "Approval rule Leads needs 1 approvals, but only 0 people can approve")
	})
}

// The warning about an approval rule that has too few approvers also shows on the organization and project rule pages.
func TestStaleOwnersOrgRulePages(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		f, _ := prepareRepoGroupGit(t)
		group, err := repo_model.GetRepoGroupByName(db.DefaultContext, f.org.ID, "proj")
		require.NoError(t, err)
		setUserCols(t, 4, func(u *user_model.User) { u.IsActive = false }, "is_active")
		session := loginUser(t, "user2")

		// the organization's rule and the project's rule each list user4, who is inactive, and count on 1 approval
		for _, c := range []struct {
			groupID int64
			page    string
		}{
			{0, "/org/" + f.org.Name + "/settings/branches/edit?rule_name=main"},
			{group.ID, "/org/" + f.org.Name + "/groups/" + strconv.FormatInt(group.ID, 10) + "/settings/branches/edit?rule_name=main"},
		} {
			rule := &git_model.ProtectedBranch{RuleName: "main"}
			require.NoError(t, git_model.UpdateOrgProtectBranch(db.DefaultContext, f.org.ID, c.groupID, rule, git_model.WhitelistOptions{}, nil))
			require.NoError(t, db.Insert(db.DefaultContext, &git_model.ApprovalRule{ProtectedBranchID: rule.ID, Name: "Leads", RequiredCount: 1, UserIDs: []int64{4}}))
			resp := session.MakeRequest(t, NewRequest(t, "GET", c.page), http.StatusOK)
			assert.Contains(t, text(NewHTMLParser(t, resp.Body), ".rule-warnings"), "Approval rule Leads needs 1 approvals, but only 0 people can approve", c.page)
		}
	})
}

// A code owner who the organization's two-factor requirement keeps out is named with that reason.
func TestStaleOwnersTwoFactor(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		f, pub := prepareRepoGroupGit(t)
		admin := loginUser(t, "user1")
		token := getTokenForLoggedInUser(t, admin, auth_model.AccessTokenScopeWriteRepository)
		call := func(method, path string, body any, status int) {
			MakeRequest(t, NewRequestWithJSON(t, method, "/api/v1/repos/"+f.org.Name+"/pub"+path, body).AddTokenAuth(token), status)
		}
		call("PUT", "/collaborators/user4", &api.AddCollaboratorOption{Permission: new("write")}, http.StatusNoContent)
		call("POST", "/contents/CODEOWNERS", &api.CreateFileOptions{ContentBase64: base64.StdEncoding.EncodeToString([]byte("a/.* @user4\n"))}, http.StatusCreated)
		view := func() string {
			resp := admin.MakeRequest(t, NewRequest(t, "GET", pub.Link()+"/src/branch/main/CODEOWNERS"), http.StatusOK)
			return text(NewHTMLParser(t, resp.Body), ".codeowners-ineligible")
		}
		assert.Empty(t, view(), "user4 can write")

		_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = ?", true, f.org.ID)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = ?", false, f.org.ID)
			require.NoError(t, err)
		})
		assert.Contains(t, view(), "Line 1: user4 can't approve (blocked by the organization's two-factor requirement)")
	})
}

// The admin edit page lists what deactivating or prohibiting a user would break, and a save that does it says so.
func TestStaleOwnersAdminPage(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newApprovalRulesEnv(t)
		e.protect("so-admin", true, &api.ApprovalRule{Name: "Only <b>user4</b>", RequiredCount: 1, Usernames: []string{"user4"}})
		session := loginUser(t, "user1")

		resp := session.MakeRequest(t, NewRequest(t, "GET", "/admin/users/4/edit"), http.StatusOK)
		doc := NewHTMLParser(t, resp.Body)
		assert.Contains(t, text(doc, ".last-approver-warnings"), "user2/repo1 so-admin: Only <b>user4</b> (repository approval rule)")
		assert.Zero(t, doc.Find(".last-approver-warnings b").Length(), "names are escaped")
		href, _ := doc.Find(".last-approver-warnings a").First().Attr("href")
		assert.Equal(t, "/user2/repo1/settings/branches/edit?rule_name=so-admin", href)

		// an unrelated user has none
		resp = session.MakeRequest(t, NewRequest(t, "GET", "/admin/users/8/edit"), http.StatusOK)
		assert.Zero(t, NewHTMLParser(t, resp.Body).Find(".last-approver-warnings").Length())

		// deactivating saves, and the page after it names the rule
		setUserCols(t, 4, func(u *user_model.User) {}, "is_active")
		form := map[string]string{"login_type": "0-0", "login_name": "user4", "email": "user4@example.com", "visibility": "0", "max_repo_creation": "-1"}
		form["prohibit_login"] = "on"
		resp = session.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/users/4/edit", form), http.StatusSeeOther)
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}).ProhibitLogin)
		resp = session.MakeRequest(t, NewRequest(t, "GET", "/admin/users/4"), http.StatusOK)
		flash := NewHTMLParser(t, resp.Body)
		assert.Contains(t, text(flash, ".flash-warning"), "These approval rules now lack approvers: user2/repo1 so-admin: Only <b>user4</b>")
		assert.Zero(t, flash.Find(".flash-warning b").Length(), "names are escaped")
	})
}
