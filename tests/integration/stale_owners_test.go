// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"encoding/base64"
	"fmt"
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

	"github.com/PuerkitoBio/goquery"
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

// ruleOf returns the protected branch rule of user2/repo1 named name.
func staleRule(t *testing.T, name string) *git_model.ProtectedBranch {
	t.Helper()
	rule, err := git_model.GetProtectedBranchRuleByName(db.DefaultContext, 1, name)
	require.NoError(t, err)
	require.NotNil(t, rule)
	return rule
}

// Owners who left keep blocking, and the CODEOWNERS file view, the merge box and the rule page say who and why:
// the reasons to repository admins, a neutral mark to every other code reader, and a team never member by member.
func TestStaleOwners(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := &pusherEnv{newApprovalRulesEnv(t)}
		setUserCols(t, 4, func(u *user_model.User) { u.IsActive = false }, "is_active")
		setUserCols(t, 5, func(u *user_model.User) { u.ProhibitLogin = true }, "prohibit_login")
		owners := &api.ApprovalRule{Name: "Code owners", RequiredCount: 1, RequireCodeOwners: true}
		// user4 is inactive, user5 prohibited, user8 can't write; team1 belongs to another organization
		codeowners := "docs/.* @user4 @user5 @user8 @org3/team1\n[Core][2]\ncore/.* @user4\n"

		e.base("so-main", create("CODEOWNERS", codeowners))
		e.protect("so-main", true, owners)
		// the approval rule's own list: user10 can't write and appears nowhere in the file
		require.NoError(t, db.Insert(db.DefaultContext, &git_model.ApprovalRule{ProtectedBranchID: staleRule(t, "so-main").ID, Name: "Leads", RequiredCount: 1, UserIDs: []int64{10}}))
		index := e.pr("so-main", create("docs/a.md", "a"))
		anonymous := func(path string) *HTMLDoc {
			return NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK).Body)
		}

		t.Run("file view", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			resp := e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/src/branch/so-main/CODEOWNERS"), http.StatusOK)
			doc := NewHTMLParser(t, resp.Body)
			marks := text(doc, ".codeowners-ineligible")
			assert.Contains(t, marks, "Line 1: user4 can't approve (inactive); user5 can't approve (login prohibited); user8 can't approve (no write access)")
			assert.Contains(t, marks, "Line 3: user4 can't approve (inactive)")
			assert.Contains(t, marks, "@team1 can't approve: a team of another organization has no access here")
			assert.NotContains(t, marks, "user2", "the members of a team are not listed")
			href, _ := doc.Find(".codeowners-ineligible a").First().Attr("href")
			assert.Equal(t, "#L1", href)

			// a plain code reader, signed in or not, gets the neutral mark only
			for _, doc := range []*HTMLDoc{anonymous("/user2/repo1/src/branch/so-main/CODEOWNERS"), func() *HTMLDoc {
				resp := loginUser(t, "user8").MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/src/branch/so-main/CODEOWNERS"), http.StatusOK)
				return NewHTMLParser(t, resp.Body)
			}()} {
				marks := text(doc, ".codeowners-ineligible")
				assert.Contains(t, marks, "user4 can't approve")
				assert.Contains(t, marks, "user8 can't approve")
				for _, reason := range []string{"inactive", "login prohibited", "no write access", "two-factor"} {
					assert.NotContains(t, marks, reason)
				}
			}
		})

		t.Run("merge box", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			box := text(e.mergeBox(e.owner, index), ".merge-section .codeowners-ineligible")
			assert.Contains(t, box, "user4 can't approve (inactive)")
			assert.Contains(t, box, "user8 can't approve (no write access)")
			assert.Contains(t, box, "user10 can't approve (no write access)", "a repository admin sees the rule's listed approvers")

			// every other code reader sees the owners of the file with the neutral mark, and not the rule's list
			box = text(anonymous(fmt.Sprintf("/user2/repo1/pulls/%d", index)), ".merge-section .codeowners-ineligible")
			assert.Contains(t, box, "user4 can't approve")
			assert.NotContains(t, box, "(")
			assert.NotContains(t, box, "user10")

			// without read access to the code the merge box stays, with no owners in it: the unit is off for everyone
			_, err := db.GetEngine(t.Context()).Exec("DELETE FROM repo_unit WHERE repo_id = 1 AND type = 1")
			require.NoError(t, err)
			defer func() {
				_, err := db.GetEngine(t.Context()).Exec("INSERT INTO repo_unit (repo_id, type, config, created_unix) VALUES (1, 1, '{}', 0)")
				require.NoError(t, err)
			}()
			doc := anonymous(fmt.Sprintf("/user2/repo1/pulls/%d", index))
			assert.Contains(t, text(doc, ".merge-section"), "Code owners")
			assert.Zero(t, doc.Find(".codeowners-ineligible").Length())
			assert.NotContains(t, text(doc, "body"), "user4")
		})

		t.Run("rule page", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			// a rule listing only people who left, and CODEOWNERS lines nobody can meet
			e.base("so-rule", create("CODEOWNERS", "[Core][2]\ncore/.* @user4 @user5\ndocs/.* @user4\nlib/.* @user2\n"))
			leads := &api.ApprovalRule{Name: "Leads", RequiredCount: 2, Usernames: []string{"user4", "user5", "user2"}}
			e.protect("so-rule", true, owners, leads)
			resp := e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/branches/edit?rule_name=so-rule"), http.StatusOK)
			doc := NewHTMLParser(t, resp.Body)
			warn := text(doc, ".rule-warnings")
			assert.Contains(t, warn, "This rule can block merges:")
			assert.Contains(t, warn, "Approval rule Leads needs 2 approvals. Only 1 person can approve. (user4 can't approve (inactive); user5 can't approve (login prohibited))")
			assert.Contains(t, warn, "CODEOWNERS line 3 has no owner who can approve")
			assert.Contains(t, warn, "CODEOWNERS section Core needs 2 approvals; see line 4. Only 1 owner can approve there.")
			assert.Contains(t, warn, "To fix it")
			var hrefs []string
			doc.Find(".rule-warnings li a").Each(func(_ int, a *goquery.Selection) { href, _ := a.Attr("href"); hrefs = append(hrefs, href) })
			assert.Contains(t, hrefs, "/user2/repo1/src/branch/so-rule/CODEOWNERS#L3")

			// a pattern has no one branch to read: the approval rule is checked, CODEOWNERS isn't, and the page says so
			e.base("so-none") // before the pattern protects it
			e.protect("so-*", true, owners, leads)
			resp = e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/branches/edit?rule_name="+url.QueryEscape("so-*")), http.StatusOK)
			doc = NewHTMLParser(t, resp.Body)
			assert.Contains(t, text(doc, ".rule-warnings"), "Approval rule Leads")
			assert.NotContains(t, text(doc, ".rule-warnings"), "CODEOWNERS line")
			assert.Contains(t, text(doc, ".ui.info.message"), "CODEOWNERS is not checked")

			// no CODEOWNERS file on the branch, no CODEOWNERS warning
			e.protect("so-none", true, owners)
			resp = e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/branches/edit?rule_name=so-none"), http.StatusOK)
			assert.Empty(t, text(NewHTMLParser(t, resp.Body), ".rule-warnings"))
		})
	})
}

// A team of the repository owner's organization is one mark with a count, never a list of its members, and a team of
// another organization is not expanded at all.
func TestStaleOwnersTeams(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		f, pub := prepareRepoGroupGit(t)
		admin := loginUser(t, "user1")
		token := getTokenForLoggedInUser(t, admin, auth_model.AccessTokenScopeWriteRepository)
		// team1 of the organization has user2 (an owner, who can write) and user4 (who can't); team 2 of org 3 is "Owners"
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/"+f.org.Name+"/pub/contents/CODEOWNERS", &api.CreateFileOptions{
			ContentBase64: base64.StdEncoding.EncodeToString([]byte("a/.* @" + f.org.Name + "/team1\nb/.* @user10\n")),
		}).AddTokenAuth(token), http.StatusCreated)
		resp := admin.MakeRequest(t, NewRequest(t, "GET", pub.Link()+"/src/branch/main/CODEOWNERS"), http.StatusOK)
		marks := text(NewHTMLParser(t, resp.Body), ".codeowners-ineligible")
		assert.Contains(t, marks, "Only 1 member of @team1 can approve")
		assert.Contains(t, marks, "user10 can't approve (no write access)")
		assert.NotContains(t, resp.Body.String(), "user4", "no member of a team is named")
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
			assert.Contains(t, text(NewHTMLParser(t, resp.Body), ".rule-warnings"), "Approval rule Leads needs 1 approval. Nobody can approve.", c.page)
		}
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
		warn := text(NewHTMLParser(t, resp.Body), ".rule-warnings")
		assert.Contains(t, warn, "Approval rule Leads needs 1 approval. Nobody can approve. (user4 can't approve (inactive))")
	})
}

// The two-factor reason is for site admins and the acting owners of the organization that requires it.
func TestStaleOwnersTwoFactor(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		f, pub := prepareRepoGroupGit(t)
		admin := loginUser(t, "user1")
		token := getTokenForLoggedInUser(t, admin, auth_model.AccessTokenScopeWriteRepository)
		call := func(method, path string, body any, status int) {
			MakeRequest(t, NewRequestWithJSON(t, method, "/api/v1/repos/"+f.org.Name+"/pub"+path, body).AddTokenAuth(token), status)
		}
		call("PUT", "/collaborators/user4", &api.AddCollaboratorOption{Permission: new("write")}, http.StatusNoContent)
		// user5 administers the repository and has a second factor, so the requirement doesn't touch them
		call("PUT", "/collaborators/user5", &api.AddCollaboratorOption{Permission: new("admin")}, http.StatusNoContent)
		require.NoError(t, db.Insert(db.DefaultContext, &auth_model.TwoFactor{UID: 5, Secret: []byte("secret"), ScratchSalt: "salt", ScratchHash: "hash"}))
		t.Cleanup(func() {
			_, err := db.GetEngine(db.DefaultContext).Where("uid = 5").Delete(&auth_model.TwoFactor{})
			require.NoError(t, err)
		})
		call("POST", "/contents/CODEOWNERS", &api.CreateFileOptions{ContentBase64: base64.StdEncoding.EncodeToString([]byte("a/.* @user4\n"))}, http.StatusCreated)
		view := func(s *TestSession) string {
			resp := s.MakeRequest(t, NewRequest(t, "GET", pub.Link()+"/src/branch/main/CODEOWNERS"), http.StatusOK)
			return text(NewHTMLParser(t, resp.Body), ".codeowners-ineligible")
		}
		assert.Empty(t, view(admin), "user4 can write")

		_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = ?", true, f.org.ID)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = ?", false, f.org.ID)
			require.NoError(t, err)
		})
		assert.Contains(t, view(admin), "Line 1: user4 can't approve (blocked by the organization's two-factor requirement)")
		// a repository admin who isn't an owner of the organization gets the neutral mark
		marks := view(loginUser(t, "user5"))
		assert.Contains(t, marks, "user4 can't approve")
		assert.NotContains(t, marks, "two-factor")
		assert.NotContains(t, marks, "no write access", "that would be false without the requirement")
	})
}

// The admin edit page lists what deactivating or suspending a user would break, and a save that does it says so.
func TestStaleOwnersAdminPage(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newApprovalRulesEnv(t)
		long := strings.Repeat("<&>", 80) // 240 characters that grow when escaped
		e.protect("so-admin", true, &api.ApprovalRule{Name: "Only <b>user4</b>", RequiredCount: 1, Usernames: []string{"user4"}})
		e.protect("so-long", true, &api.ApprovalRule{Name: long, RequiredCount: 1, Usernames: []string{"user4"}})
		session := loginUser(t, "user1")

		resp := session.MakeRequest(t, NewRequest(t, "GET", "/admin/users/4/edit"), http.StatusOK)
		doc := NewHTMLParser(t, resp.Body)
		assert.Contains(t, text(doc, ".last-approver-warnings"), "Rule \"so-admin\" in user2/repo1: Only <b>user4</b> (Repository approval rule)")
		assert.Contains(t, text(doc, ".last-approver-warnings .header"), "Turning off \"Activated account\" or turning on \"Suspended account\"")
		assert.Zero(t, doc.Find(".last-approver-warnings b").Length(), "names are escaped")
		href, _ := doc.Find(".last-approver-warnings a").First().Attr("href")
		assert.Equal(t, "/user2/repo1/settings/branches/edit?rule_name=so-admin", href)

		// an unrelated user has none
		resp = session.MakeRequest(t, NewRequest(t, "GET", "/admin/users/8/edit"), http.StatusOK)
		assert.Zero(t, NewHTMLParser(t, resp.Body).Find(".last-approver-warnings").Length())

		form := func(active bool) map[string]string {
			f := map[string]string{"login_type": "0-0", "login_name": "user4", "email": "user4@example.com", "visibility": "0", "max_repo_creation": "-1"}
			if active {
				f["active"] = "on"
			}
			return f
		}
		flash := func() *HTMLDoc {
			return NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/admin/users/4"), http.StatusOK).Body)
		}

		// a save that keeps the user active runs no check and shows no warning
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/users/4/edit", form(true)), http.StatusSeeOther)
		assert.Zero(t, flash().Find(".flash-warning").Length())
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}).IsActive)

		// deactivating saves, and the page after it names the rules in a short list that fits the cookie
		setUserCols(t, 4, func(u *user_model.User) {}, "is_active", "prohibit_login")
		resp = session.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/users/4/edit", form(false)), http.StatusSeeOther)
		assert.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}).IsActive)
		for _, c := range resp.Result().Cookies() {
			assert.Less(t, len(c.Value), 3500, c.Name)
		}
		doc = flash()
		assert.Contains(t, text(doc, ".flash-warning"), "These now lack approvers:")
		assert.Contains(t, text(doc, ".flash-warning li"), "Rule \"so-admin\" in user2/repo1: Only <b>user4</b> (Repository approval rule)")
		assert.Equal(t, 2, doc.Find(".flash-warning li").Length())
		assert.Zero(t, doc.Find(".flash-warning b").Length(), "names are escaped")
		assert.Contains(t, text(doc, ".flash-warning"), "…", "a long name is cut")
	})
}
