// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	pull_service "forgejo.org/services/pull"
	user_service "forgejo.org/services/user"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setUserCols changes columns of a user and puts back their state (active, login allowed) when the test ends.
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

// grantWrite makes the user a collaborator with write access to the repository.
func grantWrite(t *testing.T, repoID, uid int64) {
	t.Helper()
	require.NoError(t, db.Insert(db.DefaultContext, &repo_model.Collaboration{RepoID: repoID, UserID: uid, Mode: perm.AccessModeWrite}))
	require.NoError(t, db.Insert(db.DefaultContext, &access_model.Access{RepoID: repoID, UserID: uid, Mode: perm.AccessModeWrite}))
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
		// user4 is inactive, user5 prohibited, user8 can't write; org3/team1 belongs to another organization and
		// org3/ghost doesn't exist: neither resolves, and the two look the same
		codeowners := "docs/.* @user4 @user5 @user8 @org3/team1 @org3/ghost\n[Core][2]\ncore/.* @user4\n"

		e.base("so-main", create("CODEOWNERS", codeowners))
		e.protect("so-main", true, owners)
		// the approval rule's own list: user10 can't write and appears nowhere in the file
		// (and user2, who can write, is listed too)
		require.NoError(t, db.Insert(db.DefaultContext, &git_model.ApprovalRule{ProtectedBranchID: staleRule(t, "so-main").ID, Name: "Leads", RequiredCount: 1, UserIDs: []int64{10, 2}}))
		index := e.pr("so-main", create("docs/a.md", "a"))
		anonymous := func(path string) *HTMLDoc {
			return NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK).Body)
		}

		siteAdmin := APITestContext{Session: loginUser(t, "user1")}

		t.Run("file view", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			// the specific reasons are for site admins; a repository admin sees the neutral mark
			ownerView := NewHTMLParser(t, e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/src/branch/so-main/CODEOWNERS"), http.StatusOK).Body)
			ownerMarks := text(ownerView, ".codeowners-ineligible")
			assert.Contains(t, ownerMarks, "Line 1: user4 can't approve; user5 can't approve; user8 can't approve")
			for _, reason := range []string{"inactive", "login prohibited", "no write access", "two-factor"} {
				assert.NotContains(t, ownerMarks, reason)
			}
			resp := siteAdmin.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/src/branch/so-main/CODEOWNERS"), http.StatusOK)
			doc := NewHTMLParser(t, resp.Body)
			marks := text(doc, ".codeowners-ineligible")
			assert.Contains(t, marks, "Line 1: user4 can't approve (inactive); user5 can't approve (login prohibited); user8 can't approve (no write access)")
			assert.Contains(t, marks, "Line 3: user4 can't approve (inactive)")
			assert.NotContains(t, marks, "team1", "a team of another organization is as unknown as a missing one")
			assert.NotContains(t, marks, "ghost")
			assert.NotContains(t, marks, "user2", "the members of a team are not listed")
			warnings := text(doc, "body")
			assert.Contains(t, warnings, "incorrect codeowner team: org3/team1")
			assert.Contains(t, warnings, "incorrect codeowner team: org3/ghost", "the same warning for a team that doesn't exist")
			href, _ := doc.Find(".codeowners-ineligible a").First().Attr("href")
			assert.Equal(t, "#L1", href)

			// someone who can't change the file, signed in or not, sees no mark: it would tell whether an account can
			// sign in
			for _, doc := range []*HTMLDoc{anonymous("/user2/repo1/src/branch/so-main/CODEOWNERS"), func() *HTMLDoc {
				resp := loginUser(t, "user8").MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/src/branch/so-main/CODEOWNERS"), http.StatusOK)
				return NewHTMLParser(t, resp.Body)
			}()} {
				assert.Empty(t, text(doc, ".codeowners-ineligible"))
				assert.Contains(t, text(doc, "body"), "incorrect codeowner team: org3/team1", "the file's own warnings stay")
			}
		})

		t.Run("merge box", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			// a repository admin sees the rule's listed approvers by name, with the neutral mark
			ownerBox := text(e.mergeBox(e.owner, index), ".merge-section .codeowners-ineligible")
			assert.Contains(t, ownerBox, "user10 can't approve")
			assert.NotContains(t, ownerBox, "(")
			box := text(e.mergeBox(siteAdmin, index), ".merge-section .codeowners-ineligible")
			assert.Contains(t, box, "user4 can't approve (inactive)")
			assert.Contains(t, box, "user8 can't approve (no write access)")
			assert.Contains(t, box, "user10 can't approve (no write access)", "a site admin sees the rule's listed approvers")
			// the list of who can approve comes from the same check: nobody marked above is in it
			can := regexp.MustCompile(`Can approve: (\w+(?:, \w+)*)`).FindStringSubmatch(text(e.mergeBox(e.owner, index), ".merge-section"))
			require.NotNil(t, can)
			assert.Equal(t, "user2", strings.TrimSpace(can[1]), "user10 can't approve, so is not listed")

			// someone who can't change the rule or the file sees the plain status, with no marks
			anonBox := anonymous(fmt.Sprintf("/user2/repo1/pulls/%d", index))
			assert.Empty(t, text(anonBox, ".merge-section .codeowners-ineligible"))
			assert.NotContains(t, text(anonBox, ".merge-section"), "Can approve")

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
			// the reasons are for site admins; a repository admin sees the neutral mark
			resp := e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/branches/edit?rule_name=so-rule"), http.StatusOK)
			assert.Contains(t, text(NewHTMLParser(t, resp.Body), ".rule-warnings"), "Only 1 person can approve. (user4 can't approve; user5 can't approve)")
			resp = siteAdmin.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/branches/edit?rule_name=so-rule"), http.StatusOK)
			doc := NewHTMLParser(t, resp.Body)
			warn := text(doc, ".rule-warnings")
			assert.Contains(t, warn, "This rule can block merges:")
			assert.Contains(t, warn, "Approval rule Leads needs 2 approvals. Only 1 person can approve. (user4 can't approve (inactive); user5 can't approve (login prohibited))")
			assert.Contains(t, warn, "CODEOWNERS line 3: no owner who can approve")
			assert.Contains(t, warn, "CODEOWNERS line 4: section Core needs 2 approvals. Only 1 owner can approve there.")
			assert.Contains(t, warn, "To fix it")
			var hrefs []string
			doc.Find(".rule-warnings li a").Each(func(_ int, a *goquery.Selection) { href, _ := a.Attr("href"); hrefs = append(hrefs, href) })
			assert.Contains(t, hrefs, "/user2/repo1/src/branch/so-rule/CODEOWNERS#L3")
			var linked []string // only the line is the link, not the sentence
			doc.Find(".rule-warnings li a").Each(func(_ int, a *goquery.Selection) { linked = append(linked, strings.TrimSpace(a.Text())) })
			assert.Contains(t, linked, "CODEOWNERS line 3")

			// a pattern has no one branch to read: the approval rule is checked, CODEOWNERS isn't, and the page says so
			e.base("so-none") // before the pattern protects it
			e.protect("so-*", true, owners, leads)
			resp = e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/branches/edit?rule_name="+url.QueryEscape("so-*")), http.StatusOK)
			doc = NewHTMLParser(t, resp.Body)
			assert.Contains(t, text(doc, ".rule-warnings"), "Approval rule Leads")
			assert.NotContains(t, text(doc, ".rule-warnings"), "CODEOWNERS line")
			assert.Contains(t, text(doc, ".ui.info.message"), "CODEOWNERS is not checked for a rule with a pattern")

			// a file that names more people than one check looks at is not checked either, and the page says so
			defer test.MockVariableValue(&pull_service.MaxOwnerCandidates, 2)()
			resp = e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/branches/edit?rule_name=so-rule"), http.StatusOK)
			doc = NewHTMLParser(t, resp.Body)
			assert.NotContains(t, text(doc, ".rule-warnings"), "CODEOWNERS line")
			assert.Contains(t, text(doc, ".ui.info.message"), "CODEOWNERS is not checked: it names more people and teams than one check looks at.")

			// no CODEOWNERS file on the branch, no CODEOWNERS warning
			e.protect("so-none", true, owners)
			resp = e.owner.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/branches/edit?rule_name=so-none"), http.StatusOK)
			assert.Empty(t, text(NewHTMLParser(t, resp.Body), ".rule-warnings"))
		})
	})
}

// A team of the repository owner's organization is one mark named org/team, never a list of its members. A code reader
// sees it only when no member can approve (an empty team too) and never a count; a repository admin also sees how
// many can when only some can.
func TestStaleOwnersTeams(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		f, pub := prepareRepoGroupGit(t)
		admin := loginUser(t, "user1")
		token := getTokenForLoggedInUser(t, admin, auth_model.AccessTokenScopeWriteRepository)
		// team1 of the organization has user2 (an owner, who can write) and user4 (who can't); "ghosts" has no member
		require.NoError(t, db.Insert(db.DefaultContext, &organization.Team{OrgID: f.org.ID, Name: "ghosts", LowerName: "ghosts", AccessMode: perm.AccessModeWrite}))
		ghosts := f.org.Name + "/ghosts"
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/"+f.org.Name+"/pub/contents/CODEOWNERS", &api.CreateFileOptions{
			ContentBase64: base64.StdEncoding.EncodeToString([]byte("a/.* @" + f.org.Name + "/team1\nb/.* @user10\nc/.* @" + ghosts + "\n")),
		}).AddTokenAuth(token), http.StatusCreated)
		view := func(s *TestSession) string {
			var resp *httptest.ResponseRecorder
			if s == nil {
				resp = MakeRequest(t, NewRequest(t, "GET", pub.Link()+"/src/branch/main/CODEOWNERS"), http.StatusOK)
			} else {
				resp = s.MakeRequest(t, NewRequest(t, "GET", pub.Link()+"/src/branch/main/CODEOWNERS"), http.StatusOK)
			}
			assert.NotContains(t, resp.Body.String(), "user4", "no member of a team is named")
			return text(NewHTMLParser(t, resp.Body), ".codeowners-ineligible")
		}
		marks := view(admin)
		assert.Contains(t, marks, "Only 1 member of "+f.org.Name+"/team1 can approve")
		assert.Contains(t, marks, "user10 can't approve (no write access)")
		assert.Contains(t, marks, "No member of "+ghosts+" can approve")

		// someone who can't change the file sees no mark
		assert.Empty(t, view(nil))
	})
}

// The warning about an approval rule that has too few approvers also shows on the organization and project rule pages.
func TestStaleOwnersOrgRulePages(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		f, _ := prepareRepoGroupGit(t)
		group, err := repo_model.GetRepoGroupByName(db.DefaultContext, f.org.ID, "proj")
		require.NoError(t, err)
		setUserCols(t, 4, func(u *user_model.User) { u.IsActive = false }, "is_active")
		session := loginUser(t, "user1") // the reasons are for site admins

		// the organization's rule and the project's rule each list user4, who is inactive, and count on 1 approval
		orgPage := "/org/" + f.org.Name + "/settings/branches/edit?rule_name=main"
		projectPage := "/org/" + f.org.Name + "/groups/" + strconv.FormatInt(group.ID, 10) + "/settings/branches/edit?rule_name=main"
		for _, c := range []struct {
			groupID int64
			page    string
		}{{0, orgPage}, {group.ID, projectPage}} {
			rule := &git_model.ProtectedBranch{RuleName: "main"}
			require.NoError(t, git_model.UpdateOrgProtectBranch(db.DefaultContext, f.org.ID, c.groupID, rule, git_model.WhitelistOptions{}, nil))
			require.NoError(t, db.Insert(db.DefaultContext, &git_model.ApprovalRule{ProtectedBranchID: rule.ID, Name: "Leads", RequiredCount: 1, UserIDs: []int64{4}}))
		}
		warn := func(page string) string {
			return text(NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body), ".rule-warnings")
		}
		const nobody = "Approval rule Leads needs 1 approval. Nobody can approve. "
		// user4 writes a repository of the organization, but none of the project: the cause differs
		assert.Contains(t, warn(orgPage), nobody+"(user4 can't approve (inactive))")
		assert.Contains(t, warn(projectPage), nobody+"(user4 can't approve (no write access))")
		priv, err := repo_model.GetRepositoryByPath(db.DefaultContext, f.org.ID, group.Name, "priv")
		require.NoError(t, err)
		grantWrite(t, priv.ID, 4)
		assert.Contains(t, warn(projectPage), nobody+"(user4 can't approve (inactive))")
		// an owner of the organization who is no site admin sees the neutral mark
		owner := loginUser(t, "user2")
		for _, page := range []string{orgPage, projectPage} {
			body := text(NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body), ".rule-warnings")
			assert.Contains(t, body, nobody+"(user4 can't approve)", page)
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

		session := loginUser(t, "user1") // the reasons are for site admins
		resp := session.MakeRequest(t, NewRequest(t, "GET", priv.Link()+"/settings/branches/edit?rule_name=main"), http.StatusOK)
		warn := text(NewHTMLParser(t, resp.Body), ".rule-warnings")
		assert.Contains(t, warn, "Approval rule Leads needs 1 approval. Nobody can approve. (user4 can't approve (no write access))")

		// with write access to the repository, being inactive is the reason
		grantWrite(t, priv.ID, 4)
		resp = session.MakeRequest(t, NewRequest(t, "GET", priv.Link()+"/settings/branches/edit?rule_name=main"), http.StatusOK)
		assert.Contains(t, text(NewHTMLParser(t, resp.Body), ".rule-warnings"), "(user4 can't approve (inactive))")
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
		repoAdmin := loginUser(t, "user5") // before the second factor makes a sign-in need it
		require.NoError(t, db.Insert(db.DefaultContext, &auth_model.TwoFactor{UID: 5, Secret: []byte("secret"), ScratchSalt: "salt", ScratchHash: "hash"}))
		t.Cleanup(func() {
			_, err := db.GetEngine(db.DefaultContext).Where("uid = 5").Delete(&auth_model.TwoFactor{})
			require.NoError(t, err)
		})
		// two read-only collaborators, one of them with a second factor, and two outsiders, one with a second factor
		call("PUT", "/collaborators/user12", &api.AddCollaboratorOption{Permission: new("read")}, http.StatusNoContent)
		call("PUT", "/collaborators/user13", &api.AddCollaboratorOption{Permission: new("read")}, http.StatusNoContent)
		for _, uid := range []int64{11, 12} {
			require.NoError(t, db.Insert(db.DefaultContext, &auth_model.TwoFactor{UID: uid, Secret: []byte("secret"), ScratchSalt: "salt", ScratchHash: "hash"}))
		}
		t.Cleanup(func() {
			_, err := db.GetEngine(db.DefaultContext).In("uid", 11, 12).Delete(&auth_model.TwoFactor{})
			require.NoError(t, err)
		})
		call("POST", "/contents/CODEOWNERS", &api.CreateFileOptions{ContentBase64: base64.StdEncoding.EncodeToString([]byte("a/.* @user4\nb/.* @user8 @user11 @user12 @user13\n"))}, http.StatusCreated)
		view := func(s *TestSession) string {
			resp := s.MakeRequest(t, NewRequest(t, "GET", pub.Link()+"/src/branch/main/CODEOWNERS"), http.StatusOK)
			return text(NewHTMLParser(t, resp.Body), ".codeowners-ineligible")
		}
		assert.NotContains(t, view(admin), "user4", "user4 can write")

		_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = ?", true, f.org.ID)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = ?", false, f.org.ID)
			require.NoError(t, err)
		})
		marks := view(admin)
		assert.Contains(t, marks, "Line 1: user4 can't approve (blocked by the organization's two-factor requirement)")
		// whoever wouldn't write anyway is "no write access", with or without a second factor: the reason can't tell
		for _, name := range []string{"user8", "user11", "user12", "user13"} {
			assert.Contains(t, marks, name+" can't approve (no write access)")
		}
		assert.Equal(t, 1, strings.Count(marks, "two-factor"))
		// a repository admin who isn't an owner of the organization gets the neutral mark
		marks = view(repoAdmin)
		assert.Contains(t, marks, "user4 can't approve")
		assert.NotContains(t, marks, "two-factor")
		assert.NotContains(t, marks, "no write access", "that would be false without the requirement")

		// an acting owner of the organization (user2 has a second factor) sees the two-factor reason and no other
		ownerSession := loginUser(t, "user2") // before the second factor makes a sign-in need it
		require.NoError(t, db.Insert(db.DefaultContext, &auth_model.TwoFactor{UID: 2, Secret: []byte("secret"), ScratchSalt: "salt", ScratchHash: "hash"}))
		t.Cleanup(func() {
			_, err := db.GetEngine(db.DefaultContext).Where("uid = 2").Delete(&auth_model.TwoFactor{})
			require.NoError(t, err)
		})
		marks = view(ownerSession)
		assert.Contains(t, marks, "user4 can't approve (blocked by the organization's two-factor requirement)")
		assert.Contains(t, marks, "user8 can't approve")
		assert.NotContains(t, marks, "user8 can't approve (")
		assert.NotContains(t, marks, "no write access")
	})
}

// The admin edit page lists what deactivating or suspending a user would break, and a save that does it says so.
func TestStaleOwnersAdminPage(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newApprovalRulesEnv(t)
		const maxFlashItems = 5
		long := strings.Repeat(`<>&"'`, 40) // 200 characters that grow a lot when escaped and encoded
		e.protect("so-admin", true, &api.ApprovalRule{Name: "Only <b>user4</b>", RequiredCount: 1, Usernames: []string{"user4"}})
		for i := range 7 {
			e.protect(fmt.Sprintf("so-long%d", i), true, &api.ApprovalRule{Name: fmt.Sprintf("%s%d", long, i), RequiredCount: 1, Usernames: []string{"user4"}})
		}
		session := loginUser(t, "user1")

		resp := session.MakeRequest(t, NewRequest(t, "GET", "/admin/users/4/edit"), http.StatusOK)
		doc := NewHTMLParser(t, resp.Body)
		assert.Contains(t, text(doc, ".last-approver-warnings"), "Approval rule Only <b>user4</b> of branch rule so-admin in user2/repo1 (Repository approval rule)")
		assert.Contains(t, text(doc, ".last-approver-warnings .header"), "Approvers this change affects. Turning off \"Activated account\" or turning on \"Suspended account\"")
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
			assert.Less(t, len(c.String()), 4096, c.Name)
			if c.Name == "flash" {
				assert.Less(t, len(c.Value), 2500, "the flash is bounded by its encoded size")
			}
		}
		doc = flash()
		assert.Contains(t, text(doc, ".flash-warning"), "Approvers this change affects:")
		assert.Contains(t, text(doc, ".flash-warning li"), "Approval rule Only <b>user4</b> of", "the first rule, cut to fit")
		assert.LessOrEqual(t, doc.Find(".flash-warning li").Length(), maxFlashItems+1, "the list and its \"more\" line")
		assert.Zero(t, doc.Find(".flash-warning b").Length(), "names are escaped")
		assert.Contains(t, text(doc, ".flash-warning"), "…", "a long name is cut")
	})
}

// Another feature registers its own check against the shared shape: the page shows its Name, a Kind that is a locale
// key translated and any other Kind as escaped text, and a link only if it is a plain path.
func TestLastApproverRegistryFakeCheck(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		var on atomic.Bool
		user_service.RegisterLastApproverCheck(func(_ context.Context, ids []int64) ([]user_service.LastApproverWarning, error) {
			if !on.Load() {
				return nil, nil
			}
			return []user_service.LastApproverWarning{
				{UserID: ids[0], Kind: "admin.users.last_approver.kind.org_rule", Link: "/fake/one", Name: "Fake <i>one</i>"},
				{UserID: ids[0], Kind: "Custom <b>kind</b>", Link: "//evil.example/x", Name: "Fake two"},
				{UserID: ids[0], Kind: "Third", Link: "/\\evil.example", Name: "Fake three"},
			}, nil
		})
		on.Store(true)
		t.Cleanup(func() { on.Store(false) })
		session := loginUser(t, "user1")
		doc := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/admin/users/4/edit"), http.StatusOK).Body)
		box := text(doc, ".last-approver-warnings")
		assert.Contains(t, box, "Approvers this change affects")
		assert.Contains(t, box, "Fake <i>one</i> (Organization approval rule)", "a locale key is translated, the name escaped")
		assert.Contains(t, box, "Fake two (Custom <b>kind</b>)", "other kinds are plain text")
		assert.Zero(t, doc.Find(".last-approver-warnings i, .last-approver-warnings b").Length())
		var hrefs []string
		doc.Find(".last-approver-warnings a").Each(func(_ int, a *goquery.Selection) { href, _ := a.Attr("href"); hrefs = append(hrefs, href) })
		assert.Equal(t, []string{"/fake/one"}, hrefs, "links that are not plain paths are not links")
	})
}
