// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	app_context "forgejo.org/services/context"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// flashMessage returns the flash cookie of the session, decoded, and clears it.
func flashMessage(t *testing.T, session *TestSession) string {
	t.Helper()
	cookie := session.GetCookie(app_context.CookieNameFlash)
	if cookie == nil {
		return ""
	}
	v, err := url.QueryUnescape(cookie.Value)
	require.NoError(t, err)
	v, err = url.QueryUnescape(v)
	require.NoError(t, err)
	session.SetCookie(&http.Cookie{Name: app_context.CookieNameFlash, Value: "", MaxAge: -1})
	return v
}

var internalGroupPath = regexp.MustCompile(`/groups/\d|/@\d`)

// The list of projects (Projects tab, Explore) is the SQL form of CanSeeRepoGroup, which decides whether the
// project home answers: for every viewer, a project is listed exactly when its home is served.
func TestVisibleRepoGroupCondMatchesCanSee(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := db.DefaultContext
	f := prepareRepoGroupWeb(t)
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	project := func(owner *user_model.User, groupName, repoName string, private bool) *repo_model.RepoGroup {
		group, err := repo_model.GetRepoGroupByName(ctx, owner.ID, groupName)
		if err != nil {
			group, err = repo_model.CreateRepoGroup(ctx, owner, groupName, "")
			require.NoError(t, err)
		}
		if repoName != "" {
			_, err = repo_service.CreateRepository(ctx, user2, owner, repo_service.CreateRepoOptions{Name: repoName, IsPrivate: private, GroupID: group.ID})
			require.NoError(t, err)
		}
		return group
	}
	project(f.org, "empty", "", false)
	trashOnly := project(f.org, "trashonly", "gone", false)
	_, err := db.GetEngine(ctx).Exec("UPDATE `repository` SET trashed_unix = 1 WHERE group_id = ?", trashOnly.ID)
	require.NoError(t, err)
	// the outside collaborator user5 sees the private repository of "secret"
	require.NoError(t, repo_module.AddCollaborator(ctx, f.hid, user5, perm.AccessModeWrite))
	// limited_org36 (members user1, user5)
	limited := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 36})
	project(limited, "lim", "lpub", false)
	project(limited, "limpriv", "lpriv", true)
	// org17 requires two-factor authentication: its members user2, user15 and user18 have none
	org17 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 17})
	project(org17, "tf", "tfpriv", true)
	project(org17, "tfpub", "tfpub", false)
	_, err = db.GetEngine(ctx).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = ?", true, org17.ID)
	require.NoError(t, err)

	var all []*repo_model.RepoGroup
	require.NoError(t, db.GetEngine(ctx).OrderBy("id").Find(&all))
	owners := map[int64]string{}
	for _, group := range all {
		owners[group.OwnerID] = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: group.OwnerID}).Name
	}

	for _, name := range []string{"", "user1", "user2", "user4", "user5", "user8", "user15", "user28"} {
		t.Run("viewer "+name, func(t *testing.T) {
			var doer *user_model.User
			var session *TestSession
			if name != "" {
				doer = unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: name})
				session = loginUser(t, name)
			}
			listed, _, err := repo_model.FindVisibleRepoGroups(ctx, doer, 0, "", db.ListOptions{})
			require.NoError(t, err)
			for _, group := range all {
				resp := repoGroupRequest(t, session, NewRequest(t, "GET", "/"+owners[group.OwnerID]+"/"+group.Name), NoExpectedStatus)
				isListed := slices.ContainsFunc(listed, func(g *repo_model.RepoGroup) bool { return g.ID == group.ID })
				assert.Equal(t, resp.Code == http.StatusOK, isListed, "%s/%s answered %d", owners[group.OwnerID], group.Name, resp.Code)
			}
		})
	}

	t.Run("explore lists the visible projects", func(t *testing.T) {
		body := MakeRequest(t, NewRequest(t, "GET", "/explore/groups"), http.StatusOK).Body.String()
		assert.Contains(t, body, `href="/org3/proj"`)
		assert.Contains(t, body, `href="/org17/tfpub"`)
		for _, hidden := range []string{"/org3/secret", "/org3/empty", "/org3/trashonly", "/limited_org36/lim", "/privated_org/pp"} {
			assert.NotContains(t, body, `href="`+hidden+`"`)
		}
		assert.NotRegexp(t, internalGroupPath, body)
	})

	t.Run("organization in the trash", func(t *testing.T) {
		_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET trashed_unix = 1 WHERE id = ?", limited.ID)
		require.NoError(t, err)
		admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		listed, _, err := repo_model.FindVisibleRepoGroups(ctx, admin, limited.ID, "", db.ListOptions{})
		require.NoError(t, err)
		assert.Empty(t, listed)
		loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", "/org/limited_org36/groups"), http.StatusNotFound)
	})
}

func TestRepoGroupUI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := db.DefaultContext
	f := prepareRepoGroupWeb(t)
	owner := loginUser(t, "user2")      // org3 owner
	member := loginUser(t, "user4")     // plain member of org3
	teamAdmin := loginUser(t, "user28") // admin team of org3 that may create repositories, not an owner
	nonMember := loginUser(t, "user8")  // no relation to org3
	groupExists := func(name string) bool {
		_, err := repo_model.GetRepoGroupByName(ctx, f.org.ID, name)
		return err == nil
	}

	t.Run("Projects tab", func(t *testing.T) {
		resp := owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/groups"), http.StatusOK)
		body := resp.Body.String()
		assert.Contains(t, body, `href="/org3/proj"`)
		assert.Contains(t, body, `href="/org3/secret"`)
		assert.Contains(t, body, `href="/org/org3/groups/new"`)
		assert.NotRegexp(t, internalGroupPath, body)

		// anonymous: only the project with a public repository, and its public repository counted
		doc := NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", "/org/org3/groups"), http.StatusOK).Body)
		assert.Equal(t, 1, doc.Find(`a[href="/org3/proj"]`).Length())
		assert.Zero(t, doc.Find(`a[href="/org3/secret"]`).Length())
		assert.Zero(t, doc.Find(`a[href="/org/org3/groups/new"]`).Length())
		assert.Equal(t, "1", strings.TrimSpace(doc.Find(".flex-item-trailing").First().Text()))
		// the menu tab: counted per viewer
		assert.Equal(t, "1", strings.TrimSpace(doc.Find(`.menu a[href="/org/org3/groups"] .label`).Text()))

		// keyword
		body = owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/groups?q=sec"), http.StatusOK).Body.String()
		assert.Contains(t, body, `href="/org3/secret"`)
		assert.NotContains(t, body, `href="/org3/proj"`)
	})

	t.Run("project home", func(t *testing.T) {
		body := owner.MakeRequest(t, NewRequest(t, "GET", "/org3/proj"), http.StatusOK).Body.String()
		assert.Contains(t, body, `href="/org3/proj/pub"`)
		assert.Contains(t, body, `href="/org3/proj/priv"`)
		assert.Contains(t, body, fmt.Sprintf(`href="/repo/create?org=%d&group=`, f.org.ID))
		assert.Contains(t, body, `href="/org3/proj/-/settings"`)
		assert.NotRegexp(t, internalGroupPath, body)

		// a non-member sees the public repository only, and no buttons
		body = nonMember.MakeRequest(t, NewRequest(t, "GET", "/org3/proj"), http.StatusOK).Body.String()
		assert.Contains(t, body, `href="/org3/proj/pub"`)
		assert.NotContains(t, body, `href="/org3/proj/priv"`)
		assert.NotContains(t, body, `/repo/create?org=3&group=`)
		assert.NotContains(t, body, `/-/settings`)

		// a member without the right to create repositories gets no New repository button
		body = member.MakeRequest(t, NewRequest(t, "GET", "/org3/proj"), http.StatusOK).Body.String()
		assert.NotContains(t, body, `/repo/create?org=3&group=`)
		assert.NotContains(t, body, `/-/settings`)
		body = teamAdmin.MakeRequest(t, NewRequest(t, "GET", "/org3/proj"), http.StatusOK).Body.String()
		assert.Contains(t, body, `/repo/create?org=3&group=`)
		assert.NotContains(t, body, `/-/settings`)

		// the repository header and the organization's list show the project
		body = nonMember.MakeRequest(t, NewRequest(t, "GET", "/org3/proj/pub"), http.StatusOK).Body.String()
		assert.Contains(t, body, `<a class="muted" href="/org3/proj">proj</a>/`)
		assert.Contains(t, body, "<title>org3/proj/pub")
		body = owner.MakeRequest(t, NewRequest(t, "GET", "/org3?q="+url.QueryEscape("org3/proj/")), http.StatusOK).Body.String()
		assert.Contains(t, body, `href="/org3/proj/pub"`)
		assert.Contains(t, body, `href="/org3/proj/priv"`)
		assert.NotContains(t, body, `href="/org3/secret/hid"`)
	})

	t.Run("create", func(t *testing.T) {
		owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/groups/new"), http.StatusOK)
		resp := owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/groups/new", map[string]string{"name": "Payments", "description": "<b>money</b>"}), http.StatusSeeOther)
		assert.Equal(t, "/org3/Payments", resp.Header().Get("Location"))
		require.True(t, groupExists("payments"))

		// empty state, escaped description
		body := owner.MakeRequest(t, NewRequest(t, "GET", "/org3/payments"), http.StatusOK).Body.String()
		assert.Contains(t, body, "This project has no repositories yet")
		assert.Contains(t, body, "&lt;b&gt;money&lt;/b&gt;")

		for name, message := range map[string]string{
			"repo3": "The name is already used by a repository, a project or a redirect in this organization.",
			"PROJ":  "The name is already used by a repository, a project or a redirect in this organization.",
			"x.git": `The pattern &#34;*.git&#34; cannot be used in a project name.`,
			"a b":   "Project name should contain only alphanumeric",
			"..":    `The project name &#34;..&#34; is reserved.`,
		} {
			resp := owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/groups/new", map[string]string{"name": name}), http.StatusOK)
			assert.Contains(t, resp.Body.String(), message, name)
		}
		assert.Equal(t, 3, unittest.GetCount(t, &repo_model.RepoGroup{OwnerID: f.org.ID}))

		// a root repository can't take a project's name either
		resp = owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/repo/create", map[string]string{"uid": "3", "repo_name": "payments"}), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "The name is already used by a repository, a project or a redirect.")

		for _, session := range []*TestSession{member, teamAdmin, nonMember} {
			session.MakeRequest(t, NewRequest(t, "GET", "/org/org3/groups/new"), http.StatusNotFound)
			session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/groups/new", map[string]string{"name": "evil"}), http.StatusNotFound)
		}
		resp = MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/groups/new", map[string]string{"name": "evil"}), http.StatusSeeOther)
		assert.Equal(t, "/user/login", resp.Header().Get("Location"))
		assert.False(t, groupExists("evil"))
	})

	t.Run("create a repository in a project", func(t *testing.T) {
		payments, err := repo_model.GetRepoGroupByName(ctx, f.org.ID, "payments")
		require.NoError(t, err)

		// the form offers the projects of the organizations the doer may create in, and preselects one
		doc := NewHTMLParser(t, teamAdmin.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/repo/create?org=3&group=%d", payments.ID)), http.StatusOK).Body)
		assert.Equal(t, fmt.Sprint(payments.ID), doc.Find(`#repo_group option[selected]`).AttrOr("value", ""))
		assert.Zero(t, doc.Find(`#repo_group option:contains("pp")`).Length(), "a project of another organization")

		resp := teamAdmin.MakeRequest(t, NewRequestWithValues(t, "POST", "/repo/create", map[string]string{
			"uid": "3", "group_id": fmt.Sprint(payments.ID), "repo_name": "api", "private": "on",
		}), http.StatusSeeOther)
		assert.Equal(t, "/org3/Payments/api", resp.Header().Get("Location"))
		repo, err := repo_model.GetRepositoryByPath(ctx, f.org.ID, "payments", "api")
		require.NoError(t, err)
		assert.True(t, repo.IsPrivate)
		teamAdmin.MakeRequest(t, NewRequest(t, "GET", "/org3/payments/api"), http.StatusOK)

		// from a template
		resp = teamAdmin.MakeRequest(t, NewRequestWithValues(t, "POST", "/repo/create", map[string]string{
			"uid": "3", "group_id": fmt.Sprint(payments.ID), "repo_name": "fromtemplate", "repo_template": "44", "git_content": "on",
		}), http.StatusSeeOther)
		assert.Equal(t, "/org3/Payments/fromtemplate", resp.Header().Get("Location"))

		// a project of another organization, or none, is the same form error
		privOrgGroup, err := repo_model.GetRepoGroupByName(ctx, f.privOrg.ID, "pp")
		require.NoError(t, err)
		for _, id := range []int64{privOrgGroup.ID, 99999} {
			for _, template := range []string{"", "44"} {
				resp := owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/repo/create", map[string]string{
					"uid": "3", "group_id": fmt.Sprint(id), "repo_name": "stray", "repo_template": template, "git_content": "on",
				}), http.StatusOK)
				assert.Contains(t, resp.Body.String(), "The selected project does not exist.")
			}
		}
		assert.False(t, unittest.BeanExists(t, &repo_model.Repository{LowerName: "stray"}))

		// a member who may not create repositories in the organization
		member.MakeRequest(t, NewRequestWithValues(t, "POST", "/repo/create", map[string]string{
			"uid": "3", "group_id": fmt.Sprint(payments.ID), "repo_name": "nope",
		}), http.StatusForbidden)
		assert.False(t, unittest.BeanExists(t, &repo_model.Repository{LowerName: "nope"}))
	})

	t.Run("rename", func(t *testing.T) {
		owner.MakeRequest(t, NewRequest(t, "GET", "/org3/payments/-/settings"), http.StatusOK)
		for _, session := range []*TestSession{member, teamAdmin} {
			session.MakeRequest(t, NewRequest(t, "GET", "/org3/payments/-/settings"), http.StatusNotFound)
			session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/payments/-/settings", map[string]string{"name": "hijack"}), http.StatusNotFound)
		}
		assert.False(t, groupExists("hijack"))

		resp := owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/payments/-/settings", map[string]string{"name": "billing", "description": "Bills"}), http.StatusSeeOther)
		assert.Equal(t, "/org3/billing/-/settings", resp.Header().Get("Location"))
		assert.Contains(t, flashMessage(t, owner), "The project has been updated.")
		group, err := repo_model.GetRepoGroupByName(ctx, f.org.ID, "billing")
		require.NoError(t, err)
		assert.Equal(t, "Bills", group.Description)
		owner.MakeRequest(t, NewRequest(t, "GET", "/org3/billing/api"), http.StatusOK)
		resp = owner.MakeRequest(t, NewRequest(t, "GET", "/org3/payments"), http.StatusMovedPermanently)
		assert.Equal(t, "/org3/billing", resp.Header().Get("Location"), "the old name redirects")

		resp = owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/billing/-/settings", map[string]string{"name": "repo3"}), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "The name is already used by a repository, a project or a redirect in this organization.")
	})

	t.Run("delete", func(t *testing.T) {
		for _, session := range []*TestSession{member, teamAdmin} {
			session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/billing/-/settings/delete", map[string]string{"confirm_name": "org3/billing"}), http.StatusNotFound)
		}
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/billing/-/settings/delete", map[string]string{"confirm_name": "billing"}), http.StatusSeeOther)
		assert.Contains(t, flashMessage(t, owner), "The name you typed does not match the project.")
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/billing/-/settings/delete", map[string]string{"confirm_name": "org3/billing"}), http.StatusSeeOther)
		assert.Contains(t, flashMessage(t, owner), "The project still holds repositories")
		assert.True(t, groupExists("billing"))

		// only trashed repositories left: still refused
		_, err := db.GetEngine(ctx).Exec("UPDATE `repository` SET trashed_unix = 1 WHERE owner_id = ? AND group_name = ?", f.org.ID, "billing")
		require.NoError(t, err)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/billing/-/settings/delete", map[string]string{"confirm_name": "org3/billing"}), http.StatusSeeOther)
		assert.Contains(t, flashMessage(t, owner), "The project still holds repositories")
		assert.True(t, groupExists("billing"))

		_, err = repo_model.CreateRepoGroup(ctx, f.org, "tmp", "")
		require.NoError(t, err)
		resp := owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/tmp/-/settings/delete", map[string]string{"confirm_name": "org3/tmp"}), http.StatusSeeOther)
		assert.Equal(t, "/org/org3/groups", resp.Header().Get("Location"))
		assert.False(t, groupExists("tmp"))
	})

	t.Run("empty project hint", func(t *testing.T) {
		_, err := repo_model.CreateRepoGroup(ctx, f.org, "hintempty", "")
		require.NoError(t, err)
		const hint = `/repo/migrate?org=3&group=`
		const text = "Or bring one in with"
		body := owner.MakeRequest(t, NewRequest(t, "GET", "/org3/hintempty"), http.StatusOK).Body.String()
		assert.Contains(t, body, text)
		assert.Contains(t, body, hint)
		body = member.MakeRequest(t, NewRequest(t, "GET", "/org3/hintempty"), http.StatusOK).Body.String()
		assert.Contains(t, body, "This project has no repositories yet")
		assert.NotContains(t, body, text, "a member who may not create")
		assert.NotContains(t, body, hint, "a member who may not create")
		nonMember.MakeRequest(t, NewRequest(t, "GET", "/org3/hintempty"), http.StatusNotFound)

		defer test.MockVariableValue(&setting.Repository.DisableMigrations, true)()
		body = owner.MakeRequest(t, NewRequest(t, "GET", "/org3/hintempty"), http.StatusOK).Body.String()
		assert.NotContains(t, body, text)
		assert.NotContains(t, body, hint)
	})

	t.Run("archived organization empty hint", func(t *testing.T) {
		_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET is_archived = ? WHERE id = ?", true, f.org.ID)
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET is_archived = ? WHERE id = ?", false, f.org.ID)
			require.NoError(t, err)
		}()
		body := owner.MakeRequest(t, NewRequest(t, "GET", "/org3/hintempty"), http.StatusOK).Body.String()
		assert.NotContains(t, body, "Or bring one in with")
	})

	t.Run("archived organization", func(t *testing.T) {
		_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET is_archived = ? WHERE id = ?", true, f.org.ID)
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET is_archived = ? WHERE id = ?", false, f.org.ID)
			require.NoError(t, err)
		}()
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/groups/new", map[string]string{"name": "archived"}), http.StatusForbidden)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/proj/-/settings", map[string]string{"name": "renamed"}), http.StatusForbidden)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/secret/-/settings/delete", map[string]string{"confirm_name": "org3/secret"}), http.StatusForbidden)
		assert.False(t, groupExists("archived"))
		assert.True(t, groupExists("proj"))
		body := owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/groups"), http.StatusOK).Body.String()
		assert.NotContains(t, body, `href="/org/org3/groups/new"`)
	})

	t.Run("read-only maintenance", func(t *testing.T) {
		defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/groups/new", map[string]string{"name": "readonly"}), http.StatusSeeOther)
		assertMaintenanceFlash(t, owner)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/proj/-/settings", map[string]string{"name": "renamed"}), http.StatusSeeOther)
		assertMaintenanceFlash(t, owner)
		assert.False(t, groupExists("readonly"))
		assert.True(t, groupExists("proj"))
	})
}
