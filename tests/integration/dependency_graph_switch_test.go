// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	dependency_service "forgejo.org/services/dependency"
	repo_service "forgejo.org/services/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The switches of the dependency graph: site (admin page, no restart), organization (owners, with a lock) and
// repository (admins). Off answers 404 everywhere, deletes the stored rows and is recorded in the audit log.
func TestDependencyGraphSwitches(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		enableDependencyGraph(t)
		t.Cleanup(func() {
			_, err := db.GetEngine(db.DefaultContext).Where("setting_key = ?", setting.Config().DependencyGraph.DynKey()).Delete(new(system_model.Setting))
			require.NoError(t, err)
			bumpSettingsRevision(t)
		})
		sys := audit_model.WithSystem(db.DefaultContext, "test")
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		repo3 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}) // org3/repo3, private
		group, err := repo_model.CreateRepoGroup(sys, org3, "dep-switch", "")
		require.NoError(t, err)
		leaf := depNewRepo(t, org3, user2, "leaf", true, group.ID)
		personal := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}) // user2/repo1
		d := func() *repo_model.Dependency {
			return &repo_model.Dependency{Ecosystem: "Go", Name: "example.com/x", Version: "v1", Direct: true}
		}
		store := func() {
			for _, r := range []*repo_model.Repository{repo3, leaf, personal} {
				storeScanAt(t, r, headOf(t, r), d())
			}
		}
		store()
		admin := loginUser(t, "user1")
		owner := loginUser(t, "user2")
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)

		// every path the dependency graph answers on: web page and SBOM, and the API at all three mounts
		paths := func(r *repo_model.Repository) (web, api []string) {
			link := "/" + r.FullName()
			web = []string{link + "/activity/dependencies", link + "/activity/dependencies/sbom"}
			mounts := []string{fmt.Sprintf("/api/v1/repositories/%d", r.ID)}
			if r.GroupID != 0 {
				mounts = append(mounts, "/api/v1/repos/"+r.FullName()+"/-")
			} else {
				mounts = append(mounts, "/api/v1/repos/"+r.FullName())
			}
			for _, m := range mounts {
				api = append(api, m+"/dependencies", m+"/sbom")
			}
			return web, api
		}
		check := func(r *repo_model.Repository, status int) {
			t.Helper()
			web, api := paths(r)
			for _, p := range web {
				owner.MakeRequest(t, NewRequest(t, "GET", p), status)
			}
			for _, p := range api {
				MakeRequest(t, NewRequest(t, "GET", p).AddTokenAuth(token), status)
			}
			// the Activity menu shows the item only while it is on
			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/"+r.FullName()+"/activity"), http.StatusOK).Body)
			assert.Equal(t, status == http.StatusOK, doc.Find(`a[href$="/activity/dependencies"]`).Length() == 1, r.FullName())
		}
		hasRows := func(r *repo_model.Repository) bool {
			return depScanOf(t, r.ID) != nil || len(depRows(t, r.ID)) > 0
		}
		for _, r := range []*repo_model.Repository{repo3, leaf, personal} {
			check(r, http.StatusOK)
		}

		t.Run("site switch", func(t *testing.T) {
			since := auditMaxID(t)
			page := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/config/dependency-graph"), http.StatusOK).Body)
			page.AssertElement(t, "#dependency-graph-enabled[checked]", true)
			// off, as the form sends it (an unticked checkbox sends nothing); no restart: it applies at once
			admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/config/dependency-graph", map[string]string{}), http.StatusSeeOther)
			bumpSettingsRevision(t)
			assert.True(t, setting.DependencyGraph.Enabled, "app.ini still says on: the stored value wins")
			for _, r := range []*repo_model.Repository{repo3, leaf, personal} {
				check(r, http.StatusNotFound)
				assert.False(t, hasRows(r), "rows of %s deleted", r.FullName())
			}
			e := auditOne(t, since, "admin.setting.changed")
			assert.Contains(t, e.Data, "dependency_graph.enabled")
			assert.Contains(t, e.Data, `"mode":"off"`)
			// the organization and repository forms can't change anything while the site is off
			// the refusal is a message on the settings page, as other settings pages answer
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/code_security", map[string]string{"enabled": "on", "locked": "on"}), http.StatusSeeOther)
			assert.Contains(t, bwFlash(owner), "error")
			assert.Contains(t, bwFlash(owner), "Turned off by the site administrator.")
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/code_security", map[string]string{}), http.StatusSeeOther)
			assert.Contains(t, bwFlash(owner), "can't be changed here")
			sw, err := dependency_service.GetRepoSwitch(t.Context(), unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}))
			require.NoError(t, err)
			assert.True(t, sw.Own, "the refused repository save changed nothing")
			org, err := dependency_service.GetOrgSwitch(t.Context(), org3.ID)
			require.NoError(t, err)
			assert.False(t, org.Locked, "the refused organization save changed nothing")

			admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/config/dependency-graph", map[string]string{"enabled": "on"}), http.StatusSeeOther)
			bumpSettingsRevision(t)
			page = NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/config/dependency-graph"), http.StatusOK).Body)
			page.AssertElement(t, "#dependency-graph-enabled[checked]", true)
			assert.True(t, dependency_service.SiteEnabled(t.Context()))
			// only site admins reach the page
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/config/dependency-graph", map[string]string{}), http.StatusForbidden)
			assert.True(t, dependency_service.SiteEnabled(t.Context()))
			store()
		})

		t.Run("organization switch and lock", func(t *testing.T) {
			// the repository turns it off first; then the organization locks it on, which overrides that
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/repo3/settings/code_security", map[string]string{}), http.StatusSeeOther)
			check(repo3, http.StatusNotFound)
			assert.False(t, hasRows(repo3))

			since := auditMaxID(t)
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/code_security", map[string]string{"enabled": "on", "locked": "on"}), http.StatusSeeOther)
			e := auditOne(t, since, "org.dependency_graph.changed")
			assert.Contains(t, e.Data, `"dependency_graph_locked":true`)
			assert.True(t, dependency_service.Enabled(t.Context(), unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})), "the lock overrides the repository's own off")
			store()
			check(repo3, http.StatusOK)

			// locked: the repository form is disabled and its POST refused
			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/settings/code_security"), http.StatusOK).Body)
			doc.AssertElement(t, "fieldset[disabled] #dependency-graph-enabled[checked]", true)
			assert.Contains(t, doc.Find("#dependency-graph-set-by").Text(), "Set by the org3 organization.")
			assert.Contains(t, doc.Find("#dependency-graph-set-by").Text(), "the repository setting (off) applies again", "the repository's own stored choice")
			doc.AssertElement(t, `.dependency-graph-decided a[href$="/org/org3/settings/code_security"]`, true)
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/repo3/settings/code_security", map[string]string{"enabled": "on"}), http.StatusSeeOther)
			assert.Contains(t, bwFlash(owner), "can't be changed here")

			// lifting the lock brings back repo3's own off, and its rows go at once
			store()
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/code_security", map[string]string{"enabled": "on"}), http.StatusSeeOther)
			check(repo3, http.StatusNotFound)
			assert.False(t, hasRows(repo3), "rows deleted when the lock is lifted")
			assert.True(t, hasRows(leaf), "a repository that stays on keeps its rows")
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/code_security", map[string]string{"enabled": "on", "locked": "on"}), http.StatusSeeOther)

			// off for the organization: every repository of it (also in a project) answers 404 and loses its rows
			store()
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/code_security", map[string]string{}), http.StatusSeeOther)
			for _, r := range []*repo_model.Repository{repo3, leaf} {
				check(r, http.StatusNotFound)
				assert.False(t, hasRows(r), r.FullName())
			}
			check(personal, http.StatusOK)
			assert.True(t, hasRows(personal), "another owner's repository keeps its rows")
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/code_security", map[string]string{"enabled": "on"}), http.StatusSeeOther)
			store()
			check(leaf, http.StatusOK)
			// without the lock, repo3's own off applies again
			check(repo3, http.StatusNotFound)
		})

		t.Run("repository switch", func(t *testing.T) {
			store()
			since := auditMaxID(t)
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/dep-switch/leaf/settings/code_security", map[string]string{}), http.StatusSeeOther)
			e := auditOne(t, since, "repo.repository.updated")
			assert.Contains(t, e.Data, `"dependency_graph":false`)
			check(leaf, http.StatusNotFound)
			assert.False(t, hasRows(leaf))
			assert.True(t, hasRows(repo3), "another repository of the organization keeps its rows")
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/dep-switch/leaf/settings/code_security", map[string]string{"enabled": "on"}), http.StatusSeeOther)
			store()
			check(leaf, http.StatusOK)
		})

		t.Run("archived repository", func(t *testing.T) {
			require.NoError(t, repo_service.SetArchiveRepoState(sys, personal, true))
			defer func() { require.NoError(t, repo_service.SetArchiveRepoState(sys, personal, false)) }()
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/code_security", map[string]string{}), http.StatusNotFound)
			assert.True(t, dependency_service.Enabled(t.Context(), unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})))
		})

		t.Run("only owners and admins", func(t *testing.T) {
			// user4 is no owner of org3 and no admin of its repositories, and can't see user2's settings
			other := loginUser(t, "user4")
			other.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/code_security", map[string]string{}), http.StatusNotFound)
			other.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/code_security"), http.StatusNotFound)
			other.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/repo3/settings/code_security", map[string]string{}), http.StatusNotFound)
			other.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/code_security", map[string]string{}), http.StatusNotFound)
			MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/code_security", map[string]string{}), http.StatusSeeOther) // to the sign-in page
			assert.True(t, dependency_service.Enabled(t.Context(), unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})))
			assert.False(t, dependency_service.Enabled(t.Context(), unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})), "still off by its own switch")
		})
	})
}
