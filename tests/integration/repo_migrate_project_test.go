// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/services/migrations/allowlist"
	mirror_service "forgejo.org/services/mirror"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Migrations and pull mirrors can be created in a project (#506).
func TestRepoMigrateProject(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValueWithReset(&setting.Migrations.AllowLocalNetworks, true, func() { require.NoError(t, allowlist.Init()) })()
	defer allowLocalImport(t)()
	f := prepareRepoGroupWeb(t)
	ctx := t.Context()
	// the mirror syncs as its owner, the organization
	_, err := db.GetEngine(ctx).ID(f.org.ID).SetExpr("allow_import_local", true).Update(&user_model.User{})
	require.NoError(t, err)
	upstream := newFilterUpstream(t)

	proj, err := repo_model.GetRepoGroupByName(ctx, f.org.ID, "proj")
	require.NoError(t, err)
	foreign, err := repo_model.GetRepoGroupByName(ctx, f.privOrg.ID, "pp")
	require.NoError(t, err)
	team := unittest.AssertExistsAndLoadBean(t, &org_model.Team{OrgID: f.org.ID, LowerName: "team1"})
	require.NoError(t, repo_service.LinkTeamToRepoGroup(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), org_model.OrgFromUser(f.org), team.ID, proj.ID))

	session := loginUser(t, "user2")
	fid := func(id int64) string { return fmt.Sprint(id) }
	migrate := func(t *testing.T, s *TestSession, values map[string]string, status int) string {
		t.Helper()
		values["clone_addr"] = upstream.bare
		values["service"] = "1"
		resp := s.MakeRequest(t, NewRequestWithValues(t, "POST", "/repo/migrate", values), status)
		if status == http.StatusSeeOther {
			return resp.Header().Get("Location")
		}
		return resp.Body.String()
	}
	ready := func(t *testing.T, group, name string) *repo_model.Repository {
		t.Helper()
		assert.Eventually(t, func() bool {
			repo, err := repo_model.GetRepositoryByRef(db.DefaultContext, "org3", group, name)
			return err == nil && repo.Status == repo_model.RepositoryReady
		}, 30*time.Second, 200*time.Millisecond)
		repo, err := repo_model.GetRepositoryByRef(ctx, "org3", group, name)
		require.NoError(t, err)
		return repo
	}

	t.Run("picker", func(t *testing.T) {
		list := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/repo/migrate?org=3&group="+fid(proj.ID)+"&mirror=1"), http.StatusOK).Body)
		assert.Equal(t, 11, list.doc.Find(fmt.Sprintf(`a.migrate-entry[href*="group=%d"]`, proj.ID)).Length())
		for _, service := range []api.GitServiceType{api.PlainGitService, api.GithubService, api.GiteaService, api.GitlabService, api.GogsService, api.OneDevService, api.GitBucketService, api.CodebaseService, api.ForgejoService, api.PagureService, api.BitbucketDataCenterService} {
			page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/repo/migrate?service_type=%d&org=3&group=%d", service, proj.ID)), http.StatusOK).Body)
			assert.Equal(t, fid(proj.ID), page.doc.Find(`select#repo_group option[selected]`).AttrOr("value", ""), "service %d", service)
			assert.Equal(t, "group_id", page.doc.Find(`select#repo_group`).AttrOr("name", ""), "service %d", service)
		}
		// a raw query is never echoed, a number that is not a project selects nothing
		page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/repo/migrate?service_type=1&org=3&group=%22%3E%3Cb%3E"), http.StatusOK).Body)
		assert.Empty(t, page.doc.Find(`select#repo_group option[selected]`).AttrOr("value", ""))
		assert.NotContains(t, page.Find("body").Text(), "<b>")
		list = NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/repo/migrate?org=3&group=%22%3E%3Cb%3E"), http.StatusOK).Body)
		list.AssertElement(t, `a.migrate-entry[href*="%3Cb%3E"]`, false)
		list.AssertElement(t, `a.migrate-entry[href*="<b>"]`, false)
	})

	t.Run("project home link", func(t *testing.T) {
		link := fmt.Sprintf(`a[href="/repo/migrate?org=%d&group=%d&mirror=1"]`, f.org.ID, proj.ID)
		NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/org3/proj"), http.StatusOK).Body).AssertElement(t, link, true)
		NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", "/org3/proj"), http.StatusOK).Body).AssertElement(t, link, false)
		NewHTMLParser(t, loginUser(t, "user5").MakeRequest(t, NewRequest(t, "GET", "/org3/proj"), http.StatusOK).Body).AssertElement(t, link, false)
		defer test.MockVariableValue(&setting.Repository.DisableMigrations, true)()
		NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/org3/proj"), http.StatusOK).Body).AssertElement(t, link, false)
	})

	t.Run("web non-mirror", func(t *testing.T) {
		loc := migrate(t, session, map[string]string{"uid": "3", "group_id": fid(proj.ID), "repo_name": "imported"}, http.StatusSeeOther)
		assert.Equal(t, "/org3/proj/imported", loc)
		repo := ready(t, "proj", "imported")
		assert.Equal(t, proj.ID, repo.GroupID)
		assert.Equal(t, "proj", repo.GroupName)
		assert.False(t, repo.IsMirror)
		assert.Equal(t, filepath.Join(setting.RepoRootPath, "org3", "proj", "imported.git"), repo.RepoPath())
		assert.DirExists(t, repo.RepoPath())
		assert.Equal(t, repo.Link(), loc)
		_, err := repo_model.GetRepositoryByOwnerAndName(ctx, "org3", "imported") // not at the root
		require.Error(t, err)
		via, err := org_model.ViaGroupRepoIDs(ctx, team.ID)
		require.NoError(t, err)
		assert.True(t, via[repo.ID])
		unittest.CheckConsistencyFor(t, &repo_model.Repository{})
		session.MakeRequest(t, NewRequest(t, "GET", "/org3/proj/imported"), http.StatusOK)
	})

	t.Run("web mirror", func(t *testing.T) {
		migrate(t, session, map[string]string{"uid": "3", "group_id": fid(proj.ID), "repo_name": "mirrored", "mirror": "on"}, http.StatusSeeOther)
		repo := ready(t, "proj", "mirrored")
		assert.True(t, repo.IsMirror)
		assert.Equal(t, proj.ID, repo.GroupID)
		upstream.commit(t, "main", "more")
		require.True(t, mirror_service.SyncPullMirror(ctx, repo.ID))
		assert.Contains(t, gitIn(t, repo.RepoPath(), "log", "--format=%s", "main"), "more")
		session.MakeRequest(t, NewRequest(t, "GET", "/org3/proj/mirrored/settings"), http.StatusOK)
	})

	t.Run("web without a project stays at the root", func(t *testing.T) {
		assert.Equal(t, "/org3/rooted", migrate(t, session, map[string]string{"uid": "3", "repo_name": "rooted"}, http.StatusSeeOther))
		repo, err := repo_model.GetRepositoryByOwnerAndName(ctx, "org3", "rooted")
		require.NoError(t, err)
		assert.Zero(t, repo.GroupID)
	})

	t.Run("web errors", func(t *testing.T) {
		notFound := func(t *testing.T, s *TestSession, values map[string]string) {
			t.Helper()
			body := NewHTMLParser(t, bytes.NewBufferString(migrate(t, s, values, http.StatusOK))).doc.Find(".ui.negative.message").Text()
			assert.Contains(t, body, "project does not exist")
		}
		notFound(t, session, map[string]string{"uid": "3", "group_id": "99999", "repo_name": "x1"})
		notFound(t, session, map[string]string{"uid": "3", "group_id": fid(foreign.ID), "repo_name": "x2"}) // another org's project
		notFound(t, session, map[string]string{"uid": "2", "group_id": fid(proj.ID), "repo_name": "x3"})    // a user's namespace has no projects
		notFound(t, session, map[string]string{"uid": "3", "group_id": "-1", "repo_name": "x4"})
		body := NewHTMLParser(t, bytes.NewBufferString(migrate(t, session, map[string]string{"uid": "3", "group_id": fid(proj.ID), "repo_name": "imported"}, http.StatusOK))).doc.Find(".ui.negative.message").Text()
		assert.Contains(t, body, "already used by a repository")
		for _, name := range []string{"x1", "x2", "x3", "x4"} {
			_, err := repo_model.GetRepositoryByRef(ctx, "org3", "proj", name)
			require.Error(t, err)
			unittest.AssertNotExistsBean(t, &repo_model.Repository{LowerName: name})
		}

		// the owner is checked before the project: a user who may not create in org3 gets 403 for every project id
		outsider := loginUser(t, "user10")
		for _, id := range []int64{proj.ID, foreign.ID, 99999} {
			migrate(t, outsider, map[string]string{"uid": "3", "group_id": fid(id), "repo_name": "x5"}, http.StatusForbidden)
		}
	})
}

// POST /repos/migrate takes a project (#506).
func TestAPIRepoMigrateProject(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValueWithReset(&setting.Migrations.AllowLocalNetworks, true, func() { require.NoError(t, allowlist.Init()) })()
	defer allowLocalImport(t)()
	f := prepareRepoGroupWeb(t)
	ctx := t.Context()
	_, err := db.GetEngine(ctx).ID(f.org.ID).SetExpr("allow_import_local", true).Update(&user_model.User{})
	require.NoError(t, err)
	upstream := newFilterUpstream(t)
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
	post := func(t *testing.T, token string, opts api.MigrateRepoOptions, status int) {
		t.Helper()
		opts.CloneAddr = upstream.bare
		opts.RepoOwner = "org3"
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", &opts).AddTokenAuth(token), status)
	}

	t.Run("lands in the project", func(t *testing.T) {
		resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", &api.MigrateRepoOptions{
			CloneAddr: upstream.bare, RepoOwner: "org3", RepoName: "apimig", Project: "proj",
		}).AddTokenAuth(token), http.StatusCreated)
		var got api.Repository
		DecodeJSON(t, resp, &got)
		repo, err := repo_model.GetRepositoryByRef(ctx, "org3", "proj", "apimig")
		require.NoError(t, err)
		assert.Equal(t, "org3/proj/apimig", repo.FullName())
		assert.Contains(t, got.URL, "/-")
		assert.DirExists(t, repo.RepoPath())
		assert.NotNil(t, got.Project)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/proj/apimig/-").AddTokenAuth(token), http.StatusOK)
	})

	t.Run("mirror syncs", func(t *testing.T) {
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", &api.MigrateRepoOptions{
			CloneAddr: upstream.bare, RepoOwner: "org3", RepoName: "apimirror", Project: "proj", Mirror: true,
		}).AddTokenAuth(token), http.StatusCreated)
		repo, err := repo_model.GetRepositoryByRef(ctx, "org3", "proj", "apimirror")
		require.NoError(t, err)
		assert.True(t, repo.IsMirror)
		upstream.commit(t, "main", "api more")
		require.True(t, mirror_service.SyncPullMirror(ctx, repo.ID))
		assert.Contains(t, gitIn(t, repo.RepoPath(), "log", "--format=%s", "main"), "api more")
	})

	t.Run("unknown and foreign projects answer the same 404", func(t *testing.T) {
		var bodies []string
		for _, project := range []string{"nosuch", "pp", "secret-but-missing"} { // pp is in another organization
			resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", &api.MigrateRepoOptions{
				CloneAddr: upstream.bare, RepoOwner: "org3", RepoName: "apinot", Project: project,
			}).AddTokenAuth(token), http.StatusNotFound)
			bodies = append(bodies, resp.Body.String())
			assert.NotContains(t, resp.Body.String(), project)
		}
		assert.Equal(t, bodies[0], bodies[1])
		assert.Equal(t, bodies[0], bodies[2])
		unittest.AssertNotExistsBean(t, &repo_model.Repository{LowerName: "apinot"})
	})

	t.Run("a user namespace has no projects", func(t *testing.T) {
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", &api.MigrateRepoOptions{
			CloneAddr: upstream.bare, RepoOwner: "user2", RepoName: "apiuser", Project: "proj",
		}).AddTokenAuth(token), http.StatusNotFound)
	})

	t.Run("restricted tokens", func(t *testing.T) {
		publicOnly := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopePublicOnly)
		// with a project: refused before the project is looked up, for known and unknown projects alike
		for _, project := range []string{"proj", "nosuch"} {
			post(t, publicOnly, api.MigrateRepoOptions{RepoName: "apirestricted", Project: project}, http.StatusForbidden)
		}
		unittest.AssertNotExistsBean(t, &repo_model.Repository{LowerName: "apirestricted"})
		// a token limited to specific repositories
		session.MakeRequest(t, NewRequestWithURLValues(t, "POST", "/user/settings/keys/tokens/new", url.Values{
			"name": {"migrate-limited"}, "resource": {"repo-specific"}, "scope": {"write:repository"}, "selected_repo": {"org3/proj/pub"},
		}), http.StatusSeeOther)
		limited := assertAccessToken(t, session)
		for _, project := range []string{"proj", "nosuch"} {
			post(t, limited, api.MigrateRepoOptions{RepoName: "apirestricted2", Project: project}, http.StatusForbidden)
		}
		unittest.AssertNotExistsBean(t, &repo_model.Repository{LowerName: "apirestricted2"})
		// without a project: as before
		post(t, publicOnly, api.MigrateRepoOptions{RepoName: "apirestricted"}, http.StatusCreated)
	})

	t.Run("taken name", func(t *testing.T) {
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", &api.MigrateRepoOptions{
			CloneAddr: upstream.bare, RepoOwner: "org3", RepoName: "apimig", Project: "proj",
		}).AddTokenAuth(token), http.StatusConflict)
	})

	t.Run("a failed migration leaves nothing", func(t *testing.T) {
		defer test.MockVariableValueWithReset(&setting.Migrations.AllowUnencrypted, true, func() { require.NoError(t, allowlist.Init()) })()
		gone := httptest.NewServer(http.NotFoundHandler()) // passes the address checks, the clone fails after the repository was created
		defer gone.Close()
		for _, c := range []struct{ name, project, dir string }{
			{"apifail", "proj", filepath.Join("org3", "proj", "apifail.git")},
			{"apifailroot", "", filepath.Join("org3", "apifailroot.git")},
		} {
			resp := NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", &api.MigrateRepoOptions{
				CloneAddr: gone.URL + "/org/repo.git", RepoOwner: "org3", RepoName: c.name, Project: c.project,
			}).AddTokenAuth(token)
			assert.NotEqual(t, http.StatusCreated, MakeRequest(t, resp, NoExpectedStatus).Code)
			unittest.AssertNotExistsBean(t, &repo_model.Repository{LowerName: c.name})
			_, err := os.Stat(filepath.Join(setting.RepoRootPath, c.dir))
			assert.True(t, os.IsNotExist(err), c.dir)
		}
		unittest.CheckConsistencyFor(t, &repo_model.Repository{})
	})
}
