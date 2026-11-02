// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	activities_model "forgejo.org/models/activities"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/queue"
	repo_service "forgejo.org/services/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Moving a repository between the root and projects of org3 on the settings page, and every old path redirecting
// to where it is now, on the web and over git, unless the viewer can't see it there.
func TestRepoGroupMove(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		ctx := db.DefaultContext
		f := prepareRepoGroupWeb(t)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		owner := loginUser(t, "user2")
		member := loginUser(t, "user4")
		nonMember := loginUser(t, "user5")
		proj, err := repo_model.GetRepoGroupByName(ctx, f.org.ID, "proj")
		require.NoError(t, err)
		secret, err := repo_model.GetRepoGroupByName(ctx, f.org.ID, "secret")
		require.NoError(t, err)
		api, err := repo_service.CreateRepository(ctx, user2, f.org, repo_service.CreateRepoOptions{
			Name: "api", Readme: "Default", AutoInit: true, DefaultBranch: "main",
		})
		require.NoError(t, err)

		reload := func(id int64) *repo_model.Repository {
			return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: id})
		}
		move := func(t *testing.T, session *TestSession, repo *repo_model.Repository, groupID int64, status int) {
			t.Helper()
			session.MakeRequest(t, NewRequestWithValues(t, "POST", repo.Link()+"/settings", map[string]string{
				"action":    "move",
				"repo_name": repo.FullName(),
				"group_id":  strconv.FormatInt(groupID, 10),
			}), status)
		}
		assertRedirect := func(t *testing.T, session *TestSession, path, location string) {
			t.Helper()
			resp := repoGroupRequest(t, session, NewRequest(t, "GET", path), http.StatusMovedPermanently)
			assert.Equal(t, location, resp.Header().Get("Location"), path)
		}
		clone := func(t *testing.T, p string) {
			t.Helper()
			c := *u
			c.Path = p
			doGitClone(t.TempDir(), &c)(t)
		}

		t.Run("move form", func(t *testing.T) {
			resp := owner.MakeRequest(t, NewRequest(t, "GET", "/org3/api/settings"), http.StatusOK)
			assert.Contains(t, resp.Body.String(), `id="move-repo-modal"`)
			resp = owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings"), http.StatusOK)
			assert.NotContains(t, resp.Body.String(), `id="move-repo-modal"`, "users have no projects")

			// the confirmation must name the repository
			resp = owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/api/settings", map[string]string{
				"action": "move", "repo_name": "org3/other", "group_id": strconv.FormatInt(proj.ID, 10),
			}), http.StatusOK)
			assert.Contains(t, resp.Body.String(), "Enter the full name of the repository: org3/api")
			assert.EqualValues(t, 0, reload(api.ID).GroupID)

			// another organization's project is not found
			other, err := repo_model.CreateRepoGroup(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 17}), "elsewhere", "")
			require.NoError(t, err)
			move(t, owner, api, other.ID, http.StatusNotFound)
			assert.EqualValues(t, 0, reload(api.ID).GroupID)
		})

		t.Run("root to project", func(t *testing.T) {
			move(t, owner, api, proj.ID, http.StatusSeeOther)
			api = reload(api.ID)
			assert.Equal(t, "org3/proj/api", api.FullName())
			assertRedirect(t, nil, "/org3/api", "/org3/proj/api")
			assertRedirect(t, nil, "/org3/api/issues?state=open&x=1", "/org3/proj/api/issues?state=open&x=1")
			assertRedirect(t, nonMember, "/org3/api/src/branch/main", "/org3/proj/api/src/branch/main")
			clone(t, "/org3/api.git")
			// the API names the repository in its project form
			resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/api"), http.StatusMovedPermanently)
			assert.Equal(t, "/api/v1/repos/org3/proj/api/-", resp.Header().Get("Location"))
		})

		t.Run("project to project", func(t *testing.T) {
			move(t, owner, api, secret.ID, http.StatusSeeOther)
			api = reload(api.ID)
			assert.Equal(t, "org3/secret/api", api.FullName())
			assertRedirect(t, nil, "/org3/proj/api", "/org3/secret/api")
			assertRedirect(t, nil, "/org3/proj/api/-/issues?x=1", "/org3/secret/api/-/issues?x=1")
			assertRedirect(t, nil, "/org3/api/issues", "/org3/secret/api/issues")
			clone(t, "/org3/proj/api.git")
			clone(t, "/org3/api")
		})

		t.Run("project renamed", func(t *testing.T) {
			require.NoError(t, repo_service.RenameRepoGroup(ctx, f.org, secret, "vault"))
			assertRedirect(t, nil, "/org3/secret", "/org3/vault")
			assertRedirect(t, owner, "/org3/secret/-/settings", "/org3/vault/-/settings")
			assertRedirect(t, nil, "/org3/secret/api/issues", "/org3/vault/api/issues")
			clone(t, "/org3/secret/api.git")

			// and the repository renamed in it
			require.NoError(t, repo_service.ChangeRepositoryName(ctx, user2, reload(api.ID), "api2"))
			api = reload(api.ID)
			assertRedirect(t, nil, "/org3/secret/api/issues", "/org3/vault/api2/issues")
			assertRedirect(t, nil, "/org3/vault/api", "/org3/vault/api2")
			clone(t, "/org3/secret/api.git")
		})

		t.Run("hidden target answers like missing", func(t *testing.T) {
			// the private org3/secret/hid (now vault) moves to the root
			require.NoError(t, repo_service.MoveRepository(ctx, user2, reload(f.hid.ID), 0))
			assertRedirect(t, owner, "/org3/vault/hid", "/org3/hid")
			for _, session := range []*TestSession{nonMember, nil} {
				for _, rest := range []string{"", "/-/issues", "/issues"} {
					missing := comparableResponse(t, session, "GET", "/org3/vault/nothing"+rest)
					assertSameResponse(t, missing, comparableResponse(t, session, "GET", "/org3/vault/hid"+rest), rest)
				}
				// git over HTTP
				missing := gitResponse(t, NewRequest(t, "GET", "/org3/vault/nothing.git/info/refs?service=git-upload-pack"), "/org3/vault/nothing")
				assert.Equal(t, missing, gitResponse(t, NewRequest(t, "GET", "/org3/vault/hid.git/info/refs?service=git-upload-pack"), "/org3/vault/hid"))
			}
			// a write to an old path of a visible repository isn't redirected
			missing := comparableResponse(t, nonMember, "POST", "/org3/vault/nothing/issues/new")
			assertSameResponse(t, missing, comparableResponse(t, nonMember, "POST", "/org3/vault/api/issues/new"))
		})

		t.Run("project to root", func(t *testing.T) {
			move(t, owner, api, 0, http.StatusSeeOther)
			api = reload(api.ID)
			assert.Equal(t, "org3/api2", api.FullName())
			assertRedirect(t, nil, "/org3/vault/api2/issues", "/org3/api2/issues")
			assertRedirect(t, nil, "/org3/secret/api", "/org3/api2")
		})

		t.Run("feed", func(t *testing.T) {
			queue.GetManager().FlushAll(ctx, 10*time.Second)
			for _, old := range []string{"org3/api", "org3/proj/api", "org3/vault/api2"} {
				unittest.AssertExistsAndLoadBean(t, &activities_model.Action{OpType: activities_model.ActionTransferRepo, RepoID: api.ID, ActUserID: user2.ID, Content: old})
			}
		})

		t.Run("authority", func(t *testing.T) {
			// user4 is a member of org3 but no owner: the settings route is closed to them
			move(t, member, api, proj.ID, http.StatusNotFound)
			// an archived organization refuses every write
			_, err := db.GetEngine(ctx).ID(f.org.ID).Cols("is_archived").Update(&user_model.User{IsArchived: true})
			require.NoError(t, err)
			move(t, owner, api, proj.ID, http.StatusForbidden)
			_, err = db.GetEngine(ctx).ID(f.org.ID).Cols("is_archived").Update(&user_model.User{IsArchived: false})
			require.NoError(t, err)
			assert.EqualValues(t, 0, reload(api.ID).GroupID)
		})

		t.Run("redirects page", func(t *testing.T) {
			resp := owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/redirects"), http.StatusOK)
			body := resp.Body.String()
			for _, old := range []string{"org3/api", "org3/proj/api", "org3/vault/api", "org3/secret"} {
				assert.Contains(t, body, ">"+old+"<", old)
			}
			member.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/redirects"), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/redirects"), http.StatusSeeOther)

			// the name of a redirect is taken until an owner removes it
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/groups/new", map[string]string{"name": "api"}), http.StatusOK)
			redirect := unittest.AssertExistsAndLoadBean(t, &repo_model.Redirect{OwnerID: f.org.ID, LowerName: "api"}, "group_id = 0")
			member.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/redirects/delete", map[string]string{"id": strconv.FormatInt(redirect.ID, 10)}), http.StatusNotFound)
			// a redirect of another owner (fixture 2, org17) is not found
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/redirects/delete", map[string]string{"id": "2"}), http.StatusNotFound)
			unittest.AssertExistsAndLoadBean(t, &repo_model.Redirect{ID: 2})
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/redirects/delete", map[string]string{"id": strconv.FormatInt(redirect.ID, 10)}), http.StatusSeeOther)
			unittest.AssertNotExistsBean(t, &repo_model.Redirect{ID: redirect.ID})
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/groups/new", map[string]string{"name": "api"}), http.StatusSeeOther)
			MakeRequest(t, NewRequest(t, "GET", "/org3/api/issues"), http.StatusNotFound) // the project has no such page, and the redirect is gone
		})

		t.Run("git with a token on the old path", func(t *testing.T) {
			token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeReadRepository)
			req := NewRequest(t, "GET", "/org3/vault/hid.git/info/refs?service=git-upload-pack")
			req.SetBasicAuth("user2", token)
			resp := MakeRequest(t, req, http.StatusMovedPermanently)
			// git doesn't follow it after a 401 retry, as for a renamed private root repository upstream
			assert.Equal(t, "/org3/hid/info/refs?service=git-upload-pack", resp.Header().Get("Location"))

			// with the credentials sent up front (http.extraHeader, as actions/checkout does), push to the old URL
			// follows the redirect
			pushToken := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository)
			c := *u
			c.Path = "/org3/hid.git"
			c.User = url.UserPassword("user2", pushToken)
			dir := t.TempDir()
			doGitClone(dir, &c)(t)
			doGitAddSomeCommits(dir, "main")(t)
			old := *u
			old.Path = "/org3/vault/hid.git"
			header := "http.extraHeader=Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("user2:"+pushToken))
			out, err := exec.Command("git", "-C", dir, "-c", header, "push", old.String(), "main").CombinedOutput()
			require.NoError(t, err, "%s", out)
			head, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
			require.NoError(t, err)
			assert.Equal(t, strings.TrimSpace(string(head)), branchCommit(t, f.hid.ID))
		})
	})
}
