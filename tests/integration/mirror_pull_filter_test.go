// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/migration"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/services/convert"
	mirror_service "forgejo.org/services/mirror"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return strings.TrimSpace(string(out))
}

// filterUpstream is a bare local repository with branches main, release/1, release/2, feature/x, dev, the tags v1,
// v2, rc-1 and a refs/pull/1/head, plus a work clone to add more.
type filterUpstream struct {
	bare, work string
	secret     string // a commit that only feature/x and refs/pull/1/head have
}

func newFilterUpstream(t *testing.T) *filterUpstream {
	root := t.TempDir()
	u := &filterUpstream{bare: filepath.Join(root, "upstream.git"), work: filepath.Join(root, "work")}
	gitIn(t, root, "init", "-q", "--bare", "-b", "main", u.bare)
	gitIn(t, root, "clone", "-q", u.bare, u.work)
	gitIn(t, u.work, "checkout", "-q", "-b", "main")
	u.commit(t, "main", "base")
	for _, b := range []string{"release/1", "release/2", "dev"} {
		gitIn(t, u.work, "checkout", "-q", "-b", b, "main")
		u.commit(t, b, b)
	}
	gitIn(t, u.work, "checkout", "-q", "-b", "feature/x", "main")
	u.secret = u.commit(t, "feature/x", "secret")
	gitIn(t, u.work, "checkout", "-q", "main")
	for _, tag := range []string{"v1", "v2", "rc-1"} {
		gitIn(t, u.work, "tag", tag, "main")
	}
	gitIn(t, u.work, "push", "-q", "origin", "--all")
	gitIn(t, u.work, "push", "-q", "origin", "--tags")
	gitIn(t, u.bare, "update-ref", "refs/pull/1/head", u.secret)
	return u
}

func (u *filterUpstream) commit(t *testing.T, branch, msg string) string {
	gitIn(t, u.work, "commit", "-q", "--allow-empty", "-m", msg)
	gitIn(t, u.work, "push", "-q", "origin", branch)
	return gitIn(t, u.work, "rev-parse", "HEAD")
}

func (u *filterUpstream) branch(t *testing.T, name string) {
	gitIn(t, u.work, "checkout", "-q", "-b", name, "main")
	u.commit(t, name, name)
	gitIn(t, u.work, "checkout", "-q", "main")
}

func (u *filterUpstream) tag(t *testing.T, name string) {
	gitIn(t, u.work, "tag", name, "main")
	gitIn(t, u.work, "push", "-q", "origin", name)
}

// refs lists the mirror's refs, branches and tags as short names, everything else as full names.
func filterMirrorRefs(t *testing.T, repo *repo_model.Repository) []string {
	var refs []string
	for r := range strings.FieldsSeq(gitIn(t, repo.RepoPath(), "for-each-ref", "--format=%(refname)")) {
		r = strings.TrimPrefix(r, "refs/heads/")
		refs = append(refs, strings.TrimPrefix(r, "refs/tags/"))
	}
	slices.Sort(refs)
	return refs
}

// allowLocalImport lets user2 mirror (and keep syncing) the local upstream repositories.
func allowLocalImport(t *testing.T) func() {
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	restoreSetting := test.MockVariableValue(&setting.ImportLocalPaths, true)
	_, err := db.GetEngine(t.Context()).ID(user.ID).SetExpr("allow_import_local", true).Update(user)
	require.NoError(t, err)
	return func() {
		_, err := db.GetEngine(t.Context()).ID(user.ID).SetExpr("allow_import_local", false).Update(user)
		require.NoError(t, err)
		restoreSetting()
	}
}

func newFilterMirror(t *testing.T, name string, u *filterUpstream, branchFilter, tagFilter string) *repo_model.Repository {
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repo, err := repo_service.CreateRepositoryDirectly(t.Context(), user, user, repo_service.CreateRepoOptions{
		Name: name, IsMirror: true, Status: repo_model.RepositoryBeingMigrated,
	})
	require.NoError(t, err)
	repo.DefaultBranch = "" // as the migration uploader does: take it from the clone's HEAD
	repo, err = repo_service.MigrateRepositoryGitData(t.Context(), user, repo, migration.MigrateOptions{
		RepoName: name, Mirror: true, CloneAddr: u.bare, MirrorBranchFilter: branchFilter, MirrorTagFilter: tagFilter,
	}, nil)
	require.NoError(t, err)
	return repo
}

func syncFilterMirror(t *testing.T, repo *repo_model.Repository) *repo_model.Mirror {
	require.True(t, mirror_service.SyncPullMirror(t.Context(), repo.ID))
	m, err := repo_model.GetMirrorByRepoID(t.Context(), repo.ID)
	require.NoError(t, err)
	return m
}

func setFilter(t *testing.T, repo *repo_model.Repository, prune bool, branch, tag string) {
	m, err := repo_model.GetMirrorByRepoID(t.Context(), repo.ID)
	require.NoError(t, err)
	m.EnablePrune, m.BranchFilter, m.TagFilter = prune, branch, tag
	require.NoError(t, repo_model.UpdateMirrorCols(t.Context(), m, "enable_prune", "branch_filter", "tag_filter"))
}

func TestMirrorPullFilter(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Migrations.AllowUnencrypted, true)()
	defer allowLocalImport(t)()

	t.Run("initial clone keeps only matching refs", func(t *testing.T) {
		u := newFilterUpstream(t)
		repo := newFilterMirror(t, "filter-initial", u, "main, release/*", "v*")
		assert.Equal(t, []string{"main", "release/1", "release/2", "v1", "v2"}, filterMirrorRefs(t, repo))

		m, err := repo_model.GetMirrorByRepoID(t.Context(), repo.ID)
		require.NoError(t, err)
		assert.Equal(t, "main,release/*", m.BranchFilter) // stored normalized

		// the excluded commit (reachable only from feature/x and refs/pull/1/head) is gone
		cmd := exec.Command("git", "cat-file", "-e", u.secret)
		cmd.Dir = repo.RepoPath()
		require.Error(t, cmd.Run())
	})

	t.Run("sync fetches only matching refs", func(t *testing.T) {
		u := newFilterUpstream(t)
		repo := newFilterMirror(t, "filter-sync", u, "main,release/*", "v*")
		u.branch(t, "release/3")
		u.branch(t, "hotfix")
		u.tag(t, "v3")
		u.tag(t, "rc-2")
		syncFilterMirror(t, repo)
		assert.Equal(t, []string{"main", "release/1", "release/2", "release/3", "v1", "v2", "v3"}, filterMirrorRefs(t, repo))
	})

	t.Run("branch filter alone keeps all tags, tag filter alone all branches", func(t *testing.T) {
		u := newFilterUpstream(t)
		repo := newFilterMirror(t, "filter-branch-only", u, "main", "")
		assert.Equal(t, []string{"main", "rc-1", "v1", "v2"}, filterMirrorRefs(t, repo))
		u.tag(t, "v3")
		u.branch(t, "other")
		syncFilterMirror(t, repo)
		assert.Equal(t, []string{"main", "rc-1", "v1", "v2", "v3"}, filterMirrorRefs(t, repo))

		repo = newFilterMirror(t, "filter-tag-only", u, "", "v1")
		assert.Equal(t, []string{"dev", "feature/x", "main", "other", "release/1", "release/2", "v1"}, filterMirrorRefs(t, repo))
	})

	t.Run("empty filters sync everything as before", func(t *testing.T) {
		u := newFilterUpstream(t)
		repo := newFilterMirror(t, "filter-none", u, "", "")
		u.branch(t, "new")
		u.tag(t, "v9")
		syncFilterMirror(t, repo)
		refs := filterMirrorRefs(t, repo)
		for _, want := range []string{"main", "new", "feature/x", "v9", "rc-1"} {
			assert.Contains(t, refs, want)
		}
	})

	t.Run("narrowing deletes only with prune, widening fetches again", func(t *testing.T) {
		u := newFilterUpstream(t)
		repo := newFilterMirror(t, "filter-narrow", u, "", "")

		setFilter(t, repo, false, "main", "v1")
		syncFilterMirror(t, repo)
		assert.Contains(t, filterMirrorRefs(t, repo), "release/1", "prune off keeps what no longer matches")
		assert.Contains(t, filterMirrorRefs(t, repo), "refs/pull/1/head")

		setFilter(t, repo, true, "main", "v1")
		syncFilterMirror(t, repo)
		assert.Equal(t, []string{"main", "v1"}, filterMirrorRefs(t, repo))
		cmd := exec.Command("git", "cat-file", "-e", u.secret)
		cmd.Dir = repo.RepoPath()
		require.Error(t, cmd.Run(), "excluded commits can't be read by SHA after narrowing")

		setFilter(t, repo, true, "main,release/*", "v*")
		syncFilterMirror(t, repo)
		assert.Equal(t, []string{"main", "release/1", "release/2", "v1", "v2"}, filterMirrorRefs(t, repo))
	})

	t.Run("default branch is never deleted", func(t *testing.T) {
		u := newFilterUpstream(t)
		repo := newFilterMirror(t, "filter-default", u, "", "")
		setFilter(t, repo, true, "release/*", "")
		syncFilterMirror(t, repo)
		assert.Contains(t, filterMirrorRefs(t, repo), repo.DefaultBranch)
		assert.NotContains(t, filterMirrorRefs(t, repo), "dev")
	})

	t.Run("an exact ref missing upstream doesn't break the sync", func(t *testing.T) {
		u := newFilterUpstream(t)
		repo := newFilterMirror(t, "filter-missing", u, "main,gone", "v1,gone-tag")
		u.commit(t, "main", "more")
		syncFilterMirror(t, repo)
		assert.Equal(t, []string{"main", "v1"}, filterMirrorRefs(t, repo))
		assert.Equal(t, gitIn(t, u.bare, "rev-parse", "main"), gitIn(t, repo.RepoPath(), "rev-parse", "main"))
	})

	t.Run("an exact ref deleted upstream is pruned locally only with prune on", func(t *testing.T) {
		u := newFilterUpstream(t)
		repo := newFilterMirror(t, "filter-absent", u, "main,release/1,release/2", "v1")
		gitIn(t, u.bare, "update-ref", "-d", "refs/heads/release/1")
		gitIn(t, u.bare, "update-ref", "-d", "refs/heads/release/2")
		gitIn(t, u.bare, "update-ref", "-d", "refs/tags/v1")

		setFilter(t, repo, false, "main,release/1,release/2", "v1")
		syncFilterMirror(t, repo)
		assert.Equal(t, []string{"main", "release/1", "release/2", "v1"}, filterMirrorRefs(t, repo), "prune off keeps them")

		setFilter(t, repo, true, "main,release/1,release/2", "v1")
		syncFilterMirror(t, repo)
		assert.Equal(t, []string{"main"}, filterMirrorRefs(t, repo))
	})

	t.Run("upstream HEAD outside the filter is reported, the default stays", func(t *testing.T) {
		u := newFilterUpstream(t)
		repo := newFilterMirror(t, "filter-head", u, "main,release/*", "")
		gitIn(t, u.bare, "symbolic-ref", "HEAD", "refs/heads/dev")
		m := syncFilterMirror(t, repo)
		assert.Equal(t, "dev", m.FilterError)
		assert.Equal(t, "main", gitIn(t, repo.RepoPath(), "symbolic-ref", "--short", "HEAD"))

		setFilter(t, repo, true, "main,dev", "")
		m = syncFilterMirror(t, repo)
		assert.Empty(t, m.FilterError)

		// removing the filters clears a stale error too
		setFilter(t, repo, true, "main,release/*", "")
		assert.Equal(t, "dev", syncFilterMirror(t, repo).FilterError)
		setFilter(t, repo, true, "", "")
		assert.Empty(t, syncFilterMirror(t, repo).FilterError)
	})

	t.Run("a trashed repository isn't synced or touched", func(t *testing.T) {
		u := newFilterUpstream(t)
		repo := newFilterMirror(t, "filter-trashed", u, "", "")
		setFilter(t, repo, true, "main", "")
		repo.TrashedUnix = 1
		require.NoError(t, repo_model.UpdateRepositoryCols(t.Context(), repo, "trashed_unix"))
		assert.False(t, mirror_service.SyncPullMirror(t.Context(), repo.ID))
		assert.Contains(t, filterMirrorRefs(t, repo), "release/1", "nothing was deleted")
	})

	t.Run("clone takes the first matching branch when HEAD is excluded", func(t *testing.T) {
		u := newFilterUpstream(t)
		repo := newFilterMirror(t, "filter-nohead", u, "release/*", "")
		assert.Equal(t, []string{"rc-1", "release/1", "release/2", "v1", "v2"}, filterMirrorRefs(t, repo))
		assert.Equal(t, "release/1", gitIn(t, repo.RepoPath(), "symbolic-ref", "--short", "HEAD"))
	})

	t.Run("no matching branch fails the migration", func(t *testing.T) {
		u := newFilterUpstream(t)
		user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		repo, err := repo_service.CreateRepositoryDirectly(t.Context(), user, user, repo_service.CreateRepoOptions{
			Name: "filter-nomatch", IsMirror: true, Status: repo_model.RepositoryBeingMigrated,
		})
		require.NoError(t, err)
		_, err = repo_service.MigrateRepositoryGitData(t.Context(), user, repo, migration.MigrateOptions{
			RepoName: "filter-nomatch", Mirror: true, CloneAddr: u.bare, MirrorBranchFilter: "nothing",
		}, nil)
		require.ErrorContains(t, err, "no branch")
	})

	t.Run("invalid filters and non-mirror migrations are refused", func(t *testing.T) {
		user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		repo, err := repo_service.CreateRepositoryDirectly(t.Context(), user, user, repo_service.CreateRepoOptions{
			Name: "filter-bad", IsMirror: true, Status: repo_model.RepositoryBeingMigrated,
		})
		require.NoError(t, err)
		_, err = repo_service.MigrateRepositoryGitData(t.Context(), user, repo, migration.MigrateOptions{
			RepoName: "filter-bad", Mirror: true, CloneAddr: "/nonexistent", MirrorBranchFilter: "a,,b",
		}, nil)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "Clone")
		_, err = repo_service.MigrateRepositoryGitData(t.Context(), user, repo, migration.MigrateOptions{
			RepoName: "filter-bad", CloneAddr: "/nonexistent", MirrorTagFilter: "v*",
		}, nil)
		require.ErrorContains(t, err, "only for pull mirrors")
	})
}

func TestMirrorPullFilterEntryPoints(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Migrations.AllowUnencrypted, true)()
	defer allowLocalImport(t)()

	u := newFilterUpstream(t)
	repo := newFilterMirror(t, "filter-entry", u, "main,release/*", "v*")
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth.AccessTokenScopeWriteRepository)
	settingsURL := fmt.Sprintf("/user2/%s/settings", repo.Name)
	apiURL := fmt.Sprintf("/api/v1/repos/user2/%s", repo.Name)
	form := func(branch, tag string) map[string]string {
		return map[string]string{
			"action": "mirror", "enable_prune": "on", "interval": "8h0m0s",
			"mirror_address": u.bare, "mirror_branch_filter": branch, "mirror_tag_filter": tag,
		}
	}
	stored := func() *repo_model.Mirror {
		m, err := repo_model.GetMirrorByRepoID(t.Context(), repo.ID)
		require.NoError(t, err)
		return m
	}

	t.Run("web: bad pattern and default branch outside the filter are refused", func(t *testing.T) {
		resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", settingsURL, form("main,--upload-pack=x", "")), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "--upload-pack=x")
		resp = session.MakeRequest(t, NewRequestWithValues(t, "POST", settingsURL, form("release/*", "")), http.StatusOK)
		assert.Contains(t, resp.Body.String(), repo.DefaultBranch)
		assert.Equal(t, "main,release/*", stored().BranchFilter)
	})

	t.Run("web: a valid change is stored", func(t *testing.T) {
		session.MakeRequest(t, NewRequestWithValues(t, "POST", settingsURL, form(" main , dev ", "")), http.StatusSeeOther)
		m := stored()
		assert.Equal(t, "main,dev", m.BranchFilter)
		assert.Empty(t, m.TagFilter)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", settingsURL, form("main,release/*", "v*")), http.StatusSeeOther)
	})

	t.Run("web: a non-admin can't change it", func(t *testing.T) {
		session4 := loginUser(t, "user4")
		session4.MakeRequest(t, NewRequestWithValues(t, "POST", settingsURL, form("main", "")), http.StatusNotFound)
		assert.Equal(t, "main,release/*", stored().BranchFilter)
	})

	t.Run("API: PATCH validates and stores", func(t *testing.T) {
		patch := func(body map[string]any, status int, tok string) {
			session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", apiURL, body).AddTokenAuth(tok), status)
		}
		patch(map[string]any{"mirror_branch_filter": "a:b"}, http.StatusUnprocessableEntity, token)
		patch(map[string]any{"mirror_tag_filter": "a,,b"}, http.StatusUnprocessableEntity, token)
		patch(map[string]any{"mirror_branch_filter": "release/*"}, http.StatusUnprocessableEntity, token) // default branch main
		assert.Equal(t, "main,release/*", stored().BranchFilter)

		patch(map[string]any{"mirror_branch_filter": "main,hotfix/*", "mirror_tag_filter": ""}, http.StatusOK, token)
		m := stored()
		assert.Equal(t, "main,hotfix/*", m.BranchFilter)
		assert.Empty(t, m.TagFilter)
		assert.True(t, m.EnablePrune, "other mirror columns keep their value")

		token4 := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth.AccessTokenScopeWriteRepository)
		patch(map[string]any{"mirror_branch_filter": "main"}, http.StatusForbidden, token4)
		assert.Equal(t, "main,hotfix/*", stored().BranchFilter)
	})

	t.Run("API: an archived repository's filters can't be changed, and no sync runs", func(t *testing.T) {
		// "more" matches only the refused filter: a sync still queued by the last subtest's change (it runs in a
		// goroutine, late on a slow machine) must not fetch it either
		u.branch(t, "more")
		repo.IsArchived = true
		require.NoError(t, repo_model.UpdateRepositoryCols(t.Context(), repo, "is_archived"))
		patch := map[string]any{"mirror_branch_filter": "main,hotfix/*,more"}
		session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", apiURL, patch).AddTokenAuth(token), http.StatusUnprocessableEntity)
		assert.Equal(t, "main,hotfix/*", stored().BranchFilter)
		assert.NotContains(t, filterMirrorRefs(t, repo), "more")

		// the same change on a live repository does queue a sync, which fetches the new match
		repo.IsArchived = false
		require.NoError(t, repo_model.UpdateRepositoryCols(t.Context(), repo, "is_archived"))
		session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", apiURL, patch).AddTokenAuth(token), http.StatusOK)
		assert.Eventually(t, func() bool { return slices.Contains(filterMirrorRefs(t, repo), "more") }, 10*time.Second, 100*time.Millisecond)
	})

	t.Run("API: only admins see the filters, and webhooks never carry them", func(t *testing.T) {
		resp := session.MakeRequest(t, NewRequest(t, "GET", apiURL).AddTokenAuth(token), http.StatusOK)
		var got api.Repository
		DecodeJSON(t, resp, &got)
		assert.Equal(t, "main,hotfix/*,more", got.MirrorBranchFilter)

		// user4 can read the (public) repository but isn't an admin of it
		token4 := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth.AccessTokenScopeReadRepository)
		resp = MakeRequest(t, NewRequest(t, "GET", apiURL).AddTokenAuth(token4), http.StatusOK)
		assert.NotContains(t, resp.Body.String(), "mirror_branch_filter")
		assert.NotContains(t, resp.Body.String(), "mirror_tag_filter")

		// the notifiers convert with owner permission
		repo, err := repo_model.GetRepositoryByID(t.Context(), repo.ID)
		require.NoError(t, err)
		payload, err := json.Marshal(convert.ToRepo(t.Context(), repo, access_model.Permission{AccessMode: perm.AccessModeOwner}))
		require.NoError(t, err)
		assert.NotContains(t, string(payload), "mirror_branch_filter")
		assert.NotContains(t, string(payload), "mirror_filter_error")
	})

	t.Run("removing the filters clears the filter error (web and API)", func(t *testing.T) {
		for _, clear := range []func(){
			func() {
				session.MakeRequest(t, NewRequestWithValues(t, "POST", settingsURL, form("", "")), http.StatusSeeOther)
			},
			func() {
				session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", apiURL, map[string]any{"mirror_branch_filter": "", "mirror_tag_filter": ""}).AddTokenAuth(token), http.StatusOK)
			},
		} {
			m := stored()
			m.BranchFilter, m.FilterError = "main", "dev"
			require.NoError(t, repo_model.UpdateMirrorCols(t.Context(), m, "branch_filter", "filter_error"))
			clear()
			assert.Empty(t, stored().BranchFilter)
			assert.Empty(t, stored().FilterError)
		}
	})

	t.Run("a finishing sync doesn't revert a filter saved meanwhile", func(t *testing.T) {
		old := stored()
		m := stored()
		m.BranchFilter = "main,fresh"
		require.NoError(t, repo_model.UpdateMirrorCols(t.Context(), m, "branch_filter"))
		old.ScheduleNextUpdate()
		require.NoError(t, repo_model.UpdateMirrorCols(t.Context(), old, "updated_unix", "next_update_unix"))
		assert.Equal(t, "main,fresh", stored().BranchFilter)
	})
}

func TestMirrorPullFilterMigrateAPI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth.AccessTokenScopeWriteRepository)
	migrate := func(body map[string]any, status int) {
		body["clone_addr"] = "https://example.com/repo.git"
		body["repo_name"] = "migrate-filter"
		session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", body).AddTokenAuth(token), status)
	}
	migrate(map[string]any{"mirror": true, "mirror_branch_filter": "a:b"}, http.StatusUnprocessableEntity)
	migrate(map[string]any{"mirror": true, "mirror_tag_filter": "a,,b"}, http.StatusUnprocessableEntity)
	migrate(map[string]any{"mirror": false, "mirror_tag_filter": "v*"}, http.StatusUnprocessableEntity)
	migrate(map[string]any{"mirror": true, "service": "github", "mirror_tag_filter": "v*"}, http.StatusUnprocessableEntity)
}

func TestMirrorPullFilterMigrateWeb(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	migrate := func(values map[string]string) string {
		if values["service"] == "" {
			values["service"] = "1"
		}
		values["uid"], values["repo_name"], values["clone_addr"] = "2", "migrate-filter-web", "https://example.com/repo.git"
		return session.MakeRequest(t, NewRequestWithValues(t, "POST", "/repo/migrate", values), http.StatusOK).Body.String()
	}
	assert.Contains(t, migrate(map[string]string{"mirror": "on", "mirror_branch_filter": "a:b"}), "a:b")
	assert.Contains(t, migrate(map[string]string{"mirror": "on", "mirror_tag_filter": "a,,b"}), "empty pattern")
	assert.Contains(t, migrate(map[string]string{"mirror_tag_filter": "v*"}), "only for pull mirrors")
	assert.Contains(t, migrate(map[string]string{"mirror": "on", "service": "2", "mirror_tag_filter": "v*"}), "only for pull mirrors")
}
