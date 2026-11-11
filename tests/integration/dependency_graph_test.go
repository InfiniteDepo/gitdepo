// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	perm_model "forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	dependency_service "forgejo.org/services/dependency"
	migrations_allowlist "forgejo.org/services/migrations/allowlist"
	mirror_service "forgejo.org/services/mirror"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests/forgery"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	depGoMod  = "module example.com/m\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/net v0.10.0 // indirect\n)\n"
	depLockV3 = `{"lockfileVersion":3,"packages":{"":{"dependencies":{"left-pad":"^1.3.0"}},"node_modules/left-pad":{"version":"1.3.0","license":"WTFPL"}}}`
)

func enableDependencyGraph(t *testing.T) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.DependencyGraph.Enabled, true))
}

// depPush commits the files (and removes the paths in remove) on top of the repository's default branch and pushes
// the commit to ref over HTTP, with a token. It returns the SHA of the commit.
func depPush(t *testing.T, u *url.URL, token string, repo *repo_model.Repository, ref string, files map[string]string, remove ...string) string {
	t.Helper()
	dst := t.TempDir()
	gitURL := ownedTokenGitURL(u, token, repo)
	require.NoError(t, git.Clone(t.Context(), gitURL.String(), dst, git.CloneRepoOptions{}))
	doGitSetRemoteURL(dst, "origin", gitURL)(t)
	run := func(args ...string) string {
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = dst
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return strings.TrimSpace(string(out))
	}
	for _, p := range remove {
		require.NoError(t, os.RemoveAll(filepath.Join(dst, p)))
	}
	for p, c := range files {
		require.NoError(t, os.MkdirAll(filepath.Join(dst, filepath.Dir(p)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dst, p), []byte(c), 0o644))
	}
	run("add", "-A")
	run("commit", "-m", "manifests", "--allow-empty")
	sha := run("rev-parse", "HEAD")
	push := git.NewCommand(git.DefaultContext, "push", "origin")
	if strings.HasPrefix(ref, "refs/for/") {
		push = push.AddArguments("-o", "topic=dep-topic")
	}
	stdout, stderr, err := push.AddDynamicArguments("HEAD:" + ref).RunStdString(&git.RunOpts{Dir: dst})
	require.NoError(t, err, stdout+stderr)
	return sha
}

func depScanOf(t *testing.T, repoID int64) *repo_model.DependencyScan {
	t.Helper()
	scan, err := repo_model.GetRepoDependencyScan(t.Context(), repoID)
	require.NoError(t, err)
	return scan
}

func depRows(t *testing.T, repoID int64) map[string]*repo_model.Dependency {
	t.Helper()
	var rows []*repo_model.Dependency
	require.NoError(t, db.GetEngine(t.Context()).Where("repo_id = ?", repoID).Find(&rows))
	m := map[string]*repo_model.Dependency{}
	for _, r := range rows {
		m[r.Ecosystem+"|"+r.Name+"@"+r.Version+"|"+r.ManifestPath] = r
	}
	return m
}

func depNewRepo(t *testing.T, owner, doer *user_model.User, name string, private bool, groupID int64) *repo_model.Repository {
	t.Helper()
	repo, err := repo_service.CreateRepository(audit_model.WithSystem(db.DefaultContext, "test"), doer, owner, repo_service.CreateRepoOptions{
		Name: name, IsPrivate: private, Readme: "Default", AutoInit: true, DefaultBranch: "main", GroupID: groupID,
	})
	require.NoError(t, err)
	return repo
}

// storeScan stores a finished scan with the given dependencies, as a push would have.
func storeScan(t *testing.T, repo *repo_model.Repository, deps ...*repo_model.Dependency) {
	t.Helper()
	storeScanAt(t, repo, strings.Repeat("a", 40), deps...)
}

// headOf is the commit the default branch of the repository points to.
func headOf(t *testing.T, repo *repo_model.Repository) string {
	t.Helper()
	gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
	require.NoError(t, err)
	defer gitRepo.Close()
	sha, err := gitRepo.GetBranchCommitID(repo.DefaultBranch)
	require.NoError(t, err)
	return sha
}

// storeScanAt is storeScan for the given commit; a page whose scan names another commit than the branch head
// queues a new scan (which runs at once with immediate queues), so tests of the page store the head.
func storeScanAt(t *testing.T, repo *repo_model.Repository, sha string, deps ...*repo_model.Dependency) {
	t.Helper()
	for _, d := range deps {
		d.RepoID = repo.ID
		if d.ManifestPath == "" {
			d.ManifestPath = "go.mod"
		}
	}
	scan := &repo_model.DependencyScan{
		RepoID: repo.ID, CommitSHA: sha, Status: repo_model.DependencyScanOK, ManifestCount: 1, DependencyCount: len(deps),
		ScannedUnix: 1700000000,
	}
	require.NoError(t, repo_model.ReplaceRepoDependencies(t.Context(), scan, append([]*repo_model.Dependency{}, deps...)))
}

func TestDependencyGraphScanOnPush(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		enableDependencyGraph(t)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		repo := depNewRepo(t, user2, user2, "dep-push", true, 0)
		scanned := func(sha string) bool {
			scan := depScanOf(t, repo.ID)
			return scan != nil && scan.CommitSHA == sha && scan.Error == ""
		}

		t.Run("push to the default branch", func(t *testing.T) {
			sha := depPush(t, u, token, repo, "refs/heads/main", map[string]string{
				"go.mod":                             depGoMod,
				"web/package-lock.json":              depLockV3,
				"web/package.json":                   `{"dependencies":{"left-pad":"^1.3.0"}}`,
				"requirements/base.txt":              "flask==3.0.0\n",
				"dev-requirements.txt":               "pytest==8.0.0\n",
				"requirements.txt":                   "django==4.2\n-r ../../../../etc/passwd\n--index-url http://169.254.169.254\n",
				"vendor/go.mod":                      depGoMod,
				"a/node_modules/x/package-lock.json": depLockV3,
				"vendored/go.mod":                    "module v\n\nrequire example.com/vend v1.0.0\n",
				"bad/pom.xml":                        `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><project><artifactId>&e;</artifactId></project>`,
			})
			require.Eventually(t, func() bool { return scanned(sha) }, 10*time.Second, 50*time.Millisecond)

			rows := depRows(t, repo.ID)
			require.Len(t, rows, 7, "%v", rows)
			gin := rows["Go|github.com/gin-gonic/gin@v1.9.1|go.mod"]
			require.NotNil(t, gin)
			assert.True(t, gin.Direct)
			assert.False(t, rows["Go|golang.org/x/net@v0.10.0|go.mod"].Direct)
			left := rows["npm|left-pad@1.3.0|web/package-lock.json"]
			require.NotNil(t, left)
			assert.True(t, left.Direct)
			assert.Equal(t, "WTFPL", left.License)
			assert.Contains(t, rows, "PyPI|django@4.2|requirements.txt")
			assert.Contains(t, rows, "PyPI|flask@3.0.0|requirements/base.txt")
			assert.Contains(t, rows, "PyPI|pytest@8.0.0|dev-requirements.txt")
			assert.Contains(t, rows, "Go|example.com/vend@v1.0.0|vendored/go.mod")
			assert.Equal(t, []repo_model.SkippedManifest{{Path: "bad/pom.xml", Code: "parse_error"}}, depScanOf(t, repo.ID).SkippedManifests())
		})

		// a scan that ran would replace the sentinel with the head of the default branch
		sentinel := func() {
			_, err := db.GetEngine(t.Context()).Exec("UPDATE repo_dependency_scan SET commit_sha = 'sentinel' WHERE repo_id = ?", repo.ID)
			require.NoError(t, err)
		}
		untouched := func(t *testing.T) {
			t.Helper()
			time.Sleep(300 * time.Millisecond) // queues are immediate; this is only for a late goroutine
			assert.Equal(t, "sentinel", depScanOf(t, repo.ID).CommitSHA)
			assert.Len(t, depRows(t, repo.ID), 7)
		}

		t.Run("other branches, tags and refs/for don't scan", func(t *testing.T) {
			sentinel()
			depPush(t, u, token, repo, "refs/heads/feature", map[string]string{"go.mod": "module other\n\nrequire example.com/other v1.0.0\n"})
			untouched(t)
			depPush(t, u, token, repo, "refs/tags/v1", map[string]string{"x.txt": "x"})
			untouched(t)
			depPush(t, u, token, repo, "refs/for/main", map[string]string{"go.mod": "module agit\n\nrequire example.com/agit v1.0.0\n"})
			untouched(t)
		})

		t.Run("a push that removes manifests drops their rows", func(t *testing.T) {
			sha := depPush(t, u, token, repo, "refs/heads/main", nil, "go.mod", "web", "vendored", "bad", "requirements.txt", "requirements", "dev-requirements.txt")
			require.Eventually(t, func() bool { return scanned(sha) }, 10*time.Second, 50*time.Millisecond)
			assert.Empty(t, depRows(t, repo.ID))
			assert.Zero(t, depScanOf(t, repo.ID).ManifestCount)
		})

		t.Run("a new default branch scans it", func(t *testing.T) {
			// "feature" branched from main before the manifests were removed, and has go.mod with example.com/other
			session := loginUser(t, "user2")
			sentinel()
			session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/dep-push/settings/branches?action=default_branch", map[string]string{"branch": "feature"}), http.StatusSeeOther)
			require.Eventually(t, func() bool { return depScanOf(t, repo.ID).CommitSHA != "sentinel" }, 10*time.Second, 50*time.Millisecond)
			rows := depRows(t, repo.ID)
			assert.Len(t, rows, 6, "%v", rows)
			assert.Contains(t, rows, "Go|example.com/other@v1.0.0|go.mod")
			assert.NotContains(t, rows, "Go|github.com/gin-gonic/gin@v1.9.1|go.mod")
		})
	})
}

func TestDependencyGraphAPIDefaultBranch(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		enableDependencyGraph(t)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		repo := depNewRepo(t, user2, user2, "dep-api-branch", true, 0)
		depPush(t, u, token, repo, "refs/heads/feature", map[string]string{"go.mod": "module other\n\nrequire example.com/other v1.0.0\n"})
		_, err := db.GetEngine(t.Context()).Exec("DELETE FROM repo_dependency_scan WHERE repo_id = ?", repo.ID)
		require.NoError(t, err)

		// a schedule of the old default branch, as the web settings route would drop it
		require.NoError(t, db.Insert(t.Context(), &actions_model.ActionSchedule{RepoID: repo.ID, OwnerID: user2.ID, WorkflowID: "cron.yml", Ref: "refs/heads/main", Title: "cron"}))
		unittest.AssertExistsAndLoadBean(t, &actions_model.ActionSchedule{RepoID: repo.ID})

		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/dep-api-branch", &api.EditRepoOption{DefaultBranch: new("feature")}).AddTokenAuth(token), http.StatusOK)
		unittest.AssertNotExistsBean(t, &actions_model.ActionSchedule{RepoID: repo.ID})
		assert.Equal(t, "feature", unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID}).DefaultBranch)
		require.Eventually(t, func() bool { s := depScanOf(t, repo.ID); return s != nil && s.Error == "" }, 10*time.Second, 50*time.Millisecond)
		assert.Contains(t, depRows(t, repo.ID), "Go|example.com/other@v1.0.0|go.mod")
	})
}

func TestDependencyGraphMirrorSync(t *testing.T) {
	defer test.MockVariableValue(&setting.Migrations.AllowUnencrypted, true)()
	prev := setting.Migrations.AllowedDomains
	setting.Migrations.AllowedDomains = "localhost"
	migrations_allowlist.Init()
	defer func() {
		setting.Migrations.AllowedDomains = prev
		migrations_allowlist.Init()
	}()
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		enableDependencyGraph(t)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		var sha string
		source := forgery.CreateRepository(t, user2, &forgery.CreateRepositoryOptions{
			Files: forgery.MapFS{
				"docs.md": forgery.MapFile("hello"),
				"go.mod":  forgery.MapFile(depGoMod),
			},
			LatestSha: &sha,
		})
		name := createPullMirrorViaWeb(t, source, false)
		mirror, err := repo_model.GetRepositoryByOwnerAndName(t.Context(), "user2", name)
		require.NoError(t, err)
		// a migration finishes without a push: the cron task (or the first read) scans it
		require.NoError(t, dependency_service.EnqueueUnscanned(t.Context()))
		require.Eventually(t, func() bool { s := depScanOf(t, mirror.ID); return s != nil && s.CommitSHA == sha }, 10*time.Second, 50*time.Millisecond)
		assert.Len(t, depRows(t, mirror.ID), 2)

		// the upstream changes; the sync rescans
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		newSha := depPush(t, u, token, source, "refs/heads/"+source.DefaultBranch, map[string]string{"go.mod": "module m\n\nrequire example.com/synced v1.2.3\n"})
		require.True(t, mirror_service.SyncPullMirror(t.Context(), mirror.ID))
		require.Eventually(t, func() bool { return depScanOf(t, mirror.ID).CommitSHA == newSha }, 10*time.Second, 50*time.Millisecond)
		rows := depRows(t, mirror.ID)
		assert.Len(t, rows, 1, "%v", rows)
		assert.Contains(t, rows, "Go|example.com/synced@v1.2.3|go.mod")
	})
}

func TestDependencyGraphDisabled(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		require.False(t, setting.DependencyGraph.Enabled, "the feature is off by default")
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		repo := depNewRepo(t, user2, user2, "dep-off", false, 0)
		depPush(t, u, token, repo, "refs/heads/main", map[string]string{"go.mod": depGoMod})
		time.Sleep(300 * time.Millisecond)
		assert.Nil(t, depScanOf(t, repo.ID), "a push enqueues nothing")
		assert.Empty(t, depRows(t, repo.ID))

		session := loginUser(t, "user2")
		for _, base := range []string{"/api/v1/repos/user2/dep-off", fmt.Sprintf("/api/v1/repositories/%d", repo.ID)} {
			MakeRequest(t, NewRequest(t, "GET", base+"/dependencies").AddTokenAuth(token), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "GET", base+"/sbom").AddTokenAuth(token), http.StatusNotFound)
		}
		session.MakeRequest(t, NewRequest(t, "GET", "/user2/dep-off/activity/dependencies/sbom"), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/user2/dep-off/activity/dependencies/sbom"), http.StatusNotFound)
		assert.Nil(t, depScanOf(t, repo.ID), "reading enqueues nothing")

		// the cron task does nothing either
		require.NoError(t, dependency_service.EnqueueUnscanned(t.Context()))
		assert.Nil(t, depScanOf(t, repo.ID))
	})
}

func TestDependencyGraphAccess(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		enableDependencyGraph(t)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		priv := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2}) // user2/repo2, private
		require.True(t, priv.IsPrivate)
		pub := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}) // user2/repo1, public
		d := func(eco, name, version string, direct bool) *repo_model.Dependency {
			return &repo_model.Dependency{Ecosystem: eco, Name: name, Version: version, Direct: direct}
		}
		storeScan(t, priv, d("Go", "github.com/gin-gonic/gin", "v1.9.1", true), d("npm", "100%_sure", "1", false), d("npm", "left-pad", "1.3.0", true))
		storeScan(t, pub, d("Go", "example.com/pub", "v1", true))
		get := func(path, token string, status int) *httptest.ResponseRecorder {
			req := NewRequest(t, "GET", path)
			if token != "" {
				req.AddTokenAuth(token)
			}
			return MakeRequest(t, req, status)
		}
		apiPriv := "/api/v1/repos/user2/repo2"
		ownerToken := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)

		t.Run("owner", func(t *testing.T) {
			var list api.DependencyList
			DecodeJSON(t, get(apiPriv+"/dependencies", ownerToken, http.StatusOK), &list)
			assert.Equal(t, "ok", list.Scan.Status)
			assert.Equal(t, strings.Repeat("a", 40), list.Scan.CommitSHA)
			assert.Len(t, list.Dependencies, 3)
			assert.Equal(t, "pkg:npm/100%25_sure@1", list.Dependencies[0].PURL, "sorted by name, ignoring case")
			assert.Equal(t, "pkg:golang/github.com/gin-gonic/gin@v1.9.1", list.Dependencies[1].PURL)

			DecodeJSON(t, get(apiPriv+"/dependencies?q=%25", ownerToken, http.StatusOK), &list)
			require.Len(t, list.Dependencies, 1)
			assert.Equal(t, "100%_sure", list.Dependencies[0].Name)
			DecodeJSON(t, get(apiPriv+"/dependencies?ecosystem=Go", ownerToken, http.StatusOK), &list)
			assert.Len(t, list.Dependencies, 1)
			DecodeJSON(t, get(apiPriv+"/dependencies?direct=false", ownerToken, http.StatusOK), &list)
			assert.Len(t, list.Dependencies, 1)
			for v, want := range map[string]int{"1": 2, "t": 2, "TRUE": 2, "F": 1, "0": 1} {
				DecodeJSON(t, get(apiPriv+"/dependencies?direct="+v, ownerToken, http.StatusOK), &list)
				assert.Len(t, list.Dependencies, want, v)
			}
			DecodeJSON(t, get(apiPriv+"/dependencies?manifest=go.mod&limit=2&page=2", ownerToken, http.StatusOK), &list)
			assert.Len(t, list.Dependencies, 1)
			get(apiPriv+"/dependencies?ecosystem=Cobol", ownerToken, http.StatusUnprocessableEntity)
			for _, bad := range []string{"2", "maybe", "yes"} {
				get(apiPriv+"/dependencies?direct="+bad, ownerToken, http.StatusUnprocessableEntity)
			}
			get(apiPriv+"/dependencies?q="+strings.Repeat("a", 101), ownerToken, http.StatusUnprocessableEntity)

			resp := get(apiPriv+"/sbom", ownerToken, http.StatusOK)
			assert.Equal(t, "application/json", resp.Header().Get("Content-Type"))
			assert.Equal(t, "nosniff", resp.Header().Get("X-Content-Type-Options"))
			assert.Contains(t, resp.Header().Get("Content-Disposition"), `attachment; filename="user2-repo2.spdx.json"`)
			var doc map[string]any
			DecodeJSON(t, resp, &doc)
			assert.Equal(t, "SPDX-2.3", doc["spdxVersion"])
			resp = get(apiPriv+"/sbom?format=cyclonedx", ownerToken, http.StatusOK)
			assert.Contains(t, resp.Header().Get("Content-Disposition"), `filename="user2-repo2.cdx.json"`)
			DecodeJSON(t, resp, &doc)
			assert.Equal(t, "CycloneDX", doc["bomFormat"])

			get(apiPriv+"/sbom?format=../../x", ownerToken, http.StatusBadRequest)
			get(apiPriv+"/sbom?format=pdf", ownerToken, http.StatusBadRequest)
			get(apiPriv+"/dependencies", "", http.StatusNotFound)
		})

		t.Run("not scanned yet", func(t *testing.T) {
			// queues are immediate, so the first read scans at once; a scan that fails leaves nothing to export
			defer test.MockVariableValue(&setting.DependencyGraph.MaxTreeEntries, 0)()
			user5Token := getUserToken(t, "user5", auth_model.AccessTokenScopeReadRepository)
			var list api.DependencyList
			DecodeJSON(t, get("/api/v1/repos/user5/repo4/dependencies", user5Token, http.StatusOK), &list)
			assert.Equal(t, "pending", list.Scan.Status, "the first read answers before the scan it queued")
			DecodeJSON(t, get("/api/v1/repos/user5/repo4/dependencies", user5Token, http.StatusOK), &list)
			assert.Equal(t, "failed", list.Scan.Status)
			assert.Equal(t, "tree_too_large", list.Scan.Error)
			assert.Empty(t, list.Dependencies)
			assert.NotNil(t, list.Dependencies)
			resp := get("/api/v1/repos/user5/repo4/sbom", user5Token, http.StatusConflict)
			assert.Contains(t, resp.Body.String(), "not been scanned yet")
		})

		t.Run("hidden is missing", func(t *testing.T) {
			other := getUserToken(t, "user4", auth_model.AccessTokenScopeReadRepository)
			for _, tail := range []string{"/dependencies", "/sbom"} {
				anon := get(apiPriv+tail, "", http.StatusNotFound)
				nonMember := get(apiPriv+tail, other, http.StatusNotFound)
				missing := get("/api/v1/repos/user2/no-such-repo"+tail, other, http.StatusNotFound)
				assert.Equal(t, missing.Body.String(), nonMember.Body.String())
				assert.Equal(t, missing.Body.String(), anon.Body.String())
				// by ID: a plain not found
				byID := get(fmt.Sprintf("/api/v1/repositories/%d%s", priv.ID, tail), other, http.StatusNotFound)
				gone := get("/api/v1/repositories/99999999"+tail, other, http.StatusNotFound)
				assert.Equal(t, gone.Body.String(), byID.Body.String())
			}
			// the web download
			loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", "/user2/repo2/activity/dependencies/sbom"), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "GET", "/user2/repo2/activity/dependencies/sbom"), http.StatusNotFound)
		})

		t.Run("tokens", func(t *testing.T) {
			session := loginUser(t, "user2")
			readIssue := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadIssue)
			publicOnly := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeReadRepository)
			get(apiPriv+"/dependencies", readIssue, http.StatusForbidden)
			get(apiPriv+"/sbom", readIssue, http.StatusForbidden)
			get(apiPriv+"/dependencies", publicOnly, http.StatusNotFound)
			get(apiPriv+"/sbom", publicOnly, http.StatusNotFound)
			get("/api/v1/repos/user2/repo1/dependencies", publicOnly, http.StatusOK)

			scope, err := auth_model.AccessTokenScope("read:repository").Normalize()
			require.NoError(t, err)
			specific := &auth_model.AccessToken{Name: "dep-specific", UID: user2.ID, Scope: scope}
			resourceRepos := []*auth_model.AccessTokenResourceRepo{{RepoID: pub.ID}}
			require.NoError(t, auth_model.NewAccessToken(audit_model.WithSystem(t.Context(), "test"), specific, resourceRepos))
			t.Cleanup(func() {
				unittest.AssertSuccessfulDelete(t, &auth_model.AccessTokenResourceRepo{ID: resourceRepos[0].ID})
				unittest.AssertSuccessfulDelete(t, &auth_model.AccessToken{ID: specific.ID})
			})
			get("/api/v1/repos/user2/repo1/dependencies", specific.Token, http.StatusOK)
			get(apiPriv+"/dependencies", specific.Token, http.StatusNotFound)
			get(apiPriv+"/sbom", specific.Token, http.StatusNotFound)
			get(fmt.Sprintf("/api/v1/repositories/%d/dependencies", priv.ID), specific.Token, http.StatusNotFound)
		})

		t.Run("job tokens", func(t *testing.T) {
			original := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
			t.Cleanup(func() {
				require.NoError(t, actions_model.UpdateTask(db.DefaultContext, original, "repo_id", "owner_id", "is_fork_pull_request", "token_permissions", "token_salt", "token_hash", "token_last_eight"))
			})
			taskToken := func(repo *repo_model.Repository, permissions string) string {
				task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
				task.RepoID, task.OwnerID, task.IsForkPullRequest, task.TokenPermissions = repo.ID, repo.OwnerID, false, permissions
				task.GenerateToken()
				require.NoError(t, actions_model.UpdateTask(t.Context(), task, "repo_id", "owner_id", "is_fork_pull_request", "token_permissions", "token", "token_salt", "token_hash", "token_last_eight"))
				return task.Token
			}
			get(apiPriv+"/dependencies", taskToken(priv, ""), http.StatusOK)
			get(apiPriv+"/sbom", taskToken(priv, ""), http.StatusOK)
			code := actions_model.TokenPermissions{unit.TypeCode: perm_model.AccessModeRead}.Encode()
			get(apiPriv+"/dependencies", taskToken(priv, code), http.StatusOK)
			none := actions_model.TokenPermissions{unit.TypeIssues: perm_model.AccessModeWrite}.Encode()
			for _, tail := range []string{"/dependencies", "/sbom"} {
				get(apiPriv+tail, taskToken(priv, none), http.StatusForbidden) // contents: none is refused
			}
			// the token of a run in repo2 on another private repository
			other := depNewRepo(t, user2, user2, "dep-other", true, 0)
			storeScan(t, other, d("Go", "x", "1", true))
			get(fmt.Sprintf("/api/v1/repos/user2/%s/dependencies", other.Name), taskToken(priv, ""), http.StatusNotFound)
		})

		t.Run("trashed and archived", func(t *testing.T) {
			require.NoError(t, repo_service.SetArchiveRepoState(t.Context(), pub, true))
			get("/api/v1/repos/user2/repo1/dependencies", ownerToken, http.StatusOK)
			get("/api/v1/repos/user2/repo1/sbom", ownerToken, http.StatusOK)
			require.NoError(t, repo_service.SetArchiveRepoState(t.Context(), pub, false))

			_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 1700000000 WHERE id = ?", priv.ID)
			require.NoError(t, err)
			defer func() {
				_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 0 WHERE id = ?", priv.ID)
				require.NoError(t, err)
			}()
			get(apiPriv+"/dependencies", ownerToken, http.StatusNotFound)
			get(apiPriv+"/sbom", ownerToken, http.StatusNotFound)
			loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/user2/repo2/activity/dependencies/sbom"), http.StatusNotFound)
		})

		t.Run("web download", func(t *testing.T) {
			session := loginUser(t, "user2")
			since := auditMaxID(t)
			resp := session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo2/activity/dependencies/sbom?format=cyclonedx"), http.StatusOK)
			assert.Equal(t, "application/json", resp.Header().Get("Content-Type"))
			assert.Equal(t, "nosniff", resp.Header().Get("X-Content-Type-Options"))
			assert.Contains(t, resp.Header().Get("Content-Disposition"), `filename="user2-repo2.cdx.json"`)
			var doc map[string]any
			require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &doc))
			assert.Equal(t, "CycloneDX", doc["bomFormat"])
			session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo2/activity/dependencies/sbom"), http.StatusOK)
			session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo2/activity/dependencies/sbom?format=nope"), http.StatusBadRequest)
			session.MakeRequest(t, NewRequest(t, "GET", "/user5/repo4/activity/dependencies/sbom"), http.StatusConflict)
			downloads, err := db.GetEngine(t.Context()).Where("id > ? AND action = ?", since, "activity.download").Count(new(audit_model.Entry))
			require.NoError(t, err)
			assert.Zero(t, downloads, "a session download is not recorded without [audit] LOG_READS")
		})

		t.Run("audit", func(t *testing.T) {
			audit_model.ResetActivity()
			since := auditMaxID(t)
			get(apiPriv+"/sbom", ownerToken, http.StatusOK)
			var entries []*audit_model.Entry
			require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND action = ?", since, "activity.download").Find(&entries))
			require.Len(t, entries, 1)
			data := auditData(t, entries[0])
			assert.Equal(t, "sbom", data["kind"])
			assert.Equal(t, strings.Repeat("a", 40), data["object"])
			assert.Equal(t, priv.ID, entries[0].RepoID)
		})
	})
}

// A reader of the issues only sees the repository but not its code, and the dependencies come from the code.
func TestDependencyGraphIssuesOnlyReader(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		enableDependencyGraph(t)
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		org, err := org_model.GetOrgByID(t.Context(), org3.ID)
		require.NoError(t, err)
		member := forgery.CreateUser(t, nil)
		team := forgery.CreateTeam(t, org, &forgery.CreateTeamOptions{Mode: perm_model.AccessModeRead, Members: []*user_model.User{member}})
		_, err = db.GetEngine(t.Context()).Where("team_id = ? AND type <> ?", team.ID, unit.TypeIssues).Delete(new(org_model.TeamUnit))
		require.NoError(t, err)
		reader := forgery.CreateUser(t, nil)
		forgery.CreateTeam(t, org, &forgery.CreateTeamOptions{Mode: perm_model.AccessModeRead, Members: []*user_model.User{reader}})
		// both teams include all repositories, so they reach the repository created now
		repo := depNewRepo(t, org3, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), "dep-issues", true, 0)
		storeScan(t, repo, &repo_model.Dependency{Ecosystem: "Go", Name: "x", Version: "1", Direct: true})

		session := loginUserWithPassword(t, member.Name, userPassword)
		session.MakeRequest(t, NewRequest(t, "GET", "/org3/dep-issues/issues"), http.StatusOK)
		session.MakeRequest(t, NewRequest(t, "GET", "/org3/dep-issues/activity/dependencies/sbom"), http.StatusNotFound)
		session.MakeRequest(t, NewRequest(t, "GET", "/org3/dep-issues/activity/dependencies"), http.StatusNotFound)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository)
		for _, tail := range []string{"/dependencies", "/sbom"} {
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/dep-issues"+tail).AddTokenAuth(token), http.StatusForbidden)
		}

		// a reader of the code gets both
		session = loginUserWithPassword(t, reader.Name, userPassword)
		session.MakeRequest(t, NewRequest(t, "GET", "/org3/dep-issues/activity/dependencies"), http.StatusOK)
		session.MakeRequest(t, NewRequest(t, "GET", "/org3/dep-issues/activity/dependencies/sbom"), http.StatusOK)
	})
}

func TestDependencyGraphProject(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		enableDependencyGraph(t)
		sys := audit_model.WithSystem(db.DefaultContext, "test")
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		group, err := repo_model.CreateRepoGroup(sys, org3, "dep-proj", "")
		require.NoError(t, err)
		leaf := depNewRepo(t, org3, user2, "leaf", true, group.ID)
		require.Equal(t, "org3/dep-proj/leaf", leaf.FullName())
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)

		sha := depPush(t, u, token, leaf, "refs/heads/main", map[string]string{
			"go.mod":       depGoMod,
			"evil/go.mod":  "module e\n\nrequire (\n\t\"quoted<script>\" v1.0.0\n)\n",
			"pkg.lock.txt": "x",
		})
		require.Eventually(t, func() bool { s := depScanOf(t, leaf.ID); return s != nil && s.CommitSHA == sha }, 10*time.Second, 50*time.Millisecond)

		forms := []string{
			"/api/v1/repos/org3/dep-proj/leaf/-",
			fmt.Sprintf("/api/v1/repositories/%d", leaf.ID),
		}
		for _, base := range forms {
			var list api.DependencyList
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", base+"/dependencies").AddTokenAuth(token), http.StatusOK), &list)
			assert.Equal(t, sha, list.Scan.CommitSHA, base)
			assert.NotEmpty(t, list.Dependencies, base)

			resp := MakeRequest(t, NewRequest(t, "GET", base+"/sbom?format=spdx").AddTokenAuth(token), http.StatusOK)
			assert.Contains(t, resp.Header().Get("Content-Disposition"), `filename="org3-dep-proj-leaf.spdx.json"`)
			var doc struct {
				Name              string `json:"name"`
				DocumentNamespace string `json:"documentNamespace"`
				Packages          []struct {
					Name        string `json:"name"`
					VersionInfo string `json:"versionInfo"`
				} `json:"packages"`
			}
			require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &doc))
			assert.Equal(t, "org3/dep-proj/leaf", doc.Name)
			assert.Equal(t, sha, doc.Packages[0].VersionInfo)
			assert.True(t, strings.HasPrefix(doc.DocumentNamespace, setting.AppURL+"org3/dep-proj/leaf/sbom/spdx/"+sha+"/"), doc.DocumentNamespace)
		}
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/dep-proj/leaf/-/sbom?format=cyclonedx").AddTokenAuth(token), http.StatusOK)
		var cdx struct {
			Metadata struct {
				Component struct{ Name, Version string } `json:"component"`
			} `json:"metadata"`
		}
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &cdx))
		assert.Equal(t, "org3/dep-proj/leaf", cdx.Metadata.Component.Name)
		assert.Equal(t, sha, cdx.Metadata.Component.Version)

		// the web download, through the project path
		session := loginUser(t, "user2")
		web := session.MakeRequest(t, NewRequest(t, "GET", "/org3/dep-proj/leaf/activity/dependencies/sbom"), http.StatusOK)
		assert.Contains(t, web.Header().Get("Content-Disposition"), `filename="org3-dep-proj-leaf.spdx.json"`)
		assert.Contains(t, web.Body.String(), `"name":"org3/dep-proj/leaf"`)

		// hidden: a non-member gets what a missing project path gets
		other := loginUser(t, "user4")
		hidden := other.MakeRequest(t, NewRequest(t, "GET", "/org3/dep-proj/leaf/activity/dependencies/sbom"), http.StatusNotFound)
		missing := other.MakeRequest(t, NewRequest(t, "GET", "/org3/dep-proj/nothing/activity/dependencies/sbom"), http.StatusNotFound)
		assert.Equal(t, missing.Body.String(), hidden.Body.String())
		MakeRequest(t, NewRequest(t, "GET", "/org3/dep-proj/leaf/activity/dependencies/sbom"), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/dep-proj/leaf/-/dependencies"), http.StatusNotFound)

		t.Run("owned tokens", func(t *testing.T) {
			covering := newOwnedAccessToken(t, auth_model.AccessTokenOwnerProject, 3, group.ID, perm_model.AccessModeRead, "read:repository")
			orgWide := newOwnedAccessToken(t, auth_model.AccessTokenOwnerOrg, 3, 0, perm_model.AccessModeRead, "read:repository")
			otherGroup, err := repo_model.CreateRepoGroup(sys, org3, "dep-other", "")
			require.NoError(t, err)
			foreign := newOwnedAccessToken(t, auth_model.AccessTokenOwnerProject, 3, otherGroup.ID, perm_model.AccessModeRead, "read:repository")
			for _, tail := range []string{"/dependencies", "/sbom"} {
				MakeRequest(t, NewRequest(t, "GET", forms[0]+tail).AddTokenAuth(covering.Token), http.StatusOK)
				MakeRequest(t, NewRequest(t, "GET", forms[0]+tail).AddTokenAuth(orgWide.Token), http.StatusOK)
				MakeRequest(t, NewRequest(t, "GET", forms[1]+tail).AddTokenAuth(covering.Token), http.StatusOK)
				MakeRequest(t, NewRequest(t, "GET", forms[0]+tail).AddTokenAuth(foreign.Token), http.StatusNotFound)
				MakeRequest(t, NewRequest(t, "GET", forms[1]+tail).AddTokenAuth(foreign.Token), http.StatusNotFound)
			}
			// a revoked token is refused
			require.NoError(t, auth_model.DeleteOwnedAccessToken(sys, auth_model.FindOwnedAccessTokensOptions{OwnerType: auth_model.AccessTokenOwnerProject, OwnerID: 3, GroupID: group.ID}, covering.ID, 2))
			MakeRequest(t, NewRequest(t, "GET", forms[0]+"/dependencies").AddTokenAuth(covering.Token), http.StatusUnauthorized)
		})
	})
}

func TestDependencyGraphPage(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		enableDependencyGraph(t)
		sys := audit_model.WithSystem(db.DefaultContext, "test")
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		session := loginUser(t, "user2")
		page := func(session *TestSession, path string, status int) *HTMLDoc {
			resp := session.MakeRequest(t, NewRequest(t, "GET", path), status)
			return NewHTMLParser(t, resp.Body)
		}
		rowsOf := func(doc *HTMLDoc) []string {
			var names []string
			doc.Find(".repo-dependencies-row:not(.repo-dependencies-head) .repo-dependencies-package strong").Each(func(_ int, s *goquery.Selection) {
				names = append(names, s.Text())
			})
			return names
		}

		repo := depNewRepo(t, user2, user2, "dep-page", true, 0)

		t.Run("first scan running, then no manifests", func(t *testing.T) {
			// the first read queues the scan, which runs at once with immediate queues: the page shows what it saw
			doc := page(session, "/user2/dep-page/activity/dependencies", http.StatusOK)
			doc.AssertElement(t, "#dependencies-running", true)
			doc.AssertElement(t, "#dependencies-export.disabled", true)
			doc = page(session, "/user2/dep-page/activity/dependencies", http.StatusOK)
			doc.AssertElement(t, "#dependencies-none", true)
			doc.AssertElement(t, "#dependencies-export.disabled", false)
		})

		t.Run("list, filters, escaping, paging", func(t *testing.T) {
			d := func(eco, name, version string, direct bool, license, manifest string) *repo_model.Dependency {
				return &repo_model.Dependency{Ecosystem: eco, Name: name, Version: version, Direct: direct, License: license, ManifestPath: manifest}
			}
			deps := []*repo_model.Dependency{
				d("Go", "golang.org/x/net", "v0.17.0", true, "BSD-3-Clause", "go.mod"),
				d("npm", "express", "4.18.2", true, "MIT", "web/package-lock.json"),
				d("npm", "body-parser", "1.20.1", false, "MIT", "web/package-lock.json"),
				d("PyPI", "requests", "2.31.0", true, "", "tools/requirements.txt"),
				d("npm", `<script>alert(1)</script>`, `"><img src=x onerror=alert(2)>`, false, "", "web/dir with space/package-lock.json"),
			}
			head := headOf(t, repo)
			storeScanAt(t, repo, head, deps...)
			doc := page(session, "/user2/dep-page/activity/dependencies", http.StatusOK)
			assert.Equal(t, []string{"<script>alert(1)</script>", "body-parser", "express", "golang.org/x/net", "requests"}, rowsOf(doc))
			assert.Zero(t, doc.Find("script:contains('alert(1)')").Length(), "the name is escaped")
			assert.Zero(t, doc.Find("img[src='x']").Length())
			doc.AssertElement(t, "#dependencies-stale", false)
			assert.Equal(t, "Unknown", strings.TrimSpace(doc.Find(".repo-dependencies-row").Eq(1).Find("[role=cell]").Eq(3).Text()))
			doc.AssertAttrPredicate(t, `.repo-dependencies-row a[href*="dir%20with%20space"]`, "href", func(v string) {
				assert.Equal(t, "/user2/dep-page/src/commit/"+head+"/web/dir%20with%20space/package-lock.json", v)
			})
			doc.AssertAttrEqual(t, "#dependencies-export a.item:first-child", "href", "/user2/dep-page/activity/dependencies/sbom?format=spdx")
			assert.Contains(t, doc.Find("#dependencies-export").Text(), "user2-dep-page.spdx.json")
			assert.Contains(t, doc.Find("#dependencies-export").Text(), "user2-dep-page.cdx.json")
			assert.Contains(t, doc.Find("select[name=ecosystem]").Text(), "npm (3)")
			assert.Contains(t, doc.Find("select[name=relationship]").Text(), "Direct (3)")
			assert.Contains(t, doc.Find("select[name=manifest]").Text(), "web/package-lock.json (2)")

			assert.Equal(t, []string{"<script>alert(1)</script>", "body-parser"}, rowsOf(page(session, "/user2/dep-page/activity/dependencies?ecosystem=npm&relationship=transitive", http.StatusOK)))
			assert.Equal(t, []string{"body-parser", "express"}, rowsOf(page(session, "/user2/dep-page/activity/dependencies?manifest=web/package-lock.json", http.StatusOK)))
			assert.Equal(t, []string{"express"}, rowsOf(page(session, "/user2/dep-page/activity/dependencies?q=EXPR", http.StatusOK)))
			assert.Equal(t, []string{"requests"}, rowsOf(page(session, "/user2/dep-page/activity/dependencies?relationship=direct&ecosystem=PyPI", http.StatusOK)))
			// unknown filter values are ignored, never an error
			assert.Len(t, rowsOf(page(session, "/user2/dep-page/activity/dependencies?manifest=nope&relationship=x", http.StatusOK)), 5)
			page(session, "/user2/dep-page/activity/dependencies?ecosystem=Cobol", http.StatusUnprocessableEntity)
			noMatch := page(session, "/user2/dep-page/activity/dependencies?q=zzz", http.StatusOK)
			noMatch.AssertElement(t, "#dependencies-no-match", true)

			// paging: 50 rows a page
			many := make([]*repo_model.Dependency, 0, 120)
			for i := range 120 {
				many = append(many, d("Go", fmt.Sprintf("example.com/p%03d", i), "v1.0.0", false, "MIT", "go.mod"))
			}
			storeScanAt(t, repo, head, many...)
			first := rowsOf(page(session, "/user2/dep-page/activity/dependencies", http.StatusOK))
			assert.Len(t, first, 50)
			assert.Equal(t, "example.com/p000", first[0])
			third := page(session, "/user2/dep-page/activity/dependencies?page=3&q=example", http.StatusOK)
			assert.Len(t, rowsOf(third), 20)
			assert.Positive(t, third.Find(`.pagination a[href*="q=example"]`).Length())
		})

		t.Run("a scan of an older commit is rescanned", func(t *testing.T) {
			storeScan(t, repo, &repo_model.Dependency{Ecosystem: "Go", Name: "example.com/old", Version: "v1", Direct: true})
			doc := page(session, "/user2/dep-page/activity/dependencies", http.StatusOK)
			doc.AssertElement(t, "#dependencies-stale", true)
			assert.Equal(t, headOf(t, repo), depScanOf(t, repo.ID).CommitSHA, "the scan was queued again")
			// a failed last scan is left to the cron: no new scan from the page
			scan := depScanOf(t, repo.ID)
			scan.CommitSHA, scan.Status, scan.Error = strings.Repeat("b", 40), repo_model.DependencyScanFailed, repo_model.DependencyErrTimeout
			require.NoError(t, repo_model.ReplaceRepoDependencies(t.Context(), scan, []*repo_model.Dependency{}))
			page(session, "/user2/dep-page/activity/dependencies", http.StatusOK)
			assert.Equal(t, strings.Repeat("b", 40), depScanOf(t, repo.ID).CommitSHA)
		})

		t.Run("skipped manifests", func(t *testing.T) {
			scan := depScanOf(t, repo.ID)
			scan.SetSkippedManifests([]repo_model.SkippedManifest{{Path: "legacy/pom.xml", Code: "parse_error"}, {Path: "vendor-tools/yarn.lock", Code: "manifest_too_large"}, {Path: "x/Cargo.lock", Code: "<b>made up</b>"}})
			require.NoError(t, repo_model.ReplaceRepoDependencies(t.Context(), scan, []*repo_model.Dependency{}))
			doc := page(session, "/user2/dep-page/activity/dependencies", http.StatusOK)
			items := doc.Find("#dependencies-skipped li")
			require.Equal(t, 3, items.Length())
			assert.Contains(t, items.Eq(0).Text(), "legacy/pom.xml: could not be parsed")
			assert.Contains(t, items.Eq(1).Text(), "larger than the size limit")
			assert.NotContains(t, items.Eq(2).Text(), "made up", "a code outside the list is not shown")
			assert.Contains(t, doc.Find("#dependencies-skipped .header").Text(), "3 manifests were skipped")
		})

		t.Run("menu item", func(t *testing.T) {
			for _, tail := range []string{"/activity", "/activity/contributors", "/activity/dependencies"} {
				doc := page(session, "/user2/dep-page"+tail, http.StatusOK)
				doc.AssertElement(t, `.flex-container-nav a[href="/user2/dep-page/activity/dependencies"]`, true)
			}
			defer test.MockVariableValue(&setting.DependencyGraph.Enabled, false)()
			doc := page(session, "/user2/dep-page/activity", http.StatusOK)
			doc.AssertElement(t, `.flex-container-nav a[href="/user2/dep-page/activity/dependencies"]`, false)
			session.MakeRequest(t, NewRequest(t, "GET", "/user2/dep-page/activity/dependencies"), http.StatusNotFound)
		})

		t.Run("hidden is missing", func(t *testing.T) {
			other := loginUser(t, "user4")
			hidden := other.MakeRequest(t, NewRequest(t, "GET", "/user2/dep-page/activity/dependencies"), http.StatusNotFound)
			missing := other.MakeRequest(t, NewRequest(t, "GET", "/user2/nothing/activity/dependencies"), http.StatusNotFound)
			assert.Equal(t, missing.Body.String(), hidden.Body.String())
			MakeRequest(t, NewRequest(t, "GET", "/user2/dep-page/activity/dependencies"), http.StatusNotFound)
		})

		t.Run("project", func(t *testing.T) {
			org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
			group, err := repo_model.CreateRepoGroup(sys, org3, "dep-page-proj", "")
			require.NoError(t, err)
			leaf := depNewRepo(t, org3, user2, "leaf", true, group.ID)
			storeScanAt(t, leaf, headOf(t, leaf), &repo_model.Dependency{Ecosystem: "Go", Name: "example.com/inproject", Version: "v1", Direct: true})
			doc := page(session, "/org3/dep-page-proj/leaf/activity/dependencies", http.StatusOK)
			assert.Equal(t, []string{"example.com/inproject"}, rowsOf(doc))
			doc.AssertAttrEqual(t, "#dependencies-export a.item:first-child", "href", "/org3/dep-page-proj/leaf/activity/dependencies/sbom?format=spdx")
			assert.Contains(t, doc.Find("#dependencies-export").Text(), "org3-dep-page-proj-leaf.spdx.json")
			doc.AssertAttrPredicate(t, ".repo-dependencies-row a", "href", func(v string) {
				assert.True(t, strings.HasPrefix(v, "/org3/dep-page-proj/leaf/src/commit/"), v)
			})
			assert.Contains(t, doc.Find(".repo-dependencies-note").Text(), "org3/dep-page-proj/leaf")
			other := loginUser(t, "user4")
			other.MakeRequest(t, NewRequest(t, "GET", "/org3/dep-page-proj/leaf/activity/dependencies"), http.StatusNotFound)
		})
	})
}
