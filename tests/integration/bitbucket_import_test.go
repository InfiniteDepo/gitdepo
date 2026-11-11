// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/services/migrations"
	"forgejo.org/services/migrations/allowlist"
	repo_service "forgejo.org/services/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const bitbucketTestToken = "bbtoken-0123456789abcdef"

// bitbucketMock serves a Bitbucket Data Center REST API with the projects (key → name) and their repository slugs,
// and every repository's git data (dumb HTTP) from a copy of user2/repo1. Every clone link it hands out is hostile.
// PAY/api has one open pull request from a fork, ~JDOE/api (branch develop, which exists), whose git URL redirects.
type bitbucketMock struct {
	*httptest.Server
	bare    string                                                                         // the git data
	pages   map[string]any                                                                 // REST answers by path below rest/, set before the first request
	gitHook atomic.Pointer[func(w http.ResponseWriter, r *http.Request, slug string) bool] // answers a git request when it returns true
}

func newBitbucketMock(t *testing.T, projects map[string]string, repos map[string][]string) *bitbucketMock {
	t.Helper()
	bare := filepath.Join(t.TempDir(), "repo.git")
	for _, args := range [][]string{
		{"clone", "--bare", filepath.Join(setting.RepoRootPath, "user2", "repo1.git"), bare},
		{"-C", bare, "update-server-info"},
	} {
		out, err := exec.Command("git", args...).CombinedOutput()
		require.NoError(t, err, string(out))
	}
	out, err := exec.Command("git", "-C", bare, "rev-parse", "master").Output()
	require.NoError(t, err)
	head := strings.TrimSpace(string(out))
	files := http.FileServer(http.Dir(bare))

	m := &bitbucketMock{bare: bare}
	page := func(w http.ResponseWriter, values any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"isLastPage": true, "values": values})
	}
	ref := func(key, branch string) map[string]any {
		return map[string]any{"displayId": branch, "latestCommit": head, "repository": map[string]any{"slug": "api", "project": map[string]string{"key": key}}}
	}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if parts[0] == "scm" && len(parts) >= 3 { // git data: the same repository for every slug
			hook := m.gitHook.Load()
			switch {
			case parts[1] == "~jdoe":
				u := *r.URL
				u.Path = "/scm/pay/" + strings.Join(parts[2:], "/")
				http.Redirect(w, r, u.String(), http.StatusFound)
			case hook != nil && (*hook)(w, r, strings.TrimSuffix(parts[2], ".git")):
			default:
				http.StripPrefix("/"+strings.Join(parts[:3], "/"), files).ServeHTTP(w, r)
			}
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+bitbucketTestToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if v, ok := m.pages[strings.Join(parts[1:], "/")]; ok {
			_ = json.NewEncoder(w).Encode(v)
			return
		}
		rest := parts[3:] // after rest/api/1.0
		switch {
		case len(rest) == 1 && rest[0] == "projects":
			values := []map[string]string{}
			for key, name := range projects {
				values = append(values, map[string]string{"key": key, "name": name, "description": "desc\x1b[2J"})
			}
			page(w, values)
		case len(rest) == 3 && rest[2] == "repos":
			values := []map[string]any{}
			for _, slug := range repos[strings.ToUpper(rest[1])] {
				values = append(values, map[string]any{"slug": slug, "links": map[string]any{"clone": []map[string]string{
					{"name": "http", "href": "http://evil.example.com/scm/x/y.git"},
					{"name": "ssh", "href": "ssh://git@bb.example.com:7999/" + rest[1] + "/" + slug + ".git\x1b[2J"},
				}}})
			}
			page(w, values)
		case len(rest) == 4:
			_ = json.NewEncoder(w).Encode(map[string]any{"slug": rest[3], "links": map[string]any{
				"clone": []map[string]string{{"name": "http", "href": "file:///etc/passwd"}},
			}})
		case len(rest) == 6 && rest[4] == "branches":
			_, _ = w.Write([]byte(`{"displayId":"master"}`))
		case len(rest) == 5 && rest[3] == "api" && rest[4] == "pull-requests":
			page(w, []map[string]any{{
				"id": 1, "title": "From a fork", "state": "OPEN", "createdDate": 1700000000000, "updatedDate": 1700000000000,
				"author":  map[string]any{"user": map[string]any{"id": 7, "name": "jdoe", "emailAddress": "jdoe@example.com"}},
				"fromRef": ref("~JDOE", "develop"), "toRef": ref("PAY", "master"),
			}})
		default:
			page(w, []any{})
		}
	}))
	return m
}

// countBitbucketImportRows counts the rows of every table and the repository counters, to show a run wrote nothing.
func countBitbucketImportRows(t *testing.T) map[string]int64 {
	t.Helper()
	counts := map[string]int64{}
	for table := range db.GetTableNames() {
		sess := db.GetEngine(db.DefaultContext).Table(table)
		if table == "system_setting" {
			sess.Where("setting_key <> 'revision'") // created by the first settings read (GetRevision), not by an import
		}
		n, err := sess.Count()
		require.NoError(t, err)
		counts[table] = n
	}
	for _, counter := range []string{"`user`.num_repos", "team.num_repos"} {
		var sum int64
		table, column, _ := strings.Cut(counter, ".")
		_, err := db.GetEngine(db.DefaultContext).SQL("SELECT COALESCE(SUM(" + column + "), 0) FROM " + table).Get(&sum)
		require.NoError(t, err)
		counts[counter] = sum
	}
	return counts
}

func TestBitbucketImport(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValueWithReset(&setting.Migrations.AllowLocalNetworks, true, func() { require.NoError(t, allowlist.Init()) })()
		defer test.MockVariableValueWithReset(&setting.Migrations.AllowUnencrypted, true, func() { require.NoError(t, allowlist.Init()) })()
		ctx := t.Context()
		server := newBitbucketMock(t, map[string]string{"PAY": "Payments\x1b[31m Team", "ZZZ": "repo3", "~JD": "---", "-": "", "A.GIT": ""},
			map[string][]string{"PAY": {"api", "web", "zeta"}, "ZZZ": {"tools"}})
		defer server.Close()
		opts := migrations.BitbucketImportOptions{Server: server.URL, Token: bitbucketTestToken, Projects: []string{"PAY"}, PullRequests: true}
		dryRun := opts
		dryRun.DryRun = true
		const projectName = "payments-31m-team"

		// blocked runs the import and checks it stopped before any write, on a conflict of the item named
		blocked := func(t *testing.T, o migrations.BitbucketImportOptions, conflicting string) {
			t.Helper()
			before := countBitbucketImportRows(t)
			report, err := migrations.ImportBitbucket(ctx, "user2", "org3", o)
			require.NoError(t, err)
			assert.True(t, report.Blocked)
			found := false
			for _, item := range report.Items {
				if item.Bitbucket == conflicting {
					found = true
					assert.Equal(t, migrations.BitbucketConflict, item.Status, conflicting)
				}
			}
			assert.True(t, found, conflicting)
			assert.Equal(t, before, countBitbucketImportRows(t))
		}

		t.Run("a server outside the allowlist gets no request", func(t *testing.T) {
			var hits atomic.Int32
			outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
			defer outside.Close()
			defer test.MockVariableValueWithReset(&setting.Migrations.AllowLocalNetworks, false, func() { require.NoError(t, allowlist.Init()) })()
			_, err := migrations.ImportBitbucket(ctx, "user2", "org3", migrations.BitbucketImportOptions{Server: outside.URL, Token: bitbucketTestToken, DryRun: true})
			require.Error(t, err)
			assert.Zero(t, hits.Load())
		})

		t.Run("conflicts write nothing", func(t *testing.T) {
			last := opts
			last.Projects = []string{"PAY", "ZZZ"} // ZZZ, the last project, is named like org3's repo3
			blocked(t, last, "ZZZ")

			for _, key := range []string{"~JD", "-", "A.GIT"} { // their names fall back to an unusable key
				unusable := opts
				unusable.Projects = []string{key}
				blocked(t, unusable, key)
			}

			org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
			group, err := repo_model.CreateRepoGroup(ctx, org3, projectName, "")
			require.NoError(t, err)
			blocked(t, opts, "PAY")
			require.NoError(t, repo_model.DeleteRepoGroup(ctx, group))

			require.NoError(t, db.Insert(ctx, &repo_model.RepoGroupRedirect{OwnerID: 3, LowerName: projectName, RedirectGroupID: 999}))
			blocked(t, opts, "PAY")
			_, err = db.GetEngine(ctx).Where("owner_id = 3 AND lower_name = ?", projectName).Delete(new(repo_model.RepoGroupRedirect))
			require.NoError(t, err)
		})

		t.Run("dry run", func(t *testing.T) {
			for _, doer := range []string{"user2", "user1"} { // the owner, and a site admin who isn't a member
				before := countBitbucketImportRows(t)
				report, err := migrations.ImportBitbucket(ctx, doer, "org3", dryRun)
				require.NoError(t, err)
				assert.False(t, report.Blocked)
				assert.Equal(t, before, countBitbucketImportRows(t))
				require.Len(t, report.Items, 4)
				assert.Equal(t, "org3/"+projectName, report.Items[0].Name)
				for _, item := range report.Items {
					assert.Equal(t, migrations.BitbucketPlanned, item.Status, item.Bitbucket)
				}
				api := report.Items[1]
				assert.Equal(t, "PAY/api", api.Bitbucket)
				assert.Equal(t, server.URL+"/scm/pay/api.git", api.OldHTTP)
				assert.Equal(t, server.URL+"/projects/PAY/repos/api/browse", api.OldWeb)
				assert.NotContains(t, api.OldSSH, "\x1b", "display text is stripped of control characters")
			}
		})

		t.Run("through the internal route", func(t *testing.T) {
			text, extra := private.BitbucketImport(ctx, private.BitbucketImportParams{Doer: "user2", Org: "org3", Server: server.URL, Token: bitbucketTestToken, Projects: []string{"PAY"}, DryRun: true})
			require.NoError(t, extra.Error)
			assert.Contains(t, text, `"status":"planned"`)
			assert.NotContains(t, text, bitbucketTestToken)

			_, extra = private.BitbucketImport(ctx, private.BitbucketImportParams{Doer: "user5", Org: "org3", Server: server.URL, Token: bitbucketTestToken, DryRun: true})
			assert.Equal(t, http.StatusForbidden, extra.StatusCode)

			defer test.MockVariableValue(&setting.Maintenance.Mode, setting.MaintenanceReadOnly)()
			_, extra = private.BitbucketImport(ctx, private.BitbucketImportParams{Doer: "user2", Org: "org3", Server: server.URL, Token: bitbucketTestToken, Projects: []string{"PAY"}})
			assert.Equal(t, http.StatusForbidden, extra.StatusCode, "no real run in maintenance mode")
			_, extra = private.BitbucketImport(ctx, private.BitbucketImportParams{Doer: "user2", Org: "org3", Server: server.URL, Token: bitbucketTestToken, Projects: []string{"PAY"}, DryRun: true})
			require.NoError(t, extra.Error, "a dry run still works")
		})

		t.Run("a failed repository is deleted and imported by the next run", func(t *testing.T) {
			logChecker, cleanup := test.NewLogChecker(log.DEFAULT, log.TRACE)
			logChecker.Filter(bitbucketTestToken)
			defer cleanup()

			// each way to fail answers the git requests of PAY/web; PAY/api is imported by the first run
			var cancelRun context.CancelFunc
			var conflictInserted atomic.Bool
			// the cancel first, so zeta, after web, is still to import and reported cancelled
			for _, c := range []struct {
				name string
				hook func(w http.ResponseWriter, r *http.Request) bool
			}{
				{"the run is cancelled during the clone", func(w http.ResponseWriter, r *http.Request) bool {
					cancelRun()
					select { // until the clone is killed
					case <-r.Context().Done():
					case <-time.After(30 * time.Second):
					}
					return true
				}},
				{"clone fails", func(w http.ResponseWriter, r *http.Request) bool {
					w.WriteHeader(http.StatusNotFound)
					return true
				}},
				{"recording the origin fails", func(w http.ResponseWriter, r *http.Request) bool {
					if !conflictInserted.Swap(true) { // the origin insert then hits the unique key
						assert.NoError(t, db.Insert(db.DefaultContext, &repo_model.BitbucketOrigin{RepoID: 99999, ProjectKey: "PAY", Slug: "web", Server: server.URL}))
					}
					return false
				}},
			} {
				name, hook := c.name, c.hook
				t.Run(name, func(t *testing.T) {
					runCtx, cancel := context.WithCancel(ctx)
					defer cancel()
					cancelRun = cancel
					server.gitHook.Store(new(func(w http.ResponseWriter, r *http.Request, slug string) bool {
						return slug == "web" && hook(w, r)
					}))
					report, err := migrations.ImportBitbucket(runCtx, "user2", "org3", opts)
					server.gitHook.Store(nil)
					require.NoError(t, err)
					assert.Equal(t, name == "the run is cancelled during the clone", runCtx.Err() != nil)
					require.Len(t, report.Items, 4)
					assert.Contains(t, []string{migrations.BitbucketCreated, migrations.BitbucketReused}, report.Items[0].Status, report.Items[0].Reason)
					assert.Contains(t, []string{migrations.BitbucketCreated, migrations.BitbucketReused}, report.Items[1].Status, report.Items[1].Reason)
					assert.Equal(t, migrations.BitbucketFailed, report.Items[2].Status)
					assert.NotContains(t, report.Items[2].Reason, "delete ", "the purge worked")
					if name == "the run is cancelled during the clone" {
						assert.Equal(t, migrations.BitbucketFailed, report.Items[3].Status)
						assert.Equal(t, "the import was cancelled", report.Items[3].Reason)
						group := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroup{OwnerID: 3, LowerName: projectName})
						_, err = repo_model.GetRepositoryByPath(db.DefaultContext, 3, group.Name, "zeta")
						assert.True(t, repo_model.IsErrRepoNotExist(err), "zeta wasn't started")
					} else {
						assert.Contains(t, []string{migrations.BitbucketCreated, migrations.BitbucketReused}, report.Items[3].Status, report.Items[3].Reason)
					}
					b, err := json.Marshal(report)
					require.NoError(t, err)
					assert.NotContains(t, string(b), bitbucketTestToken)

					_, err = db.GetEngine(db.DefaultContext).Where("repo_id = 99999").Delete(new(repo_model.BitbucketOrigin))
					require.NoError(t, err)
					group := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroup{OwnerID: 3, LowerName: projectName})
					_, err = repo_model.GetRepositoryByPath(db.DefaultContext, 3, group.Name, "web")
					assert.True(t, repo_model.IsErrRepoNotExist(err), "the failed repository is gone")
					assert.NoDirExists(t, repo_model.GroupRepoPath("org3", group.Name, "web"))
					unittest.AssertNotExistsBean(t, &repo_model.BitbucketOrigin{ProjectKey: "PAY", Slug: "web"})
				})
			}
			assert.True(t, conflictInserted.Load())
			found, _ := logChecker.Check(time.Second)
			assert.False(t, found[0], "the token is never logged")

			again, err := migrations.ImportBitbucket(ctx, "user2", "org3", opts)
			require.NoError(t, err)
			assert.Equal(t, []string{migrations.BitbucketReused, migrations.BitbucketReused, migrations.BitbucketCreated, migrations.BitbucketReused},
				[]string{again.Items[0].Status, again.Items[1].Status, again.Items[2].Status, again.Items[3].Status}, again.Items[2].Reason)
		})

		t.Run("imported repositories", func(t *testing.T) {
			group := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroup{OwnerID: 3, LowerName: projectName})
			assert.Equal(t, "desc?[2J", group.Description)
			unittest.AssertExistsAndLoadBean(t, &repo_model.BitbucketOrigin{OwnerID: 3, GroupID: group.ID, ProjectKey: "PAY", Server: server.URL})
			for _, slug := range []string{"api", "web"} {
				repo, err := repo_model.GetRepositoryByPath(ctx, 3, group.Name, slug)
				require.NoError(t, err)
				assert.Equal(t, repo_model.RepositoryReady, repo.Status)
				assert.True(t, repo.IsPrivate)
				assert.Equal(t, server.URL+"/projects/PAY/repos/"+slug+"/browse", repo.OriginalURL)
				origin := unittest.AssertExistsAndLoadBean(t, &repo_model.BitbucketOrigin{RepoID: repo.ID})
				assert.Zero(t, origin.OwnerID)

				// the git data is at the project path and nothing at the owner's root
				assert.DirExists(t, repo.RepoPath())
				assert.NoDirExists(t, repo_model.RepoPath("org3", slug))
				config, err := os.ReadFile(filepath.Join(repo.RepoPath(), "config"))
				require.NoError(t, err)
				assert.NotContains(t, string(config), bitbucketTestToken)
				assert.NotContains(t, string(config), `[remote "origin"]`)
				out, err := exec.Command("git", "-C", repo.RepoPath(), "rev-parse", "--verify", "refs/heads/master").CombinedOutput()
				require.NoError(t, err, string(out))
			}

			// the fork pull request is imported, but its head behind a redirect is not fetched
			api, err := repo_model.GetRepositoryByPath(ctx, 3, group.Name, "api")
			require.NoError(t, err)
			pulls, err := issues_model.Issues(ctx, &issues_model.IssuesOptions{RepoIDs: []int64{api.ID}, IsPull: optional.Some(true)})
			require.NoError(t, err)
			require.Len(t, pulls, 1)
			branches := func(path string) string {
				out, err := exec.Command("git", "-C", path, "for-each-ref", "--format=%(refname)", "refs/heads/").Output()
				require.NoError(t, err)
				return string(out)
			}
			assert.Equal(t, branches(server.bare), branches(api.RepoPath()), "no branch from the fork's develop")

			// the 14b origin search finds it, for the owner only
			for user, want := range map[string]bool{"user2": true, "user5": false} {
				doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: user})
				repos, _, err := repo_model.SearchRepositoryByName(ctx, &repo_model.SearchRepoOptions{Keyword: "PAY/api", Actor: doer, Private: true})
				require.NoError(t, err)
				assert.Equal(t, want, len(repos) == 1 && repos[0].ID == api.ID, user)
			}
		})

		t.Run("a second run reuses everything", func(t *testing.T) {
			before := countBitbucketImportRows(t)
			again, err := migrations.ImportBitbucket(ctx, "user2", "org3", opts)
			require.NoError(t, err)
			for _, item := range again.Items {
				assert.Equal(t, migrations.BitbucketReused, item.Status, item.Bitbucket)
			}
			assert.Equal(t, before, countBitbucketImportRows(t))
		})

		t.Run("a resume never reuses a repository that left its place", func(t *testing.T) {
			admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
			group := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoGroup{OwnerID: 3, LowerName: projectName})
			api, err := repo_model.GetRepositoryByPath(ctx, 3, group.Name, "api")
			require.NoError(t, err)

			_, err = db.Exec(ctx, "UPDATE repository SET trashed_unix = 1 WHERE id = ?", api.ID)
			require.NoError(t, err)
			blocked(t, opts, "PAY/api")
			_, err = db.Exec(ctx, "UPDATE repository SET trashed_unix = 0 WHERE id = ?", api.ID)
			require.NoError(t, err)

			other, err := repo_model.CreateRepoGroup(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}), "other", "")
			require.NoError(t, err)
			require.NoError(t, repo_service.MoveRepository(ctx, admin, api, other.ID))
			blocked(t, opts, "PAY/api")

			api = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: api.ID})
			require.NoError(t, repo_service.MoveRepository(ctx, admin, api, 0))
			blocked(t, opts, "PAY/api")

			api = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: api.ID})
			require.NoError(t, repo_service.TransferOwnership(audit_model.WithSystem(ctx, "test"), admin, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 17}), api, nil))
			blocked(t, opts, "PAY/api")
		})

		t.Run("the existing web migration still works", func(t *testing.T) {
			session := loginUser(t, "user2")
			req := NewRequestWithValues(t, "POST", "/repo/migrate", map[string]string{
				"clone_addr": server.URL + "/scm/pay/api.git",
				"auth_token": bitbucketTestToken,
				"uid":        "2",
				"repo_name":  "from-bitbucket",
				"service":    "11",
			})
			session.MakeRequest(t, req, http.StatusSeeOther)
			assert.Eventually(t, func() bool {
				repo, err := repo_model.GetRepositoryByOwnerAndName(db.DefaultContext, "user2", "from-bitbucket")
				return err == nil && repo.Status == repo_model.RepositoryReady
			}, 30*time.Second, 200*time.Millisecond)
			repo, err := repo_model.GetRepositoryByOwnerAndName(ctx, "user2", "from-bitbucket")
			require.NoError(t, err)
			assert.NotContains(t, repo.OriginalURL, bitbucketTestToken)
			assert.Equal(t, structs.BitbucketDataCenterService, repo.OriginalServiceType)
		})
	})
}
