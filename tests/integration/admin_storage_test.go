// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/git"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/modules/translation"
	"forgejo.org/services/convert"
	wiki_service "forgejo.org/services/wiki"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
)

func TestAdminStorage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	require.NoError(t, repo_model.UpdateRepoSize(db.DefaultContext, 3, 1<<30, 1<<20, 0)) // org3/repo3, private

	admin := loginUser(t, "user1")
	user := loginUser(t, "user2")

	t.Run("NonAdmin", func(t *testing.T) {
		user.MakeRequest(t, NewRequest(t, "GET", "/admin/storage"), http.StatusForbidden)
		user.MakeRequest(t, NewRequest(t, "GET", "/admin/storage?format=csv"), http.StatusForbidden)
		user.MakeRequest(t, NewRequest(t, "GET", "/admin/storage?format=json"), http.StatusForbidden)
		user.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?format=csv"), http.StatusForbidden)
		user.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?format=json"), http.StatusForbidden)
	})

	t.Run("Page", func(t *testing.T) {
		resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/storage"), http.StatusOK)
		htmlDoc := NewHTMLParser(t, resp.Body)
		first := htmlDoc.Find("table tbody tr td a[href^='/admin/repos?uid=']").First()
		assert.Equal(t, "org3", first.Text())
		assert.Equal(t, "/admin/repos?uid=3&sort=reversesize", first.AttrOr("href", ""))
	})

	t.Run("CSV", func(t *testing.T) {
		resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/storage?format=csv&sort=reversegitsize"), http.StatusOK)
		assert.Equal(t, "text/csv; charset=utf-8", resp.Header().Get("Content-Type"))
		assert.Contains(t, resp.Header().Get("Content-Disposition"), "attachment")
		rows, err := csv.NewReader(resp.Body).ReadAll()
		require.NoError(t, err)

		owners, _, err := repo_model.FindOwnerStorage(db.DefaultContext, repo_model.FindOwnerStorageOptions{OrderBy: "reversegitsize"})
		require.NoError(t, err)
		require.Len(t, rows, len(owners)+1)
		assert.Equal(t, []string{
			"owner", "type", "repos", "git_size", "lfs_size", "total_size", "percent",
			"wiki_size", "attachments_size", "packages_size", "artifacts_size", "logs_size", "trash_size",
		}, rows[0])
		assert.Equal(t, []string{"org3", "org", strconv.FormatInt(owners[0].NumRepos, 10), "1073741824", "1048576", "1074790400"}, rows[1][:6])
		for i, o := range owners {
			assert.Equal(t, o.Owner.Name, rows[i+1][0])
			assert.Equal(t, strconv.FormatInt(o.Size(), 10), rows[i+1][5])
			assert.Equal(t, []string{
				strconv.FormatInt(o.WikiSize, 10), strconv.FormatInt(o.AttachmentsSize, 10), strconv.FormatInt(o.PackagesSize, 10),
				strconv.FormatInt(o.ArtifactsSize, 10), strconv.FormatInt(o.LogsSize, 10), strconv.FormatInt(o.TrashSize, 10),
			}, rows[i+1][7:])
		}
	})

	t.Run("OwnerJSON", func(t *testing.T) {
		defer test.MockVariableValue(&setting.UI.Admin.RepoPagingNum, 1)() // exports must not page
		resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/storage?format=json&sort=reversegitsize"), http.StatusOK)
		assert.Equal(t, "application/json; charset=utf-8", resp.Header().Get("Content-Type"))
		assert.Equal(t, "nosniff", resp.Header().Get("X-Content-Type-Options"))
		assert.Contains(t, resp.Header().Get("Content-Disposition"), `attachment; filename="storage.json"`)
		var got []*api.OwnerStorage
		DecodeJSON(t, resp, &got)

		totals, err := repo_model.GetStorageTotals(db.DefaultContext)
		require.NoError(t, err)
		owners, _, err := repo_model.FindOwnerStorage(db.DefaultContext, repo_model.FindOwnerStorageOptions{OrderBy: "reversegitsize"})
		require.NoError(t, err)
		require.Greater(t, len(owners), 1)
		want := make([]*api.OwnerStorage, len(owners))
		for i, o := range owners {
			want[i] = convert.ToOwnerStorage(o, totals)
		}
		assert.Equal(t, want, got)
		assert.Equal(t, "org3", got[0].OwnerName)
	})

	repoCSV := func(t *testing.T, query string) [][]string {
		t.Helper()
		resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?format=csv"+query), http.StatusOK)
		assert.Equal(t, "text/csv; charset=utf-8", resp.Header().Get("Content-Type"))
		assert.Contains(t, resp.Header().Get("Content-Disposition"), `attachment; filename="repo-storage.csv"`)
		rows, err := csv.NewReader(resp.Body).ReadAll()
		require.NoError(t, err)
		require.NotEmpty(t, rows)
		assert.Equal(t, []string{
			"repo_id", "owner", "repo", "private", "git_size", "lfs_size", "total_size", "percent",
			"wiki_size", "attachments_size", "artifacts_size", "logs_size",
		}, rows[0])
		return rows[1:]
	}
	type repoRow struct {
		RepoID          int64   `json:"repo_id"`
		OwnerName       string  `json:"owner_name"`
		RepoName        string  `json:"repo_name"`
		Private         bool    `json:"private"`
		GitSize         int64   `json:"git_size"`
		LFSSize         int64   `json:"lfs_size"`
		TotalSize       int64   `json:"total_size"`
		Percent         float64 `json:"percent"`
		WikiSize        int64   `json:"wiki_size"`
		AttachmentsSize int64   `json:"attachments_size"`
		ArtifactsSize   int64   `json:"artifacts_size"`
		LogsSize        int64   `json:"logs_size"`
	}
	repoJSON := func(t *testing.T, query string) []repoRow {
		t.Helper()
		resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?format=json"+query), http.StatusOK)
		assert.Equal(t, "application/json; charset=utf-8", resp.Header().Get("Content-Type"))
		assert.Contains(t, resp.Header().Get("Content-Disposition"), `attachment; filename="repo-storage.json"`)
		var rows []repoRow
		DecodeJSON(t, resp, &rows)
		return rows
	}

	t.Run("RepoCSV", func(t *testing.T) {
		defer test.MockVariableValue(&setting.UI.Admin.RepoPagingNum, 1)() // exports must not page
		rows := repoCSV(t, "&sort=reversesize")
		assert.Len(t, rows, unittest.GetCount(t, &repo_model.Repository{}))
		assert.Equal(t, []string{"3", "org3", "repo3", "true", "1073741824", "1048576", "1074790400"}, rows[0][:7])
		assert.Equal(t, rows, repoCSV(t, "&sort=bogus"), "unknown sort keys fall back to reversesize")
		assert.Equal(t, rows, repoCSV(t, "&uid=0&sort=reversesize"), "uid=0 means all owners")

		rows = repoCSV(t, "&uid=2&sort=gitsize")
		assert.Len(t, rows, unittest.GetCount(t, &repo_model.Repository{OwnerID: 2}))
		for _, row := range rows {
			assert.Equal(t, "user2", row[1])
		}
	})

	t.Run("RepoJSON", func(t *testing.T) {
		defer test.MockVariableValue(&setting.UI.Admin.RepoPagingNum, 1)() // exports must not page
		rows := repoJSON(t, "&sort=reversesize")
		assert.Len(t, rows, unittest.GetCount(t, &repo_model.Repository{}))
		assert.Equal(t, repoRow{3, "org3", "repo3", true, 1 << 30, 1 << 20, 1<<30 + 1<<20, rows[0].Percent, 0, 0, 0, 0}, rows[0])
		assert.Positive(t, rows[0].Percent)

		rows = repoJSON(t, "&uid=2")
		assert.Len(t, rows, unittest.GetCount(t, &repo_model.Repository{OwnerID: 2}))
		for _, row := range rows {
			assert.Equal(t, "user2", row.OwnerName)
		}

		resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?format=json&uid=999999"), http.StatusOK)
		assert.Equal(t, "[]\n", resp.Body.String())
	})

	t.Run("RepoExportBadUID", func(t *testing.T) {
		admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?format=csv&uid=abc"), http.StatusBadRequest)
		admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?format=json&uid=2%20OR%201=1"), http.StatusBadRequest)
	})

	t.Run("RepoExportAbort", func(t *testing.T) {
		if !setting.Database.Type.IsSQLite3() {
			t.Skip("needs SQLite-specific SQL to force a mid-stream scan error")
		}
		// a num_stars that can't be scanned makes the query fail after the rows sorted before it were written
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET num_stars = 'x' WHERE id = 3")
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET num_stars = 0 WHERE id = 3")
			require.NoError(t, err)
		}()

		// the CSV writer buffers 4 KiB: pad the names so the first rows reach the client before the error
		_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET name = name || printf('%0300d', 0)")
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET name = substr(name, 1, length(name) - 300)")
			require.NoError(t, err)
		}()

		export := func(format string) *httptest.ResponseRecorder {
			req := NewRequest(t, "GET", "/admin/repos?sort=gitsize&format="+format).Request
			req.RemoteAddr = "test-mock:12345"
			baseURL, err := url.Parse(setting.AppURL)
			require.NoError(t, err)
			for _, c := range admin.jar.Cookies(baseURL) {
				req.AddCookie(c)
			}
			recorder := httptest.NewRecorder()
			assert.PanicsWithValue(t, http.ErrAbortHandler, func() { testWebRoutes.ServeHTTP(recorder, req) })
			return recorder
		}

		resp := export("csv")
		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Greater(t, strings.Count(resp.Body.String(), "\n"), 1, "header and at least one row")
		assert.NotContains(t, resp.Body.String(), "<html")

		resp = export("json")
		assert.Equal(t, http.StatusOK, resp.Code)
		assert.True(t, strings.HasPrefix(resp.Body.String(), `[{"repo_id":`))
		assert.False(t, json.Valid(resp.Body.Bytes()))
	})

	t.Run("RepoListOwnerFilter", func(t *testing.T) {
		resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?uid=2"), http.StatusOK)
		htmlDoc := NewHTMLParser(t, resp.Body)
		rows := htmlDoc.Find("table tbody tr")
		assert.Equal(t, unittest.GetCount(t, &repo_model.Repository{OwnerID: 2}), rows.Length())
		rows.Each(func(_ int, row *goquery.Selection) {
			assert.Equal(t, "user2", row.Find("td").Eq(1).Find("a").Text())
		})
		assert.Equal(t, 1, htmlDoc.Find("table tbody tr td a[href='/user2/repo2']").Length(), "private repos are listed")

		resp = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?sort=reversesize"), http.StatusOK)
		htmlDoc = NewHTMLParser(t, resp.Body)
		assert.Equal(t, "/org3/repo3", htmlDoc.Find("table tbody tr").First().Find("td").Eq(2).Find("a").AttrOr("href", ""))
	})

	t.Run("MedianAndRecalculation", func(t *testing.T) {
		totals, err := repo_model.GetStorageTotals(db.DefaultContext)
		require.NoError(t, err)
		median, err := repo_model.GetMedianRepoSize(db.DefaultContext, totals.NumRepos)
		require.NoError(t, err)

		resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/storage"), http.StatusOK)
		htmlDoc := NewHTMLParser(t, resp.Body)
		row := htmlDoc.Find("table tbody tr").FilterFunction(func(_ int, s *goquery.Selection) bool {
			return s.Find("td").First().Text() == "Median per repository"
		})
		assert.Equal(t, translation.NewLocale("en-US").TrSize(median).String(), row.Find("td").Eq(1).Text())
		recalc := htmlDoc.Find(".size-recalculation")
		assert.Contains(t, recalc.Text(), "git_gc_repos")
		assert.Equal(t, 1, recalc.Find("a[href='/admin/monitor/cron']").Length())
	})

	require.NoError(t, repo_model.UpdateRepoSize(db.DefaultContext, 1, 10, 2<<20, 0)) // user2/repo1
	require.NoError(t, repo_model.UpdateRepoSize(db.DefaultContext, 4, 5<<20, 0, 0))  // user5/repo4
	repoLinks := func(t *testing.T, query string) []string {
		t.Helper()
		resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?"+query), http.StatusOK)
		return NewHTMLParser(t, resp.Body).Find("table tbody tr td:nth-child(3) > a").Map(func(_ int, s *goquery.Selection) string {
			return s.AttrOr("href", "")
		})
	}

	t.Run("SizeFilter", func(t *testing.T) {
		assert.Equal(t, []string{"/user2/repo1", "/org3/repo3"}, repoLinks(t, "sizefield=lfs&minsize=1MiB&sort=reverselfssize"))
		assert.Equal(t, []string{"/org3/repo3", "/user2/repo1"}, repoLinks(t, "sizefield=lfs&minsize=1MiB&sort=lfssize"))
		assert.Equal(t, []string{"/org3/repo3"}, repoLinks(t, "sizefield=lfs&minsize=1MiB&maxsize=1.5MiB"))
		assert.Equal(t, []string{"/org3/repo3", "/user5/repo4"}, repoLinks(t, "sizefield=total&minsize=3MiB&sort=reversesize"))
		assert.Equal(t, []string{"/org3/repo3", "/user5/repo4"}, repoLinks(t, "sizefield=git&minsize=5+MB&sort=reversegitsize"))
		assert.Equal(t, []string{"/org3/repo3"}, repoLinks(t, "uid=3&sizefield=total&minsize=1MiB"))
		assert.Empty(t, repoLinks(t, "uid=2&sizefield=total&minsize=1GB"))

		// the exports honour the filter
		rows := repoCSV(t, "&sizefield=lfs&minsize=1MiB&sort=reverselfssize")
		require.Len(t, rows, 2)
		assert.Equal(t, []string{"1", "3"}, []string{rows[0][0], rows[1][0]})
		empty, err := db.GetEngine(db.DefaultContext).Where("git_size + lfs_size = 0").Count(new(repo_model.Repository))
		require.NoError(t, err)
		assert.Len(t, repoJSON(t, "&sizefield=total&maxsize=0"), int(empty))

		// the pager keeps the filter
		defer test.MockVariableValue(&setting.UI.Admin.RepoPagingNum, 1)()
		resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?sizefield=lfs&minsize=1MiB"), http.StatusOK)
		next := NewHTMLParser(t, resp.Body).Find(".pagination a.navigation").Last().AttrOr("href", "")
		assert.Contains(t, next, "sizefield=lfs")
		assert.Contains(t, next, "minsize=1MiB")
	})

	t.Run("SizeFilterInvalid", func(t *testing.T) {
		all := len(repoLinks(t, ""))
		for _, query := range []string{
			"sizefield=lfs&minsize=abc",
			"sizefield=evil&minsize=1",
			"sizefield=lfs&minsize=2MB&maxsize=1MB",
			"sizefield=git&minsize=-1",
			"sizefield=git&minsize=1%3BDROP+TABLE+repository",
			"minsize=1MB",
			"sizefield=git&maxsize=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
		} {
			resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?"+query), http.StatusOK)
			assert.NotContains(t, resp.Body.String(), "<script>alert(1)</script>", query)
			htmlDoc := NewHTMLParser(t, resp.Body)
			assert.Contains(t, htmlDoc.Find(".flash-error").Text(), "The size filter is invalid", query)
			assert.Len(t, htmlDoc.Find("table tbody tr td:nth-child(3) > a").Nodes, all, "%s lists the repositories unfiltered", query)

			admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?format=csv&"+query), http.StatusBadRequest)
			admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?format=json&"+query), http.StatusBadRequest)
		}
	})

	t.Run("HostileNames", func(t *testing.T) {
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET name = ?, lower_name = ? WHERE id = 1", `=HYPERLINK("http://evil")`, `=hyperlink("http://evil")`)
		require.NoError(t, err)
		_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET name = '-1+1', lower_name = '-1+1' WHERE id = 3")
		require.NoError(t, err)
		_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET name = '@cmd', lower_name = '@cmd' WHERE id = 3")
		require.NoError(t, err)
		_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET owner_name = '@cmd' WHERE owner_id = 3")
		require.NoError(t, err)

		resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/storage?format=csv"), http.StatusOK)
		rows, err := csv.NewReader(resp.Body).ReadAll()
		require.NoError(t, err)
		assert.Equal(t, "'@cmd", rows[1][0])

		rows = repoCSV(t, "&sort=reversesize")
		assert.Equal(t, []string{"3", "'@cmd", "'-1+1"}, rows[0][:3])
		names := map[string]string{}
		for _, row := range rows {
			names[row[0]] = row[2]
		}
		assert.Equal(t, `'=HYPERLINK("http://evil")`, names["1"])

		resp = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/storage?format=json"), http.StatusOK)
		var owners []*api.OwnerStorage
		DecodeJSON(t, resp, &owners)
		assert.Equal(t, "@cmd", owners[0].OwnerName)
		repos := repoJSON(t, "&sort=reversesize")
		assert.Equal(t, "@cmd", repos[0].OwnerName)
		assert.Equal(t, "-1+1", repos[0].RepoName)
	})

	t.Run("ExploreIgnoresOwnerFilter", func(t *testing.T) {
		links := func(url string) []string {
			resp := user.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK)
			return NewHTMLParser(t, resp.Body).Find(".flex-item-title a").Map(func(_ int, s *goquery.Selection) string {
				return s.AttrOr("href", "")
			})
		}
		want := links("/explore/repos")
		assert.NotEmpty(t, want)
		assert.Equal(t, want, links("/explore/repos?uid=5"))
	})
}

// AC1-AC4 of #124: wiki, attachment, artifact, log and trash sizes, and the recalculation.
func TestAdminStorageTypes(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		ctx := db.DefaultContext
		admin := loginUser(t, "user1")
		user2 := loginUser(t, "user2")
		repoSizes := func(t *testing.T, id int64) [3]int64 {
			t.Helper()
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: id})
			return [3]int64{repo.GitSize, repo.LFSSize, repo.WikiSize}
		}

		t.Run("WikiWebEdit", func(t *testing.T) {
			require.NoError(t, repo_model.UpdateRepoSize(ctx, 1, 1, 0, 0))
			user2.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/wiki/Home?action=_edit", map[string]string{
				"title":   "Home",
				"content": strings.Repeat("wiki ", 1000),
			}), http.StatusSeeOther)
			assert.Positive(t, repoSizes(t, 1)[2], "a web edit measures the wiki")
			assert.Greater(t, repoSizes(t, 1)[0], int64(1), "and the repository")
		})

		recalculate := func(t *testing.T, session *TestSession, owner string, status int) {
			t.Helper()
			session.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/storage/recalculate", map[string]string{"owner": owner}), status)
		}
		// unmeasured marks the repositories of an owner (all for 0) with a git size no measurement gives
		unmeasured := func(t *testing.T, ownerID int64) {
			t.Helper()
			_, err := db.GetEngine(ctx).Where("owner_id = ? OR ? = 0", ownerID, ownerID).Cols("git_size").Update(&repo_model.Repository{GitSize: -1})
			require.NoError(t, err)
		}
		// waitForRecalculation waits until the background task has measured every repository of the owner
		waitForRecalculation := func(t *testing.T, ownerID int64) {
			t.Helper()
			assert.Eventually(t, func() bool {
				return unittest.GetCount(t, &repo_model.Repository{}, builder.Expr("git_size = -1 AND (owner_id = ? OR ? = 0)", ownerID, ownerID)) == 0
			}, 30*time.Second, 50*time.Millisecond)
		}

		t.Run("RecalculateAfterWikiPush", func(t *testing.T) {
			before := repoSizes(t, 1)[2]
			wikiURL := *u
			wikiURL.Path = "user2/repo1.wiki.git"
			wikiURL.User = url.UserPassword("user2", userPassword)
			dst := t.TempDir()
			require.NoError(t, git.CloneWithArgs(t.Context(), nil, wikiURL.String(), dst, git.CloneRepoOptions{}))
			doGitSetRemoteURL(dst, "origin", &wikiURL)(t)
			generateCommitWithNewData(t, 64*1024, dst, "user2@example.com", "User Two", "big-page-")
			doGitPushTestRepository(dst, "origin", "master")(t)
			assert.Greater(t, repoSizes(t, 1)[2], before+60*1024, "a wiki git push measures the wiki (#491)")

			unmeasured(t, 2)
			unmeasured(t, 3) // org3: not recalculated
			recalculate(t, admin, "user2", http.StatusSeeOther)
			waitForRecalculation(t, 2)
			assert.Greater(t, repoSizes(t, 1)[2], before+60*1024, "the pushed wiki page is counted")
			assert.EqualValues(t, -1, repoSizes(t, 3)[0], "only the named owner is recalculated")
		})

		t.Run("RecalculateAll", func(t *testing.T) {
			unmeasured(t, 0)
			recalculate(t, admin, "", http.StatusSeeOther)
			waitForRecalculation(t, 0)
			assert.Positive(t, repoSizes(t, 3)[0])
		})

		t.Run("RecalculateRefused", func(t *testing.T) {
			recalculate(t, user2, "", http.StatusForbidden)
			recalculate(t, admin, "no-such-owner", http.StatusSeeOther)
			resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/storage"), http.StatusOK)
			assert.Contains(t, NewHTMLParser(t, resp.Body).Find(".flash-error").Text(), "There is no user or organization with this name.")

			func() {
				defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()
				recalculate(t, admin, "", http.StatusSeeOther)
				assertMaintenanceFlash(t, admin)
			}()
		})

		t.Run("DeleteWiki", func(t *testing.T) {
			require.Positive(t, repoSizes(t, 1)[2])
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
			require.NoError(t, wiki_service.DeleteWiki(ctx, repo))
			assert.Zero(t, repoSizes(t, 1)[2])
		})

		t.Run("TrashAndAssets", func(t *testing.T) {
			require.NoError(t, repo_model.UpdateRepoSize(ctx, 3, 1<<30, 0, 0))
			require.NoError(t, repo_model.UpdateRepoSize(ctx, 5, 3<<20, 0, 1<<20)) // org3, trashed
			_, err := db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 5")
			require.NoError(t, err)
			_, err = db.GetEngine(ctx).Exec("UPDATE attachment SET size = 2048 WHERE id = 1") // user2/repo1
			require.NoError(t, err)

			owners, _, err := repo_model.FindOwnerStorage(ctx, repo_model.FindOwnerStorageOptions{})
			require.NoError(t, err)
			byName := map[string]*repo_model.OwnerStorage{}
			for _, o := range owners {
				byName[o.Owner.Name] = o
			}
			assert.EqualValues(t, 4<<20, byName["org3"].TrashSize)
			assert.EqualValues(t, unittest.GetCount(t, &repo_model.Repository{OwnerID: 3})-1, byName["org3"].NumRepos)
			assert.EqualValues(t, 2048, byName["user2"].AttachmentsSize)
			assert.Positive(t, byName["user5"].ArtifactsSize)
			assert.Positive(t, byName["user5"].LogsSize)

			resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/storage?sort=reversetrashsize"), http.StatusOK)
			htmlDoc := NewHTMLParser(t, resp.Body)
			headers := htmlDoc.Find("table thead th").Map(func(_ int, s *goquery.Selection) string { return strings.TrimSpace(s.Text()) })
			assert.Equal(t, []string{"Owner", "Type", "Repositories", "Git", "LFS", "Wiki", "Attachments", "Packages", "Artifacts", "Logs", "Trash", "Total", "Share"}, headers)
			owner := htmlDoc.Find("table tbody tr td a[href^='/admin/repos?uid=']").First()
			assert.Equal(t, "org3", owner.Text(), "sorted by trash")
			assert.Equal(t, "4 MiB", owner.Closest("tr").Find("td").Eq(10).Text())

			summary := map[string]string{}
			htmlDoc.Find("table").First().Find("tr").Each(func(_ int, s *goquery.Selection) {
				summary[s.Find("td").First().Text()] = s.Find("td").Eq(1).Text()
			})
			totals, err := repo_model.GetStorageTotals(ctx)
			require.NoError(t, err)
			locale := translation.NewLocale("en-US")
			assert.Equal(t, locale.TrSize(totals.TrashSize).String(), summary["Trash"])
			assert.Equal(t, locale.TrSize(totals.ArtifactsSize).String(), summary["Actions artifacts"])
			assert.Equal(t, locale.TrSize(totals.Size()).String(), summary["Total"])

			resp = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos?uid=2"), http.StatusOK)
			assert.Equal(t, 1, NewHTMLParser(t, resp.Body).Find("table thead th:contains('Wiki size')").Length())
		})
	})
}
