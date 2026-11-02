// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/routers/common"
	dependency_service "forgejo.org/services/dependency"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secRows reads the rows of a result table as "cell | cell | …", whitespace squeezed.
func secRows(t *testing.T, resp *httptest.ResponseRecorder) []string {
	t.Helper()
	var rows []string
	NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).Find("table.security-search-table tbody tr").Each(func(_ int, tr *goquery.Selection) {
		var cells []string
		tr.Find("td").Each(func(_ int, td *goquery.Selection) {
			cells = append(cells, strings.Join(strings.Fields(td.Text()), " "))
		})
		rows = append(rows, strings.Join(cells, " | "))
	})
	return rows
}

// secText is the visible text of one element of the page, whitespace squeezed.
func secText(t *testing.T, resp *httptest.ResponseRecorder, selector string) string {
	t.Helper()
	return strings.Join(strings.Fields(NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).Find(selector).Text()), " ")
}

// secMain is the HTML of the page's main element (the footer's timings differ between requests).
func secMain(t *testing.T, resp *httptest.ResponseRecorder) string {
	t.Helper()
	html, err := NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).Find("div[role=main]").Html()
	require.NoError(t, err)
	return html
}

func secGet(t *testing.T, s *TestSession, path string, status int) *httptest.ResponseRecorder {
	t.Helper()
	return s.MakeRequest(t, NewRequest(t, "GET", path), status)
}

func TestOrgSecurityTab(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	newSearchFixture(t)
	const tab = `href="/org/org3/security"`
	hasTab := func(s *TestSession, path string) bool {
		return strings.Contains(secGet(t, s, path, http.StatusOK).Body.String(), tab)
	}

	t.Run("shown to an owner and a site admin, hidden from a member", func(t *testing.T) {
		for _, path := range []string{"/org3", "/org/org3/groups"} {
			assert.True(t, hasTab(loginUser(t, "user2"), path), "owner "+path)
			assert.True(t, hasTab(loginUser(t, "user1"), path), "site admin "+path)
			assert.False(t, hasTab(loginUser(t, "user4"), path), "member "+path)
			assert.False(t, hasTab(loginUser(t, "user8"), path), "stranger "+path)
			assert.NotContains(t, MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK).Body.String(), tab, "anonymous "+path)
		}
	})

	t.Run("the pages", func(t *testing.T) {
		owner := loginUser(t, "user2")
		resp := owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/security"), http.StatusSeeOther)
		assert.Equal(t, "/org/org3/security/vulnerabilities", resp.Header().Get("Location"))
		for _, p := range []string{"/org/org3/security/vulnerabilities", "/org/org3/security/dependencies"} {
			secGet(t, owner, p, http.StatusOK)
			secGet(t, loginUser(t, "user1"), p, http.StatusOK)
			secGet(t, loginUser(t, "user4"), p, http.StatusNotFound)     // a member
			secGet(t, loginUser(t, "user8"), p, http.StatusNotFound)     // not a member of a public organization
			MakeRequest(t, NewRequest(t, "GET", p), http.StatusSeeOther) // anonymous: to the sign-in page
			// a private organization hides itself
			secGet(t, loginUser(t, "user2"), strings.Replace(p, "org3", "privated_org", 1), http.StatusNotFound)
		}
		secGet(t, loginUser(t, "user4"), "/org/org3/security", http.StatusNotFound)
	})

	t.Run("hidden while the graph is off", func(t *testing.T) {
		owner := loginUser(t, "user2")
		off := func(t *testing.T) {
			t.Helper()
			assert.False(t, hasTab(owner, "/org3"))
			for _, p := range []string{"/org/org3/security", "/org/org3/security/vulnerabilities", "/org/org3/security/dependencies"} {
				secGet(t, owner, p, http.StatusNotFound) // owners too
				secGet(t, loginUser(t, "user1"), p, http.StatusNotFound)
			}
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/security/dependencies/export", map[string]string{"format": "csv"}), http.StatusNotFound)
		}
		t.Run("for the organization", func(t *testing.T) {
			require.NoError(t, user_model.SetUserSetting(t.Context(), 3, repo_model.DependencyGraphOrgKey, "false"))
			off(t)
			require.NoError(t, user_model.SetUserSetting(t.Context(), 3, repo_model.DependencyGraphOrgKey, "true"))
			assert.True(t, hasTab(owner, "/org3"))
		})
		t.Run("for the instance", func(t *testing.T) {
			defer test.MockVariableValue(&setting.DependencyGraph.Enabled, false)()
			off(t)
		})
	})
}

func TestOrgSecurityPages(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := newSearchFixture(t)
	owner := loginUser(t, "user2")
	const vulns, deps = "/org/org3/security/vulnerabilities", "/org/org3/security/dependencies"

	t.Run("vulnerabilities by advisory", func(t *testing.T) {
		resp := secGet(t, owner, vulns+"?advisory=CVE-2024-1111&state=all", http.StatusOK)
		assert.Equal(t, []string{
			"org3/repo21 | npm lodash 3.9.0 | Fixed in: 4.17.21 | in a-old/package-lock.json | State: Open",
			"org3/repo3 | npm lodash 4.17.20 | Fixed in: 4.17.21 | in package-lock.json | State: Open",
			"org3/repo3 | npm lodash ^4.0.0 | Fixed in: 4.17.21 | in package.json | State: Open",
			"org3/repo5 | npm lodash 3.10.1 | Fixed in: 4.17.21 | in package-lock.json | State: Open",
		}, secRows(t, resp))
		assert.Equal(t, "4 alerts in 3 repositories", secText(t, resp, "#security-search-total"))
		assert.Equal(t, "High GHSA-aaaa-bbbb-cccc in lodash GHSA-aaaa-bbbb-cccc · CVE-2024-1111 · CVSS 7.5", secText(t, resp, ".security-search-card"))
		// each state links the repository's alert page
		var link string
		NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).Find("table.security-search-table tbody tr").First().Find("a").Last().Each(func(_ int, a *goquery.Selection) { link, _ = a.Attr("href") })
		assert.Regexp(t, `^/org3/repo21/security/alerts/\d+$`, link)

		// a project filter, and a project's repositories are named with it
		resp = secGet(t, owner, vulns+"?advisory=CVE-2023-2222&project=dep-proj&state=all", http.StatusOK)
		assert.Equal(t, []string(nil), secRows(t, resp), "the project's only repository is not affected")
		resp = secGet(t, owner, vulns+"?ecosystem=npm&name=lodash&project=nobody", http.StatusOK)
		assert.Contains(t, secText(t, resp, ".info.message"), "No repository in org3 matches this search.")
	})

	t.Run("vulnerabilities by package", func(t *testing.T) {
		resp := secGet(t, owner, vulns+"?ecosystem=npm&name=lodash&version=3.10.1", http.StatusOK)
		rows := secRows(t, resp)
		require.NotEmpty(t, rows)
		for _, r := range rows {
			assert.True(t, strings.HasPrefix(r, "org3/repo5 | npm lodash 3.10.1 |"), r)
		}
		assert.Empty(t, NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).Find(".security-search-card").Nodes, "no card without an advisory")
	})

	t.Run("dependencies", func(t *testing.T) {
		resp := secGet(t, owner, deps+"?ecosystem=npm&name=lodash", http.StatusOK)
		assert.Equal(t, []string{
			"org3/dep-proj/leaf | Version: 4.17.21 | in package-lock.json | Direct: Yes",
			"org3/repo21 | Version: 3.9.0 | in a-old/package-lock.json | Direct: No",
			"org3/repo21 | Version: 4.17.21 | in package-lock.json | Direct: Yes",
			"org3/repo3 | Version: 4.17.20 | in package-lock.json | Direct: No",
			"org3/repo3 | Version: ^4.0.0 | in package.json | Direct: Yes",
			"org3/repo5 | Version: 3.10.1 | in package-lock.json | Direct: Yes",
		}, secRows(t, resp))
		assert.Equal(t, "6 uses in 4 repositories", secText(t, resp, "#security-search-total"))

		resp = secGet(t, owner, deps+"?ecosystem=npm&name=lodash&version=4.17.21", http.StatusOK)
		assert.Len(t, secRows(t, resp), 2)

		resp = secGet(t, owner, deps+"?ecosystem=npm&name=lodash&version="+url.QueryEscape("^4.17.0"), http.StatusOK)
		rows := secRows(t, resp)
		assert.Len(t, rows, 4)
		assert.Contains(t, rows, "org3/repo3 | Version: ^4.0.0 may match | in package.json | Direct: Yes")
		assert.Equal(t, "4 uses in 3 repositories", secText(t, resp, "#security-search-total"))

		// an operator makes it a range (and finds the rows), a plain version is matched as written
		resp = secGet(t, owner, deps+"?ecosystem=npm&name=lodash&version="+url.QueryEscape("=4.17.21"), http.StatusOK)
		assert.Contains(t, secRows(t, resp), "org3/repo21 | Version: 4.17.21 | in package-lock.json | Direct: Yes")
		assert.Empty(t, secRows(t, secGet(t, owner, deps+"?ecosystem=npm&name=lodash&version=4.17", http.StatusOK)), "4.17 is a version no row has")

		resp = secGet(t, owner, deps+"?ecosystem=npm&name=lodash&direct=true", http.StatusOK)
		assert.Len(t, secRows(t, resp), 4)
		assert.Contains(t, resp.Body.String(), `name="direct" value="true" checked`)

		resp = secGet(t, owner, deps+"?ecosystem=npm&name=lodash&project=dep-proj", http.StatusOK)
		assert.Equal(t, []string{"org3/dep-proj/leaf | Version: 4.17.21 | in package-lock.json | Direct: Yes"}, secRows(t, resp))
		assert.Contains(t, resp.Body.String(), `<option value="dep-proj" selected>`)
		assert.Contains(t, resp.Body.String(), `href="/org3/dep-proj/leaf"`)
	})

	t.Run("paging keeps the filters", func(t *testing.T) {
		defer test.MockVariableValue(&setting.UI.IssuePagingNum, 2)()
		resp := secGet(t, owner, deps+"?ecosystem=npm&name=lodash&direct=true", http.StatusOK)
		assert.Len(t, secRows(t, resp), 2)
		var next string
		NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).Find(".pagination a.item").Each(func(_ int, a *goquery.Selection) {
			if h, _ := a.Attr("href"); strings.Contains(h, "page=2") && next == "" {
				next = h
			}
		})
		require.NotEmpty(t, next)
		for _, kv := range []string{"ecosystem=npm", "name=lodash", "direct=true"} {
			assert.Contains(t, next, kv)
		}
		resp = secGet(t, owner, next, http.StatusOK)
		assert.Len(t, secRows(t, resp), 2)
		assert.Equal(t, "4 uses in 4 repositories", secText(t, resp, "#security-search-total"))
	})

	t.Run("states", func(t *testing.T) {
		// before a search: the hint, and no search is run (the count is that of a page that searches, less)
		empty := secGet(t, owner, vulns, http.StatusOK)
		assert.Contains(t, secText(t, empty, ".ui.message"), "Search for an advisory")
		assert.Empty(t, secRows(t, empty))
		_ = secGet(t, owner, deps, http.StatusOK)
		withoutSearch := countQueries(t, func() { secGet(t, owner, vulns+"?state=all", http.StatusOK) })
		withSearch := countQueries(t, func() { secGet(t, owner, vulns+"?advisory=CVE-2024-1111&state=all", http.StatusOK) })
		assert.Greater(t, withSearch, withoutSearch)

		// nothing matches: an advisory that is unknown and one nothing uses give the same page
		unaffected := secGet(t, owner, vulns+"?advisory=GHSA-cccc-dddd-eeee", http.StatusOK)
		var unknown *httptest.ResponseRecorder
		assert.Contains(t, secText(t, unaffected, ".info.message"), `No repository in org3 has an open alert for GHSA-cccc-dddd-eeee. Clear the search`)
		unknown = secGet(t, owner, vulns+"?advisory=GHSA-zzzz-zzzz-zzzz", http.StatusOK)
		assert.Equal(t, strings.ReplaceAll(secMain(t, unaffected), "GHSA-cccc-dddd-eeee", "GHSA-zzzz-zzzz-zzzz"), secMain(t, unknown))
		all := secGet(t, owner, vulns+"?advisory=GHSA-cccc-dddd-eeee&state=all", http.StatusOK)
		assert.Contains(t, secText(t, all, ".info.message"), "No repository in org3 is affected by GHSA-cccc-dddd-eeee. Clear the search")
		assert.Empty(t, NewHTMLParser(t, bytes.NewBufferString(unaffected.Body.String())).Find(".security-search-card").Nodes)

		// forms that name nothing run no search: the same page costs less without the fields that name something. A
		// reading can catch a stray query of another goroutine, so each is repeated until two agree.
		stable := func(path string) int64 {
			prev := int64(-1)
			for range 10 {
				n := countQueries(t, func() { secGet(t, owner, path, http.StatusOK) })
				if n == prev {
					return n
				}
				prev = n
			}
			return prev
		}
		_ = secGet(t, owner, deps, http.StatusOK)
		blank := stable(deps + "?ecosystem=npm&direct=true")
		searched := stable(deps + "?ecosystem=npm&direct=true&name=lodash")
		assert.Less(t, blank, searched)
		assert.Equal(t, blank, stable(deps+"?ecosystem=npm&direct=true&state=all"))

		// a name with "Any" ecosystem searches every ecosystem, a version without a name marks the package, advisory or not
		for _, q := range []string{"?name=lodash", "?advisory=CVE-2024-1111&name=lodash"} {
			resp := secGet(t, owner, vulns+q, http.StatusOK)
			assert.Empty(t, NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).Find(".negative.message").Nodes, q)
			assert.NotEmpty(t, secRows(t, resp), q)
		}
		for _, q := range []string{"?version=1.0.0", "?advisory=CVE-2024-1111&version=1.0.0", "?ecosystem=npm&advisory=CVE-2024-1111&version=1.0.0"} {
			resp := secGet(t, owner, vulns+q, http.StatusOK)
			assert.Equal(t, "Enter a package name.", secText(t, resp, ".negative.message"), q)
			assert.Contains(t, resp.Body.String(), `<input name="name" value="" maxlength="512" placeholder="e.g. lodash" aria-invalid="true"`, q)
		}

		// a package without an ecosystem marks the ecosystem, a version alone marks the package
		resp := secGet(t, owner, deps+"?name=lodash", http.StatusOK)
		assert.Equal(t, "Choose an ecosystem.", secText(t, resp, ".negative.message"))
		assert.Contains(t, resp.Body.String(), `<select name="ecosystem" aria-invalid="true" aria-describedby="security-search-error">`)
		assert.Contains(t, resp.Body.String(), `<option value="" selected>Choose an ecosystem</option>`)

		// a long wrong value is cut in the message
		resp = secGet(t, owner, vulns+"?advisory="+strings.Repeat("a", 40)+"%20"+strings.Repeat("b", 100), http.StatusOK)
		assert.NotContains(t, secText(t, resp, ".negative.message"), strings.Repeat("b", 30))

		// invalid input marks the field
		resp = secGet(t, owner, vulns+"?advisory="+url.QueryEscape("CVE 2026"), http.StatusOK)
		assert.Equal(t, `"CVE 2026" is not an advisory ID. Use an ID such as CVE-2026-12345, GHSA-xxxx-xxxx-xxxx or PYSEC-2026-123.`, secText(t, resp, ".negative.message"))
		assert.Contains(t, resp.Body.String(), `<label class="security-search-wide invalid">`)
		assert.Contains(t, resp.Body.String(), `aria-invalid="true"`)
		resp = secGet(t, owner, deps+"?ecosystem=npm&name=lodash&version="+url.QueryEscape(">=x y"), http.StatusOK)
		assert.Contains(t, secText(t, resp, ".negative.message"), "is not a version range")
		resp = secGet(t, owner, deps+"?ecosystem=npm&version=1.0.0", http.StatusOK)
		assert.Equal(t, "Enter a package name.", secText(t, resp, ".negative.message"))
		resp = secGet(t, owner, vulns+"?state=bogus&advisory=CVE-2024-1111", http.StatusOK)
		assert.Equal(t, "Choose one of the listed states.", secText(t, resp, ".negative.message"))

		// too broad
		defer test.MockVariableValue(&dependency_service.MaxUsageCandidates, 2)()
		resp = secGet(t, owner, deps+"?ecosystem=npm&name=lodash&version="+url.QueryEscape("^4"), http.StatusOK)
		assert.Equal(t, "More than 2 matches. Choose a project or narrow the search.", secText(t, resp, ".warning.message"))
		assert.Empty(t, secRows(t, resp))
		assert.Contains(t, resp.Body.String(), `class="ui warning message" role="alert"`)
	})

	t.Run("hidden repositories are never shown", func(t *testing.T) {
		q := "?ecosystem=npm&name=lodash&state=all"
		listed := func(repo *repo_model.Repository) (inDeps, inVulns bool) {
			for _, p := range []string{deps + q, vulns + q} {
				found := false
				for _, r := range secRows(t, secGet(t, owner, p, http.StatusOK)) {
					found = found || strings.HasPrefix(r, repo.FullName()+" |")
				}
				if p == deps+q {
					inDeps = found
				} else {
					inVulns = found
				}
			}
			return inDeps, inVulns
		}
		in, iv := listed(f.repo5)
		assert.True(t, in && iv)
		exec := func(query string, args ...any) {
			t.Helper()
			_, err := db.GetEngine(t.Context()).Exec(append([]any{query}, args...)...)
			require.NoError(t, err)
		}
		exec("UPDATE repository SET trashed_unix = 1 WHERE id = ?", f.repo5.ID)
		in, iv = listed(f.repo5)
		assert.False(t, in || iv, "trashed")
		exec("UPDATE repository SET trashed_unix = 0 WHERE id = ?", f.repo5.ID)
		require.NoError(t, db.Insert(t.Context(), &repo_model.OrgUnit{OrgID: 3, Type: unit.TypeCode, Disabled: true}))
		in, iv = listed(f.repo3)
		assert.False(t, in || iv, "Code hidden")
		_, err := db.DeleteByBean(t.Context(), &repo_model.OrgUnit{OrgID: 3, Type: unit.TypeCode})
		require.NoError(t, err)
		exec("UPDATE repository SET dependency_graph_disabled = ? WHERE id = ?", true, f.repo3.ID)
		in, iv = listed(f.repo3)
		assert.False(t, in || iv, "graph off for the repository")
		exec("UPDATE repository SET dependency_graph_disabled = ? WHERE id = ?", false, f.repo3.ID)
		in, iv = listed(f.repo3)
		assert.True(t, in && iv)
	})
}

func TestAdminSecurityPages(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := newSearchFixture(t)
	audit_model.ResetActivity()
	const vulns, deps = "/admin/config/dependency-graph/vulnerabilities", "/admin/config/dependency-graph/dependencies"
	admin := loginUser(t, "user1")
	setUserFlag(t, 8, "is_auditor", true)

	t.Run("who may open them", func(t *testing.T) {
		for _, p := range []string{vulns, deps} {
			secGet(t, admin, p, http.StatusOK)
			secGet(t, loginUser(t, "user8"), p, http.StatusOK)        // the auditor
			secGet(t, loginUser(t, "user2"), p, http.StatusForbidden) // an organization owner
			secGet(t, loginUser(t, "user4"), p, http.StatusForbidden)
			MakeRequest(t, NewRequest(t, "GET", p), http.StatusSeeOther)
		}
	})

	t.Run("rows, the owner filter and the nav", func(t *testing.T) {
		resp := secGet(t, admin, vulns+"?advisory=CVE-2024-1111&state=all", http.StatusOK)
		rows := secRows(t, resp)
		require.NotEmpty(t, rows)
		assert.Contains(t, rows, "Owner: org3 | org3/repo5 | npm lodash 3.10.1 | Fixed in: 4.17.21 | in package-lock.json | State: Open")
		assert.Regexp(t, `^\d+ alerts in \d+ repositories in 2 owners$`, secText(t, resp, "#security-search-total"))
		assert.Contains(t, secText(t, resp, ".security-search-card"), "GHSA-aaaa-bbbb-cccc")
		assert.Contains(t, resp.Body.String(), `href="/admin/config/dependency-graph/dependencies"`)
		resp = secGet(t, admin, vulns+"?advisory=CVE-2024-1111&state=all&owner=org17", http.StatusOK)
		for _, r := range secRows(t, resp) {
			assert.True(t, strings.HasPrefix(r, "Owner: org17 | org17/"), r)
		}
		assert.Contains(t, secText(t, resp, "#security-search-total"), "in 1 owner")

		resp = secGet(t, loginUser(t, "user8"), deps+"?ecosystem=npm&name=lodash", http.StatusOK)
		assert.Len(t, secRows(t, resp), 7)
		assert.Equal(t, "7 uses in 5 repositories in 2 owners", secText(t, resp, "#security-search-total"))
		resp = secGet(t, admin, deps+"?ecosystem=npm&name=lodash&owner=nobody", http.StatusOK)
		assert.Contains(t, secText(t, resp, ".info.message"), "No repository on this instance matches this search.")
		resp = secGet(t, admin, deps+"?ecosystem=npm&name=lodash&version="+url.QueryEscape("^4.17.0"), http.StatusOK)
		assert.Contains(t, secText(t, resp, "#security-search-total"), "in 2 owners")
	})

	t.Run("a search is recorded, an empty form is not", func(t *testing.T) {
		audit_model.ResetActivity() // the first search of a kind in a minute is written at once
		since := auditMaxID(t)
		secGet(t, admin, vulns, http.StatusOK)
		secGet(t, admin, deps+"?ecosystem=npm", http.StatusOK)
		assert.Empty(t, auditActions(t, since, "activity.dependency_graph.searched"))
		secGet(t, admin, deps+"?ecosystem=npm&name=lodash&owner=org3", http.StatusOK)
		e := auditActivity(t, since, "activity.dependency_graph.searched")
		assert.EqualValues(t, 1, e.ActorID)
		data := auditData(t, e)
		assert.Equal(t, "dependencies", data["kind"])
		assert.Equal(t, "org3", data["owner"])
		assert.EqualValues(t, 6, data["total"])
	})

	t.Run("hidden repositories are never shown", func(t *testing.T) {
		exec := func(query string, args ...any) {
			t.Helper()
			_, err := db.GetEngine(t.Context()).Exec(append([]any{query}, args...)...)
			require.NoError(t, err)
		}
		shown := func(repo *repo_model.Repository) bool {
			for _, p := range []string{deps, vulns} {
				for _, r := range secRows(t, secGet(t, admin, p+"?ecosystem=npm&name=lodash&state=all", http.StatusOK)) {
					if strings.Contains(r, repo.FullName()+" |") {
						return true
					}
				}
			}
			return false
		}
		assert.True(t, shown(f.repo5))
		assert.True(t, shown(f.repo3))
		exec("UPDATE repository SET trashed_unix = 1 WHERE id = ?", f.repo5.ID)
		assert.False(t, shown(f.repo5), "trashed")
		exec("UPDATE repository SET trashed_unix = 0 WHERE id = ?", f.repo5.ID)
		require.NoError(t, db.Insert(t.Context(), &repo_model.OrgUnit{OrgID: 3, Type: unit.TypeCode, Disabled: true}))
		assert.False(t, shown(f.repo3), "Code hidden")
		_, err := db.DeleteByBean(t.Context(), &repo_model.OrgUnit{OrgID: 3, Type: unit.TypeCode})
		require.NoError(t, err)
		exec("UPDATE repository SET dependency_graph_disabled = ? WHERE id = ?", true, f.repo3.ID)
		assert.False(t, shown(f.repo3), "graph off for the repository")
		exec("UPDATE repository SET dependency_graph_disabled = ? WHERE id = ?", false, f.repo3.ID)
		assert.True(t, shown(f.repo3))
	})

	t.Run("states", func(t *testing.T) {
		resp := secGet(t, admin, deps+"?ecosystem=npm&name=lodash&version="+url.QueryEscape(">=x y"), http.StatusOK)
		assert.Contains(t, secText(t, resp, ".negative.message"), "is not a version range")
		resp = secGet(t, admin, vulns+"?advisory="+url.QueryEscape("CVE 2026"), http.StatusOK)
		assert.Contains(t, secText(t, resp, ".negative.message"), "is not an advisory ID")
		resp = secGet(t, admin, vulns+"?advisory=GHSA-cccc-dddd-eeee", http.StatusOK)
		assert.Contains(t, secText(t, resp, ".info.message"), `No repository on this instance has an open alert for GHSA-cccc-dddd-eeee.`)
		defer test.MockVariableValue(&dependency_service.MaxUsageCandidates, 2)()
		resp = secGet(t, admin, deps+"?ecosystem=npm&name=lodash&version="+url.QueryEscape("^4"), http.StatusOK)
		assert.Equal(t, "More than 2 matches. Choose an owner or narrow the search.", secText(t, resp, ".warning.message"))
	})

	t.Run("the menu links to the pages while they exist", func(t *testing.T) {
		body := secGet(t, admin, "/admin/config/dependency-graph", http.StatusOK).Body.String()
		assert.Contains(t, body, `href="/admin/config/dependency-graph/vulnerabilities"`)
		assert.Contains(t, body, `href="/admin/config/dependency-graph/dependencies"`)
	})

	t.Run("the instance switch is off", func(t *testing.T) {
		defer test.MockVariableValue(&setting.DependencyGraph.Enabled, false)()
		since := auditMaxID(t)
		for _, p := range []string{vulns, deps} {
			secGet(t, admin, p+"?ecosystem=npm&name=lodash", http.StatusNotFound)
			secGet(t, loginUser(t, "user8"), p, http.StatusNotFound)
			secGet(t, loginUser(t, "user2"), p, http.StatusForbidden) // the gate comes first
			admin.MakeRequest(t, NewRequestWithValues(t, "POST", p+"/export", map[string]string{"format": "csv", "ecosystem": "npm", "name": "lodash"}), http.StatusNotFound)
		}
		assert.Empty(t, auditActions(t, since, "activity.dependency_graph.searched"))
		assert.Empty(t, auditActions(t, since, "admin.dependency_graph.exported"))
		// the menu does not link to pages that answer 404
		assert.NotContains(t, secGet(t, admin, "/admin/config/dependency-graph", http.StatusOK).Body.String(), `href="/admin/config/dependency-graph/vulnerabilities"`)
	})
}

func TestSecurityPagesExport(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	newSearchFixture(t)
	audit_model.ResetActivity()
	owner, admin := loginUser(t, "user2"), loginUser(t, "user1")
	setUserFlag(t, 8, "is_auditor", true)
	today := time.Now().UTC().Format("2006-01-02")
	const orgDeps, orgVulns = "/org/org3/security/dependencies", "/org/org3/security/vulnerabilities"
	const adminDeps, adminVulns = "/admin/config/dependency-graph/dependencies", "/admin/config/dependency-graph/vulnerabilities"
	post := func(t *testing.T, s *TestSession, path, format string, values map[string]string, status int) *httptest.ResponseRecorder {
		t.Helper()
		values["format"] = format
		return s.MakeRequest(t, NewRequestWithValues(t, "POST", path+"/export", values), status)
	}
	dep := map[string]string{"ecosystem": "npm", "name": "lodash"}
	vul := map[string]string{"advisory": "CVE-2024-1111", "state": "all"}
	clone := maps.Clone[map[string]string]

	t.Run("the buttons post the filters", func(t *testing.T) {
		resp := secGet(t, owner, orgVulns+"?advisory=CVE-2024-1111&state=all&ecosystem=npm", http.StatusOK)
		form := NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).Find(`form[action$="/export"]`)
		action, _ := form.Attr("action")
		assert.Equal(t, orgVulns+"/export", action)
		var names []string
		form.Find("input[type=hidden]").Each(func(_ int, i *goquery.Selection) {
			n, _ := i.Attr("name")
			names = append(names, n)
		})
		assert.ElementsMatch(t, []string{"advisory", "state", "ecosystem"}, names)
		assert.Equal(t, 2, form.Find(`button[name="format"]`).Length())
	})

	t.Run("csv and json with the file headers and an audit entry", func(t *testing.T) {
		for _, c := range []struct {
			s                *TestSession
			path, owner, act string
			rows             int
			actorID          int64
		}{{owner, orgDeps, "org3", "org.dependency_graph.exported", 6, 2}, {admin, adminDeps, "instance", "admin.dependency_graph.exported", 7, 1}, {loginUser(t, "user8"), adminDeps, "instance", "admin.dependency_graph.exported", 7, 8}} {
			since := auditMaxID(t)
			resp := post(t, c.s, c.path, "csv", clone(dep), http.StatusOK)
			assert.Equal(t, "text/csv; charset=utf-8", resp.Header().Get("Content-Type"))
			assert.Equal(t, "nosniff", resp.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, "no-store", resp.Header().Get("Cache-Control"))
			assert.Contains(t, resp.Header().Get("Content-Disposition"), `attachment; filename="dependencies-`+c.owner+"-"+today+`.csv"`)
			records, err := csv.NewReader(resp.Body).ReadAll()
			require.NoError(t, err)
			require.Len(t, records, c.rows+1)
			assert.Equal(t, []string{"repository", "ecosystem", "name", "version", "requirement", "manifest", "direct", "uncertain"}, records[0])
			resp = post(t, c.s, c.path, "json", clone(dep), http.StatusOK)
			assert.Equal(t, "application/json; charset=utf-8", resp.Header().Get("Content-Type"))
			assert.Contains(t, resp.Header().Get("Content-Disposition"), `.json"`)
			entries := auditActions(t, since, c.act)
			require.Len(t, entries, 2)
			assert.Equal(t, map[string]any{"kind": "dependencies", "format": "csv", "ecosystem": "npm", "name": "lodash", "count": float64(c.rows)}, auditData(t, entries[0]))
			assert.Equal(t, audit_model.ActorUser, entries[0].ActorType)
			assert.Equal(t, c.actorID, entries[0].ActorID)
		}
		resp := post(t, owner, orgVulns, "csv", clone(vul), http.StatusOK)
		assert.Contains(t, resp.Header().Get("Content-Disposition"), `vulnerability-alerts-org3-`+today+`.csv"`)
		records, err := csv.NewReader(resp.Body).ReadAll()
		require.NoError(t, err)
		assert.Len(t, records, 5)
		resp = post(t, admin, adminVulns, "json", clone(vul), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "GHSA-aaaa-bbbb-cccc")
	})

	t.Run("the same file as the API", func(t *testing.T) {
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository)
		api := MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/dependencies?ecosystem=npm&name=lodash&format=csv").AddTokenAuth(token), http.StatusOK)
		assert.Equal(t, api.Body.String(), post(t, owner, orgDeps, "csv", clone(dep), http.StatusOK).Body.String())
	})

	t.Run("who may post", func(t *testing.T) {
		since := auditMaxID(t)
		post(t, loginUser(t, "user4"), orgDeps, "csv", clone(dep), http.StatusNotFound)
		post(t, loginUser(t, "user2"), adminDeps, "csv", clone(dep), http.StatusForbidden)
		post(t, loginUser(t, "user4"), adminVulns, "csv", clone(vul), http.StatusForbidden)
		MakeRequest(t, NewRequestWithValues(t, "POST", orgDeps+"/export", map[string]string{"format": "csv"}), http.StatusSeeOther)
		assert.Empty(t, auditActions(t, since, "org.dependency_graph.exported"))
		assert.Empty(t, auditActions(t, since, "admin.dependency_graph.exported"))
	})

	t.Run("a cross-origin post is refused", func(t *testing.T) {
		since := auditMaxID(t)
		for _, path := range []string{orgDeps, orgVulns} {
			req := NewRequestWithValues(t, "POST", path+"/export", map[string]string{"format": "csv", "ecosystem": "npm", "name": "lodash", "advisory": "CVE-2024-1111"})
			req.Header.Set("Sec-Fetch-Site", "cross-site")
			owner.MakeRequest(t, req, http.StatusForbidden)
		}
		req := NewRequestWithValues(t, "POST", adminDeps+"/export", map[string]string{"format": "csv", "ecosystem": "npm", "name": "lodash"})
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		admin.MakeRequest(t, req, http.StatusForbidden)
		assert.Empty(t, auditActions(t, since, "org.dependency_graph.exported"))
		assert.Empty(t, auditActions(t, since, "admin.dependency_graph.exported"))
	})

	t.Run("a refusal goes back to the page with a message and records nothing", func(t *testing.T) {
		refused := func(s *TestSession, path, format string, values map[string]string, want string) {
			t.Helper()
			since := auditMaxID(t)
			resp := post(t, s, path, format, values, http.StatusSeeOther)
			loc := resp.Header().Get("Location")
			assert.True(t, strings.HasPrefix(loc, path+"?"), loc)
			assert.Empty(t, resp.Header().Get("Content-Disposition"))
			assert.Empty(t, resp.Header().Get("Content-Type"))
			page := s.MakeRequest(t, NewRequest(t, "GET", loc), http.StatusOK)
			assert.Contains(t, secText(t, page, ".flash-message"), want)
			assert.Empty(t, auditActions(t, since, "org.dependency_graph.exported"))
			assert.Empty(t, auditActions(t, since, "admin.dependency_graph.exported"))
		}
		t.Run("too many rows", func(t *testing.T) {
			defer test.MockVariableValue(&dependency_service.MaxExportRows, 2)()
			refused(owner, orgDeps, "csv", clone(dep), "More than 2 rows match. Narrow the search to download it.")
			refused(admin, adminVulns, "json", clone(vul), "More than 2 rows match")
		})
		t.Run("no free slot", func(t *testing.T) {
			release, ok := common.TakeExportSlot(2)
			require.True(t, ok)
			defer release()
			refused(owner, orgDeps, "csv", clone(dep), "Too many downloads are running.")
		})
		t.Run("a filter that is wrong", func(t *testing.T) {
			refused(owner, orgVulns, "csv", map[string]string{"advisory": "CVE 2026"}, "The search is not valid.")
		})
		t.Run("an unknown format", func(t *testing.T) {
			refused(owner, orgDeps, "xml", clone(dep), "The search is not valid.")
		})
		t.Run("too many candidates", func(t *testing.T) {
			defer test.MockVariableValue(&dependency_service.MaxUsageCandidates, 2)()
			r := clone(dep)
			r["version"] = "^4"
			refused(owner, orgDeps, "csv", r, "More than 2 matches. Choose a project or narrow the search.")
		})
		t.Run("a failed audit insert", func(t *testing.T) {
			defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error { return errors.New("audit down") })()
			since := auditMaxID(t)
			resp := post(t, owner, orgDeps, "csv", clone(dep), http.StatusInternalServerError)
			assert.Empty(t, resp.Header().Get("Content-Disposition"))
			assert.NotContains(t, resp.Body.String(), "lodash")
			assert.Empty(t, auditActions(t, since, "org.dependency_graph.exported"))
		})
	})

	t.Run("an archived organization still downloads", func(t *testing.T) {
		_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET is_archived = ? WHERE id = 3", true)
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET is_archived = ? WHERE id = 3", false)
			require.NoError(t, err)
		}()
		secGet(t, owner, orgDeps, http.StatusOK)
		post(t, owner, orgDeps, "csv", clone(dep), http.StatusOK)
		post(t, owner, orgVulns, "json", clone(vul), http.StatusOK)
	})

	assertExportSlotsFree(t)
}
