// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	perm_model "forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	vulnerability_model "forgejo.org/models/vulnerability"
	"forgejo.org/modules/dependency"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/modules/vulnerability"
	"forgejo.org/routers/common"
	dependency_service "forgejo.org/services/dependency"
	org_service "forgejo.org/services/org"
	vulnerability_service "forgejo.org/services/vulnerability"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// searchFixture is org3 with a private repository (3), another private one (5), a public one (32, org3/repo21) and
// one in a project, and org17's public repository (23), all using lodash; org3/repo3 and repo5 also use PyPI
// packages. Advisories for lodash are imported and matched.
type searchFixture struct {
	repo3, repo5, repo21, leaf, other *repo_model.Repository
	project                           *repo_model.RepoGroup
}

func searchDep(eco, name, version, requirement, manifest string, direct bool) *repo_model.Dependency {
	return &repo_model.Dependency{Ecosystem: eco, Name: name, Version: version, Requirement: requirement, ManifestPath: manifest, Direct: direct}
}

func newSearchFixture(t *testing.T) *searchFixture {
	t.Helper()
	enableDependencyGraph(t)
	sys := audit_model.WithSystem(db.DefaultContext, "test")
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	f := &searchFixture{}
	var err error
	f.project, err = repo_model.CreateRepoGroup(sys, org3, "dep-proj", "")
	require.NoError(t, err)
	f.leaf = depNewRepo(t, org3, user2, "leaf", true, f.project.ID)
	f.repo3 = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	f.repo5 = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 5})
	f.repo21 = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 32})
	f.other = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 23})

	storeScanAt(t, f.repo3, strings.Repeat("a", 40),
		searchDep(dependency.NPM, "lodash", "4.17.20", "", "package-lock.json", false),
		searchDep(dependency.NPM, "lodash", "", "^4.0.0", "package.json", true),
		searchDep(dependency.PyPI, "Foo_Bar", "2.1.0", "", "requirements.txt", true))
	storeScanAt(t, f.repo5, strings.Repeat("a", 40),
		searchDep(dependency.NPM, "lodash", "3.10.1", "", "package-lock.json", true),
		searchDep(dependency.PyPI, "foo.bar", "3.0.0", "", "requirements.txt", true))
	storeScanAt(t, f.repo21, strings.Repeat("a", 40),
		searchDep(dependency.NPM, "lodash", "3.9.0", "", "a-old/package-lock.json", false), // sorts before the row below, and is outside ^4.17
		searchDep(dependency.NPM, "lodash", "4.17.21", "", "package-lock.json", true))
	storeScanAt(t, f.leaf, strings.Repeat("a", 40), searchDep(dependency.NPM, "lodash", "4.17.21", "", "package-lock.json", true))
	storeScanAt(t, f.other, strings.Repeat("a", 40), searchDep(dependency.NPM, "lodash", "4.17.0", "", "package-lock.json", true))

	advisory := func(id string, aliases []string, level, name, fixed string) *vulnerability.Advisory {
		return &vulnerability.Advisory{
			ID: id, Aliases: aliases, Summary: id + " in " + name, Details: "details", Level: level, Modified: time.Unix(100, 0),
			Affected: []vulnerability.Affected{{Name: name, Ranges: []vulnerability.Range{{Type: "SEMVER", Events: []vulnerability.Event{{Introduced: "0"}, {Fixed: fixed}}}}}},
		}
	}
	scored := advisory("GHSA-aaaa-bbbb-cccc", []string{"CVE-2024-1111"}, vulnerability.SeverityHigh, "lodash", "4.17.21")
	scored.Score = 7.5
	_, err = vulnerability_model.ImportBatch(t.Context(), dependency.NPM, []*vulnerability.Advisory{
		scored,
		advisory("CVE-2023-2222", nil, vulnerability.SeverityCritical, "lodash", "3.10.2"),
		advisory("GHSA-cccc-dddd-eeee", []string{"CVE-2020-3333"}, vulnerability.SeverityLow, "never-used", "2.0.0"),
	}, &vulnerability_model.ChangedSet{})
	require.NoError(t, err)
	for _, r := range []*repo_model.Repository{f.repo3, f.repo5, f.repo21, f.leaf, f.other} {
		require.NoError(t, vulnerability_service.Rematch(t.Context(), r.ID))
	}
	return f
}

func dsGet(t *testing.T, path, token string, status int) *httptest.ResponseRecorder {
	t.Helper()
	req := NewRequest(t, "GET", path)
	if token != "" {
		req.AddTokenAuth(token)
	}
	return MakeRequest(t, req, status)
}

// dsUsage reads a dependency search as "full name version manifest" per row, and the total.
func dsUsage(t *testing.T, path, token string) (rows, uncertain []string, total string) {
	t.Helper()
	resp := dsGet(t, path, token, http.StatusOK)
	var list []*api.DependencyUsage
	DecodeJSON(t, resp, &list)
	for _, d := range list {
		row := fmt.Sprintf("%s %s %s", d.Repository.FullName, d.Version, d.ManifestPath)
		rows = append(rows, row)
		if d.Uncertain {
			uncertain = append(uncertain, row)
		}
	}
	return rows, uncertain, resp.Header().Get("X-Total-Count")
}

func dsAlerts(t *testing.T, path, token string) (rows []string, total string) {
	t.Helper()
	resp := dsGet(t, path, token, http.StatusOK)
	var list []*api.RepoVulnerabilityAlert
	DecodeJSON(t, resp, &list)
	for _, a := range list {
		rows = append(rows, fmt.Sprintf("%s %s %s %s %s", a.Repository.FullName, a.Advisory.ID, a.Version, a.State, a.Severity))
	}
	return rows, resp.Header().Get("X-Total-Count")
}

func TestOrgDependencySearch(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := newSearchFixture(t)
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository)
	base := "/api/v1/orgs/org3/dependencies"

	t.Run("by ecosystem and name", func(t *testing.T) {
		rows, uncertain, total := dsUsage(t, base+"?ecosystem=npm&name=lodash", token)
		assert.Equal(t, []string{ // owner, then project or repository name
			"org3/dep-proj/leaf 4.17.21 package-lock.json",
			"org3/repo21 3.9.0 a-old/package-lock.json",
			"org3/repo21 4.17.21 package-lock.json",
			"org3/repo3 4.17.20 package-lock.json",
			"org3/repo3  package.json",
			"org3/repo5 3.10.1 package-lock.json",
		}, rows)
		assert.Equal(t, "6", total)
		assert.Empty(t, uncertain, "uncertain is only set by a range")
		var one []*api.DependencyUsage
		DecodeJSON(t, dsGet(t, base+"?ecosystem=npm&name=lodash&version=4.17.20", token, http.StatusOK), &one)
		require.Len(t, one, 1)
		assert.Equal(t, f.repo3.ID, one[0].Repository.ID)
		assert.True(t, one[0].Repository.Private)
		assert.Equal(t, f.repo3.HTMLURL(), one[0].Repository.HTMLURL)
		assert.False(t, one[0].Direct)
	})

	t.Run("version, direct and range", func(t *testing.T) {
		rows, _, total := dsUsage(t, base+"?ecosystem=npm&name=lodash&version=4.17.21", token)
		assert.Equal(t, []string{"org3/dep-proj/leaf 4.17.21 package-lock.json", "org3/repo21 4.17.21 package-lock.json"}, rows)
		assert.Equal(t, "2", total)
		rows, _, _ = dsUsage(t, base+"?ecosystem=npm&name=lodash&direct=false", token)
		assert.Equal(t, []string{"org3/repo21 3.9.0 a-old/package-lock.json", "org3/repo3 4.17.20 package-lock.json"}, rows)

		rows, uncertain, total := dsUsage(t, base+"?ecosystem=npm&name=lodash&range="+url.QueryEscape("^4.17.0"), token)
		assert.Equal(t, []string{
			"org3/dep-proj/leaf 4.17.21 package-lock.json",
			"org3/repo21 4.17.21 package-lock.json",
			"org3/repo3 4.17.20 package-lock.json",
			"org3/repo3  package.json",
		}, rows)
		assert.Equal(t, []string{"org3/repo3  package.json"}, uncertain, "the row with only a requirement overlaps")
		assert.Equal(t, "4", total)

		rows, uncertain, _ = dsUsage(t, base+"?ecosystem=npm&name=lodash&range="+url.QueryEscape(">=3 <4"), token)
		assert.Equal(t, []string{"org3/repo21 3.9.0 a-old/package-lock.json", "org3/repo5 3.10.1 package-lock.json"}, rows)
		assert.Empty(t, uncertain)

		// PyPI syntax
		rows, _, _ = dsUsage(t, base+"?ecosystem=PyPI&name=foo-bar&range="+url.QueryEscape(">=2,<3"), token)
		assert.Equal(t, []string{"org3/repo3 2.1.0 requirements.txt"}, rows)
	})

	t.Run("PyPI names are normalized", func(t *testing.T) {
		for _, name := range []string{"Foo_Bar", "foo-bar", "FOO.BAR"} {
			rows, _, total := dsUsage(t, base+"?ecosystem=PyPI&name="+name, token)
			assert.Equal(t, []string{"org3/repo3 2.1.0 requirements.txt", "org3/repo5 3.0.0 requirements.txt"}, rows, name)
			assert.Equal(t, "2", total)
		}
		// npm names are case sensitive
		rows, _, _ := dsUsage(t, base+"?ecosystem=npm&name=Lodash", token)
		assert.Empty(t, rows)
	})

	t.Run("bad requests", func(t *testing.T) {
		for _, q := range []string{
			"", "ecosystem=npm", "direct=true", // the search needs an ecosystem and a name
			"ecosystem=npm&name=lodash&owner=org17",              // a filter of the instance routes
			"name=lodash",                                        // name needs an ecosystem
			"ecosystem=Cobol&name=x",                             // unknown ecosystem
			"ecosystem=npm&name=lodash&range=%5E%5E%5E",          // unparseable range
			"ecosystem=npm&name=lodash&version=1.0.0&range=%5E1", // version and range
			"ecosystem=npm&name=" + strings.Repeat("a", 513),     // name too long
			"ecosystem=npm&name=lodash&direct=maybe",
		} {
			dsGet(t, base+"?"+q, token, http.StatusUnprocessableEntity)
		}
		dsGet(t, base+"?ecosystem=npm&name="+strings.Repeat("a", 512), token, http.StatusOK)
	})

	t.Run("a page number that overflows", func(t *testing.T) {
		for _, q := range []string{"", "&range=" + url.QueryEscape("^4")} {
			rows, _, total := dsUsage(t, base+"?ecosystem=npm&name=lodash&page=9223372036854775807"+q, token)
			assert.Empty(t, rows)
			assert.NotEqual(t, "0", total, "the total is the real one")
		}
	})

	t.Run("candidate cap", func(t *testing.T) {
		defer test.MockVariableValue(&dependency_service.MaxUsageCandidates, 5)()
		resp := dsGet(t, base+"?ecosystem=npm&name=lodash&range="+url.QueryEscape("^4"), token, http.StatusUnprocessableEntity)
		assert.Contains(t, resp.Body.String(), "add a project filter")
		// the plain search and a narrower one are not capped
		dsGet(t, base+"?ecosystem=npm&name=lodash", token, http.StatusOK)
		rows, _, _ := dsUsage(t, base+"?ecosystem=npm&name=lodash&project=dep-proj&range="+url.QueryEscape("^4"), token)
		assert.Len(t, rows, 1)
	})

	t.Run("paging happens after the range filter", func(t *testing.T) {
		rangeQ := base + "?ecosystem=npm&name=lodash&range=" + url.QueryEscape("^4.17.0") + "&limit=2"
		page1, _, total := dsUsage(t, rangeQ+"&page=1", token)
		assert.Equal(t, "4", total, "the total counts what the filter keeps")
		assert.Equal(t, []string{"org3/dep-proj/leaf 4.17.21 package-lock.json", "org3/repo21 4.17.21 package-lock.json"}, page1, "the row of repo21 outside the range sits between them")
		page2, _, total := dsUsage(t, rangeQ+"&page=2", token)
		assert.Equal(t, "4", total)
		assert.Equal(t, []string{"org3/repo3 4.17.20 package-lock.json", "org3/repo3  package.json"}, page2)
		page3, _, _ := dsUsage(t, rangeQ+"&page=3", token)
		assert.Empty(t, page3)
		resp := dsGet(t, rangeQ+"&page=1", token, http.StatusOK)
		assert.Contains(t, resp.Header().Get("Link"), `rel="next"`)
	})

	t.Run("projects", func(t *testing.T) {
		rows, _, total := dsUsage(t, base+"?ecosystem=npm&name=lodash&project=dep-proj", token)
		assert.Equal(t, []string{"org3/dep-proj/leaf 4.17.21 package-lock.json"}, rows)
		assert.Equal(t, "1", total)
		rows, _, total = dsUsage(t, base+"?ecosystem=npm&name=lodash&project=nope", token)
		assert.Empty(t, rows)
		assert.Equal(t, "0", total)
	})

	t.Run("another organization's repository is never listed", func(t *testing.T) {
		rows, _, _ := dsUsage(t, base+"?ecosystem=npm&name=lodash&limit=50", token)
		for _, r := range rows {
			assert.NotContains(t, r, "org17")
		}
	})
}

func TestOrgVulnerabilitySearch(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := newSearchFixture(t)
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository)
	base := "/api/v1/orgs/org3/vulnerability-alerts"

	// dismiss the alert of GHSA-aaaa on repo3's lock file and mark repo5's CVE-2023-2222 alert fixed
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	alertOf := func(repoID int64, version, advisory string) *vulnerability_model.Alert {
		ids, err := vulnerability_model.FindAdvisoryIDsByID(t.Context(), advisory)
		require.NoError(t, err)
		alert := &vulnerability_model.Alert{}
		has, err := db.GetEngine(t.Context()).Where("repo_id = ? AND version = ?", repoID, version).In("advisory_id", ids).Get(alert)
		require.NoError(t, err)
		require.True(t, has)
		return alert
	}
	_, err := vulnerability_service.Dismiss(t.Context(), f.repo3, user2, alertOf(f.repo3.ID, "4.17.20", "GHSA-aaaa-bbbb-cccc").ID, vulnerability_model.DismissReasons[0], "")
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Exec("UPDATE repo_vulnerability_alert SET state = ?, fixed_unix = 100, fixed_reason = 'fixed' WHERE id = ?",
		vulnerability_model.StateFixed, alertOf(f.repo5.ID, "3.10.1", "CVE-2023-2222").ID)
	require.NoError(t, err)

	t.Run("by OSV ID and by alias", func(t *testing.T) {
		byOSV, total := dsAlerts(t, base+"?advisory=GHSA-aaaa-bbbb-cccc", token)
		assert.Equal(t, []string{
			"org3/repo21 GHSA-aaaa-bbbb-cccc 3.9.0 open high",
			"org3/repo3 GHSA-aaaa-bbbb-cccc  open high", // the requirement of package.json, no version
			"org3/repo5 GHSA-aaaa-bbbb-cccc 3.10.1 open high",
		}, byOSV)
		assert.Equal(t, "3", total)
		for _, a := range []string{"CVE-2024-1111", "cve-2024-1111"} {
			byAlias, _ := dsAlerts(t, base+"?advisory="+a, token)
			assert.Equal(t, byOSV, byAlias, a)
		}
	})

	t.Run("unknown and unaffected advisories answer alike", func(t *testing.T) {
		unknown := dsGet(t, base+"?advisory=CVE-1999-0000", token, http.StatusOK)
		known := dsGet(t, base+"?advisory=GHSA-cccc-dddd-eeee", token, http.StatusOK)
		viaAlias := dsGet(t, base+"?advisory=CVE-2020-3333", token, http.StatusOK)
		assert.JSONEq(t, "[]", unknown.Body.String())
		assert.Equal(t, unknown.Body.String(), known.Body.String())
		assert.Equal(t, unknown.Body.String(), viaAlias.Body.String())
		assert.Equal(t, unknown.Header().Get("X-Total-Count"), known.Header().Get("X-Total-Count"))
	})

	t.Run("state and severity", func(t *testing.T) {
		open, _ := dsAlerts(t, base+"?advisory=GHSA-aaaa-bbbb-cccc", token)
		dismissed, _ := dsAlerts(t, base+"?advisory=GHSA-aaaa-bbbb-cccc&state=dismissed", token)
		everything, _ := dsAlerts(t, base+"?advisory=GHSA-aaaa-bbbb-cccc&state=all", token)
		require.Len(t, dismissed, 1)
		assert.Equal(t, "org3/repo3 GHSA-aaaa-bbbb-cccc 4.17.20 dismissed high", dismissed[0])
		assert.Len(t, everything, len(open)+1)
		fixed, _ := dsAlerts(t, base+"?advisory=CVE-2023-2222&state=fixed", token)
		require.Len(t, fixed, 1)
		assert.Contains(t, fixed[0], "org3/repo5")
		openCritical, _ := dsAlerts(t, base+"?ecosystem=npm&name=lodash&severity=critical", token)
		for _, r := range openCritical {
			assert.True(t, strings.HasSuffix(r, " open critical"), r)
		}
		require.NotEmpty(t, openCritical)
		low, total := dsAlerts(t, base+"?ecosystem=npm&name=lodash&severity=low&state=all", token)
		assert.Empty(t, low)
		assert.Equal(t, "0", total)
	})

	t.Run("by package", func(t *testing.T) {
		rows, total := dsAlerts(t, base+"?ecosystem=npm&name=lodash&state=all", token)
		assert.Equal(t, fmt.Sprint(len(rows)), total)
		for _, r := range rows {
			assert.True(t, strings.HasPrefix(r, "org3/"), r)
		}
		exact, _ := dsAlerts(t, base+"?ecosystem=npm&name=lodash&version=3.9.0", token)
		require.NotEmpty(t, exact)
		for _, r := range exact {
			assert.Contains(t, r, "org3/repo21")
		}
		pageA, _ := dsAlerts(t, base+"?ecosystem=npm&name=lodash&limit=2&page=1", token)
		pageB, _ := dsAlerts(t, base+"?ecosystem=npm&name=lodash&limit=2&page=2", token)
		assert.Len(t, pageA, 2)
		assert.NotEqual(t, pageA, pageB)
	})

	t.Run("projects", func(t *testing.T) {
		rows, total := dsAlerts(t, base+"?ecosystem=npm&name=lodash&state=all&project=dep-proj", token)
		assert.Empty(t, rows, "the repository in the project uses a fixed version")
		assert.Equal(t, "0", total)
		_, err := db.GetEngine(t.Context()).Exec("UPDATE repo_dependency SET version = '1.0.0' WHERE repo_id = ?", f.leaf.ID)
		require.NoError(t, err)
		require.NoError(t, vulnerability_service.Rematch(t.Context(), f.leaf.ID))
		rows, _ = dsAlerts(t, base+"?ecosystem=npm&name=lodash&project=dep-proj", token)
		require.NotEmpty(t, rows)
		for _, r := range rows {
			assert.True(t, strings.HasPrefix(r, "org3/dep-proj/leaf "), r)
		}
		rows, _ = dsAlerts(t, base+"?ecosystem=npm&name=lodash&project=nope", token)
		assert.Empty(t, rows)
	})

	t.Run("paging past the end", func(t *testing.T) {
		rows, total := dsAlerts(t, base+"?ecosystem=npm&name=lodash&state=all&limit=2&page=100", token)
		assert.Empty(t, rows)
		all, allTotal := dsAlerts(t, base+"?ecosystem=npm&name=lodash&state=all&limit=50", token)
		assert.NotEmpty(t, all)
		assert.Equal(t, allTotal, total, "the total is the real one on a page past the end")
		rows, total = dsAlerts(t, base+"?ecosystem=npm&name=lodash&state=all&page=9223372036854775807", token)
		assert.Empty(t, rows)
		assert.Equal(t, allTotal, total)
	})

	t.Run("a name in every ecosystem", func(t *testing.T) {
		npm, npmTotal := dsAlerts(t, base+"?ecosystem=npm&name=lodash&state=all", token)
		anyEco, anyTotal := dsAlerts(t, base+"?name=lodash&state=all", token)
		require.NotEmpty(t, npm)
		assert.Equal(t, npm, anyEco)
		assert.Equal(t, npmTotal, anyTotal)

		// each ecosystem compares the name as its registry does
		_, err := vulnerability_model.ImportBatch(t.Context(), dependency.PyPI, []*vulnerability.Advisory{{
			ID: "PYSEC-2026-1", Summary: "in foo-bar", Level: vulnerability.SeverityModerate, Modified: time.Unix(100, 0),
			Affected: []vulnerability.Affected{{Name: "foo-bar", Versions: []string{"2.1.0", "3.0.0"}}},
		}}, &vulnerability_model.ChangedSet{})
		require.NoError(t, err)
		require.NoError(t, vulnerability_service.Rematch(t.Context(), f.repo3.ID))
		require.NoError(t, vulnerability_service.Rematch(t.Context(), f.repo5.ID))
		for _, name := range []string{"Foo_Bar", "foo-bar", "FOO.BAR"} {
			rows, _ := dsAlerts(t, base+"?name="+name, token)
			assert.Equal(t, []string{"org3/repo3 PYSEC-2026-1 2.1.0 open moderate", "org3/repo5 PYSEC-2026-1 3.0.0 open moderate"}, rows, name)
		}
		rows, _ := dsAlerts(t, base+"?name=Lodash", token) // npm names are case sensitive, and PyPI has no lodash
		assert.Empty(t, rows)
		rows, _ = dsAlerts(t, base+"?name=foo-bar&version=3.0.0", token)
		assert.Equal(t, []string{"org3/repo5 PYSEC-2026-1 3.0.0 open moderate"}, rows)
	})

	t.Run("bad requests", func(t *testing.T) {
		for _, q := range []string{
			"ecosystem=npm&name=lodash&owner=org17", // a filter of the instance routes
			"", "state=open", "ecosystem=npm",       // neither an advisory nor a name
			"version=1.0.0", // a version needs a name
			"advisory=bad%20id!", "advisory=" + strings.Repeat("A", 65),
			"advisory=CVE-2024-1111&state=bogus", "advisory=CVE-2024-1111&severity=bogus", "ecosystem=Cobol&name=x",
		} {
			dsGet(t, base+"?"+q, token, http.StatusUnprocessableEntity)
		}
	})
}

func TestDependencySearchVisibility(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := newSearchFixture(t)
	owner := getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository)
	admin := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin, auth_model.AccessTokenScopeReadRepository)
	q := "?ecosystem=npm&name=lodash&limit=50"
	listed := func(t *testing.T, repo *repo_model.Repository, want bool, why string) {
		t.Helper()
		for _, c := range []struct{ path, token string }{{"/api/v1/orgs/org3/dependencies", owner}, {"/api/v1/admin/dependencies", admin}} {
			rows, _, total := dsUsage(t, c.path+q, c.token)
			found := 0
			for _, r := range rows {
				if strings.HasPrefix(r, repo.FullName()+" ") {
					found++
				}
			}
			assert.Equal(t, want, found > 0, "%s %s: %s", c.path, repo.FullName(), why)
			assert.Equal(t, fmt.Sprint(len(rows)), total, "the count follows the list")
		}
		for _, c := range []struct{ path, token string }{{"/api/v1/orgs/org3/vulnerability-alerts", owner}, {"/api/v1/admin/vulnerability-alerts", admin}} {
			rows, total := dsAlerts(t, c.path+q+"&state=all", c.token)
			found := false
			for _, r := range rows {
				found = found || strings.HasPrefix(r, repo.FullName()+" ")
			}
			assert.Equal(t, want, found, "alerts %s %s: %s", c.path, repo.FullName(), why)
			assert.Equal(t, fmt.Sprint(len(rows)), total)
		}
	}
	listed(t, f.repo5, true, "visible")
	listed(t, f.repo3, true, "visible")

	t.Run("trashed", func(t *testing.T) {
		_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = ?", f.repo5.ID)
		require.NoError(t, err)
		listed(t, f.repo5, false, "in the trash")
		_, err = db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 0 WHERE id = ?", f.repo5.ID)
		require.NoError(t, err)
		listed(t, f.repo5, true, "restored")
	})
	t.Run("Code unit hidden by the organization", func(t *testing.T) {
		require.NoError(t, db.Insert(t.Context(), &repo_model.OrgUnit{OrgID: 3, Type: unit.TypeCode, Disabled: true}))
		listed(t, f.repo3, false, "Code hidden")
		_, err := db.DeleteByBean(t.Context(), &repo_model.OrgUnit{OrgID: 3, Type: unit.TypeCode})
		require.NoError(t, err)
		listed(t, f.repo3, true, "Code visible again")
	})
	t.Run("repository without a Code unit", func(t *testing.T) {
		_, err := db.GetEngine(t.Context()).Exec("DELETE FROM repo_unit WHERE repo_id = ? AND type = ?", f.repo21.ID, unit.TypeCode)
		require.NoError(t, err)
		listed(t, f.repo21, false, "no Code unit")
	})
	t.Run("dependency graph off", func(t *testing.T) {
		_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET dependency_graph_disabled = ? WHERE id = ?", true, f.repo3.ID)
		require.NoError(t, err)
		listed(t, f.repo3, false, "the repository's switch is off")
		_, err = db.GetEngine(t.Context()).Exec("UPDATE repository SET dependency_graph_disabled = ? WHERE id = ?", false, f.repo3.ID)
		require.NoError(t, err)
		listed(t, f.repo3, true, "on again")
		require.NoError(t, user_model.SetUserSetting(t.Context(), 3, repo_model.DependencyGraphOrgKey, "false"))
		listed(t, f.repo3, false, "the organization's switch is off")
	})
}

func TestOrgDependencySearchAccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	newSearchFixture(t)
	q := "?ecosystem=npm&name=lodash"
	paths := []string{"/api/v1/orgs/org3/dependencies" + q, "/api/v1/orgs/org3/vulnerability-alerts" + q}
	check := func(t *testing.T, _, token string, status int) {
		t.Helper()
		for _, p := range paths {
			dsGet(t, p, token, status)
		}
	}
	scope := auth_model.AccessTokenScopeReadOrganization
	t.Run("owner and site admin", func(t *testing.T) {
		check(t, "owner", getUserToken(t, "user2", scope, auth_model.AccessTokenScopeReadRepository), http.StatusOK)
		check(t, "admin", getUserToken(t, "user1", scope, auth_model.AccessTokenScopeReadRepository), http.StatusOK)
	})
	t.Run("a member who is not an owner", func(t *testing.T) {
		check(t, "member", getUserToken(t, "user4", scope, auth_model.AccessTokenScopeReadRepository), http.StatusForbidden)
	})
	t.Run("a non-member of a public organization", func(t *testing.T) {
		check(t, "stranger", getUserToken(t, "user8", scope, auth_model.AccessTokenScopeReadRepository), http.StatusForbidden)
	})
	t.Run("a non-member of a private organization", func(t *testing.T) {
		stranger := getUserToken(t, "user2", scope, auth_model.AccessTokenScopeReadRepository)
		for _, p := range []string{"/api/v1/orgs/privated_org/dependencies" + q, "/api/v1/orgs/privated_org/vulnerability-alerts" + q} {
			dsGet(t, p, stranger, http.StatusNotFound)
			dsGet(t, p, getUserToken(t, "user2", scope), http.StatusNotFound) // the scope check can't tell the org exists
		}
	})
	t.Run("anonymous", func(t *testing.T) {
		check(t, "anonymous", "", http.StatusUnauthorized)
	})
	t.Run("tokens", func(t *testing.T) {
		check(t, "public only", getUserToken(t, "user2", scope, auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopePublicOnly), http.StatusForbidden)
		check(t, "specific repositories", createFineGrainedRepoAccessToken(t, "user2", []auth_model.AccessTokenScope{scope, auth_model.AccessTokenScopeReadRepository}, []int64{3}), http.StatusForbidden)
		check(t, "wrong scope", getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository), http.StatusForbidden)
		check(t, "organization scope only", getUserToken(t, "user2", scope), http.StatusForbidden)
		org := newOwnedAccessToken(t, auth_model.AccessTokenOwnerOrg, 3, 0, perm_model.AccessModeAdmin, scope)
		check(t, "org-owned token", org.Token, http.StatusForbidden)
		repoToken := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, 3, 0, perm_model.AccessModeRead, auth_model.AccessTokenScopeReadRepository)
		check(t, "repository token", repoToken.Token, http.StatusForbidden)
		check(t, "job token", "8061e833a55f6fc0157c98b883e91fcfeeb1a71a", http.StatusForbidden)
	})
	t.Run("an owner blocked by the two-factor requirement", func(t *testing.T) {
		_, err := db.Exec(t.Context(), "UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
		require.NoError(t, err)
		check(t, "blocked owner", getUserToken(t, "user2", scope, auth_model.AccessTokenScopeReadRepository), http.StatusForbidden)
		_, err = db.Exec(t.Context(), "UPDATE `user` SET require_two_factor = ? WHERE id = 3", false)
		require.NoError(t, err)
	})
	t.Run("an archived organization", func(t *testing.T) {
		org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 3})
		require.NoError(t, org_service.ArchiveOrganization(audit_model.WithSystem(t.Context(), "test"), org, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), false))
		check(t, "owner", getUserToken(t, "user2", scope, auth_model.AccessTokenScopeReadRepository), http.StatusOK)
	})
	t.Run("the site switch is off", func(t *testing.T) {
		defer test.MockVariableValue(&setting.DependencyGraph.Enabled, false)()
		both := auth_model.AccessTokenScopeReadRepository
		// every caller gets 404, before the owner and audit-reader gates
		for _, token := range []string{
			getUserToken(t, "user2", scope, both), getUserToken(t, "user4", scope, both), getUserToken(t, "user8", scope, both), "",
		} {
			check(t, "", token, http.StatusNotFound)
		}
		for _, token := range []string{getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin, both), getUserToken(t, "user2", auth_model.AccessTokenScopeReadAdmin, both), ""} {
			for _, p := range []string{"/api/v1/admin/dependencies", "/api/v1/admin/vulnerability-alerts"} {
				dsGet(t, p+q, token, http.StatusNotFound)
			}
		}
	})
}

func TestAdminDependencySearch(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	newSearchFixture(t)
	q := "?ecosystem=npm&name=lodash&limit=50"
	paths := []string{"/api/v1/admin/dependencies" + q, "/api/v1/admin/vulnerability-alerts" + q}
	check := func(token string, status int) {
		t.Helper()
		for _, p := range paths {
			dsGet(t, p, token, status)
		}
	}
	scope := auth_model.AccessTokenScopeReadAdmin
	admin := getUserToken(t, "user1", scope, auth_model.AccessTokenScopeReadRepository)

	t.Run("who may ask", func(t *testing.T) {
		check(admin, http.StatusOK)
		_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET is_auditor = ? WHERE id = 8", true)
		require.NoError(t, err)
		check(getUserToken(t, "user8", scope, auth_model.AccessTokenScopeReadRepository), http.StatusOK)
		check(getUserToken(t, "user2", scope, auth_model.AccessTokenScopeReadRepository), http.StatusForbidden) // owner of org3
		check(getUserToken(t, "user1", auth_model.AccessTokenScopeReadRepository), http.StatusForbidden)
		check(getUserToken(t, "user1", scope), http.StatusForbidden) // admin scope only
		check("", http.StatusUnauthorized)
	})
	t.Run("restricted tokens have no admin override", func(t *testing.T) {
		check(getUserToken(t, "user1", scope, auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopePublicOnly), http.StatusForbidden)
		check(createFineGrainedRepoAccessToken(t, "user1", []auth_model.AccessTokenScope{scope, auth_model.AccessTokenScopeReadRepository}, []int64{3}), http.StatusForbidden)
		check(getUserToken(t, "user8", scope, auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopePublicOnly), http.StatusForbidden)
	})
	t.Run("a filter of the organization routes", func(t *testing.T) {
		dsGet(t, paths[0]+"&project=dep-proj", admin, http.StatusUnprocessableEntity)
		dsGet(t, paths[1]+"&project=dep-proj", admin, http.StatusUnprocessableEntity)
		dsGet(t, "/api/v1/admin/dependencies", admin, http.StatusUnprocessableEntity)
		dsGet(t, "/api/v1/admin/dependencies?ecosystem=npm", admin, http.StatusUnprocessableEntity)
	})
	t.Run("the cap names the owner filter", func(t *testing.T) {
		defer test.MockVariableValue(&dependency_service.MaxUsageCandidates, 2)()
		resp := dsGet(t, paths[0]+"&range="+url.QueryEscape("^4"), admin, http.StatusUnprocessableEntity)
		assert.Contains(t, resp.Body.String(), "add an owner filter")
	})
	t.Run("every owner, and the owner filter", func(t *testing.T) {
		rows, _, total := dsUsage(t, paths[0], admin)
		assert.Equal(t, "7", total)
		assert.Contains(t, strings.Join(rows, "\n"), "org17/big_test_public_4 4.17.0")
		assert.Contains(t, strings.Join(rows, "\n"), "org3/dep-proj/leaf")
		rows, _, total = dsUsage(t, paths[0]+"&owner=org17", admin)
		assert.Equal(t, []string{"org17/big_test_public_4 4.17.0 package-lock.json"}, rows)
		assert.Equal(t, "1", total)
		rows, _, _ = dsUsage(t, paths[0]+"&owner=nobody", admin)
		assert.Empty(t, rows)
		alerts, _ := dsAlerts(t, paths[1]+"&owner=org17", admin)
		require.NotEmpty(t, alerts)
		for _, a := range alerts {
			assert.True(t, strings.HasPrefix(a, "org17/"), a)
		}
	})
	t.Run("a name in every ecosystem", func(t *testing.T) {
		npm, npmTotal := dsAlerts(t, paths[1], admin)
		anyEco, anyTotal := dsAlerts(t, "/api/v1/admin/vulnerability-alerts?name=lodash&limit=50", admin)
		require.NotEmpty(t, npm)
		assert.Equal(t, npm, anyEco)
		assert.Equal(t, npmTotal, anyTotal)
	})
}

func TestDependencySearchQueryCount(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	newSearchFixture(t)
	ctx := t.Context()
	owner := getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository)
	rangeQ := "&range=" + url.QueryEscape("^4")
	paths := []string{
		"/api/v1/orgs/org3/dependencies?ecosystem=npm&name=lodash&limit=50",
		"/api/v1/orgs/org3/dependencies?ecosystem=npm&name=lodash&limit=50" + rangeQ,
		"/api/v1/orgs/org3/vulnerability-alerts?ecosystem=npm&name=lodash&limit=50&state=all",
	}
	count := func() []int64 {
		var out []int64
		for _, p := range paths {
			dsGet(t, p, owner, http.StatusOK) // warm the caches
			out = append(out, stableQueryCount(t, func() { dsGet(t, p, owner, http.StatusOK) }))
		}
		return out
	}
	few := count()
	// many more matching repositories, each with an alert
	for i := range 12 {
		name := fmt.Sprintf("many%d", i)
		repo := &repo_model.Repository{OwnerID: 3, OwnerName: "org3", Name: name, LowerName: name, IsPrivate: i%2 == 0, Status: repo_model.RepositoryReady}
		require.NoError(t, db.Insert(ctx, repo))
		require.NoError(t, db.Insert(ctx, &repo_model.RepoUnit{RepoID: repo.ID, Type: unit.TypeCode}))
		require.NoError(t, db.Insert(ctx, &organization.TeamRepo{OrgID: 3, TeamID: 1, RepoID: repo.ID})) // the Owners team
		storeScanAt(t, repo, strings.Repeat("a", 40), searchDep(dependency.NPM, "lodash", "3.0.0", "", "package-lock.json", true))
		require.NoError(t, vulnerability_service.Rematch(ctx, repo.ID))
	}
	rows, _, total := dsUsage(t, paths[0], owner)
	require.Len(t, rows, 18)
	assert.Equal(t, "18", total)
	assert.Equal(t, few, count(), "the number of queries doesn't grow with the repositories on the page")
}

func TestAdminDependencySearchAudit(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	newSearchFixture(t)
	audit_model.ResetActivity()
	admin := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin, auth_model.AccessTokenScopeReadRepository)
	since := auditMaxID(t)
	dsGet(t, "/api/v1/admin/dependencies?ecosystem=npm&name=lodash&owner=org3", admin, http.StatusOK)
	e := auditActivity(t, since, "activity.dependency_graph.searched")
	assert.EqualValues(t, 1, e.ActorID)
	data := auditData(t, e)
	assert.Equal(t, "dependencies", data["kind"])
	assert.Equal(t, "npm", data["ecosystem"])
	assert.Equal(t, "lodash", data["name"])
	assert.Equal(t, "org3", data["owner"])
	assert.EqualValues(t, 6, data["total"])
	assert.NotContains(t, e.Data, "repo")

	dsGet(t, "/api/v1/admin/vulnerability-alerts?advisory=CVE-2024-1111&state=all", admin, http.StatusOK)
	dsGet(t, "/api/v1/admin/vulnerability-alerts?advisory=CVE-2024-1111&state=all", admin, http.StatusOK)
	written := auditActions(t, since, "activity.dependency_graph.searched") // the first of each kind is written at once
	require.Len(t, written, 2)
	assert.Equal(t, "alerts", auditData(t, written[1])["kind"])
	audit_model.FlushAggregated(t.Context(), true)
	assert.EqualValues(t, 1, auditData(t, auditActivity(t, since, "activity.dependency_graph.searched.aggregated"))["count"])

	// an owner reading their own organization leaves no such entry
	since = auditMaxID(t)
	dsGet(t, "/api/v1/orgs/org3/dependencies?ecosystem=npm&name=lodash", getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository), http.StatusOK)
	audit_model.FlushAggregated(t.Context(), true)
	assert.Empty(t, auditActions(t, since, "activity.dependency_graph.searched"))
}

func TestDependencySearchExport(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := newSearchFixture(t)
	audit_model.ResetActivity()
	owner := getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository)
	admin := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin, auth_model.AccessTokenScopeReadRepository)
	today := time.Now().UTC().Format("2006-01-02")
	const orgDeps, adminDeps = "/api/v1/orgs/org3/dependencies", "/api/v1/admin/dependencies"
	const orgAlerts, adminAlerts = "/api/v1/orgs/org3/vulnerability-alerts", "/api/v1/admin/vulnerability-alerts"
	q := "?ecosystem=npm&name=lodash"

	readCSV := func(t *testing.T, resp *httptest.ResponseRecorder) [][]string {
		t.Helper()
		records, err := csv.NewReader(resp.Body).ReadAll()
		require.NoError(t, err)
		return records
	}

	t.Run("csv and json, all rows, on both mounts", func(t *testing.T) {
		for _, c := range []struct {
			path, token, owner, audit string
			rows                      int
			actorID                   int64
		}{{orgDeps, owner, "org3", "org.dependency_graph.exported", 6, 2}, {adminDeps, admin, "instance", "admin.dependency_graph.exported", 7, 1}} {
			since := auditMaxID(t)
			resp := dsGet(t, c.path+q+"&limit=1&format=csv", c.token, http.StatusOK) // no paging
			assert.Equal(t, "nosniff", resp.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, "text/csv; charset=utf-8", resp.Header().Get("Content-Type"))
			assert.Contains(t, resp.Header().Get("Content-Disposition"), `attachment; filename="dependencies-`+c.owner+"-"+today+`.csv"`)
			records := readCSV(t, resp)
			require.Len(t, records, c.rows+1)
			assert.Equal(t, []string{"repository", "ecosystem", "name", "version", "requirement", "manifest", "direct", "uncertain"}, records[0])
			var names []string
			for _, r := range records[1:] {
				names = append(names, r[0])
			}
			assert.Contains(t, names, "org3/dep-proj/leaf")

			resp = dsGet(t, c.path+q+"&limit=1&format=json", c.token, http.StatusOK)
			assert.Contains(t, resp.Header().Get("Content-Disposition"), `dependencies-`+c.owner+"-"+today+`.json"`)
			assert.Equal(t, "application/json; charset=utf-8", resp.Header().Get("Content-Type"))
			var list []*api.DependencyUsage
			DecodeJSON(t, resp, &list)
			assert.Len(t, list, c.rows)

			e := auditActions(t, since, c.audit)
			require.Len(t, e, 2)
			assert.Equal(t, map[string]any{"kind": "dependencies", "format": "csv", "ecosystem": "npm", "name": "lodash", "count": float64(c.rows)}, auditData(t, e[0]))
			assert.NotContains(t, e[0].Data, "leaf")
			assert.Equal(t, audit_model.ActorUser, e[0].ActorType)
			assert.Equal(t, c.actorID, e[0].ActorID)
			assert.Empty(t, auditActions(t, since, "activity.dependency_graph.searched"))
		}
		resp := dsGet(t, orgAlerts+q+"&state=all&format=csv", owner, http.StatusOK)
		assert.Contains(t, resp.Header().Get("Content-Disposition"), `vulnerability-alerts-org3-`+today+`.csv"`)
		records := readCSV(t, resp)
		assert.Equal(t, []string{"repository", "advisory", "aliases", "severity", "ecosystem", "package", "version", "fixed in", "manifest", "state"}, records[0])
		paged, _ := dsAlerts(t, orgAlerts+q+"&state=all&limit=50", owner)
		assert.Len(t, records, len(paged)+1)
		var found bool
		for _, r := range records[1:] {
			found = found || (r[1] == "GHSA-aaaa-bbbb-cccc" && r[2] == "CVE-2024-1111" && r[3] == "high" && r[7] == "4.17.21")
		}
		assert.True(t, found)
		var list []*api.RepoVulnerabilityAlert
		DecodeJSON(t, dsGet(t, adminAlerts+q+"&state=all&format=json", admin, http.StatusOK), &list)
		assert.NotEmpty(t, list)
		assert.Equal(t, "[]\n", dsGet(t, adminAlerts+"?advisory=CVE-9999-0000&format=json", admin, http.StatusOK).Body.String())
	})

	t.Run("cells that a spreadsheet would run are prefixed", func(t *testing.T) {
		storeScanAt(t, f.repo5, strings.Repeat("a", 40), searchDep(dependency.NPM, `=HYPERLINK("x")`, "1.0.0", "", "+cmd", true))
		records := readCSV(t, dsGet(t, orgDeps+"?ecosystem=npm&name="+url.QueryEscape(`=HYPERLINK("x")`)+"&format=csv", owner, http.StatusOK))
		require.Len(t, records, 2)
		assert.Equal(t, `'=HYPERLINK("x")`, records[1][2])
		assert.Equal(t, "'+cmd", records[1][5])
	})

	t.Run("hidden repositories are not exported", func(t *testing.T) {
		exported := func(path, token string) (names []string) {
			for _, r := range readCSV(t, dsGet(t, path+q+"&format=csv", token, http.StatusOK))[1:] {
				names = append(names, r[0])
			}
			return names
		}
		assert.Contains(t, exported(orgDeps, owner), f.repo3.FullName())
		assert.Contains(t, exported(adminDeps, admin), f.repo3.FullName())
		_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = ?", f.repo3.ID)
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 0 WHERE id = ?", f.repo3.ID)
			require.NoError(t, err)
		}()
		assert.NotContains(t, exported(orgDeps, owner), f.repo3.FullName())
		assert.NotContains(t, exported(adminDeps, admin), f.repo3.FullName())
	})

	t.Run("a range search exports what the Go filter keeps", func(t *testing.T) {
		records := readCSV(t, dsGet(t, adminDeps+q+"&range="+url.QueryEscape("^4.17")+"&format=csv", admin, http.StatusOK))
		require.NotEmpty(t, records[1:])
		for _, r := range records[1:] {
			assert.True(t, slices.Contains([]string{"4.17.0", "4.17.20", "4.17.21"}, r[3]) || (r[3] == "" && r[7] == "true"), r) // 3.9.0 and 3.10.1 are out
		}
		rows, _, _ := dsUsage(t, adminDeps+q+"&range="+url.QueryEscape("^4.17")+"&limit=50", admin)
		assert.Len(t, records, len(rows)+1)
	})

	t.Run("too many rows", func(t *testing.T) {
		defer test.MockVariableValue(&dependency_service.MaxExportRows, 2)()
		since := auditMaxID(t)
		resp := dsGet(t, orgDeps+q+"&format=csv", owner, http.StatusUnprocessableEntity)
		assert.Contains(t, resp.Body.String(), "add a project filter")
		assert.Empty(t, resp.Header().Get("Content-Disposition"))
		resp = dsGet(t, adminAlerts+q+"&state=all&format=json", admin, http.StatusUnprocessableEntity)
		assert.Contains(t, resp.Body.String(), "add an owner filter")
		assert.Empty(t, auditActions(t, since, "org.dependency_graph.exported"))
		assert.Empty(t, auditActions(t, since, "admin.dependency_graph.exported"))
	})

	t.Run("the advice names the filter that is missing", func(t *testing.T) {
		defer test.MockVariableValue(&dependency_service.MaxExportRows, 2)()
		resp := dsGet(t, orgDeps+q+"&format=csv", owner, http.StatusUnprocessableEntity)
		assert.Contains(t, resp.Body.String(), "narrow by version or range")
		resp = dsGet(t, adminDeps+q+"&owner=org3&format=csv", admin, http.StatusUnprocessableEntity)
		assert.NotContains(t, resp.Body.String(), "add an owner filter")
		assert.Contains(t, resp.Body.String(), "narrow by version or range")
	})

	t.Run("one export per user and two at once", func(t *testing.T) {
		since := auditMaxID(t)
		release, ok := common.TakeExportSlot(2) // user2 is exporting
		require.True(t, ok)
		t.Cleanup(release)
		resp := dsGet(t, orgDeps+q+"&format=csv", owner, http.StatusTooManyRequests)
		assert.Empty(t, resp.Header().Get("Content-Disposition"))
		assert.Empty(t, auditActions(t, since, "org.dependency_graph.exported"))
		dsGet(t, adminDeps+q+"&format=csv", admin, http.StatusOK) // another user is not held back
		releaseOther, ok := common.TakeExportSlot(99)
		require.True(t, ok)
		t.Cleanup(releaseOther)
		dsGet(t, adminDeps+q+"&format=csv", admin, http.StatusTooManyRequests) // the process is full
		release()
		releaseOther()
		dsGet(t, orgDeps+q+"&format=csv", owner, http.StatusOK)
		assertExportSlotsFree(t)
	})

	t.Run("an export over its time budget ends after a batch", func(t *testing.T) {
		defer test.MockVariableValue(&common.ExportTimeLimit, -time.Second)()
		defer test.MockVariableValue(&dependency_service.ExportBatch, 1)() // several batches: the first is sent, the second is refused
		req := NewRequest(t, "GET", adminDeps+q+"&format=json").AddTokenAuth(admin)
		assert.PanicsWithValue(t, http.ErrAbortHandler, func() { MakeRequest(t, req, http.StatusOK) })
		assertExportSlotsFree(t) // the slot is given back
	})

	t.Run("an alert export leaves out the advisory texts", func(t *testing.T) {
		long := strings.Repeat("long-advisory-text ", 50)
		var before []*vulnerability_model.Advisory
		require.NoError(t, db.GetEngine(t.Context()).Find(&before))
		t.Cleanup(func() {
			for _, a := range before {
				_, err := db.GetEngine(db.DefaultContext).ID(a.ID).Cols("details", "summary").Update(a)
				require.NoError(t, err)
			}
		})
		_, err := db.GetEngine(t.Context()).Exec("UPDATE vulnerability_advisory SET details = ?, summary = 'short summary'", long)
		require.NoError(t, err)
		body := dsGet(t, adminAlerts+q+"&state=all&format=json", admin, http.StatusOK).Body.String()
		assert.NotContains(t, body, "long-advisory-text")
		assert.Contains(t, body, "short summary")
		assert.Contains(t, body, `"references":[]`)
		assert.Contains(t, dsGet(t, adminAlerts+q+"&state=all&limit=50", admin, http.StatusOK).Body.String(), "long-advisory-text") // the paged answer keeps them
	})

	t.Run("a failed audit insert sends nothing", func(t *testing.T) {
		defer test.MockVariableValue(&audit_model.InsertEntry, func(context.Context, *audit_model.Entry) error { return errors.New("audit down") })()
		for _, c := range []struct{ path, token string }{{orgDeps + q, owner}, {adminDeps + q, admin}, {orgAlerts + q, owner}, {adminAlerts + q, admin}} {
			resp := dsGet(t, c.path+"&format=csv", c.token, http.StatusInternalServerError)
			assert.Empty(t, resp.Header().Get("Content-Disposition"))
			assert.NotContains(t, resp.Body.String(), "lodash")
		}
	})

	t.Run("unknown format", func(t *testing.T) {
		dsGet(t, orgDeps+q+"&format=xml", owner, http.StatusUnprocessableEntity)
		dsGet(t, adminAlerts+q+"&format=CSV", admin, http.StatusUnprocessableEntity)
	})
}

// An alert dismissed while a state=open export runs is not exported; what was already sent stays.
func TestDependencySearchExportAlertSnapshot(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	newSearchFixture(t)
	admin := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin, auth_model.AccessTokenScopeReadRepository)
	path := "/api/v1/admin/vulnerability-alerts?ecosystem=npm&name=lodash"
	paged, _ := dsAlerts(t, path+"&limit=50", admin)
	require.Greater(t, len(paged), 1)
	want := paged[:1] // the first batch; the rest is dismissed before it is read

	defer test.MockVariableValue(&dependency_service.ExportBatch, 1)()
	done := false
	defer test.MockVariableValue(&vulnerability_service.AfterExportBatch, func() {
		if !done {
			done = true
			_, err := db.GetEngine(t.Context()).Exec("UPDATE repo_vulnerability_alert SET state = 'dismissed'")
			require.NoError(t, err)
		}
	})()
	var list []*api.RepoVulnerabilityAlert
	DecodeJSON(t, dsGet(t, path+"&format=json", admin, http.StatusOK), &list)
	var got []string
	for _, a := range list {
		got = append(got, fmt.Sprintf("%s %s %s %s %s", a.Repository.FullName, a.Advisory.ID, a.Version, a.State, a.Severity))
	}
	assert.Equal(t, want, got)
}

// assertExportSlotsFree checks that both export slots of the process can be taken.
func assertExportSlotsFree(t *testing.T) {
	t.Helper()
	release1, ok1 := common.TakeExportSlot(-101)
	release2, ok2 := common.TakeExportSlot(-102)
	for _, release := range []func(){release1, release2} {
		if release != nil {
			release()
		}
	}
	assert.True(t, ok1 && ok2, "every export slot is free")
}
