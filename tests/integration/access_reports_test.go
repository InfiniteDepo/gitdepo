// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	activities_model "forgejo.org/models/activities"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	perm_model "forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting/config"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"code.forgejo.org/xorm/xorm/contexts"
	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const orgAccessReportLink = "/org/org3/settings/access-report"

// reportLine identifies a line of an access report, the same way in the page, CSV and JSON.
func reportLine(name, repo, unit, path, team string) string {
	return strings.Join([]string{name, repo, unit, path, team}, "|")
}

func pageLines(t *testing.T, session *TestSession, link string) []string {
	t.Helper()
	var lines []string
	accessRows(t, session, link).Find("table.access-report-lines tbody tr").Each(func(_ int, s *goquery.Selection) {
		attr := func(k string) string { v, _ := s.Attr("data-" + k); return v }
		lines = append(lines, reportLine(attr("name"), attr("repo"), attr("unit"), attr("path"), attr("team")))
	})
	return lines
}

func csvLines(t *testing.T, resp *httptest.ResponseRecorder) ([]string, []string, [][]string) {
	t.Helper()
	assert.Equal(t, "text/csv; charset=utf-8", resp.Header().Get("Content-Type"))
	assert.Contains(t, resp.Header().Get("Content-Disposition"), "attachment")
	records, err := csv.NewReader(strings.NewReader(resp.Body.String())).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, records)
	header := records[0]
	col := func(rec []string, k string) string {
		for i, h := range header {
			if h == k {
				return rec[i]
			}
		}
		return ""
	}
	var lines []string
	for _, rec := range records[1:] {
		lines = append(lines, reportLine(col(rec, "name"), col(rec, "repository"), col(rec, "unit"), col(rec, "path"), col(rec, "team")))
	}
	return header, lines, records[1:]
}

func jsonLines(t *testing.T, resp *httptest.ResponseRecorder) ([]string, []*api.AccessReportLine) {
	t.Helper()
	assert.Equal(t, "application/json; charset=utf-8", resp.Header().Get("Content-Type"))
	var out []*api.AccessReportLine
	DecodeJSON(t, resp, &out)
	var lines []string
	for _, l := range out {
		lines = append(lines, reportLine(l.Name, l.Repository, l.Unit, l.Path, l.Team))
	}
	return lines, out
}

func TestOrgAccessReport(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareAccessReport(t)

	t.Run("refused", func(t *testing.T) {
		MakeRequest(t, NewRequest(t, "GET", orgAccessReportLink), http.StatusSeeOther)
		loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", orgAccessReportLink), http.StatusNotFound)  // team member
		loginUser(t, "user28").MakeRequest(t, NewRequest(t, "GET", orgAccessReportLink), http.StatusNotFound) // org member
		loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", orgAccessReportLink+"?format=csv"), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/access-report"), http.StatusUnauthorized)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/access-report").AddTokenAuth(getUserToken(t, "user4", auth_model.AccessTokenScopeReadOrganization)), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/access-report").AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)), http.StatusForbidden)
	})

	session := loginUser(t, "user2")
	lines := pageLines(t, session, orgAccessReportLink)
	assert.Contains(t, lines, reportLine("user5", "org3/repo3", "repo.code", "team", "team1"))
	assert.Contains(t, lines, reportLine("user5", "org3/repo3", "repo.code", "collaborator", ""))
	assert.Contains(t, lines, reportLine("ci-push", "org3/repo3", "repo.code", "deploy_key", ""))
	assert.Contains(t, lines, reportLine("", "org3/repo3", "*", "instance_roles", ""))
	assert.NotContains(t, lines, reportLine("ci-push", "org3/repo3", "repo.issues", "deploy_key", ""))
	repos := map[string]bool{}
	for _, l := range lines {
		repos[strings.Split(l, "|")[1]] = true
		assert.NotEqual(t, "user1", strings.Split(l, "|")[0], "site admins are named to site admins only")
	}
	assert.Equal(t, map[string]bool{"org3/repo3": true, "org3/repo5": true, "org3/repo21": true}, repos)

	t.Run("access tokens", func(t *testing.T) {
		orgToken := newOwnedAccessToken(t, auth_model.AccessTokenOwnerOrg, 3, 0, perm_model.AccessModeWrite, "write:repository")
		repoToken := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, 3, 0, perm_model.AccessModeRead, "read:repository")
		defer func() {
			_, err := db.GetEngine(db.DefaultContext).In("id", orgToken.ID, repoToken.ID).Delete(&auth_model.AccessToken{})
			require.NoError(t, err)
		}()
		tokens := pageLines(t, session, orgAccessReportLink+"?type=token")
		assert.Contains(t, tokens, reportLine(orgToken.Name, "org3/repo5", "repo.code", "org_token", ""))
		assert.Contains(t, tokens, reportLine(orgToken.Name, "org3/repo3", "repo.issues", "org_token", ""))
		assert.Contains(t, tokens, reportLine(repoToken.Name, "org3/repo3", "repo.code", "repo_token", ""))
		assert.NotContains(t, tokens, reportLine(repoToken.Name, "org3/repo5", "repo.code", "repo_token", ""))
		// the report names the scopes of a token, in the page, the JSON and the CSV
		rows := accessRows(t, session, orgAccessReportLink+"?type=token").Find(`table.access-report-lines tbody tr[data-name="` + orgToken.Name + `"]`)
		require.Positive(t, rows.Length())
		assert.Contains(t, rows.First().Text(), "Scopes: write:repository")
		_, jsonTokens := jsonLines(t, session.MakeRequest(t, NewRequest(t, "GET", orgAccessReportLink+"?type=token&format=json"), http.StatusOK))
		scopesOf := func(lines []*api.AccessReportLine, name string) []string {
			for _, l := range lines {
				if l.Name == name {
					return l.Scopes
				}
			}
			return nil
		}
		assert.Equal(t, []string{"write:repository"}, scopesOf(jsonTokens, orgToken.Name))
		header, _, records := csvLines(t, session.MakeRequest(t, NewRequest(t, "GET", orgAccessReportLink+"?type=token&format=csv"), http.StatusOK))
		scopesCol := slices.Index(header, "scopes")
		require.GreaterOrEqual(t, scopesCol, 0)
		assert.Contains(t, slices.Collect(func(yield func(string) bool) {
			for _, rec := range records {
				if rec[1] == repoToken.Name && !yield(rec[scopesCol]) {
					return
				}
			}
		}), "read:repository")
		doc := accessRows(t, session, "/org3/repo3/settings/access?type=token")
		assert.Contains(t, doc.Find(`tr[data-token="`+orgToken.Name+`"]`).Text(), "Write")
		assert.Contains(t, doc.Find(`tr[data-token="`+repoToken.Name+`"]`).Text(), "Repository access token")
	})

	t.Run("filters", func(t *testing.T) {
		keys := pageLines(t, session, orgAccessReportLink+"?type=key")
		assert.ElementsMatch(t, []string{
			reportLine("ci-push", "org3/repo3", "repo.code", "deploy_key", ""),
			reportLine("prod-deploy", "org3/repo3", "repo.code", "deploy_key", ""),
		}, keys)
		for _, l := range pageLines(t, session, orgAccessReportLink+"?external=true") {
			assert.True(t, strings.HasPrefix(l, "user5|"), l)
		}
	})

	t.Run("paged by repository", func(t *testing.T) {
		repoSet := func(lines []string) map[string]bool {
			m := map[string]bool{}
			for _, l := range lines {
				m[strings.Split(l, "|")[1]] = true
			}
			return m
		}
		assert.Equal(t, map[string]bool{"org3/repo3": true, "org3/repo5": true}, repoSet(pageLines(t, session, orgAccessReportLink+"?limit=2")))
		assert.Equal(t, map[string]bool{"org3/repo21": true}, repoSet(pageLines(t, session, orgAccessReportLink+"?limit=2&page=2")))
		assert.Empty(t, pageLines(t, session, orgAccessReportLink+"?limit=2&page=3"))
		// the pager counts repositories
		doc := accessRows(t, session, orgAccessReportLink+"?limit=2")
		assert.Positive(t, doc.Find(`.pagination a[href*="page=2"]`).Length())
		assert.Equal(t, 0, doc.Find(`.pagination a[href*="page=3"]`).Length())
	})
}

func TestInstanceAccessReport(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareAccessReport(t)
	link := "/admin/access-reports"

	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", link), http.StatusForbidden)
	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", link+"?format=csv"), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", link), http.StatusSeeOther)

	lines := pageLines(t, loginUser(t, "user1"), link)
	assert.Contains(t, lines, reportLine("user2", "user2/repo1", "repo.code", "owner", ""))
	assert.Contains(t, lines, reportLine("user5", "org3/repo3", "repo.code", "team", "team1"))
	assert.Contains(t, lines, reportLine("user1", "org3/repo3", "repo.code", "site_admin", ""))

	// a token line names its scopes in the page and the exports
	token := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, 3, 0, perm_model.AccessModeRead, "read:repository")
	rows := accessRows(t, loginUser(t, "user1"), link+"?type=token").Find(`table.access-report-lines tbody tr[data-name="` + token.Name + `"]`)
	require.Positive(t, rows.Length())
	assert.Contains(t, rows.First().Text(), "Scopes: read:repository")
	_, exported := jsonLines(t, loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", link+"?type=token&format=json"), http.StatusOK))
	var found bool
	for _, l := range exported {
		if l.Name == token.Name {
			found = true
			assert.Equal(t, []string{"read:repository"}, l.Scopes)
		}
	}
	assert.True(t, found)
	header, _, _ := csvLines(t, loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", link+"?type=token&format=csv"), http.StatusOK))
	assert.Contains(t, header, "scopes")
}

// setAccessReportPeople gives user5 TOTP and suspends them, makes user4 an LDAP user, and records pushes:
// user4 to org3/repo3, later to org3/repo5, and later still to user2/repo2, a private repository outside org3.
func setAccessReportPeople(t *testing.T) (push int64) {
	t.Helper()
	ctx := db.DefaultContext
	require.NoError(t, db.Insert(ctx, &auth_model.TwoFactor{UID: 5, Secret: []byte("secret")}))
	_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET prohibit_login = ? WHERE id = 5", true)
	require.NoError(t, err)
	source := unittest.AssertExistsAndLoadBean(t, &auth_model.Source{Name: "corp-ldap"})
	_, err = db.GetEngine(ctx).Exec("UPDATE `user` SET login_type = ?, login_source = ?, last_login_unix = ? WHERE id = 4", auth_model.LDAP, source.ID, 1700000000)
	require.NoError(t, err)

	push = 1710000500
	for _, a := range []struct {
		repo int64
		op   activities_model.ActionType
		when int64
	}{{3, activities_model.ActionCommitRepo, push - 600}, {3, activities_model.ActionPushTag, push - 500}, {5, activities_model.ActionCommitRepo, push}, {2, activities_model.ActionCommitRepo, push + 1000}} {
		action := &activities_model.Action{UserID: 4, ActUserID: 4, RepoID: a.repo, OpType: a.op}
		require.NoError(t, db.Insert(ctx, action))
		_, err := db.GetEngine(ctx).Exec("UPDATE action SET created_unix = ? WHERE id = ?", a.when, action.ID)
		require.NoError(t, err)
	}
	return push
}

func TestAccessReportPersonColumns(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareAccessReport(t)
	push := setAccessReportPeople(t)

	t.Run("site admin", func(t *testing.T) {
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/access-report").AddTokenAuth(getUserToken(t, "user1", auth_model.AccessTokenScopeReadOrganization)), http.StatusOK)
		_, lines := jsonLines(t, resp)
		var seen4, seen5 bool
		for _, l := range lines {
			switch l.Name {
			case "user4":
				seen4 = true
				require.NotNil(t, l.LastPush, "P2: the push outside org3 doesn't count")
				assert.Equal(t, push, l.LastPush.Unix())
				require.NotNil(t, l.LastLogin)
				assert.EqualValues(t, 1700000000, l.LastLogin.Unix())
				assert.Equal(t, "LDAP (via BindDN): corp-ldap", l.AccountSource)
				require.NotNil(t, l.TwoFactor)
				assert.False(t, *l.TwoFactor)
				require.NotNil(t, l.Suspended)
				assert.False(t, *l.Suspended)
			case "user5":
				seen5 = true
				require.NotNil(t, l.TwoFactor)
				assert.True(t, *l.TwoFactor)
				require.NotNil(t, l.Suspended)
				assert.True(t, *l.Suspended)
				assert.Nil(t, l.LastPush)
				assert.Equal(t, "local", l.AccountSource)
			}
		}
		assert.True(t, seen4)
		assert.True(t, seen5)

		doc := accessRows(t, loginUser(t, "user1"), orgAccessReportLink)
		assert.Positive(t, doc.Find("th.person-column").Length())
		// M3: the page with org3/repo3 only shows the push to org3/repo5 too
		date, _ := accessRows(t, loginUser(t, "user1"), orgAccessReportLink+"?limit=1").Find(`tr[data-name="user4"][data-repo="org3/repo3"] td.last-push absolute-date`).First().Attr("date")
		when, err := time.Parse(time.RFC3339, date)
		require.NoError(t, err)
		assert.Equal(t, push, when.Unix())
		assert.Contains(t, doc.Find(`tr[data-name="user4"] td.account-source`).First().Text(), "corp-ldap")

		header, _, _ := csvLines(t, loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", orgAccessReportLink+"?format=csv"), http.StatusOK))
		assert.Contains(t, header, "last_push")
		assert.Contains(t, header, "two_factor")
	})

	// P1: anyone can add any user to an org, so its owners don't see these columns
	t.Run("org owner", func(t *testing.T) {
		session := loginUser(t, "user2")
		doc := accessRows(t, session, orgAccessReportLink)
		assert.Equal(t, 0, doc.Find("th.person-column").Length())
		assert.Equal(t, 0, doc.Find("td.account-source").Length())
		assert.NotContains(t, doc.Find("table.access-report-lines").Text(), "corp-ldap")

		header, _, records := csvLines(t, session.MakeRequest(t, NewRequest(t, "GET", orgAccessReportLink+"?format=csv"), http.StatusOK))
		for _, k := range []string{"last_sign_in", "last_push", "two_factor", "account_source", "suspended"} {
			assert.NotContains(t, header, k)
		}
		assert.NotContains(t, fmt.Sprint(records), "corp-ldap")

		for _, link := range []string{"/api/v1/orgs/org3/access-report", "/api/v1/orgs/org3/access-report?format=json"} {
			resp := MakeRequest(t, NewRequest(t, "GET", link).AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization)), http.StatusOK)
			var raw []map[string]any
			require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &raw))
			require.NotEmpty(t, raw)
			for _, l := range raw {
				for _, k := range []string{"last_login", "last_push", "two_factor", "account_source", "suspended"} {
					assert.NotContains(t, l, k)
				}
			}
		}
	})
}

func TestAccessReportExport(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareAccessReport(t)
	ctx := db.DefaultContext
	_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET full_name = ? WHERE id = 5", "=HYPERLINK(\"http://evil\")")
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Exec("UPDATE user_group SET name = ? WHERE name = ?", "+platform-devs", "platform-devs")
	require.NoError(t, err)

	for _, user := range []string{"user1", "user2"} {
		t.Run(user, func(t *testing.T) {
			session := loginUser(t, user)
			token := getUserToken(t, user, auth_model.AccessTokenScopeReadOrganization)
			page := pageLines(t, session, orgAccessReportLink+"?limit=100")
			require.NotEmpty(t, page)

			// every page, whatever the page size
			header, fromCSV, records := csvLines(t, session.MakeRequest(t, NewRequest(t, "GET", orgAccessReportLink+"?format=csv&limit=1"), http.StatusOK))
			assert.Equal(t, page, fromCSV)
			assert.Equal(t, []string{"type", "name", "full_name", "repository", "unit", "access", "path", "team", "user_groups", "grant", "applied"}, header[:11])
			fromJSON, _ := jsonLines(t, session.MakeRequest(t, NewRequest(t, "GET", orgAccessReportLink+"?format=json&limit=1"), http.StatusOK))
			assert.Equal(t, page, fromJSON)
			fromAPI, _ := jsonLines(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/access-report").AddTokenAuth(token), http.StatusOK))
			assert.Equal(t, page, fromAPI)
			_, fromAPICSV, _ := csvLines(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/access-report?format=csv").AddTokenAuth(token), http.StatusOK))
			assert.Equal(t, page, fromAPICSV)

			// the same filters
			keys := pageLines(t, session, orgAccessReportLink+"?type=key")
			_, keysCSV, _ := csvLines(t, session.MakeRequest(t, NewRequest(t, "GET", orgAccessReportLink+"?type=key&format=csv"), http.StatusOK))
			assert.Equal(t, keys, keysCSV)
			keysAPI, _ := jsonLines(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/access-report?type=key").AddTokenAuth(token), http.StatusOK))
			assert.Equal(t, keys, keysAPI)

			// AC13: no cell reads as a formula
			var fullName, groups string
			for _, rec := range records {
				if rec[1] == "user5" && rec[6] == "team" {
					fullName, groups = rec[2], rec[8]
				}
			}
			assert.Equal(t, "'=HYPERLINK(\"http://evil\")", fullName)
			assert.True(t, strings.HasPrefix(groups, "'+platform-devs"), groups)
		})
	}

	_, all, _ := csvLines(t, loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", "/admin/access-reports?format=csv"), http.StatusOK))
	assert.Contains(t, all, reportLine("user2", "user2/repo1", "repo.code", "owner", ""))
	assert.Contains(t, all, reportLine("user5", "org3/repo3", "repo.code", "team", "team1"))
	// past the first page
	var last repo_model.Repository
	_, err = db.GetEngine(ctx).OrderBy("id DESC").Get(&last)
	require.NoError(t, err)
	assert.Contains(t, strings.Join(all, "\n"), "|"+last.FullName()+"|")
}

var (
	queryCountOnce sync.Once
	queryCounting  atomic.Bool
	queryCount     atomic.Int64
)

type queryCounter struct{}

func (queryCounter) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if queryCounting.Load() {
		queryCount.Add(1)
	}
	// xorm keeps the context of the last hook, and db.TracingHook needs its own
	return db.TracingHook{}.BeforeProcess(c)
}

func (queryCounter) AfterProcess(*contexts.ContextHook) error { return nil }

// frozenRevision serves a fixed settings revision, so the cache refresh (once a second) is not counted.
type frozenRevision struct {
	config.DynKeyGetter
	revision int
}

func (f frozenRevision) GetRevision(context.Context) int { return f.revision }

// countQueries returns the number of database queries f makes.
func countQueries(t *testing.T, f func()) int64 {
	t.Helper()
	queryCountOnce.Do(func() {
		engine, err := db.GetMasterEngine(db.GetEngine(db.DefaultContext))
		require.NoError(t, err)
		engine.AddHook(queryCounter{})
	})
	getter := config.GetDynGetter()
	config.SetDynGetter(frozenRevision{getter, getter.GetRevision(db.DefaultContext)})
	defer config.SetDynGetter(getter)
	queryCount.Store(0)
	queryCounting.Store(true)
	defer queryCounting.Store(false)
	f()
	return queryCount.Load()
}

// AC14
func TestReportQueriesDontGrowWithUsersAndRepos(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := db.DefaultContext
	admin := loginUser(t, "user1")
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

	count := func(n int) []int64 {
		org := &organization.Organization{Name: fmt.Sprintf("report-org-%d", n)}
		require.NoError(t, organization.CreateOrganization(ctx, org, owner))
		team := &organization.Team{OrgID: org.ID, Name: "devs", LowerName: "devs", AccessMode: perm_model.AccessModeWrite}
		require.NoError(t, db.Insert(ctx, team))
		require.NoError(t, db.Insert(ctx, &organization.TeamUnit{OrgID: org.ID, TeamID: team.ID, Type: unit.TypeCode, AccessMode: perm_model.AccessModeWrite}))
		var repos []*repo_model.Repository
		for i := range n {
			repo := &repo_model.Repository{OwnerID: org.ID, OwnerName: org.Name, Name: fmt.Sprintf("r%d", i), LowerName: fmt.Sprintf("r%d", i), IsPrivate: i%2 == 0}
			require.NoError(t, db.Insert(ctx, repo))
			require.NoError(t, db.Insert(ctx, &repo_model.RepoUnit{RepoID: repo.ID, Type: unit.TypeCode}))
			require.NoError(t, db.Insert(ctx, &organization.TeamRepo{OrgID: org.ID, TeamID: team.ID, RepoID: repo.ID}))
			repos = append(repos, repo)
		}
		for i := range n {
			u := &user_model.User{Name: fmt.Sprintf("report-%d-%d", n, i), LowerName: fmt.Sprintf("report-%d-%d", n, i), Email: fmt.Sprintf("report-%d-%d@example.com", n, i), IsActive: true}
			require.NoError(t, db.Insert(ctx, u))
			require.NoError(t, db.Insert(ctx, &organization.TeamUser{OrgID: org.ID, TeamID: team.ID, UID: u.ID}))
			require.NoError(t, db.Insert(ctx, &organization.OrgUser{OrgID: org.ID, UID: u.ID}))
			for _, repo := range repos {
				require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: repo.ID, UserID: u.ID, Mode: perm_model.AccessModeRead}))
				require.NoError(t, db.Insert(ctx, &activities_model.Action{UserID: u.ID, ActUserID: u.ID, RepoID: repo.ID, OpType: activities_model.ActionCommitRepo}))
			}
			require.NoError(t, db.Insert(ctx, &auth_model.TwoFactor{UID: u.ID, Secret: []byte("secret")}))
		}
		for _, repo := range repos {
			require.NoError(t, access_model.RecalculateAccesses(ctx, repo))
		}
		link := "/org/" + org.Name + "/settings/access-report"
		// once per user, ToUser saves a generated avatar
		admin.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
		var counts []int64
		for _, l := range []string{link, link + "?format=csv", link + "?format=json"} {
			counts = append(counts, stableQueryCount(t, func() { admin.MakeRequest(t, NewRequest(t, "GET", l), http.StatusOK) }))
		}
		return counts
	}
	small := count(2)
	assert.Equal(t, small, count(6))
}

// S1: the API report keeps to the repositories the token can read. S2: a site admin's restricted token doesn't act
// as a site admin.
func TestAccessReportRestrictedTokens(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareAccessReport(t)
	ctx := db.DefaultContext
	setAccessReportPeople(t)
	// user1, a site admin, is also an owner of org3
	require.NoError(t, db.Insert(ctx, &organization.TeamUser{OrgID: 3, TeamID: 1, UID: 1}))
	require.NoError(t, db.Insert(ctx, &organization.OrgUser{OrgID: 3, UID: 1}))
	require.NoError(t, access_model.RecalculateAccesses(ctx, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})))

	repos := func(token string) map[string]bool {
		_, lines := jsonLines(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/access-report").AddTokenAuth(token), http.StatusOK))
		m := map[string]bool{}
		for _, l := range lines {
			m[l.Repository] = true
		}
		return m
	}
	publicOnly := getUserToken(t, "user2", auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeReadOrganization)
	assert.Equal(t, map[string]bool{"org3/repo21": true}, repos(publicOnly))
	specific := createFineGrainedRepoAccessToken(t, "user2", []auth_model.AccessTokenScope{auth_model.AccessTokenScopeReadOrganization}, []int64{32})
	assert.Equal(t, map[string]bool{"org3/repo21": true}, repos(specific))
	specific = createFineGrainedRepoAccessToken(t, "user2", []auth_model.AccessTokenScope{auth_model.AccessTokenScopeReadOrganization}, []int64{3})
	assert.Equal(t, map[string]bool{"org3/repo3": true, "org3/repo21": true}, repos(specific))
	_, all, _ := csvLines(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/access-report?format=csv").AddTokenAuth(specific), http.StatusOK))
	assert.NotContains(t, strings.Join(all, "\n"), "org3/repo5")

	adminToken := createFineGrainedRepoAccessToken(t, "user1", []auth_model.AccessTokenScope{auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository}, []int64{3})
	resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/access-report").AddTokenAuth(adminToken), http.StatusOK)
	var raw []map[string]any
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &raw))
	require.NotEmpty(t, raw)
	var instanceRoles bool
	for _, l := range raw {
		for _, k := range []string{"last_login", "last_push", "two_factor", "account_source", "suspended"} {
			assert.NotContains(t, l, k)
		}
		assert.NotEqual(t, "site_admin", l["path"], "F1")
		instanceRoles = instanceRoles || l["path"] == "instance_roles"
	}
	assert.True(t, instanceRoles)

	// the repository access API needs repo admin, which a restricted token never has
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3/access").AddTokenAuth(adminToken), http.StatusForbidden)
}
