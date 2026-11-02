// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	perm_model "forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/routers/common"
	dependency_service "forgejo.org/services/dependency"
	secretscan_service "forgejo.org/services/secretscan"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type secretListFixture struct {
	root, leaf, readOnly, off, noCode, repo3, pub *repo_model.Repository
	writers                                       *organization.Team
}

// newSecretListFixture builds the organization org3 of the lists: root and leaf (in the project slproj) that user4 can
// write through a team, readOnly that user4 only reads, off (scanning off for the repository), noCode (no Code
// unit), the fixture repository 3 that user4 writes through the fixture team, and pub, a public repository of user2.
// Each has alerts. user2 owns the organization, user4 is its member.
func newSecretListFixture(t *testing.T) *secretListFixture {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.Enabled, true))
	ctx := db.DefaultContext
	sys := audit_model.WithSystem(ctx, "test")
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	project, err := repo_model.CreateRepoGroup(sys, org3, "slproj", "")
	require.NoError(t, err)
	f := &secretListFixture{
		root:     depNewRepo(t, org3, user2, "sl-root", true, 0),
		leaf:     depNewRepo(t, org3, user2, "sl-leaf", true, project.ID),
		readOnly: depNewRepo(t, org3, user2, "sl-read", true, 0),
		off:      depNewRepo(t, org3, user2, "sl-off", true, 0),
		noCode:   depNewRepo(t, org3, user2, "sl-nocode", true, 0),
		repo3:    unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}),
		pub:      depNewRepo(t, user2, user2, "sl-pub", false, 0),
	}
	_, err = db.GetEngine(ctx).Exec("UPDATE repository SET secret_scanning_disabled = ? WHERE id = ?", true, f.off.ID)
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Exec("DELETE FROM repo_unit WHERE repo_id = ? AND type = ?", f.noCode.ID, unit.TypeCode)
	require.NoError(t, err)

	team := func(name string, mode perm_model.AccessMode, repos ...*repo_model.Repository) *organization.Team {
		tm := &organization.Team{OrgID: 3, Name: name, LowerName: name, AccessMode: mode}
		require.NoError(t, db.Insert(ctx, tm))
		require.NoError(t, db.Insert(ctx, &organization.TeamUnit{OrgID: 3, TeamID: tm.ID, Type: unit.TypeCode, AccessMode: mode}))
		require.NoError(t, db.Insert(ctx, &organization.TeamUser{OrgID: 3, TeamID: tm.ID, UID: 4}))
		for _, r := range repos {
			require.NoError(t, db.Insert(ctx, &organization.TeamRepo{OrgID: 3, TeamID: tm.ID, RepoID: r.ID}))
			require.NoError(t, access_model.RecalculateAccesses(ctx, r))
		}
		return tm
	}
	f.writers = team("sl-writers", perm_model.AccessModeWrite, f.root, f.leaf, f.off, f.noCode)
	team("sl-readers", perm_model.AccessModeRead, f.readOnly)

	seedSecretAlert(t, f.root, "github-token", "github", secretscan_model.KindRepo, "root/deploy.env")
	seedSecretAlert(t, f.root, "aws-access-key-id", "aws", secretscan_model.KindRepo, "root/aws.ini")
	seedSecretAlert(t, f.root, "github-token", "github", secretscan_model.KindWiki, "Wiki-Only.md") // not in a code list
	seedSecretAlert(t, f.leaf, "slack-token", "slack", secretscan_model.KindRepo, "leaf/notify.js")
	seedSecretAlert(t, f.readOnly, "github-token", "github", secretscan_model.KindRepo, "read/ci.sh")
	seedSecretAlert(t, f.off, "github-token", "github", secretscan_model.KindRepo, "off/x")
	seedSecretAlert(t, f.noCode, "github-token", "github", secretscan_model.KindRepo, "nocode/x")
	seedSecretAlert(t, f.repo3, "github-token", "github", secretscan_model.KindRepo, "repo3/y")
	seedSecretAlert(t, f.pub, "github-token", "github", secretscan_model.KindRepo, "pub/z")
	// one closed alert, with a closer
	closed := seedSecretAlert(t, f.root, "private-key", "private-key", secretscan_model.KindRepo, "root/server.pem")
	_, err = secretscan_model.CloseAlert(ctx, f.root.ID, closed.Index, secretscan_model.StateWontFix, "=cmd|' /C calc'!A0", 2)
	require.NoError(t, err)
	return f
}

// secretListRows reads the rows of a list as "repository | type | location | state label", without the time and closer.
func secretListRows(t *testing.T, resp *httptest.ResponseRecorder) []string {
	t.Helper()
	rows := []string{}
	NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).Find("table.secret-search-table tbody tr").Each(func(_ int, tr *goquery.Selection) {
		var cells []string
		tr.Find("td").Each(func(i int, td *goquery.Selection) {
			td.Find(".security-search-cl").Remove()
			switch i {
			case 3:
				cells = append(cells, strings.Join(strings.Fields(td.Find(".label").First().Text()), " "))
			case 0, 1, 2:
				cells = append(cells, strings.Join(strings.Fields(td.Text()), " "))
			}
		})
		rows = append(rows, strings.Join(cells, " | "))
	})
	return rows
}

func secretListTotal(t *testing.T, resp *httptest.ResponseRecorder) string {
	t.Helper()
	return secText(t, resp, "#secret-search-total")
}

const (
	slOrg   = "/org/org3/security/secrets"
	slAdmin = "/admin/security/secrets"
)

// The rows of the fixture, newest first.
const (
	slClosed = "org3/sl-root | Private key | root/server.pem:3 | Closed as won't fix"
	slPub    = "user2/sl-pub | GitHub token | pub/z:3 | Open"
	slRepo3  = "org3/repo3 | GitHub token | repo3/y:3 | Open"
	slRead   = "org3/sl-read | GitHub token | read/ci.sh:3 | Open"
	slLeaf   = "org3/slproj/sl-leaf | Slack token | leaf/notify.js:3 | Open"
	slAWS    = "org3/sl-root | AWS access key ID | root/aws.ini:3 | Open"
	slGitHub = "org3/sl-root | GitHub token | root/deploy.env:3 | Open"
)

func slPost(t *testing.T, s *TestSession, path string, values map[string]string, status int) *httptest.ResponseRecorder {
	t.Helper()
	return s.MakeRequest(t, NewRequestWithValues(t, "POST", path+"/export", values), status)
}

func TestOrgSecretAlertList(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := newSecretListFixture(t)
	setUserFlag(t, 8, "is_auditor", true)
	owner, admin, member, auditor := loginUser(t, "user2"), loginUser(t, "user1"), loginUser(t, "user4"), loginUser(t, "user8")
	ownerRows := []string{slClosed, slRepo3, slRead, slLeaf, slAWS, slGitHub}
	memberRows := []string{slClosed, slRepo3, slLeaf, slAWS, slGitHub} // no sl-read: read access only

	t.Run("who sees what", func(t *testing.T) {
		for name, s := range map[string]*TestSession{"owner": owner, "site admin": admin, "auditor": auditor} {
			resp := secGet(t, s, slOrg+"?state=all", http.StatusOK)
			assert.Equal(t, ownerRows, secretListRows(t, resp), name)
			assert.Equal(t, "6 secret alerts in 4 repositories", secretListTotal(t, resp), name)
			assert.Contains(t, secText(t, resp, "#secret-search-note"), "Showing every repository in this organization that you can read.", name)
			assert.Contains(t, secText(t, resp, "#secret-search-note"), "Downloads are recorded in the audit log.", name)
			// the open alerts by default, as the repository list
			resp = secGet(t, s, slOrg, http.StatusOK)
			assert.Equal(t, ownerRows[1:], secretListRows(t, resp), name)
			assert.Equal(t, "5 secret alerts in 4 repositories", secretListTotal(t, resp), name)
		}
		// a member sees the repositories they can write, as on the repository's own pages, and is told so under the count
		resp := secGet(t, member, slOrg+"?state=all", http.StatusOK)
		assert.Equal(t, memberRows, secretListRows(t, resp))
		assert.Equal(t, "5 secret alerts in 3 repositories", secretListTotal(t, resp))
		assert.Equal(t, "Showing alerts in the 4 repositories you can write to. Organization owners see every repository.", secText(t, resp, "#secret-search-narrow"))
		assert.Equal(t, "Secrets are never stored or shown. Downloads are recorded in the audit log.", secText(t, resp, "#secret-search-note"))
		// members with nothing to write are told so, not that the organization has no alert
		resp = secGet(t, loginUser(t, "user28"), slOrg, http.StatusOK) // in an admin team that has no repository
		assert.Empty(t, secretListRows(t, resp))
		assert.Contains(t, secText(t, resp, "#secret-search-none"), "You have write access to no repository in this organization")
		secGet(t, loginUser(t, "user15"), slOrg, http.StatusNotFound) // in a team, but not a member of the organization
		secGet(t, loginUser(t, "user5"), slOrg, http.StatusNotFound)  // not a member of the organization
		MakeRequest(t, NewRequest(t, "GET", slOrg), http.StatusSeeOther)
		// a private organization is hidden from a stranger and open to the auditor
		secGet(t, auditor, "/org/privated_org/security/secrets", http.StatusOK)
		secGet(t, member, "/org/privated_org/security/secrets", http.StatusNotFound)
	})

	t.Run("a token is no web session", func(t *testing.T) {
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization, auth_model.AccessTokenScopeReadRepository)
		resp := MakeRequest(t, NewRequest(t, "GET", slOrg).AddTokenAuth(token), NoExpectedStatus)
		assert.NotEqual(t, http.StatusOK, resp.Code)
		resp = MakeRequest(t, NewRequestWithValues(t, "POST", slOrg+"/export", map[string]string{}).AddTokenAuth(token), NoExpectedStatus)
		assert.NotEqual(t, http.StatusOK, resp.Code)
	})

	t.Run("the tab", func(t *testing.T) {
		const tab = `href="/org/org3/security/secrets"`
		for name, c := range map[string]struct {
			s    *TestSession
			want bool
		}{"owner": {owner, true}, "member": {member, true}, "auditor": {auditor, true}, "stranger": {loginUser(t, "user5"), false}} {
			assert.Equal(t, c.want, strings.Contains(secGet(t, c.s, "/org3", http.StatusOK).Body.String(), tab), name)
		}
		// the tab of the Security page holds the three pages for an owner while the graph is on
		doc := NewHTMLParser(t, secGet(t, owner, slOrg, http.StatusOK).Body)
		assert.Equal(t, "Secret alerts", strings.TrimSpace(doc.Find(`.repo-security-tabs a[aria-current="page"]`).Text()))
		assert.True(t, strings.HasPrefix(strings.TrimSpace(doc.Find("title").Text()), "Secret alerts"))
		assert.Equal(t, 2, doc.Find(`.repo-security-tabs a`).Length(), "no dependency graph: the secret alerts and the patterns")
		enableDependencyGraph(t)
		doc = NewHTMLParser(t, secGet(t, owner, slOrg, http.StatusOK).Body)
		assert.Equal(t, 4, doc.Find(`.repo-security-tabs a`).Length())
		assert.Contains(t, secGet(t, owner, "/org/org3/security/vulnerabilities", http.StatusOK).Body.String(), tab)
		secGet(t, member, "/org/org3/security/vulnerabilities", http.StatusNotFound) // owners only, as before
	})

	t.Run("filters", func(t *testing.T) {
		rows := func(query string) ([]string, *httptest.ResponseRecorder) {
			resp := secGet(t, owner, slOrg+query, http.StatusOK)
			return secretListRows(t, resp), resp
		}
		for query, want := range map[string][]string{
			"?state=open":                            {slRepo3, slRead, slLeaf, slAWS, slGitHub},
			"?state=closed":                          {slClosed},
			"?state=closed&reason=wont_fix":          {slClosed},
			"?state=closed&reason=revoked":           {},
			"?type=github-token":                     {slRepo3, slRead, slGitHub},
			"?state=all":                             {slClosed, slRepo3, slRead, slLeaf, slAWS, slGitHub},
			"?reason=wont_fix":                       {slClosed}, // a reason alone lists closed alerts
			"?type=slack-token&state=open":           {slLeaf},
			"?q=leaf":                                {slLeaf},
			"?q=SL-":                                 {slRead, slLeaf, slAWS, slGitHub}, // case-insensitive, name or owner
			"?q=%25":                                 {},                                // % is no wildcard
			"?q=_":                                   {},                                // nor is _
			"?project=slproj":                        {slLeaf},
			"?q=repo3&type=aws-access-key-id":        {},
			"?q=sl-root&state=open&type=slack-token": {},
		} {
			got, _ := rows(query)
			assert.Equal(t, want, got, query)
		}
		// a filter that isn't valid is left out and said so, never shown as if it were applied
		for query, field := range map[string]string{
			"?state=bogus": "State", "?state=open&reason=revoked": "Reason", "?reason=bogus": "Reason",
			"?q=" + strings.Repeat("a", 129): "Search by repository", "?type=bogus": "Secret type", "?project=nothere": "Project",
			"?q=%00": "Search by repository", "?q=sl%00x": "Search by repository", "?project=slproj%00": "Project", // a NUL would cut the pattern short
		} {
			got, resp := rows(query)
			assert.Equal(t, "Some filters in the link aren't valid and were left out: "+field+".", secText(t, resp, "#secret-filter-ignored"), query)
			assert.Equal(t, []string{slRepo3, slRead, slLeaf, slAWS, slGitHub}, got, query)
		}
		_, resp := rows("?state=bogus&type=bogus")
		assert.Contains(t, secText(t, resp, "#secret-filter-ignored"), "left out: State, Secret type.")
		_, resp = rows("?state=closed&reason=revoked")
		none := secText(t, resp, "#secret-search-none")
		assert.Contains(t, none, "No alerts match the filter.")
		assert.Contains(t, none, "Repositories with secret scanning turned off are not listed.")
		assert.Contains(t, none, "Clear filters")
		assert.Contains(t, none, "See which repositories have it off.", "an owner gets the link to the list of them")
		assert.NotContains(t, resp.Body.String(), `id="secret-filter-ignored"`)
		assert.NotContains(t, secText(t, secGet(t, member, slOrg+"?state=closed&reason=revoked", http.StatusOK), "#secret-search-none"), "See which")
		// the form keeps the values
		_, resp = rows("?state=closed&reason=wont_fix&type=private-key&q=root&project=slproj")
		doc := NewHTMLParser(t, bytes.NewBufferString(resp.Body.String()))
		doc.AssertElement(t, `select[name="state"] option[value="closed"][selected]`, true)
		doc.AssertElement(t, `select[name="reason"] option[value="wont_fix"][selected]`, true)
		doc.AssertElement(t, `select[name="type"] option[value="private-key"][selected]`, true)
		doc.AssertElement(t, `select[name="project"] option[value="slproj"][selected]`, true)
		assert.Equal(t, "root", doc.Find(`input[name="q"]`).AttrOr("value", ""))
	})

	t.Run("a page holds ten alerts and the pager keeps the filters", func(t *testing.T) {
		page := setting.UI.IssuePagingNum
		for range page {
			seedSecretAlert(t, f.root, "github-token", "github", secretscan_model.KindRepo, "root/more.env")
		}
		resp := secGet(t, owner, slOrg+"?state=all&q=sl-root", http.StatusOK)
		assert.Len(t, secretListRows(t, resp), page)
		assert.Equal(t, fmt.Sprintf("%d secret alerts in 1 repository", page+3), secretListTotal(t, resp))
		next := NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).Find(`.pagination a[href*="page=2"]`).First().AttrOr("href", "")
		assert.Contains(t, next, "state=all")
		assert.Contains(t, next, "q=sl-root")
		resp = secGet(t, owner, next, http.StatusOK)
		assert.Len(t, secretListRows(t, resp), 3)
		resp = secGet(t, owner, slOrg+"?state=open", http.StatusOK)
		assert.Equal(t, fmt.Sprintf("%d secret alerts in 4 repositories", page+5), secretListTotal(t, resp))
	})

	t.Run("a member who can write too many repositories is told so, never a failed page", func(t *testing.T) {
		defer test.MockVariableValue(&secretscan_service.MaxNarrowRepos, 3)()
		resp := secGet(t, member, slOrg, http.StatusOK)
		assert.Equal(t, "You can write to more than 3 repositories in this organization, too many to list here. Ask an organization owner for the list.", secText(t, resp, "#secret-search-too-many"))
		assert.Empty(t, secretListRows(t, resp))
		resp = slPost(t, member, slOrg, map[string]string{}, http.StatusSeeOther)
		assert.Equal(t, slOrg, resp.Header().Get("Location"))
		assert.NotContains(t, secGet(t, owner, slOrg, http.StatusOK).Body.String(), `id="secret-search-too-many"`, "an owner's list is not narrowed")
		// at the cap the list works, its candidates checked in chunks of the cap
		defer test.MockVariableValue(&secretscan_service.MaxNarrowRepos, 4)()
		resp = secGet(t, member, slOrg+"?state=all", http.StatusOK)
		assert.NotEmpty(t, secretListRows(t, resp))
		assert.Contains(t, secText(t, resp, "#secret-search-narrow"), "the 4 repositories")
	})

	t.Run("a member who only reads loads no repository and is told so", func(t *testing.T) {
		ctx := db.DefaultContext
		require.NoError(t, db.Insert(ctx, &organization.OrgUser{OrgID: 3, UID: 5}))
		tm := &organization.Team{OrgID: 3, Name: "sl-only-read", LowerName: "sl-only-read", AccessMode: perm_model.AccessModeRead}
		require.NoError(t, db.Insert(ctx, tm))
		require.NoError(t, db.Insert(ctx, &organization.TeamUnit{OrgID: 3, TeamID: tm.ID, Type: unit.TypeCode, AccessMode: perm_model.AccessModeRead}))
		require.NoError(t, db.Insert(ctx, &organization.TeamUser{OrgID: 3, TeamID: tm.ID, UID: 5}))
		require.NoError(t, db.Insert(ctx, &organization.TeamRepo{OrgID: 3, TeamID: tm.ID, RepoID: f.readOnly.ID}))
		require.NoError(t, access_model.RecalculateAccesses(ctx, f.readOnly))
		resp := secGet(t, loginUser(t, "user5"), slOrg, http.StatusOK)
		assert.Contains(t, secText(t, resp, "#secret-search-none"), "You have write access to no repository in this organization")
	})

	t.Run("the closed row names the reason and who closed it, the closer's name only", func(t *testing.T) {
		resp := secGet(t, owner, slOrg+"?state=closed", http.StatusOK)
		text := secText(t, resp, "table.secret-search-table tbody tr")
		assert.Contains(t, text, "Closed as won't fix")
		assert.Contains(t, text, "user2")
		assert.NotContains(t, text, "calc", "the comment is in the download only")
		assert.NotContains(t, resp.Body.String(), "cmd|")
		// the link goes to the alert in its repository
		doc := NewHTMLParser(t, bytes.NewBufferString(secGet(t, owner, slOrg+"?q=sl-leaf", http.StatusOK).Body.String()))
		assert.Equal(t, "/org3/slproj/sl-leaf/security/secrets/1", doc.Find("table.secret-search-table tbody tr td a").Eq(1).AttrOr("href", ""))
	})
}

func slCSV(t *testing.T, resp *httptest.ResponseRecorder) [][]string {
	t.Helper()
	assert.Equal(t, "text/csv; charset=utf-8", resp.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", resp.Header().Get("Cache-Control"))
	assert.Contains(t, resp.Header().Get("Content-Disposition"), "attachment")
	records, err := csv.NewReader(resp.Body).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, records)
	assert.Equal(t, []string{"state", "reason", "closed_by", "closed_at", "comment", "first_seen", "repository", "type", "location", "alert_url"}, records[0])
	return records[1:]
}

func TestOrgSecretAlertExport(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	newSecretListFixture(t)
	setUserFlag(t, 8, "is_auditor", true)
	owner, member := loginUser(t, "user2"), loginUser(t, "user4")
	audit_model.ResetActivity()

	t.Run("the button posts the filters", func(t *testing.T) {
		resp := secGet(t, owner, slOrg+"?state=open&type=slack-token&q=sl&project=slproj&reason=revoked", http.StatusOK)
		form := NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).Find(`form[action$="/export"]`)
		assert.Equal(t, slOrg+"/export", form.AttrOr("action", ""))
		var names []string
		form.Find("input[type=hidden]").Each(func(_ int, i *goquery.Selection) { names = append(names, i.AttrOr("name", "")) })
		assert.ElementsMatch(t, []string{"type", "q", "project"}, names) // the reason is not valid with open and was dropped; open is the default
	})

	t.Run("csv with the file headers, the closer, the link and an audit entry", func(t *testing.T) {
		since := auditMaxID(t)
		resp := slPost(t, owner, slOrg, map[string]string{"state": "all"}, http.StatusOK)
		assert.Contains(t, resp.Header().Get("Content-Disposition"), `attachment; filename="secret-alerts-org3-`)
		assert.Equal(t, "nosniff", resp.Header().Get("X-Content-Type-Options"))
		rows := slCSV(t, resp)
		require.Len(t, rows, 6)
		closed := rows[0] // newest first
		assert.Equal(t, []string{"closed", "wont_fix", "user2"}, closed[:3])
		assert.NotEmpty(t, closed[3])
		assert.Equal(t, "'=cmd|' /C calc'!A0", closed[4], "a spreadsheet doesn't run a formula")
		assert.Equal(t, []string{"org3/sl-root", "Private key", "root/server.pem:3"}, closed[6:9])
		assert.Equal(t, setting.AppURL+"org3/sl-root/security/secrets/4", closed[9])
		assert.Equal(t, []string{"open", "", "", "", ""}, rows[5][:5])
		var repos []string
		for _, r := range rows {
			repos = append(repos, r[6])
			assert.NotContains(t, strings.Join(r, ","), "Wiki-Only", "the wiki's place is not in a code list")
		}
		assert.NotContains(t, repos, "org3/sl-off")
		assert.NotContains(t, repos, "user2/sl-pub")
		assert.Contains(t, repos, "org3/slproj/sl-leaf")
		assert.Equal(t, setting.AppURL+"org3/slproj/sl-leaf/security/secrets/1", rows[3][9])

		entries := auditActions(t, since, "org.secret_alerts.exported")
		require.Len(t, entries, 1)
		assert.Equal(t, audit_model.ActorUser, entries[0].ActorType)
		assert.EqualValues(t, 2, entries[0].ActorID)
		assert.EqualValues(t, 3, entries[0].TargetID)
		assert.Equal(t, map[string]any{"kind": "secrets", "format": "csv", "state": "all", "count": float64(6)}, auditData(t, entries[0]))
		assert.Len(t, slCSV(t, slPost(t, owner, slOrg, map[string]string{}, http.StatusOK)), 5, "the open alerts by default, as the page")
	})

	t.Run("the filters narrow the download and are recorded", func(t *testing.T) {
		since := auditMaxID(t)
		rows := slCSV(t, slPost(t, owner, slOrg, map[string]string{"state": "open", "type": "github-token", "q": "sl-root"}, http.StatusOK))
		require.Len(t, rows, 1)
		assert.Equal(t, "org3/sl-root", rows[0][6])
		entries := auditActions(t, since, "org.secret_alerts.exported")
		require.Len(t, entries, 1)
		assert.Equal(t, map[string]any{"kind": "secrets", "format": "csv", "state": "open", "type": "github-token", "q": "sl-root", "count": float64(1)}, auditData(t, entries[0]), "the search text is recorded: the evidence says what the file holds")
		assert.Len(t, slCSV(t, slPost(t, owner, slOrg, map[string]string{"project": "slproj"}, http.StatusOK)), 1)
	})

	t.Run("a member downloads what the list shows", func(t *testing.T) {
		rows := slCSV(t, slPost(t, member, slOrg, map[string]string{"state": "all"}, http.StatusOK))
		var repos []string
		for _, r := range rows {
			repos = append(repos, r[6])
		}
		assert.Len(t, rows, 5)
		assert.NotContains(t, repos, "org3/sl-read")
	})

	// an auditor downloads what the page shows them: every repository, a member of the organization too
	t.Run("auditors", func(t *testing.T) {
		for name, uid := range map[string]int64{"auditor": 8, "member auditor": 4} {
			setUserFlag(t, uid, "is_auditor", true)
			s := loginUser(t, fmt.Sprintf("user%d", uid))
			assert.NotContains(t, secGet(t, s, slOrg, http.StatusOK).Body.String(), `id="secret-search-narrow"`, name)
			since := auditMaxID(t)
			rows := slCSV(t, slPost(t, s, slOrg, map[string]string{"state": "all"}, http.StatusOK))
			assert.Len(t, rows, 6, name)
			assert.Contains(t, slCSVColumn(rows, 6), "org3/sl-read", name)
			entries := auditActions(t, since, "org.secret_alerts.exported")
			require.Len(t, entries, 1, name)
			assert.Equal(t, uid, entries[0].ActorID, name)
			setUserFlag(t, uid, "is_auditor", false)
		}
		// the download of a private organization is open to the auditor too
		setUserFlag(t, 8, "is_auditor", true)
		slPost(t, loginUser(t, "user8"), "/org/privated_org/security/secrets", map[string]string{}, http.StatusOK)
		slPost(t, member, "/org/privated_org/security/secrets", map[string]string{}, http.StatusNotFound)
	})

	t.Run("refusals before the first byte write nothing", func(t *testing.T) {
		since := auditMaxID(t)
		slPost(t, loginUser(t, "user5"), slOrg, map[string]string{}, http.StatusNotFound)
		MakeRequest(t, NewRequestWithValues(t, "POST", slOrg+"/export", map[string]string{}), http.StatusSeeOther)
		// a filter that isn't valid: back to the page with a message
		// (the way back carries only the filters that were applied, never an invalid or over-long value)
		resp := slPost(t, owner, slOrg, map[string]string{"state": "bogus", "q": "x"}, http.StatusSeeOther)
		assert.Equal(t, slOrg+"?q=x", resp.Header().Get("Location"))
		resp = slPost(t, owner, slOrg, map[string]string{"project": "nothere"}, http.StatusSeeOther) // never an empty file that looks complete
		assert.Equal(t, slOrg, resp.Header().Get("Location"))
		resp = slPost(t, owner, slOrg, map[string]string{"type": strings.Repeat("t", 5000), "state": "closed"}, http.StatusSeeOther)
		assert.Equal(t, slOrg+"?state=closed", resp.Header().Get("Location"))
		resp = slPost(t, owner, slOrg, map[string]string{"q": "a\x00b", "reason": "revoked"}, http.StatusSeeOther)
		assert.Equal(t, slOrg+"?reason=revoked&state=closed", resp.Header().Get("Location"))
		assert.Empty(t, auditActions(t, since, "org.secret_alerts.exported"))
		// too many alerts
		defer test.MockVariableValue(&dependency_service.MaxExportRows, 2)()
		resp = slPost(t, owner, slOrg, map[string]string{"state": "all"}, http.StatusSeeOther)
		assert.Equal(t, slOrg+"?state=all", resp.Header().Get("Location"))
		assert.Empty(t, auditActions(t, since, "org.secret_alerts.exported"))
		// the download of one's own turn is taken
		release, ok := common.TakeExportSlot(2)
		require.True(t, ok)
		defer release()
		slPost(t, owner, slOrg, map[string]string{"q": "leaf"}, http.StatusSeeOther)
		assert.Empty(t, auditActions(t, since, "org.secret_alerts.exported"))
	})
}

func TestAdminSecretAlertList(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := newSecretListFixture(t)
	setUserFlag(t, 8, "is_auditor", true)
	admin, auditor, owner := loginUser(t, "user1"), loginUser(t, "user8"), loginUser(t, "user2")
	all := []string{slClosed, slPub, slRepo3, slRead, slLeaf, slAWS, slGitHub}

	t.Run("who sees what", func(t *testing.T) {
		for name, s := range map[string]*TestSession{"site admin": admin, "auditor": auditor} {
			resp := secGet(t, s, slAdmin+"?state=all", http.StatusOK)
			assert.Equal(t, all, secretListRows(t, resp), name)
			assert.Equal(t, "7 secret alerts in 5 repositories", secretListTotal(t, resp), name)
			assert.Contains(t, secText(t, resp, "#secret-search-note"), "Every repository on the instance, trashed ones excluded", name)
			NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).AssertElement(t, `input[name="owner"]`, true)
		}
		secGet(t, owner, slAdmin, http.StatusForbidden) // an organization owner is no site admin
		secGet(t, loginUser(t, "user4"), slAdmin, http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "GET", slAdmin), http.StatusSeeOther)
		token := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin, auth_model.AccessTokenScopeReadRepository)
		resp := MakeRequest(t, NewRequest(t, "GET", slAdmin).AddTokenAuth(token), NoExpectedStatus)
		assert.NotEqual(t, http.StatusOK, resp.Code, "a token is no web session")
	})

	t.Run("the menu", func(t *testing.T) {
		for name, s := range map[string]*TestSession{"site admin": admin} {
			resp := secGet(t, s, "/admin/audit", http.StatusOK)
			assert.Contains(t, resp.Body.String(), `href="/admin/security/secrets"`, name)
		}
		resp := secGet(t, admin, slAdmin, http.StatusOK)
		doc := NewHTMLParser(t, bytes.NewBufferString(resp.Body.String()))
		assert.Equal(t, "Secret alerts", strings.TrimSpace(doc.Find(`.flex-container-nav a.active.item`).Text()))
		assert.Equal(t, "Secret alerts", strings.TrimSpace(doc.Find(".admin-setting-content h4").Text()))
	})

	t.Run("filters", func(t *testing.T) {
		for query, want := range map[string][]string{
			"?owner=org3&state=all":         {slClosed, slRepo3, slRead, slLeaf, slAWS, slGitHub},
			"?owner=org3":                   {slRepo3, slRead, slLeaf, slAWS, slGitHub},
			"?owner=user2":                  {slPub},
			"?owner=nobody":                 {},
			"?state=open&type=github-token": {slPub, slRepo3, slRead, slGitHub},
			"?state=closed&reason=wont_fix": {slClosed},
			"?q=pub":                        {slPub},
			"?q=ORG3":                       {slRepo3, slRead, slLeaf, slAWS, slGitHub}, // the owner's name too
			"?owner=org3&q=leaf&state=open": {slLeaf},
			"?owner=user2&type=slack-token": {},
		} {
			assert.Equal(t, want, secretListRows(t, secGet(t, admin, slAdmin+query, http.StatusOK)), query)
		}
		// an owner name too long to be one is left out and said so
		resp := secGet(t, admin, slAdmin+"?owner="+strings.Repeat("a", 300), http.StatusOK)
		assert.Contains(t, secText(t, resp, "#secret-filter-ignored"), "left out: Owner.")
		assert.Len(t, secretListRows(t, resp), 6)
		resp = secGet(t, admin, slAdmin+"?owner=org3%00", http.StatusOK)
		assert.Contains(t, secText(t, resp, "#secret-filter-ignored"), "left out: Owner.")
	})

	t.Run("hidden: trash, the code unit, scanning off at each level", func(t *testing.T) {
		ctx := db.DefaultContext
		rowsNow := func() []string {
			return secretListRows(t, secGet(t, admin, slAdmin+"?owner=org3&state=all", http.StatusOK))
		}
		_, err := db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = ?", f.leaf.ID)
		require.NoError(t, err)
		assert.NotContains(t, rowsNow(), slLeaf)
		_, err = db.GetEngine(ctx).Exec("UPDATE repository SET trashed_unix = 0 WHERE id = ?", f.leaf.ID)
		require.NoError(t, err)
		assert.Contains(t, rowsNow(), slLeaf)

		// the organization turns it off: its repositories drop out, the others stay; locking it overrides the repositories
		require.NoError(t, user_model.SetUserSetting(ctx, 3, secretscan_model.OrgKey, "false"))
		assert.Empty(t, rowsNow())
		assert.Equal(t, []string{slPub}, secretListRows(t, secGet(t, admin, slAdmin, http.StatusOK)))
		// the organization's list says so, and where to turn it on
		resp := secGet(t, owner, slOrg, http.StatusOK)
		assert.Empty(t, secretListRows(t, resp))
		banner := secText(t, resp, "#secret-banner-off")
		assert.Contains(t, banner, "Secret scanning is off for all repositories of org3.")
		assert.Contains(t, NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).Find("#secret-banner-off a").AttrOr("href", ""), "/org/org3/settings/code_security")
		assert.Contains(t, secText(t, secGet(t, loginUser(t, "user4"), slOrg, http.StatusOK), "#secret-banner-off"), "Ask an organization owner to turn it on.")
		slPost(t, owner, slOrg, map[string]string{}, http.StatusNotFound)
		require.NoError(t, user_model.SetUserSetting(ctx, 3, secretscan_model.OrgKey, "true"))
		assert.Len(t, rowsNow(), 6, "sl-off stays hidden: its own switch is off")
		require.NoError(t, user_model.SetUserSetting(ctx, 3, secretscan_model.OrgLockedKey, "true"))
		assert.Len(t, rowsNow(), 7, "locked on: the repository's own switch doesn't count")
		require.NoError(t, user_model.SetUserSetting(ctx, 3, secretscan_model.OrgLockedKey, "false"))

		// the site switch: the lists say so to site admins (and the instance list to auditors, the menu entry stays),
		// nothing to download; members and owners have neither tab nor list, since only a site admin can turn it on
		defer test.MockVariableValue(&setting.SecretScanning.Enabled, false)()
		slPost(t, admin, slAdmin, map[string]string{}, http.StatusNotFound)
		slPost(t, admin, slOrg, map[string]string{}, http.StatusNotFound)
		assert.Contains(t, secGet(t, admin, "/admin/audit", http.StatusOK).Body.String(), `href="/admin/security/secrets"`)
		assert.Contains(t, secGet(t, auditor, "/admin/audit", http.StatusOK).Body.String(), `href="/admin/security/secrets"`)
		banner = secText(t, secGet(t, admin, slAdmin, http.StatusOK), "#secret-banner-off")
		assert.Contains(t, banner, "Secret scanning is off on this instance")
		assert.Contains(t, banner, "Turn it on in the site's secret scanning settings.")
		assert.Contains(t, secText(t, secGet(t, auditor, slAdmin, http.StatusOK), "#secret-banner-off"), "Ask a site admin to turn it on.")
		assert.Contains(t, secText(t, secGet(t, admin, slOrg, http.StatusOK), "#secret-banner-off"), "Turn it on in the site's secret scanning settings.")
		assert.Contains(t, secGet(t, admin, "/org3", http.StatusOK).Body.String(), `href="/org/org3/security`)
		secGet(t, owner, slOrg, http.StatusNotFound)
		secGet(t, loginUser(t, "user4"), slOrg, http.StatusNotFound)
		assert.NotContains(t, secGet(t, owner, "/org3", http.StatusOK).Body.String(), `href="/org/org3/security`)
	})

	t.Run("a repository that has no Code unit is not listed, whoever asks", func(t *testing.T) {
		assert.NotContains(t, secretListRows(t, secGet(t, admin, slAdmin, http.StatusOK)), "org3/sl-nocode | GitHub token | nocode/x:3 | Open")
	})
}

func TestAdminSecretAlertExport(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	newSecretListFixture(t)
	setUserFlag(t, 8, "is_auditor", true)
	admin, auditor := loginUser(t, "user1"), loginUser(t, "user8")
	audit_model.ResetActivity()

	for _, c := range []struct {
		name  string
		s     *TestSession
		actor int64
	}{{"site admin", admin, 1}, {"auditor", auditor, 8}} {
		t.Run(c.name, func(t *testing.T) {
			since := auditMaxID(t)
			resp := slPost(t, c.s, slAdmin, map[string]string{"owner": "org3", "state": "open"}, http.StatusOK)
			assert.Contains(t, resp.Header().Get("Content-Disposition"), `attachment; filename="secret-alerts-instance-`)
			rows := slCSV(t, resp)
			assert.Len(t, rows, 5)
			for _, r := range rows {
				assert.True(t, strings.HasPrefix(r[6], "org3/"), r[6])
			}
			entries := auditActions(t, since, "admin.secret_alerts.exported")
			require.Len(t, entries, 1)
			assert.Equal(t, c.actor, entries[0].ActorID)
			assert.Equal(t, map[string]any{"kind": "secrets", "format": "csv", "owner": "org3", "state": "open", "count": float64(5)}, auditData(t, entries[0]))
			assert.Len(t, slCSV(t, slPost(t, c.s, slAdmin, map[string]string{"state": "all"}, http.StatusOK)), 7)
		})
	}
	t.Run("refusals", func(t *testing.T) {
		since := auditMaxID(t)
		slPost(t, loginUser(t, "user2"), slAdmin, map[string]string{}, http.StatusForbidden)
		MakeRequest(t, NewRequestWithValues(t, "POST", slAdmin+"/export", map[string]string{}), http.StatusSeeOther)
		defer test.MockVariableValue(&dependency_service.MaxExportRows, 3)()
		resp := slPost(t, admin, slAdmin, map[string]string{"state": "open", "owner": "org3"}, http.StatusSeeOther)
		assert.Equal(t, slAdmin+"?owner=org3", resp.Header().Get("Location"))
		assert.Empty(t, auditActions(t, since, "admin.secret_alerts.exported"))
	})
}

// A member the organization's two-factor requirement blocks is a stranger there: the lists show none of its
// repositories to them, as the repositories themselves are hidden.
func TestSecretAlertListsTwoFactor(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	newSecretListFixture(t)
	// a public repository of the (public) organization: a stranger reads it, but the blocked auditor's alert rule
	// is the repository page's (AuditorView), which refuses them
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	public := depNewRepo(t, org3, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), "sl-public", false, 0)
	seedSecretAlert(t, public, "github-token", "github", secretscan_model.KindRepo, "public/x")
	setUserFlag(t, 8, "is_auditor", true)
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
	require.NoError(t, err)
	owner, member, admin, auditor := loginUser(t, "user2"), loginUser(t, "user4"), loginUser(t, "user1"), loginUser(t, "user8")

	for name, s := range map[string]*TestSession{"owner": owner, "member": member, "auditor": auditor} {
		secGet(t, s, slOrg, http.StatusNotFound)
		slPost(t, s, slOrg, map[string]string{"state": "all"}, http.StatusNotFound)
		assert.NotContains(t, secGet(t, s, "/org3", http.StatusOK).Body.String(), `href="/org/org3/security`, name)
	}
	secGet(t, auditor, "/org3/sl-public/security/secrets", http.StatusNotFound) // the repository page agrees
	// a site admin is exempt
	assert.Len(t, secretListRows(t, secGet(t, admin, slOrg+"?state=all", http.StatusOK)), 7)
	// the instance list keeps the repositories of everyone else, and a blocked auditor loses the organization's,
	// its public repositories too
	assert.Equal(t, []string{slPub}, secretListRows(t, secGet(t, auditor, slAdmin+"?state=all", http.StatusOK)))
	assert.Len(t, secretListRows(t, secGet(t, admin, slAdmin+"?state=all", http.StatusOK)), 8)
	assert.Equal(t, []string{"user2/sl-pub"}, slCSVColumn(slCSV(t, slPost(t, auditor, slAdmin, map[string]string{"state": "all"}, http.StatusOK)), 6))

	// with two-factor on the account, the owner is acting again
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = 3", false)
	require.NoError(t, err)
	assert.Len(t, secretListRows(t, secGet(t, owner, slOrg+"?state=all", http.StatusOK)), 7)
	assert.Contains(t, secretListRows(t, secGet(t, auditor, slAdmin, http.StatusOK)), "org3/sl-public | GitHub token | public/x:3 | Open")
}

func slCSVColumn(rows [][]string, col int) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r[col])
	}
	return out
}

// The number of queries of the lists and downloads doesn't grow with the repositories, alerts, closers and teams.
func TestSecretAlertListsQueryCount(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := newSecretListFixture(t)
	ctx := db.DefaultContext
	setUserFlag(t, 8, "is_auditor", true)
	owner, member, admin, auditor := loginUser(t, "user2"), loginUser(t, "user4"), loginUser(t, "user1"), loginUser(t, "user8")
	paths := map[string]struct {
		s    *TestSession
		path string
		post bool
	}{
		"owner":        {owner, slOrg + "?state=all", false},
		"owner open":   {owner, slOrg, false},
		"member":       {member, slOrg, false},
		"admin":        {admin, slAdmin, false},
		"auditor":      {auditor, slAdmin, false},
		"owner csv":    {owner, slOrg, true},
		"member csv":   {member, slOrg, true},
		"admin csv":    {admin, slAdmin, true},
		"filtered":     {admin, slAdmin + "?owner=org3&state=closed&type=private-key&q=sl", false},
		"org project":  {owner, slOrg + "?project=slproj", false},
		"member empty": {member, slOrg + "?q=nothing", false},
	}
	request := func(name string) {
		c := paths[name]
		if c.post {
			c.s.MakeRequest(t, NewRequestWithValues(t, "POST", c.path+"/export", map[string]string{}), http.StatusOK)
		} else {
			c.s.MakeRequest(t, NewRequest(t, "GET", c.path), http.StatusOK)
		}
	}
	count := func() map[string]int64 {
		out := map[string]int64{}
		for name := range paths {
			request(name) // warm the caches
			out[name] = stableQueryCount(t, func() { request(name) })
		}
		return out
	}
	few := count()
	// many more repositories the member writes, each with open and closed alerts of other closers
	for i := range 12 {
		name := fmt.Sprintf("many%d", i)
		repo := &repo_model.Repository{OwnerID: 3, OwnerName: "org3", Name: name, LowerName: name, IsPrivate: i%2 == 0, Status: repo_model.RepositoryReady}
		require.NoError(t, db.Insert(ctx, repo))
		require.NoError(t, db.Insert(ctx, &repo_model.RepoUnit{RepoID: repo.ID, Type: unit.TypeCode}))
		require.NoError(t, db.Insert(ctx, &organization.TeamRepo{OrgID: 3, TeamID: f.writers.ID, RepoID: repo.ID}))
		require.NoError(t, access_model.RecalculateAccesses(ctx, repo))
		seedSecretAlert(t, repo, "github-token", "github", secretscan_model.KindRepo, "a/b")
		closed := seedSecretAlert(t, repo, "slack-token", "slack", secretscan_model.KindRepo, "c/d")
		_, err := secretscan_model.CloseAlert(ctx, repo.ID, closed.Index, secretscan_model.StateRevoked, "", int64(2+i%3))
		require.NoError(t, err)
	}
	assert.Equal(t, few, count(), "the number of queries doesn't grow with the repositories and alerts")
	resp := secGet(t, member, slOrg+"?state=all", http.StatusOK)
	assert.Len(t, secretListRows(t, resp), 20) // a full page
	assert.Equal(t, "29 secret alerts in 15 repositories", secretListTotal(t, resp))
}

// A client that stops reading a download frees its export slot once a batch has waited ExportStallTime, through the
// real router (gzip on, as in the test config), not after the export time limit.
func TestSecretAlertExportStalledClient(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.SecretScanning.Enabled, true)()
		defer test.MockVariableValue(&common.ExportStallTime, time.Second)()
		ctx := db.DefaultContext
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		repo := depNewRepo(t, org3, owner, "sl-big", true, 0)
		// enough rows of random text that the file, even compressed, is larger than the socket buffers
		const rows = 40000
		random := make([]byte, rows*150)
		_, err := rand.Read(random)
		require.NoError(t, err)
		require.NoError(t, db.WithTx(ctx, func(ctx context.Context) error {
			for start := 0; start < rows; start += 500 {
				alerts := make([]*secretscan_model.Alert, 0, 500)
				for i := start; i < start+500; i++ {
					alerts = append(alerts, &secretscan_model.Alert{
						RepoID: repo.ID, Index: int64(i + 1), RuleID: "github-token", SecretType: "github",
						Fingerprint: fmt.Sprintf("%064x", i), State: secretscan_model.StateOpen, LocationCount: 1,
					})
				}
				if _, err := db.GetEngine(ctx).Insert(alerts); err != nil {
					return err
				}
				alerts = alerts[:0] // a multi-row insert doesn't fill in the IDs
				if err := db.GetEngine(ctx).Where("repo_id = ? AND `index` > ?", repo.ID, start).OrderBy("`index`").Find(&alerts); err != nil {
					return err
				}
				locations := make([]*secretscan_model.Location, 0, 500)
				for _, a := range alerts {
					path := base64.RawURLEncoding.EncodeToString(random[(a.Index-1)*150 : a.Index*150])
					l := secretscan_model.NewLocation(repo.ID, secretscan_model.KindRepo, "blob", path, 3, 3, "c", "A", "a@example.com", 1700000000)
					l.AlertID = a.ID
					locations = append(locations, l)
				}
				if _, err := db.GetEngine(ctx).Insert(locations); err != nil {
					return err
				}
			}
			return nil
		}))
		cookie := loginUser(t, "user2").GetCookie(setting.SessionConfig.CookieName)
		require.NotNil(t, cookie)

		// a small receive window from the start: set after connecting, Linux keeps the window it agreed on
		dialer := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096) })
		}}
		conn, err := dialer.Dial("tcp", u.Host)
		require.NoError(t, err)
		defer conn.Close()
		body := "state=all"
		_, err = fmt.Fprintf(conn, "POST /org/org3/security/secrets/export HTTP/1.1\r\nHost: %s\r\nCookie: %s=%s\r\nAccept-Encoding: gzip\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", u.Host, cookie.Name, cookie.Value, len(body), body)
		require.NoError(t, err)
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Minute)))
		resp, err := http.ReadResponse(bufio.NewReaderSize(conn, 4096), nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, resp.Header)
		_, err = io.ReadFull(resp.Body, make([]byte, 64*1024))
		require.NoError(t, err)
		// the client stops reading: the export holds the slot until its write waits too long, then gives it back
		release, ok := common.TakeExportSlot(2)
		if ok {
			release()
		}
		require.False(t, ok, "the export is still writing")
		assert.Eventually(t, func() bool {
			release, ok := common.TakeExportSlot(2)
			if ok {
				release()
			}
			return ok
		}, 30*time.Second, 100*time.Millisecond)
	})
}
