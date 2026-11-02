// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/ratelimit"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	audit_service "forgejo.org/services/audit"
	"forgejo.org/tests"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// insertAuditRows adds four entries: two credential changes (one with hostile text, one made with sudo), a repo
// event without a phrase and a sign-in.
func insertAuditRows(t *testing.T) []int64 {
	t.Helper()
	rows := []*audit_model.Entry{
		{
			CreatedUnix: 1000, Category: "credential", Action: "credential.access_token.created", Result: "success",
			ActorType: "user", ActorID: 2, ActorName: "user2", CredentialType: "access_token", CredentialID: 5, CredentialName: "ci", CredentialOwnerID: 2,
			OwnerID: 2, SubjectUserID: 2, TargetType: "access_token", TargetID: 5, TargetName: "tok<script>alert(1)</script>",
			UserAgent: "<script>ua()</script>", RequestID: "req1", IP: "10.0.0.1", Data: `{"after":{"name":"<b>x</b>"}}`,
		},
		{
			CreatedUnix: 2000, Category: "credential", Action: "credential.access_token.deleted", Result: "success",
			ActorType: "user", ActorID: 2, ActorName: "user2", SudoByID: 1, CredentialType: "access_token", CredentialID: 6, TargetName: "t2",
		},
		{CreatedUnix: 3000, Category: "repo", Action: "x.unknown", Result: "refused", ActorType: "user", ActorID: 4, ActorName: "user4<script>actor()</script>", OwnerID: 3, RepoID: 3, TargetName: "tgt"},
		{CreatedUnix: 4000, Category: "auth", Action: "auth.signin", Result: "success", ActorType: "user", ActorID: 2, ActorName: "user2"},
	}
	ids := make([]int64, 0, len(rows))
	for _, e := range rows {
		require.NoError(t, db.Insert(t.Context(), e))
		ids = append(ids, e.ID)
	}
	return ids
}

func setUserFlag(t *testing.T, id int64, col string, value bool) {
	t.Helper()
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET "+col+" = ? WHERE id = ?", value, id)
	require.NoError(t, err)
}

func rowID(id int64) string { return `data-id="` + strconv.FormatInt(id, 10) + `"` }

func countExports(t *testing.T) int {
	return unittest.GetCount(t, &audit_model.Entry{Action: "audit.exported"})
}

func TestAdminAuditPage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ids := insertAuditRows(t)
	admin := loginUser(t, "user1")

	body := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusOK).Body.String()
	for _, id := range ids[:3] {
		assert.Contains(t, body, rowID(id), "the changes tab is the default")
	}
	assert.NotContains(t, body, rowID(ids[3]))

	// stored text is escaped everywhere
	assert.NotContains(t, body, "<script>alert")
	assert.NotContains(t, body, "<script>ua")
	assert.NotContains(t, body, "<b>x</b>")
	assert.NotContains(t, body, "<script>actor")
	assert.Contains(t, body, ">user4&lt;script&gt;actor()&lt;/script&gt;</a>")
	// the credential type is shown by its label
	assert.Regexp(t, `<td class="audit-credential">\s*access token\s*"ci"`, body)
	assert.Contains(t, body, "Created access token tok&lt;script&gt;alert(1)&lt;/script&gt;")
	assert.Contains(t, body, "&lt;script&gt;ua()&lt;/script&gt;")
	assert.Contains(t, body, "&lt;b&gt;x&lt;/b&gt;")
	// an action without a phrase, sudo, a refusal, the credential
	assert.Contains(t, body, "x.unknown · tgt")
	assert.Contains(t, body, `user1</a> acting as <a href="?category=all&user=2">user2</a>`)
	assert.Contains(t, body, "refused")
	assert.Contains(t, body, `"ci"`)
	assert.Contains(t, body, "credential=access_token:5")
	assert.Contains(t, body, `?category=all&request_id=req1`)

	body = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?category=signins"), http.StatusOK).Body.String()
	assert.Contains(t, body, rowID(ids[3]))
	assert.NotContains(t, body, rowID(ids[0]))

	t.Run("filters", func(t *testing.T) {
		body := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?category=all&credential=access_token:5"), http.StatusOK).Body.String()
		assert.Contains(t, body, rowID(ids[0]))
		assert.NotContains(t, body, rowID(ids[1]))
		assert.Contains(t, body, "audit-credential-pill")

		body = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?org=nope"), http.StatusUnprocessableEntity).Body.String()
		assert.Contains(t, body, "No organization named nope.")
		body = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?ip=nope"), http.StatusUnprocessableEntity).Body.String()
		assert.Contains(t, body, "Invalid value for ip: nope")

		body = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?category=all&user=user4"), http.StatusOK).Body.String()
		assert.Contains(t, body, rowID(ids[2]))
		assert.NotContains(t, body, rowID(ids[0]))
		assert.Contains(t, body, "User: user4 (#4)")
		body = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?category=all&org=3&repo=1&user=999"), http.StatusOK).Body.String()
		assert.Contains(t, body, "Organization: org3 (#3) · User: #999 (no longer exists) · Repository: user2/repo1 (#1)")

		body = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?action=nothing.here"), http.StatusOK).Body.String()
		assert.Contains(t, body, "Nothing matches these filters.")
	})

	t.Run("time zone", func(t *testing.T) {
		// a stored zone that can't be loaded shows UTC
		require.NoError(t, db.Insert(db.DefaultContext, &user_model.Setting{UserID: 1, SettingKey: user_model.SettingsKeyTimeZone, SettingValue: "No/Such_Zone"}))
		assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusOK).Body.String(), "Times in UTC")
	})

	t.Run("links", func(t *testing.T) {
		assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/users/2"), http.StatusOK).Body.String(), "/admin/audit?category=all&user=2")
		assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/orgs"), http.StatusOK).Body.String(), "/admin/audit?category=all&org=3")
		assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repos"), http.StatusOK).Body.String(), "/admin/audit?category=all&repo=user2%2frepo1")
	})

	t.Run("phrases without a placeholder", func(t *testing.T) {
		for _, a := range []string{"activity.api.write", "activity.api.write.aggregated", "credential.access_token.created"} {
			require.NoError(t, db.Insert(t.Context(), &audit_model.Entry{CreatedUnix: 5000, Category: "activity", Action: a, Result: "success", ActorType: "user", ActorID: 2, ActorName: "user2", TargetName: "user2/r1"}))
		}
		body := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?category=all"), http.StatusOK).Body.String()
		assert.Contains(t, body, "API write request · user2/r1")
		assert.Contains(t, body, "Failed API write requests (aggregated) · user2/r1")
		assert.Contains(t, body, "Created access token user2/r1")
		assert.NotContains(t, body, "%!")
	})

	t.Run("read logging and write errors", func(t *testing.T) {
		body := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusOK).Body.String()
		assert.Contains(t, body, "Read logging: off")
		assert.NotContains(t, body, "audit-write-errors")

		defer test.MockVariableValue(&setting.Audit.LogReads, true)()
		audit_model.WriteErrors.Add(2)
		defer audit_model.WriteErrors.Add(-2)
		body = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusOK).Body.String()
		assert.Contains(t, body, "Read logging: on")
		assert.Contains(t, body, fmt.Sprintf("%d activity entries could not be written on this server", audit_model.WriteErrors.Load()))
	})

	t.Run("empty", func(t *testing.T) {
		_, err := db.GetEngine(db.DefaultContext).Exec("DELETE FROM audit_event")
		require.NoError(t, err)
		body := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusOK).Body.String()
		assert.Contains(t, body, "No audit entries yet.")
	})
}

func TestAdminAuditAccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ids := insertAuditRows(t)
	marker := rowID(ids[0])
	readAdmin := auth_model.AccessTokenScopeReadAdmin

	admin := loginUser(t, "user1")
	adminToken := getTokenForLoggedInUser(t, admin, readAdmin)
	setUserFlag(t, 2, "is_auditor", true)
	auditor := loginUser(t, "user2")
	auditorToken := getTokenForLoggedInUser(t, auditor, readAdmin)

	t.Run("web", func(t *testing.T) {
		assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusOK).Body.String(), marker)
		assert.Contains(t, auditor.MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusOK).Body.String(), marker)
		auditor.MakeRequest(t, NewRequest(t, "HEAD", "/admin/audit"), http.StatusOK)
		assert.NotContains(t, loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusForbidden).Body.String(), marker)
		MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusSeeOther)
	})

	t.Run("api", func(t *testing.T) {
		get := func(token string, status int) {
			t.Helper()
			resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/audit?category=all&before=2000-01-01T00:00:00Z").AddTokenAuth(token), status)
			if status == http.StatusOK {
				var events []*api.AuditEvent
				DecodeJSON(t, resp, &events)
				assert.Len(t, events, 4)
				assert.Empty(t, resp.Header().Get("X-Total-Count"))
			}
		}
		get(adminToken, http.StatusOK)
		get(auditorToken, http.StatusOK)
		get(getUserToken(t, "user1", auth_model.AccessTokenScopeReadRepository), http.StatusForbidden)
		get(getUserToken(t, "user1", readAdmin, auth_model.AccessTokenScopePublicOnly), http.StatusForbidden)
		get(createFineGrainedRepoAccessToken(t, "user1", []auth_model.AccessTokenScope{readAdmin}, []int64{1}), http.StatusForbidden)
		get(getUserToken(t, "user4", readAdmin), http.StatusForbidden)
		get(createOAuth2Token(t, auditor, []auth_model.AccessTokenScope{readAdmin}), http.StatusForbidden)
		ait := newAITester(t) // an all-access integration of user2, the auditor
		defer ait.close()
		get(ait.signedJWT(), http.StatusForbidden)
	})

	t.Run("suspended", func(t *testing.T) {
		for _, col := range []string{"prohibit_login", "is_active"} {
			t.Run(col, func(t *testing.T) {
				for _, id := range []int64{1, 2} {
					setUserFlag(t, id, col, col == "prohibit_login")
					defer setUserFlag(t, id, col, col != "prohibit_login")
				}
				// a session gets the shared middleware's page, without any audit data
				for _, s := range []*TestSession{admin, auditor} {
					assert.NotContains(t, s.MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), NoExpectedStatus).Body.String(), marker)
				}
				for _, token := range []string{adminToken, auditorToken} {
					MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/audit").AddTokenAuth(token), http.StatusForbidden)
					MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/audit?format=csv").AddTokenAuth(token), http.StatusForbidden)
				}
			})
		}
	})
}

// TestAdminAuditRoutes checks that the auditor reaches the audit log and nothing else under /admin: every other
// admin route stays behind adminReq.
func TestAdminAuditRoutes(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableDependencyGraph(t) // the search pages answer 404 while it is off
	// so does the secret alert list
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.Enabled, true))
	setUserFlag(t, 2, "is_auditor", true)
	auditor := loginUser(t, "user2")

	n := 0
	require.NoError(t, chi.Walk(testWebRoutes.R, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.ReplaceAll(route, "/*/", "/")
		if route != "/admin" && !strings.HasPrefix(route, "/admin/") {
			return nil
		}
		n++
		path := route
		for strings.Contains(path, "{") {
			i, j := strings.Index(path, "{"), strings.Index(path, "}")
			path = path[:i] + "1" + path[j+1:]
		}
		path = strings.ReplaceAll(path, "*", "x")
		resp := auditor.MakeRequest(t, NewRequest(t, method, path), NoExpectedStatus)
		switch {
		case method == "GET" && (route == "/admin/audit" || route == "/admin/config/secret-scanning" || strings.HasPrefix(route, "/admin/config/dependency-graph")):
			assert.Equal(t, http.StatusOK, resp.Code, route)
		case method == "GET" && (route == "/admin/security/secrets" || route == "/admin/security/patterns"):
			assert.Equal(t, http.StatusOK, resp.Code, route)
		case method == "POST" && route == "/admin/security/secrets/export":
			assert.Equal(t, http.StatusOK, resp.Code, method+" "+route) // the audited download of the list: a CSV
		case method == "POST" && strings.HasPrefix(route, "/admin/config/dependency-graph/") && strings.HasSuffix(route, "/export"):
			// the audited download of the dependency and vulnerability search is open to the auditor: it gets past the
			// gate and is sent back to the page: the form names no format
			assert.Equal(t, http.StatusSeeOther, resp.Code, method+" "+route)
		default:
			assert.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, resp.Code, method+" "+route)
		}
		return nil
	}))
	assert.Greater(t, n, 50)
}

func TestAdminAuditExport(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ids := insertAuditRows(t)
	admin := loginUser(t, "user1")
	token := getTokenForLoggedInUser(t, admin, auth_model.AccessTokenScopeReadAdmin)

	before := countExports(t)
	resp := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?category=credential&before=2000-01-01T00:00:00Z&format=csv"), http.StatusOK)
	h := resp.Header()
	assert.Equal(t, "text/csv; charset=utf-8", h.Get("Content-Type"))
	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.True(t, strings.HasPrefix(h.Get("Content-Disposition"), "attachment"), h.Get("Content-Disposition"))
	assert.Equal(t, "category=credential&before=2000-01-01T00%3A00%3A00Z", h.Get("X-Audit-Filter"))
	assert.Equal(t, "false", h.Get("X-Audit-Truncated"))
	_, err := time.Parse(time.RFC3339, h.Get("X-Audit-Generated-At"))
	require.NoError(t, err)
	webCSV := resp.Body.String()
	records, err := csv.NewReader(strings.NewReader(webCSV)).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 3)
	assert.Equal(t, strconv.FormatInt(ids[0], 10), records[1][0])
	assert.Equal(t, before+1, countExports(t))
	e := &audit_model.Entry{}
	has, err := db.GetEngine(db.DefaultContext).Where("action = ?", "audit.exported").Desc("id").Get(e)
	require.NoError(t, err)
	require.True(t, has)
	assert.EqualValues(t, 1, e.ActorID)
	assert.JSONEq(t, `{"format":"csv","filter":["category=credential","before=2000-01-01T00:00:00Z"],"capped":false}`, e.Data)

	t.Run("HEAD records nothing", func(t *testing.T) {
		before := countExports(t)
		admin.MakeRequest(t, NewRequest(t, "HEAD", "/admin/audit?category=credential&before=2000-01-01T00:00:00Z&format=csv"), http.StatusOK)
		assert.Equal(t, before, countExports(t))
	})

	t.Run("cli", func(t *testing.T) {
		// stdout can carry log lines (the root warning in containers), so compare the --output file
		path := filepath.Join(t.TempDir(), "audit.csv")
		_, err := runMainApp("admin", "audit", "export", "--category", "credential", "--until", "2000-01-01T00:00:00Z", "--output", path)
		require.NoError(t, err)
		out, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, webCSV, string(out))
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		_, err = runMainApp("admin", "audit", "export", "--output", path)
		require.Error(t, err, "an existing file is not overwritten")
		e := &audit_model.Entry{}
		_, err = db.GetEngine(db.DefaultContext).Where("action = ?", "audit.exported").Desc("id").Get(e)
		require.NoError(t, err)
		assert.Equal(t, audit_model.ActorCLI, e.ActorType)
	})

	t.Run("api", func(t *testing.T) {
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/audit?category=all&before=2000-01-01T00:00:00Z&limit=2").AddTokenAuth(token), http.StatusOK)
		var events []*api.AuditEvent
		DecodeJSON(t, resp, &events)
		require.Len(t, events, 2)
		newest := events[0].ID
		assert.Contains(t, resp.Header().Get("Link"), "before_id="+strconv.FormatInt(events[1].ID, 10))
		// the page shows the same entries first for the same query
		body := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?category=all&before=2000-01-01T00:00:00Z"), http.StatusOK).Body.String()
		assert.Less(t, strings.Index(body, rowID(newest)), strings.Index(body, rowID(events[1].ID)))

		MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/audit?org=nope").AddTokenAuth(token), http.StatusUnprocessableEntity)

		defer test.MockVariableValue(&audit_service.ExportCap, 1)()
		resp = MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/audit?category=credential&format=json").AddTokenAuth(token), http.StatusOK)
		assert.Equal(t, "application/json; charset=utf-8", resp.Header().Get("Content-Type"))
		assert.Equal(t, "true", resp.Header().Get("X-Audit-Truncated"))
		assert.Contains(t, resp.Header().Get("Link"), "after_id="+strconv.FormatInt(ids[0], 10))
		DecodeJSON(t, resp, &events)
		require.Len(t, events, 1)
		assert.Equal(t, map[string]any{"after": map[string]any{"name": "<b>x</b>"}}, events[0].Data)
	})

	t.Run("heavy class", func(t *testing.T) {
		mockRateLimit(t, map[string]setting.RateLimitClass{
			ratelimit.Heavy: {AuthenticatedRate: slow, AuthenticatedBurst: 1, AnonymousRate: slow, AnonymousBurst: 1},
		}, "")
		admin.MakeRequest(t, fromIP(NewRequest(t, "GET", "/admin/audit?format=csv"), "198.51.100.40"), http.StatusOK)
		admin.MakeRequest(t, fromIP(NewRequest(t, "HEAD", "/admin/audit?format=csv"), "198.51.100.40"), http.StatusOK)
		admin.MakeRequest(t, fromIP(NewRequest(t, "GET", "/admin/audit?format=csv"), "198.51.100.40"), http.StatusTooManyRequests)
		admin.MakeRequest(t, fromIP(NewRequest(t, "GET", "/admin/audit"), "198.51.100.40"), http.StatusOK)
		mockRateLimit(t, map[string]setting.RateLimitClass{
			ratelimit.Heavy: {AuthenticatedRate: slow, AuthenticatedBurst: 1, AnonymousRate: slow, AnonymousBurst: 1},
		}, "")
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/admin/audit?format=json").AddTokenAuth(token), "198.51.100.41"), http.StatusOK)
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/admin/audit?format=json").AddTokenAuth(token), "198.51.100.41"), http.StatusTooManyRequests)
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/api/v1/admin/audit").AddTokenAuth(token), "198.51.100.41"), http.StatusOK)
	})

	t.Run("maintenance", func(t *testing.T) {
		defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()
		before := countExports(t)
		admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusOK)
		admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?format=json"), http.StatusOK)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/audit?format=csv").AddTokenAuth(token), http.StatusOK)
		assert.Equal(t, before+2, countExports(t))
	})
}

// TestAdminAuditPaging checks the API page size cap and that the page and the API select the same entries for the
// same query string.
func TestAdminAuditPaging(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	for i := range 105 {
		require.NoError(t, db.Insert(db.DefaultContext, &audit_model.Entry{CreatedUnix: timeutil.TimeStamp(5000 + i), Category: "credential", Action: "credential.access_token.created", Result: "success", ActorType: "user", ActorID: 2}))
	}
	require.NoError(t, db.Insert(db.DefaultContext, &audit_model.Entry{CreatedUnix: 6000, Category: "credential", Action: "credential.access_token.deleted", Result: "failure", ActorType: "user", ActorID: 2}))
	admin := loginUser(t, "user1")
	token := getTokenForLoggedInUser(t, admin, auth_model.AccessTokenScopeReadAdmin)
	apiIDs := func(query string) []string {
		var events []*api.AuditEvent
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/audit?"+query).AddTokenAuth(token), http.StatusOK), &events)
		ids := make([]string, 0, len(events))
		for _, e := range events {
			ids = append(ids, strconv.FormatInt(e.ID, 10))
		}
		return ids
	}

	assert.Len(t, apiIDs("category=all&before=2000-01-01T00:00:00Z&limit=200"), 100)

	query := "category=credential&result=success&before=2000-01-01T00:00:00Z"
	want := apiIDs(query)
	require.Len(t, want, 50)
	body := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?"+query), http.StatusOK).Body.String()
	var got []string
	for _, m := range regexp.MustCompile(`<tr data-id="(\d+)"`).FindAllStringSubmatch(body, -1) {
		got = append(got, m[1])
	}
	assert.Equal(t, want, got)
}

func TestAdminAuditUI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	admin := loginUser(t, "user1")
	const first, last = 1760648400, 1760648460
	rows := []*audit_model.Entry{
		{CreatedUnix: first, Category: "activity", Action: "activity.api.write", Result: "success", ActorType: "user", ActorID: 2, ActorName: "user2", IP: "10.0.0.7"},
		{
			CreatedUnix: last + 30, Category: "activity", Action: "activity.api.write.aggregated", Result: "success", ActorType: "user", ActorID: 2, ActorName: "user2", IP: "10.0.0.7",
			Data: `{"count":12,"first":1760648400,"last":1760648460}`,
		},
		{CreatedUnix: last + 40, Category: "activity", Action: "activity.api.read", Result: "success", ActorType: "user", ActorID: 2, ActorName: "user2", IP: "10.0.0.8"},
	}
	for _, e := range rows {
		require.NoError(t, db.Insert(t.Context(), e))
	}

	body := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit?category=activity"), http.StatusOK).Body.String()
	t.Run("categories", func(t *testing.T) {
		for _, c := range []string{"changes", "signins", "activity", "all", "auth", "credential", "account", "admin", "org", "repo", "audit"} {
			assert.Contains(t, body, `<option value="`+c+`"`, c)
		}
		assert.Contains(t, body, `<option value="activity" selected>`)
		assert.Equal(t, 1, strings.Count(body, `<option value="activity"`))
		for _, e := range rows {
			assert.Contains(t, body, rowID(e.ID))
		}
		changes := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit"), http.StatusOK).Body.String()
		assert.NotContains(t, changes, rowID(rows[0].ID), "activity is not in the default tab")
	})

	t.Run("result", func(t *testing.T) {
		assert.Regexp(t, `<td class="audit-result">success</td>`, body)
	})

	t.Run("aggregated", func(t *testing.T) {
		assert.Equal(t, 1, strings.Count(body, "12 more like this between "), "only the aggregated row is labelled")
		assert.Contains(t, body, "between 2025-10-16 21:00:00 and 2025-10-16 21:01:00")
		m := regexp.MustCompile(`<a href="(\?[^"]*action=activity\.api\.write[^"]*)">Show them</a>`).FindStringSubmatch(body)
		require.NotNil(t, m, body)
		link := strings.ReplaceAll(m[1], "&amp;", "&")
		assert.Contains(t, link, "ip=10.0.0.7")

		got := admin.MakeRequest(t, NewRequest(t, "GET", "/admin/audit"+link), http.StatusOK).Body.String()
		assert.Contains(t, got, rowID(rows[0].ID), "the link lists the base row")
		assert.NotContains(t, got, rowID(rows[2].ID), "another action and IP is left out")
	})

	t.Run("time values", func(t *testing.T) {
		assert.Contains(t, body, "<dt>first</dt><dd>2025-10-16 21:00:00 (1760648400)</dd>")
	})
}
