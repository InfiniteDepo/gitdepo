// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/ratelimit"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	app_context "forgejo.org/services/context"
	secretscan_service "forgejo.org/services/secretscan"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	spOrgPage  = "/org/org3/settings/code_security"
	spOrgBase  = spOrgPage + "/patterns"
	spOrgView  = "/org/org3/security/secrets/patterns"
	spAdmin    = "/admin/security/patterns"
	spPatternR = `acme-key-[a-z0-9]{20}`
)

// spSample is a secret of the test rule, built from parts so that no source line holds one.
func spSample(seed string) string { return "K=acme-" + "key-" + strings.Repeat(seed, 10)[:20] }

func spValues(name string) map[string]string {
	return map[string]string{"name": name, "pattern": spPatternR, "keywords": "acme-key", "sample": spSample("a1")}
}

// spRows reads the rows of the patterns table as their text.
func spRows(t *testing.T, resp *httptest.ResponseRecorder) []string {
	t.Helper()
	var out []string
	NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).Find("table.secret-patterns-table tbody tr").Each(func(_ int, tr *goquery.Selection) {
		out = append(out, strings.Join(strings.Fields(tr.Text()), " "))
	})
	return out
}

func spCreate(t *testing.T, owner *user_model.User, name string) *secretscan_model.CustomPattern {
	t.Helper()
	o := secretscan_service.SitePatterns
	if owner != nil {
		o = secretscan_service.OrgPatterns(owner)
	}
	p, err := secretscan_service.CreatePattern(audit_model.WithSystem(db.DefaultContext, "test"), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}), o,
		secretscan_service.PatternInput{Name: name, Pattern: spPatternR, Keywords: []string{"acme-key"}, Sample: spSample("a1")})
	require.NoError(t, err)
	return p
}

func spOrg3(t *testing.T) *user_model.User {
	t.Helper()
	return unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
}

func spAudit(t *testing.T, action string) int64 {
	t.Helper()
	n, err := db.GetEngine(db.DefaultContext).Table("audit_event").Where("action = ?", action).Count()
	require.NoError(t, err)
	return n
}

func spJSON(t *testing.T, resp *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	DecodeJSON(t, resp, &out)
	return out
}

func spPost(t *testing.T, s *TestSession, path string, v map[string]string, status int) *httptest.ResponseRecorder {
	t.Helper()
	return s.MakeRequest(t, NewRequestWithValues(t, "POST", path, v), status)
}

func spCount(t *testing.T, owner int64) int64 {
	t.Helper()
	n, err := db.GetEngine(db.DefaultContext).Where("owner_id = ? AND deleted_unix = 0", owner).Count(new(secretscan_model.CustomPattern))
	require.NoError(t, err)
	return n
}

// refusals of an add: the page is shown again (422) with the reason, the typed values stay, the sample does not.
func spRefusals(t *testing.T, s *TestSession, owner *user_model.User, base string) {
	t.Helper()
	spCreate(t, owner, "taken")
	var ownerID int64
	if owner != nil {
		ownerID = owner.ID
	}
	before := spCount(t, ownerID)
	cases := map[string]struct {
		change func(map[string]string)
		title  string
		field  string
		text   string
	}{
		"invalid":         {func(v map[string]string) { v["pattern"] = `acme-key-(` }, "Invalid pattern", "pattern", `A "(" has no matching ")".`},
		"lookahead":       {func(v map[string]string) { v["pattern"] = `acme-key-(?=x)` }, "Invalid pattern", "pattern", "Lookaheads, lookbehinds and backreferences"},
		"backreference":   {func(v map[string]string) { v["pattern"] = `(acme)-key-\1` }, "Invalid pattern", "pattern", "Lookaheads, lookbehinds and backreferences"},
		"bad escape":      {func(v map[string]string) { v["pattern"] = `acme-key-\q` }, "Invalid pattern", "pattern", `"\q" is not a valid escape.`},
		"complex":         {func(v map[string]string) { v["pattern"] = `(acme-key-[a-z0-9]+)+` }, "Pattern is too complex", "pattern", ""},
		"keyword":         {func(v map[string]string) { v["keywords"] = "zzz-key" }, "A keyword must appear in the match", "keywords", "starts acme"},
		"no keyword":      {func(v map[string]string) { v["keywords"] = " , " }, "Keywords needed", "keywords", ""},
		"control keyword": {func(v map[string]string) { v["keywords"] = "acme-key\x01" }, "Keywords needed", "keywords", ""},
		"common word":     {func(v map[string]string) { v["keywords"] = "https" }, "A keyword is too common", "keywords", ""},
		"has secret":      {func(v map[string]string) { v["name"] = "leak " + "ghp_" + "Zk3Qx9Tm2Lp7Vb4Nc8Rd" + "1Hs6Jw5Yf0Ga2Xeq" }, "Contains a known token format", "name", "The name contains text in a known token format (GitHub token)"},
		"no match":        {func(v map[string]string) { v["sample"] = "nothing to see" }, "No match", "sample", ""},
		"name taken":      {func(v map[string]string) { v["name"] = "taken" }, "Name is taken", "name", ""},
		"bad name":        {func(v map[string]string) { v["name"] = "a\x1bb" }, "Invalid name", "name", ""},
		"bidi name":       {func(v map[string]string) { v["name"] = "a\u202eb" }, "Invalid name", "name", ""},
		"long sample":     {func(v map[string]string) { v["sample"] = strings.Repeat("x", 4097) }, "Test string is too long", "sample", ""},
	}
	for name, c := range cases {
		v := spValues("fresh")
		c.change(v)
		resp := spPost(t, s, base, v, http.StatusUnprocessableEntity)
		doc := NewHTMLParser(t, bytes.NewBufferString(resp.Body.String()))
		assert.Contains(t, secText(t, resp, "#secret-pattern-error"), c.title, name)
		assert.Contains(t, secText(t, resp, "#secret-pattern-error"), c.text, name)
		assert.NotContains(t, resp.Body.String(), "error parsing regexp", name)
		doc.AssertElement(t, fmt.Sprintf(`#secret-pattern-form .field.error [name=%q][aria-invalid="true"][aria-describedby="secret-pattern-error"]`, c.field), true)
		assert.Equal(t, 1, doc.Find("[aria-invalid]").Length(), name+": one field is marked")
		assert.Equal(t, base+"#secret-pattern-form", doc.Find("#secret-pattern-form").AttrOr("action", ""), name+": the page lands at the form")
		assert.Equal(t, v["keywords"], doc.Find(`input[name="keywords"]`).AttrOr("value", ""), name)
		assert.NotContains(t, resp.Body.String(), spSample("a1"), name+": the sample is not echoed")
		assert.Empty(t, doc.Find(`textarea[name="sample"]`).Text(), name)
	}
	assert.Equal(t, before, spCount(t, ownerID), "nothing was stored")
}

func TestOrgSecretPatterns(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.Enabled, true))
	owner := loginUser(t, "user2")

	t.Run("the empty page", func(t *testing.T) {
		resp := secGet(t, owner, spOrgPage, http.StatusOK)
		assert.Contains(t, secText(t, resp, "#secret-patterns-none"), "No custom patterns yet. Add one below.")
		assert.Contains(t, secText(t, resp, "#secret-patterns-count"), "0 of 50 patterns are on, including the site's.")
		assert.Empty(t, spRows(t, resp))
	})

	t.Run("add, and what the page shows", func(t *testing.T) {
		resp := spPost(t, owner, spOrgBase, spValues("  Acme internal key "), http.StatusSeeOther)
		assert.Equal(t, spOrgPage+"#custom-patterns", resp.Header().Get("Location"))
		page := secGet(t, owner, spOrgPage, http.StatusOK)
		rows := spRows(t, page)
		require.Len(t, rows, 1)
		for _, want := range []string{"Acme internal key", "acme-key", spPatternR, "On"} {
			assert.Contains(t, rows[0], want)
		}
		assert.NotContains(t, page.Body.String(), spSample("a1"), "the sample is never shown back")
		assert.EqualValues(t, 1, spAudit(t, "org.secret_pattern.created"))
	})

	t.Run("refusals", func(t *testing.T) {
		spRefusals(t, owner, spOrg3(t), spOrgBase)
	})

	t.Run("test: nothing stored, the sample not echoed", func(t *testing.T) {
		before := spAudit(t, "org.secret_pattern.created")
		out := spJSON(t, spPost(t, owner, spOrgBase+"/test", spValues("tested"), http.StatusOK))
		assert.Equal(t, true, out["ok"])
		assert.Equal(t, "Match found", out["title"])
		assert.Contains(t, out["message"], "29 characters")
		assert.Contains(t, out["message"], "acme")
		assert.NotContains(t, out["message"], strings.Repeat("a1", 4))
		v := spValues("tested")
		v["keywords"] = "zzz-key"
		resp := spPost(t, owner, spOrgBase+"/test", v, http.StatusOK)
		out = spJSON(t, resp)
		assert.Equal(t, false, out["ok"])
		assert.Equal(t, "A keyword must appear in the match", out["title"])
		assert.Equal(t, "keywords", out["field"])
		assert.NotContains(t, resp.Body.String(), spSample("a1"))
		assert.NotContains(t, resp.Body.String(), strings.Repeat("a1", 4))
		v["pattern"] = `(acme-key-[a-z0-9]+)+`
		out = spJSON(t, spPost(t, owner, spOrgBase+"/test", v, http.StatusOK))
		assert.Equal(t, "Pattern is too complex", out["title"])
		assert.Equal(t, before, spAudit(t, "org.secret_pattern.created"))
		assert.EqualValues(t, 2, spCount(t, 3), "the test stored no pattern (the one added above and the taken one)")
	})

	t.Run("test, add and rename are rate limited", func(t *testing.T) {
		p := spCreate(t, spOrg3(t), "Limited")
		for _, c := range []struct {
			path   string
			values map[string]string
			status int
		}{
			{spOrgBase + "/test", spValues("x"), http.StatusOK},
			{spOrgBase, spValues("limited one"), http.StatusSeeOther},
			{fmt.Sprintf("%s/%d/rename", spOrgBase, p.ID), map[string]string{"name": "Limited 2"}, http.StatusSeeOther},
		} {
			mockRateLimit(t, map[string]setting.RateLimitClass{
				ratelimit.Heavy: {AuthenticatedRate: slow, AuthenticatedBurst: 1, AnonymousRate: slow, AnonymousBurst: 1},
			}, "")
			spPost(t, owner, c.path, c.values, c.status)
			spPost(t, owner, c.path, c.values, http.StatusTooManyRequests)
		}
		mockRateLimit(t, map[string]setting.RateLimitClass{}, "")
	})

	t.Run("a pattern never runs before the engine bounded it", func(t *testing.T) {
		// a keyword with a control character is refused before the engine's checks: the pattern (over the size
		// limit) must not run on the sample (over its limit) for the Test answer or the refused add's message
		v := map[string]string{
			"name": "big", "pattern": strings.Repeat(`(?:[a-z0-9]|x[0-9]y)`, 200) + "q", "keywords": "abc\x01", "sample": strings.Repeat("a", 8<<10),
		}
		start := time.Now()
		out := spJSON(t, spPost(t, owner, spOrgBase+"/test", v, http.StatusOK))
		assert.Equal(t, "Keywords needed", out["title"])
		assert.NotContains(t, out["message"], "starts")
		resp := spPost(t, owner, spOrgBase, v, http.StatusUnprocessableEntity)
		assert.Contains(t, secText(t, resp, "#secret-pattern-error"), "Keywords needed")
		assert.Less(t, time.Since(start), 5*time.Second)
		// a body larger than the fields can be is refused before it is read
		v["pattern"], v["sample"] = strings.Repeat(`(?:[a-z0-9]|x[0-9]y)`, 2000)+"q", strings.Repeat("a", 200<<10)
		for _, path := range []string{spOrgBase + "/test", spOrgBase, spAdmin + "/test", spAdmin} {
			s := owner
			if strings.HasPrefix(path, "/admin") {
				s = loginUser(t, "user1")
			}
			spPost(t, s, path, v, http.StatusRequestEntityTooLarge)
		}
		// the Test button sends FormData (multipart)
		var body bytes.Buffer
		w := multipart.NewWriter(&body)
		for k, val := range v {
			require.NoError(t, w.WriteField(k, val))
		}
		require.NoError(t, w.Close())
		req := NewRequestWithBody(t, "POST", spOrgBase+"/test", &body)
		req.Header.Set("Content-Type", w.FormDataContentType())
		owner.MakeRequest(t, req, http.StatusRequestEntityTooLarge)
		assert.Less(t, time.Since(start), 10*time.Second)
	})

	t.Run("rename, disable, enable and delete", func(t *testing.T) {
		p := spCreate(t, spOrg3(t), "Lifecycle")
		id := fmt.Sprint(p.ID)
		renamed := spAudit(t, "org.secret_pattern.renamed")
		spPost(t, owner, spOrgBase+"/"+id+"/rename", map[string]string{"name": "Renamed"}, http.StatusSeeOther)
		assert.Contains(t, strings.Join(spRows(t, secGet(t, owner, spOrgPage, http.StatusOK)), "\n"), "Renamed")
		assert.Equal(t, renamed+1, spAudit(t, "org.secret_pattern.renamed"))
		spPost(t, owner, spOrgBase+"/"+id+"/rename", map[string]string{"name": "Acme internal key"}, http.StatusSeeOther) // taken: a flash, no change
		// a new name gets the checks of a new pattern's
		spPost(t, owner, spOrgBase+"/"+id+"/rename", map[string]string{"name": "leak " + "ghp_" + "Zk3Qx9Tm2Lp7Vb4Nc8Rd" + "1Hs6Jw5Yf0Ga2Xeq"}, http.StatusSeeOther)
		flash := owner.GetCookie(app_context.CookieNameFlash)
		require.NotNil(t, flash)
		v, err := url.QueryUnescape(flash.Value)
		require.NoError(t, err)
		v, err = url.QueryUnescape(v)
		require.NoError(t, err)
		assert.Contains(t, v, "The name contains text in a known token format (GitHub token)")
		spPost(t, owner, spOrgBase+"/"+id+"/rename", map[string]string{"name": "Re\u202enamed"}, http.StatusSeeOther)
		got, err := secretscan_model.GetCustomPattern(t.Context(), 3, p.ID)
		require.NoError(t, err)
		assert.Equal(t, "Renamed", got.Name)

		page := secGet(t, owner, spOrgPage, http.StatusOK)
		NewHTMLParser(t, bytes.NewBufferString(page.Body.String())).AssertElement(t, "#pattern-disable-"+id, true)
		spPost(t, owner, spOrgBase+"/"+id+"/disable", map[string]string{}, http.StatusSeeOther)
		got, _ = secretscan_model.GetCustomPattern(t.Context(), 3, p.ID)
		assert.False(t, got.Enabled)
		assert.Contains(t, strings.Join(spRows(t, secGet(t, owner, spOrgPage, http.StatusOK)), "\n"), "Off")
		spPost(t, owner, spOrgBase+"/"+id+"/enable", map[string]string{}, http.StatusSeeOther)
		got, _ = secretscan_model.GetCustomPattern(t.Context(), 3, p.ID)
		assert.True(t, got.Enabled)

		// delete asks for the name, on the server too
		spPost(t, owner, spOrgBase+"/"+id+"/delete", map[string]string{"confirm_name": "wrong"}, http.StatusSeeOther)
		got, _ = secretscan_model.GetCustomPattern(t.Context(), 3, p.ID)
		assert.Zero(t, got.DeletedUnix)
		spPost(t, owner, spOrgBase+"/"+id+"/delete", map[string]string{"confirm_name": " renamed "}, http.StatusSeeOther)
		got, _ = secretscan_model.GetCustomPattern(t.Context(), 3, p.ID)
		assert.NotZero(t, got.DeletedUnix)
		spPost(t, owner, spOrgBase+"/"+id+"/delete", map[string]string{"confirm_name": "renamed"}, http.StatusNotFound)
		spPost(t, owner, spOrgBase+"/"+id+"/enable", map[string]string{}, http.StatusNotFound)
		assert.NotContains(t, secGet(t, owner, spOrgPage, http.StatusOK).Body.String(), `id="pattern-`+id+`"`)
	})

	t.Run("another owner's pattern is not found", func(t *testing.T) {
		site := spCreate(t, nil, "site rule")
		for _, action := range []string{"rename", "enable", "disable", "delete"} {
			spPost(t, owner, fmt.Sprintf("%s/%d/%s", spOrgBase, site.ID, action), map[string]string{"name": "x", "confirm_name": "site rule"}, http.StatusNotFound)
		}
		got, err := secretscan_model.GetCustomPattern(t.Context(), 0, site.ID)
		require.NoError(t, err)
		assert.True(t, got.Enabled)
		assert.Zero(t, got.DeletedUnix)
		// the site's pattern is listed, with no buttons and no rule
		rows := spRows(t, secGet(t, owner, spOrgPage, http.StatusOK))
		var siteRow string
		for _, r := range rows {
			if strings.Contains(r, "site rule") {
				siteRow = r
			}
		}
		assert.Contains(t, siteRow, "Site")
		assert.NotContains(t, siteRow, spPatternR)
		assert.NotContains(t, siteRow, "Delete")
	})

	t.Run("the cap", func(t *testing.T) {
		for spCount(t, 3)+spCount(t, 0) < 50 {
			spCreate(t, spOrg3(t), fmt.Sprintf("filler %d", spCount(t, 3)))
		}
		resp := spPost(t, owner, spOrgBase, spValues("one too many"), http.StatusUnprocessableEntity)
		assert.Contains(t, secText(t, resp, "#secret-pattern-error"), "Too many patterns")
		assert.Contains(t, secText(t, resp, "#secret-pattern-error"), "At most 50 patterns")
	})
}

func TestSecretPatternsAccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.Enabled, true))
	setUserFlag(t, 8, "is_auditor", true)
	org := spOrg3(t)
	own := spCreate(t, org, "Org rule")
	site := spCreate(t, nil, "Site rule")
	owner, admin, member, auditor, stranger := loginUser(t, "user2"), loginUser(t, "user1"), loginUser(t, "user4"), loginUser(t, "user8"), loginUser(t, "user5")

	t.Run("who may change them", func(t *testing.T) {
		secGet(t, owner, spOrgPage, http.StatusOK)
		secGet(t, admin, spOrgPage, http.StatusOK)
		for name, s := range map[string]*TestSession{"member": member, "auditor": auditor, "stranger": stranger} {
			secGet(t, s, spOrgPage, http.StatusNotFound)
			spPost(t, s, spOrgBase, spValues("nope"), http.StatusNotFound)
			spPost(t, s, spOrgBase+"/test", spValues("nope"), http.StatusNotFound)
			spPost(t, s, fmt.Sprintf("%s/%d/delete", spOrgBase, own.ID), map[string]string{"confirm_name": "Org rule"}, http.StatusNotFound)
			assert.EqualValues(t, 1, spCount(t, 3), name)
		}
		MakeRequest(t, NewRequest(t, "GET", spOrgPage), http.StatusSeeOther)
		spPost(t, admin, spOrgBase, spValues("by the site admin"), http.StatusSeeOther)
		assert.EqualValues(t, 2, spCount(t, 3))
	})

	t.Run("who reads them, and what", func(t *testing.T) {
		for name, c := range map[string]struct {
			s        *TestSession
			wantText bool
			status   int
		}{"owner": {owner, true, 200}, "site admin": {admin, true, 200}, "member": {member, false, 200}, "auditor": {auditor, false, 200}, "stranger": {stranger, false, 404}} {
			if c.status == http.StatusNotFound {
				secGet(t, c.s, spOrgView, c.status)
				continue
			}
			resp := secGet(t, c.s, spOrgView, c.status)
			rows := strings.Join(spRows(t, resp), "\n")
			assert.Contains(t, rows, "Org rule", name)
			assert.Contains(t, rows, "acme-key", name)
			assert.Contains(t, rows, "Site rule", name)
			assert.Equal(t, c.wantText, strings.Contains(resp.Body.String(), spPatternR), name+": the rule text")
			doc := NewHTMLParser(t, bytes.NewBufferString(resp.Body.String()))
			doc.AssertElement(t, "#secret-pattern-form", false)
			doc.AssertElement(t, ".secret-pattern-actions", false)
			doc.AssertElement(t, "#secret-patterns-manage", c.wantText)
			assert.Equal(t, "Custom patterns", strings.TrimSpace(doc.Find(`.repo-security-tabs a[aria-current="page"]`).Text()), name)
		}
		// the manage link follows the acting owner: a site admin who is no member gets it too
		doc := NewHTMLParser(t, bytes.NewBufferString(secGet(t, admin, spOrgView, http.StatusOK).Body.String()))
		doc.AssertElement(t, "#secret-patterns-manage", true)
		assert.Contains(t, secText(t, secGet(t, member, spOrgView, http.StatusOK), "#secret-patterns-intro"), "Patterns the organization and the site scan for")
		// the tab is on the other pages of the Security area too
		assert.Contains(t, secGet(t, member, "/org/org3/security/secrets", http.StatusOK).Body.String(), `href="/org/org3/security/secrets/patterns"`)
	})

	t.Run("a token is no web session", func(t *testing.T) {
		token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		for _, path := range []string{spOrgBase, spOrgBase + "/test", spOrgBase + fmt.Sprintf("/%d/delete", own.ID)} {
			req := NewRequestWithValues(t, "POST", path, spValues("by token")).AddTokenAuth(token)
			assert.NotEqual(t, http.StatusOK, MakeRequest(t, req, NoExpectedStatus).Code, path)
		}
		assert.EqualValues(t, 3, spCount(t, 3)+spCount(t, 0))
	})

	t.Run("two-factor requirement", func(t *testing.T) {
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = 3", false)
			require.NoError(t, err)
		}()
		// a blocked owner and member are strangers: nothing to read, nothing to change
		for _, s := range []*TestSession{owner, member} {
			secGet(t, s, spOrgPage, http.StatusNotFound)
			secGet(t, s, spOrgView, http.StatusNotFound)
			spPost(t, s, spOrgBase, spValues("blocked"), http.StatusNotFound)
		}
		secGet(t, admin, spOrgPage, http.StatusOK) // a site admin is exempt
	})

	t.Run("archived organization", func(t *testing.T) {
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET is_archived = ? WHERE id = 3", true)
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET is_archived = ? WHERE id = 3", false)
			require.NoError(t, err)
		}()
		resp := secGet(t, owner, spOrgPage, http.StatusOK)
		assert.Contains(t, secText(t, resp, "#secret-patterns-locked"), "archived")
		doc := NewHTMLParser(t, bytes.NewBufferString(resp.Body.String()))
		doc.AssertElement(t, "#secret-pattern-form", false)
		doc.AssertElement(t, ".secret-pattern-actions", false)
		before := spCount(t, 3)
		spPost(t, owner, spOrgBase, spValues("archived"), http.StatusForbidden)
		spPost(t, owner, fmt.Sprintf("%s/%d/delete", spOrgBase, own.ID), map[string]string{"confirm_name": "Org rule"}, http.StatusForbidden)
		assert.Equal(t, before, spCount(t, 3))
		secGet(t, member, spOrgView, http.StatusOK) // reading stays open
	})

	t.Run("maintenance", func(t *testing.T) {
		defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()
		resp := secGet(t, owner, spOrgPage, http.StatusOK)
		assert.Contains(t, secText(t, resp, "#secret-patterns-locked"), "read-only maintenance")
		NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).AssertElement(t, "#secret-pattern-form", false)
		before := spCount(t, 3)
		spPost(t, owner, spOrgBase, spValues("maintenance"), http.StatusSeeOther)
		assertMaintenanceFlash(t, owner)
		assert.Equal(t, before, spCount(t, 3))
		spPost(t, owner, fmt.Sprintf("%s/%d/disable", spOrgBase, own.ID), map[string]string{}, http.StatusSeeOther)
		assertMaintenanceFlash(t, owner)
		got, err := secretscan_model.GetCustomPattern(t.Context(), 3, own.ID)
		require.NoError(t, err)
		assert.True(t, got.Enabled)
		// the test only reads
		assert.Equal(t, true, spJSON(t, spPost(t, owner, spOrgBase+"/test", spValues("x"), http.StatusOK))["ok"])
	})
	_ = site
}

func TestAdminSecretPatterns(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.Enabled, true))
	setUserFlag(t, 8, "is_auditor", true)
	admin, auditor, user := loginUser(t, "user1"), loginUser(t, "user8"), loginUser(t, "user2")

	t.Run("an admin changes them", func(t *testing.T) {
		resp := secGet(t, admin, spAdmin, http.StatusOK)
		assert.Contains(t, secText(t, resp, "#secret-patterns-none"), "No custom patterns yet.")
		assert.Equal(t, spAdmin, spPost(t, admin, spAdmin, spValues("Site key"), http.StatusSeeOther).Header().Get("Location"))
		resp = secGet(t, admin, spAdmin, http.StatusOK)
		rows := spRows(t, resp)
		require.Len(t, rows, 1)
		assert.Contains(t, rows[0], spPatternR)
		assert.EqualValues(t, 1, spAudit(t, "admin.secret_pattern.created"))
		assert.Equal(t, true, spJSON(t, spPost(t, admin, spAdmin+"/test", spValues("x"), http.StatusOK))["ok"])
		spRefusals(t, admin, nil, spAdmin)
		var id int64
		_, err := db.GetEngine(db.DefaultContext).Table("secret_custom_pattern").Where("owner_id = 0").Cols("id").Get(&id)
		require.NoError(t, err)
		base := fmt.Sprintf("%s/%d", spAdmin, id)
		spPost(t, admin, base+"/rename", map[string]string{"name": "Site key 2"}, http.StatusSeeOther)
		spPost(t, admin, base+"/disable", map[string]string{}, http.StatusSeeOther)
		spPost(t, admin, base+"/enable", map[string]string{}, http.StatusSeeOther)
		for _, action := range []string{"admin.secret_pattern.renamed", "admin.secret_pattern.disabled", "admin.secret_pattern.enabled"} {
			assert.EqualValues(t, 1, spAudit(t, action), action)
		}
		spPost(t, admin, base+"/delete", map[string]string{"confirm_name": "no"}, http.StatusSeeOther)
		assert.EqualValues(t, 2, spCount(t, 0), "the pattern and the one the refusals made")
		spPost(t, admin, base+"/delete", map[string]string{"confirm_name": "site key 2"}, http.StatusSeeOther)
		assert.EqualValues(t, 1, spCount(t, 0))
		// an organization's pattern is not found here
		own := spCreate(t, spOrg3(t), "Org rule")
		spPost(t, admin, fmt.Sprintf("%s/%d/delete", spAdmin, own.ID), map[string]string{"confirm_name": "Org rule"}, http.StatusNotFound)
		assert.EqualValues(t, 1, spCount(t, 3))
	})

	t.Run("an auditor reads names and keywords only", func(t *testing.T) {
		spCreate(t, nil, "Visible site rule")
		resp := secGet(t, auditor, spAdmin, http.StatusOK)
		rows := strings.Join(spRows(t, resp), "\n")
		assert.Contains(t, rows, "Visible site rule")
		assert.Contains(t, rows, "acme-key")
		assert.NotContains(t, resp.Body.String(), spPatternR)
		doc := NewHTMLParser(t, bytes.NewBufferString(resp.Body.String()))
		doc.AssertElement(t, "#secret-pattern-form", false)
		doc.AssertElement(t, ".secret-pattern-actions", false)
		spPost(t, auditor, spAdmin, spValues("by the auditor"), http.StatusForbidden)
		spPost(t, auditor, spAdmin+"/test", spValues("x"), http.StatusForbidden)
		assert.EqualValues(t, 2, spCount(t, 0))
	})

	t.Run("nobody else", func(t *testing.T) {
		assert.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, secGet(t, user, spAdmin, http.StatusForbidden).Code)
		spPost(t, user, spAdmin, spValues("by a user"), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "GET", spAdmin), http.StatusSeeOther)
	})

	t.Run("while scanning is off the patterns can be prepared", func(t *testing.T) {
		defer test.MockVariableValue(&setting.SecretScanning.Enabled, false)()
		bumpSettingsRevision(t)
		resp := secGet(t, admin, spAdmin, http.StatusOK)
		assert.Contains(t, secText(t, resp, "#secret-patterns-site-off"), "Secret scanning is off")
		spPost(t, admin, spAdmin, spValues("prepared"), http.StatusSeeOther)
	})

	t.Run("maintenance", func(t *testing.T) {
		defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()
		resp := secGet(t, admin, spAdmin, http.StatusOK)
		assert.Contains(t, secText(t, resp, "#secret-patterns-locked"), "read-only maintenance")
		before := spCount(t, 0)
		spPost(t, admin, spAdmin, spValues("maintenance"), http.StatusSeeOther)
		assertMaintenanceFlash(t, admin)
		assert.Equal(t, before, spCount(t, 0))
		assert.Equal(t, true, spJSON(t, spPost(t, admin, spAdmin+"/test", spValues("x"), http.StatusOK))["ok"])
	})
}

// The type filter of the lists offers the custom patterns of the list's owner and the site, and filters by them.
func TestSecretAlertListsCustomTypeFilter(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := newSecretListFixture(t)
	org, member, admin := spOrg3(t), loginUser(t, "user4"), loginUser(t, "user1")
	own, site, gone := spCreate(t, org, "Org rule"), spCreate(t, nil, "Site rule"), spCreate(t, org, "Gone rule")
	other := spCreate(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 6}), "Other org rule")
	require.NoError(t, secretscan_service.DeletePattern(audit_model.WithSystem(db.DefaultContext, "test"), secretscan_service.OrgPatterns(org), gone.ID))
	seedSecretAlert(t, f.root, own.RuleID(), "custom", secretscan_model.KindRepo, "custom/own.env")
	seedSecretAlert(t, f.root, site.RuleID(), "custom", secretscan_model.KindRepo, "custom/site.env")

	options := func(resp *httptest.ResponseRecorder) map[string]string {
		out := map[string]string{}
		NewHTMLParser(t, bytes.NewBufferString(resp.Body.String())).Find(`select[name="type"] option`).Each(func(_ int, o *goquery.Selection) {
			out[o.AttrOr("value", "")] = strings.TrimSpace(o.Text())
		})
		return out
	}
	for name, s := range map[string]*TestSession{"owner": loginUser(t, "user2"), "member": member} {
		got := options(secGet(t, s, slOrg, http.StatusOK))
		assert.Equal(t, "Org rule", got[own.RuleID()], name)
		assert.Equal(t, "Site rule", got[site.RuleID()], name)
		assert.NotContains(t, got, gone.RuleID(), name+": a deleted pattern is not offered")
		assert.NotContains(t, got, other.RuleID(), name+": another organization's")
	}
	got := options(secGet(t, admin, slAdmin, http.StatusOK))
	assert.Equal(t, "Site rule", got[site.RuleID()])
	assert.Equal(t, "Org rule (org3)", got[own.RuleID()], "the instance list offers the organizations' patterns too")
	assert.Equal(t, "Other org rule (org6)", got[other.RuleID()])
	assert.NotContains(t, got, gone.RuleID())
	assert.Contains(t, got, "github-token", "the built-in rules are still there")
	rows := secretListRows(t, secGet(t, admin, slAdmin+"?type="+own.RuleID(), http.StatusOK))
	assert.Equal(t, []string{"org3/sl-root | Org rule | custom/own.env:3 | Open"}, rows)

	// an auditor kept out of an organization by its 2FA requirement isn't offered its patterns
	setUserFlag(t, 8, "is_auditor", true)
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
	require.NoError(t, err)
	got = options(secGet(t, loginUser(t, "user8"), slAdmin, http.StatusOK))
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = 3", false)
	require.NoError(t, err)
	assert.NotContains(t, got, own.RuleID())
	assert.Contains(t, got, other.RuleID())

	rows = secretListRows(t, secGet(t, member, slOrg+"?type="+own.RuleID(), http.StatusOK))
	assert.Equal(t, []string{"org3/sl-root | Org rule | custom/own.env:3 | Open"}, rows)
	rows = secretListRows(t, secGet(t, admin, slAdmin+"?type="+site.RuleID(), http.StatusOK))
	assert.Equal(t, []string{"org3/sl-root | Site rule | custom/site.env:3 | Open"}, rows)
	doc := NewHTMLParser(t, bytes.NewBufferString(secGet(t, member, slOrg+"?type="+own.RuleID(), http.StatusOK).Body.String()))
	doc.AssertElement(t, fmt.Sprintf(`select[name="type"] option[value=%q][selected]`, own.RuleID()), true)
	doc = NewHTMLParser(t, bytes.NewBufferString(secGet(t, admin, slAdmin, http.StatusOK).Body.String()))
	doc.AssertElement(t, "#secret-types-cut", false)

	// a list cut at its limit says so
	t.Run("a shortened list says so", func(t *testing.T) {
		rows := make([]*secretscan_model.CustomPattern, 1000)
		for i := range rows {
			rows[i] = &secretscan_model.CustomPattern{Name: fmt.Sprintf("bulk %d", i), Pattern: spPatternR, Keywords: secretscan_model.EncodeKeywords([]string{"acme-key"})}
		}
		_, err := db.GetEngine(db.DefaultContext).Insert(rows)
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(db.DefaultContext).Where("name LIKE 'bulk %'").Delete(new(secretscan_model.CustomPattern))
			require.NoError(t, err)
		}()
		resp := secGet(t, admin, slAdmin, http.StatusOK)
		assert.Contains(t, secText(t, resp, "#secret-types-cut"), "List shortened")
		custom := 0
		for id := range options(resp) {
			if strings.HasPrefix(id, secretscan_model.CustomRulePrefix) {
				custom++
			}
		}
		assert.Equal(t, 1000, custom)
	})
}

// The patterns pages cost a fixed number of queries.
func TestSecretPatternsQueryCount(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	t.Cleanup(test.MockVariableValue(&setting.SecretScanning.Enabled, true))
	f := newSecretListFixture(t)
	setUserFlag(t, 8, "is_auditor", true)
	org := spOrg3(t)
	paths := map[string]struct {
		s    *TestSession
		path string
	}{
		"owner": {loginUser(t, "user2"), spOrgPage}, "view": {loginUser(t, "user2"), spOrgView}, "member": {loginUser(t, "user4"), spOrgView},
		"admin": {loginUser(t, "user1"), spAdmin}, "auditor": {loginUser(t, "user8"), spAdmin},
	}
	add := func(owner *user_model.User, i int) {
		p := spCreate(t, owner, fmt.Sprintf("many %d %v", i, owner == nil))
		seedSecretAlert(t, f.root, p.RuleID(), "custom", secretscan_model.KindRepo, fmt.Sprintf("many/%d", p.ID))
	}
	add(org, 0)
	add(nil, 0)
	count := func() map[string]int64 {
		out := map[string]int64{}
		for name, c := range paths {
			request := func() { c.s.MakeRequest(t, NewRequest(t, "GET", c.path), http.StatusOK) }
			request()
			out[name] = stableQueryCount(t, request)
		}
		return out
	}
	few := count()
	for i := range 12 {
		add(org, i+1)
		add(nil, i+1)
	}
	assert.Equal(t, few, count())
}
