// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"maps"
	"net/http"
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"
	secretscan_service "forgejo.org/services/secretscan"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecretAlertsOfCustomPatterns: the lists, the repository pages and the API name the alerts of a custom
// pattern by the pattern, label a deleted one, and show the name of a deleted one only to its owners.
func TestSecretAlertsOfCustomPatterns(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := newSecretListFixture(t)
	sys := audit_model.WithSystem(db.DefaultContext, "test")
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	input := func(name string) secretscan_service.PatternInput {
		return secretscan_service.PatternInput{
			Name: name, Pattern: `acme-key-[a-z0-9]{20}`, Keywords: []string{"acme-key"}, Sample: "K=acme-" + "key-" + strings.Repeat("a1", 10),
		}
	}
	create := func(owner secretscan_service.PatternOwner, name string) *secretscan_model.CustomPattern {
		p, err := secretscan_service.CreatePattern(sys, admin, owner, input(name))
		require.NoError(t, err)
		return p
	}
	orgOwner, site := secretscan_service.OrgPatterns(org), secretscan_service.SitePatterns
	live, off := create(orgOwner, "org live"), create(site, "site off")
	orgGone, siteGone := create(orgOwner, "org gone"), create(site, "site gone")
	require.NoError(t, secretscan_service.SetPatternEnabled(sys, secretscan_service.SitePatterns, off.ID, false))
	require.NoError(t, secretscan_service.DeletePattern(sys, secretscan_service.OrgPatterns(org), orgGone.ID))
	require.NoError(t, secretscan_service.DeletePattern(sys, secretscan_service.SitePatterns, siteGone.ID))
	for i, p := range []*secretscan_model.CustomPattern{live, off, orgGone, siteGone} {
		seedSecretAlert(t, f.root, p.RuleID(), "custom", secretscan_model.KindRepo, "custom/"+string(rune('a'+i))+".env")
	}
	seedSecretAlert(t, f.root, "custom-99999", "custom", secretscan_model.KindRepo, "custom/z.env") // its row is gone

	custom := func(rows []string) []string {
		var out []string
		for _, r := range rows {
			if strings.Contains(r, "custom/") {
				out = append(out, r)
			}
		}
		return out
	}
	row := func(label, path string) string { return "org3/sl-root | " + label + " | custom/" + path + ":3 | Open" }

	t.Run("an organization's owners", func(t *testing.T) {
		got := custom(secretListRows(t, secGet(t, loginUser(t, "user2"), slOrg, http.StatusOK)))
		assert.Equal(t, []string{
			row("Deleted pattern", "z.env"), // newest first
			row("Deleted pattern", "d.env"), // a site pattern: its name is not for an organization
			row("Deleted pattern (org gone)", "c.env"),
			row("site off (disabled)", "b.env"),
			row("org live", "a.env"),
		}, got)
	})
	t.Run("a member narrowed to their repositories", func(t *testing.T) {
		got := custom(secretListRows(t, secGet(t, loginUser(t, "user4"), slOrg, http.StatusOK)))
		assert.Equal(t, []string{
			row("Deleted pattern", "z.env"), row("Deleted pattern", "d.env"), row("Deleted pattern", "c.env"),
			row("site off (disabled)", "b.env"), row("org live", "a.env"),
		}, got)
	})
	t.Run("the instance list", func(t *testing.T) {
		got := custom(secretListRows(t, secGet(t, loginUser(t, "user1"), slAdmin, http.StatusOK)))
		assert.Equal(t, []string{
			row("Deleted pattern", "z.env"), row("Deleted pattern (site gone)", "d.env"), row("Deleted pattern", "c.env"),
			row("site off (disabled)", "b.env"), row("org live", "a.env"),
		}, got)
	})
	t.Run("the repository page and the API", func(t *testing.T) {
		resp := secGet(t, loginUser(t, "user2"), "/org3/sl-root/security/secrets", http.StatusOK)
		body := resp.Body.String()
		assert.Contains(t, body, "org live")
		assert.Contains(t, body, "site off (disabled)")
		assert.Contains(t, body, "Deleted pattern")
		assert.NotContains(t, body, "org gone")
		assert.NotContains(t, body, "site gone")

		token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
		var list []*api.SecretScanningAlert
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/sl-root/secret-scanning/alerts?state=open").AddTokenAuth(token), http.StatusOK), &list)
		names := map[string]string{}
		for _, a := range list {
			names[a.SecretType] = a.SecretTypeDisplayName
		}
		assert.Equal(t, "org live", names[live.RuleID()])
		assert.Equal(t, "site off (disabled)", names[off.RuleID()])
		assert.Equal(t, "Deleted pattern", names[orgGone.RuleID()])
		assert.Equal(t, "Deleted pattern", names[siteGone.RuleID()])
		assert.Equal(t, "Deleted pattern", names["custom-99999"])
	})
	t.Run("the CSV names them the same way", func(t *testing.T) {
		types := func(s *TestSession, path string) map[string]string {
			out := map[string]string{} // location → type
			for _, r := range slCSV(t, slPost(t, s, path, map[string]string{"q": "sl-root"}, http.StatusOK)) {
				if strings.HasPrefix(r[8], "custom/") {
					out[r[8]] = r[7]
				}
			}
			return out
		}
		member := map[string]string{
			"custom/a.env:3": "org live", "custom/b.env:3": "site off (disabled)", "custom/c.env:3": "Deleted pattern",
			"custom/d.env:3": "Deleted pattern", "custom/z.env:3": "Deleted pattern",
		}
		assert.Equal(t, member, types(loginUser(t, "user4"), slOrg))
		owner := maps.Clone(member)
		owner["custom/c.env:3"] = "Deleted pattern (org gone)"
		assert.Equal(t, owner, types(loginUser(t, "user2"), slOrg))
		instance := maps.Clone(member)
		instance["custom/d.env:3"] = "Deleted pattern (site gone)"
		assert.Equal(t, instance, types(loginUser(t, "user1"), slAdmin))
	})
	t.Run("after a transfer the organization's pattern has no name", func(t *testing.T) {
		moved := depNewRepo(t, org, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), "sl-moved", true, 0)
		seedSecretAlert(t, moved, live.RuleID(), "custom", secretscan_model.KindRepo, "moved/org.env")
		seedSecretAlert(t, moved, off.RuleID(), "custom", secretscan_model.KindRepo, "moved/site.env")
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		require.NoError(t, repo_service.TransferOwnership(sys, admin, user2, moved, nil))

		body := secGet(t, loginUser(t, "user2"), "/user2/sl-moved/security/secrets", http.StatusOK).Body.String()
		assert.Contains(t, body, "Pattern of a previous owner")
		assert.Contains(t, body, "site off (disabled)", "a site pattern keeps its name")
		assert.NotContains(t, body, "org live")

		token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
		var list []*api.SecretScanningAlert
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/sl-moved/secret-scanning/alerts").AddTokenAuth(token), http.StatusOK), &list)
		names := map[string]string{}
		for _, a := range list {
			names[a.SecretType] = a.SecretTypeDisplayName
		}
		assert.Equal(t, map[string]string{live.RuleID(): "Pattern of a previous owner", off.RuleID(): "site off (disabled)"}, names)

		admin := loginUser(t, "user1")
		rows := secretListRows(t, secGet(t, admin, slAdmin+"?q=sl-moved", http.StatusOK))
		assert.Equal(t, []string{
			"user2/sl-moved | site off (disabled) | moved/site.env:3 | Open",
			"user2/sl-moved | Pattern of a previous owner | moved/org.env:3 | Open",
		}, rows)
		var cells []string
		for _, r := range slCSV(t, slPost(t, admin, slAdmin, map[string]string{"q": "sl-moved"}, http.StatusOK)) {
			cells = append(cells, r[7])
		}
		assert.Equal(t, []string{"site off (disabled)", "Pattern of a previous owner"}, cells)
	})
	t.Run("purging the previous owner keeps the label", func(t *testing.T) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		gone := &organization.Organization{Name: "sl-purged"}
		require.NoError(t, organization.CreateOrganization(sys, gone, user2))
		p := create(secretscan_service.OrgPatterns(gone.AsUser()), "purged org live")
		moved := depNewRepo(t, gone.AsUser(), user2, "sl-from-purged", true, 0)
		seedSecretAlert(t, moved, p.RuleID(), "custom", secretscan_model.KindRepo, "purged/org.env")
		require.NoError(t, repo_service.TransferOwnership(sys, admin, user2, moved, nil))
		require.NoError(t, org_service.DeleteOrganization(sys, gone, true))

		body := secGet(t, loginUser(t, "user2"), "/user2/sl-from-purged/security/secrets", http.StatusOK).Body.String()
		assert.Contains(t, body, "Pattern of a previous owner")
		assert.NotContains(t, body, "Deleted pattern")
		assert.NotContains(t, body, "purged org live")
		rows := secretListRows(t, secGet(t, loginUser(t, "user1"), slAdmin+"?q=sl-from-purged", http.StatusOK))
		assert.Equal(t, []string{"user2/sl-from-purged | Pattern of a previous owner | purged/org.env:3 | Open"}, rows)
	})
}

// The labels of custom patterns cost one query per list, however many patterns the page holds.
func TestSecretAlertListsQueryCountCustom(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := newSecretListFixture(t)
	sys := audit_model.WithSystem(db.DefaultContext, "test")
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	n := 0
	add := func(owner secretscan_service.PatternOwner, deleted bool) {
		n++
		p, err := secretscan_service.CreatePattern(sys, admin, owner, secretscan_service.PatternInput{
			Name: "p" + string(rune('a'+n)), Pattern: `acme-key-[a-z0-9]{20}`, Keywords: []string{"acme-key"}, Sample: "K=acme-" + "key-" + strings.Repeat("a1", 10),
		})
		require.NoError(t, err)
		seedSecretAlert(t, f.root, p.RuleID(), "custom", secretscan_model.KindRepo, "c/"+p.Name)
		if deleted {
			require.NoError(t, secretscan_service.DeletePattern(sys, owner, p.ID))
		}
	}
	add(secretscan_service.OrgPatterns(org), false)
	cases := map[string]struct {
		s    *TestSession
		path string
		post bool
	}{
		"owner": {loginUser(t, "user2"), slOrg, false}, "member": {loginUser(t, "user4"), slOrg, false},
		"admin": {loginUser(t, "user1"), slAdmin, false}, "csv": {loginUser(t, "user2"), slOrg, true},
	}
	count := func() map[string]int64 {
		out := map[string]int64{}
		for name, c := range cases {
			request := func() {
				if c.post {
					c.s.MakeRequest(t, NewRequestWithValues(t, "POST", c.path+"/export", map[string]string{}), http.StatusOK)
				} else {
					c.s.MakeRequest(t, NewRequest(t, "GET", c.path), http.StatusOK)
				}
			}
			request()
			out[name] = stableQueryCount(t, request)
		}
		return out
	}
	few := count()
	for i := range 12 {
		add(util.Iif(i%2 == 0, secretscan_service.OrgPatterns(org), secretscan_service.SitePatterns), i%3 == 0)
	}
	assert.Equal(t, few, count())
}
