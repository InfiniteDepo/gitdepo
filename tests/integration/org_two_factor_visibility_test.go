// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"code.forgejo.org/xorm/xorm/contexts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func flagOrg3(t *testing.T) {
	t.Helper()
	_, err := db.GetEngine(db.DefaultContext).ID(3).Cols("require_two_factor").Update(&user_model.User{RequireTwoFactor: true})
	require.NoError(t, err)
}

// org3 has the members user2 (owner), user4 (member) and user28 (admin team); user5 is not a member.
func TestOrgTwoFactorMembersPage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	owner := loginUser(t, "user2")
	member := loginUser(t, "user4")
	auditor := loginUser(t, "user5")
	admin := loginUser(t, "user1")
	enrolTOTP(t, 28)

	column := func(session *TestSession) (hasColumn bool, enrolled int) {
		body := session.MakeRequest(t, NewRequest(t, "GET", "/org/org3/members"), http.StatusOK).Body
		page := NewHTMLParser(t, body)
		list := page.Find(".list")
		hasColumn = strings.Contains(list.Text(), "2FA")
		return hasColumn, list.Find(".text.green").Length()
	}

	// the column is shown with the flag off too
	has, _ := column(owner)
	assert.True(t, has)
	has, _ = column(admin)
	assert.True(t, has)
	for name, s := range map[string]*TestSession{"member": member, "non-member": auditor} {
		has, _ = column(s)
		assert.False(t, has, name)
	}
	req := NewRequest(t, "GET", "/org/org3/members")
	assert.NotContains(t, MakeRequest(t, req, http.StatusOK).Body.String(), "2FA")

	// an owner the requirement blocks is no owner: no column and no data
	flagOrg3(t)
	has, _ = column(owner)
	assert.False(t, has)
	enrolTOTP(t, 2)
	has, enrolled := column(owner)
	assert.True(t, has)
	assert.Equal(t, 2, enrolled) // user2 and user28
}

func TestOrgTwoFactorMembersFilter(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	scopes := []auth_model.AccessTokenScope{auth_model.AccessTokenScopeAll}
	ownerToken := getTokenForLoggedInUser(t, loginUser(t, "user2"), scopes...)
	adminToken := getTokenForLoggedInUser(t, loginUser(t, "user1"), scopes...)
	memberToken := getTokenForLoggedInUser(t, loginUser(t, "user4"), scopes...)
	readOwnerToken := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeReadOrganization)
	otherToken := getTokenForLoggedInUser(t, loginUser(t, "user5"), scopes...)
	enrolTOTP(t, 2)
	require.NoError(t, db.Insert(db.DefaultContext, &auth_model.WebAuthnCredential{UserID: 28, Name: "k", LowerName: "k", CredentialID: []byte{1}}))

	names := func(t *testing.T, token, query string, status int) (out []string, total string) {
		t.Helper()
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/members"+query).AddTokenAuth(token), status)
		if status != http.StatusOK {
			return nil, ""
		}
		var users []*api.User
		DecodeJSON(t, resp, &users)
		for _, u := range users {
			out = append(out, u.UserName)
		}
		return out, resp.Header().Get("X-Total-Count")
	}

	// owner and admin; TOTP (user2) and WebAuthn (user28) users are excluded; X-Total-Count is exact
	for _, token := range []string{ownerToken, adminToken, readOwnerToken} {
		got, total := names(t, token, "?filter=2fa_disabled", http.StatusOK)
		assert.Equal(t, []string{"user4"}, got)
		assert.Equal(t, "1", total)
	}
	// without the filter all three are listed
	got, total := names(t, ownerToken, "", http.StatusOK)
	assert.Len(t, got, 3)
	assert.Equal(t, "3", total)

	// paging composes with the filter
	unenrolTOTP(t, 2)
	got, total = names(t, ownerToken, "?filter=2fa_disabled&limit=1&page=1", http.StatusOK)
	assert.Len(t, got, 1)
	assert.Equal(t, "2", total)
	got2, total := names(t, ownerToken, "?filter=2fa_disabled&limit=1&page=2", http.StatusOK)
	assert.Len(t, got2, 1)
	assert.NotEqual(t, got, got2)
	assert.Equal(t, "2", total)
	got, _ = names(t, ownerToken, "?filter=2fa_disabled&limit=1&page=3", http.StatusOK)
	assert.Empty(t, got)

	// 403 first for anyone not allowed, whatever the value (no oracle on validity either)
	for _, token := range []string{memberToken, otherToken} {
		names(t, token, "?filter=2fa_disabled", http.StatusForbidden)
		names(t, token, "?filter=nonsense", http.StatusForbidden)
	}
	// an owner without 2FA in a flagged org is no owner
	flagOrg3(t)
	names(t, ownerToken, "?filter=2fa_disabled", http.StatusForbidden)
	names(t, ownerToken, "?filter=nonsense", http.StatusForbidden)
	enrolTOTP(t, 2)
	names(t, ownerToken, "?filter=nonsense", http.StatusUnprocessableEntity)
	names(t, ownerToken, "?filter=", http.StatusOK) // empty counts as unset
	// no filter: unchanged for everyone
	names(t, memberToken, "", http.StatusOK)
}

func TestOrgTwoFactorAPIField(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	scopes := []auth_model.AccessTokenScope{auth_model.AccessTokenScopeAll}
	ownerSession := loginUser(t, "user2")
	ownerToken := getTokenForLoggedInUser(t, ownerSession, scopes...)
	readToken := getTokenForLoggedInUser(t, ownerSession, auth_model.AccessTokenScopeReadOrganization)
	adminToken := getTokenForLoggedInUser(t, loginUser(t, "user1"), scopes...)
	memberToken := getTokenForLoggedInUser(t, loginUser(t, "user4"), scopes...)

	get := func(token string) map[string]any {
		t.Helper()
		var m map[string]any
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3").AddTokenAuth(token), http.StatusOK), &m)
		return m
	}
	patch := func(token string, on bool, status int) {
		t.Helper()
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/org3", map[string]any{"require_two_factor": on}).AddTokenAuth(token), status)
	}

	// visible to acting owners and site admins only; absent (not false) for everyone else
	for _, token := range []string{ownerToken, readToken, adminToken} {
		v, ok := get(token)["require_two_factor"]
		assert.True(t, ok)
		assert.Equal(t, false, v)
	}
	_, ok := get(memberToken)["require_two_factor"]
	assert.False(t, ok)
	_, ok = get("")["require_two_factor"]
	assert.False(t, ok)
	body := MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs").AddTokenAuth(ownerToken), http.StatusOK).Body.String()
	assert.NotContains(t, body, "require_two_factor")
	body = MakeRequest(t, NewRequest(t, "GET", "/api/v1/user/orgs").AddTokenAuth(ownerToken), http.StatusOK).Body.String()
	assert.NotContains(t, body, "require_two_factor")

	// PATCH: non-owner and read-only token refused, a doer without 2FA refused, a site admin allowed
	patch(memberToken, true, http.StatusForbidden)
	patch(readToken, true, http.StatusForbidden)
	patch(ownerToken, true, http.StatusForbidden)
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).RequireTwoFactor)
	patch(adminToken, true, http.StatusOK)
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).RequireTwoFactor)
	assert.Equal(t, true, get(adminToken)["require_two_factor"])
	patch(adminToken, false, http.StatusOK)
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).RequireTwoFactor)

	// all owners lack 2FA: none can manage the org, only a site admin can
	patch(adminToken, true, http.StatusOK)
	patch(ownerToken, false, http.StatusForbidden)
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).RequireTwoFactor)
	patch(adminToken, false, http.StatusOK)

	// an owner with 2FA turns it on and off; other fields leave it alone
	enrolTOTP(t, 2)
	patch(ownerToken, true, http.StatusOK)
	assert.Equal(t, true, get(ownerToken)["require_two_factor"])
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/org3", map[string]any{"description": "x"}).AddTokenAuth(ownerToken), http.StatusOK)
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).RequireTwoFactor)
	patch(ownerToken, false, http.StatusOK)
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).RequireTwoFactor)
}

// org3: repo3 is private, repo21 is public; user4 is a member, user5 is not.
func TestOrgTwoFactorBanner(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	member := loginUser(t, "user4")
	other := loginUser(t, "user5")
	flagOrg3(t)

	get := func(s *TestSession, path string, status int) string {
		t.Helper()
		return s.MakeRequest(t, NewRequest(t, "GET", path), status).Body.String()
	}
	const banner = "/user/settings/security"

	// a blocked member: the same 403 for an existing private repo and a missing one
	for _, path := range []string{"/org3/repo3", "/org3/repo3/issues", "/org3/no-such-repo"} {
		body := get(member, path, http.StatusForbidden)
		assert.Contains(t, body, banner, path)
	}
	// public repo and org pages stay available; the org home carries the banner
	get(member, "/org3/repo21", http.StatusOK)
	assert.Contains(t, get(member, "/org3", http.StatusOK), banner)
	assert.NotContains(t, get(other, "/org3", http.StatusOK), banner)
	// other owners' repos are not touched
	get(member, "/user2/repo1", http.StatusOK)

	// a non-member: 404, the body of a private repo equals the body of a missing one
	existing := get(other, "/org3/repo3", http.StatusNotFound)
	missing := get(other, "/org3/no-such-repo", http.StatusNotFound)
	assert.Equal(t, missing, existing)
	assert.NotContains(t, existing, banner)

	// every way a name can fail to resolve answers the blocked member alike: existing, missing, renamed away, trashed
	require.NoError(t, db.Insert(db.DefaultContext, &repo_model.Redirect{OwnerID: 3, LowerName: "old-name", RedirectRepoID: 3}))
	require.NoError(t, db.Insert(db.DefaultContext, &repo_model.Redirect{OwnerID: 3, LowerName: "old-trashed", RedirectRepoID: 5}))
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 5")
	require.NoError(t, err)
	// (the page echoes the requested URL and its render time, which differ by request)
	same := regexp.MustCompile(`(?m)^.*(og:url|rel="canonical"|Page: <strong>|Template: <strong>).*$`)
	want := same.ReplaceAllString(get(member, "/org3/repo3", http.StatusForbidden), "")
	for _, path := range []string{"/org3/no-such-repo", "/org3/old-name", "/org3/old-trashed", "/org3/repo5"} {
		assert.Equal(t, want, same.ReplaceAllString(get(member, path, http.StatusForbidden), ""), path)
	}
	// the same in an organization of private visibility
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET visibility = 2 WHERE id = 3")
	require.NoError(t, err)
	for _, path := range []string{"/org3/repo3", "/org3/no-such-repo", "/org3/old-name"} {
		assert.Equal(t, want, same.ReplaceAllString(get(member, path, http.StatusForbidden), ""), path)
	}
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET visibility = 0 WHERE id = 3")
	require.NoError(t, err)
	// by ID there is no banner: an existing and a missing ID answer alike
	assert.Equal(t, member.MakeRequest(t, NewRequest(t, "GET", "/fork/99999"), http.StatusNotFound).Code,
		member.MakeRequest(t, NewRequest(t, "GET", "/fork/3"), http.StatusNotFound).Code)
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET trashed_unix = 0 WHERE id = 5")
	require.NoError(t, err)

	// enrolling lifts it
	enrolTOTP(t, 4)
	get(member, "/org3/repo3", http.StatusOK)
	assert.NotContains(t, get(member, "/org3", http.StatusOK), banner)
	get(member, "/org3/no-such-repo", http.StatusNotFound)
}

// twoFactorQueries counts the lookups of a user's 2FA.
var (
	twoFactorQueries  atomic.Int64
	twoFactorHookOnce sync.Once
)

type twoFactorQueryHook struct{}

func (twoFactorQueryHook) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	// a lookup of one user's factors; the list conditions only name the tables in a subquery
	if strings.Contains(c.SQL, "FROM `two_factor` WHERE (uid=?)") || strings.Contains(c.SQL, "FROM `webauthn_credential` WHERE (user_id = ?)") {
		twoFactorQueries.Add(1)
	}
	return db.TracingHook{}.BeforeProcess(c)
}

func (twoFactorQueryHook) AfterProcess(*contexts.ContextHook) error { return nil }

// An unflagged organization never reads the 2FA tables: not on the denial path of a repo, not on the org pages for a
// member. The flagged one does, so the counter is known to work.
func TestOrgTwoFactorUnflaggedNoLookup(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	twoFactorHookOnce.Do(func() {
		engine, err := db.GetMasterEngine(db.GetEngine(db.DefaultContext))
		require.NoError(t, err)
		engine.AddHook(twoFactorQueryHook{})
	})
	other := loginUser(t, "user5")
	member := loginUser(t, "user4")
	reads := func(s *TestSession, path string, status int) int64 {
		twoFactorQueries.Store(0)
		s.MakeRequest(t, NewRequest(t, "GET", path), status)
		return twoFactorQueries.Load()
	}

	for _, path := range []string{"/org3/repo3", "/org3/no-such-repo"} {
		assert.Zero(t, reads(other, path, http.StatusNotFound), path)
	}
	assert.Zero(t, reads(member, "/org3", http.StatusOK))
	assert.Zero(t, reads(member, "/org/org3/members", http.StatusOK))

	flagOrg3(t)
	assert.Positive(t, reads(other, "/org3/repo3", http.StatusNotFound))
	assert.Positive(t, reads(member, "/org3", http.StatusOK))
}

// With sudo the effective user decides what the organization shows.
func TestOrgTwoFactorAPISudo(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	adminToken := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeAll)
	get := func(sudo string) map[string]any {
		var m map[string]any
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3?sudo="+sudo).AddTokenAuth(adminToken), http.StatusOK), &m)
		return m
	}
	_, ok := get("user4")["require_two_factor"]
	assert.False(t, ok)
	_, ok = get("user2")["require_two_factor"]
	assert.True(t, ok)
	// the member behind sudo can't turn it on
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/org3?sudo=user4", map[string]any{"require_two_factor": true}).AddTokenAuth(adminToken), http.StatusForbidden)
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).RequireTwoFactor)
}
