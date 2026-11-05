// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/services/auth/source"
	org_service "forgejo.org/services/org"
	"forgejo.org/services/usergroup"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const verifiedDomainsURL = "/org/org3/settings/verified_domains"

func mockDomainRecords(t *testing.T) {
	// every domain has the record of org3
	t.Cleanup(test.MockVariableValue(&org_service.LookupTXT, func(_ context.Context, name string) ([]string, error) {
		domain := strings.TrimSuffix(strings.TrimPrefix(name, "_gitdepo-verify."), ".")
		return []string{org_service.DomainRecordValue(3, domain)}, nil
	}))
}

func flashError(t *testing.T, session *TestSession, url string) string {
	t.Helper()
	doc := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK).Body)
	return strings.TrimSpace(doc.Find(".flash-error").Text())
}

func requireVerifiedDomain(t *testing.T) bool {
	t.Helper()
	on, err := organization.IsVerifiedDomainRequired(t.Context(), 3)
	require.NoError(t, err)
	return on
}

func TestOrgVerifiedDomainSettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	mockDomainRecords(t)
	defer test.MockVariableValue(&setting.Service.RegisterEmailConfirm, true)()
	defer test.MockVariableValue(&setting.OAuth2Client.RegisterEmailConfirm, true)()
	owner := loginUser(t, "user2")

	t.Run("not an owner", func(t *testing.T) {
		member := loginUser(t, "user4")
		member.MakeRequest(t, NewRequest(t, "GET", verifiedDomainsURL), http.StatusNotFound)
		member.MakeRequest(t, NewRequestWithValues(t, "POST", verifiedDomainsURL+"/verify", map[string]string{"domain": "company.com"}), http.StatusNotFound)
		member.MakeRequest(t, NewRequestWithValues(t, "POST", verifiedDomainsURL+"/require", map[string]string{"require": "on"}), http.StatusNotFound)
		unittest.AssertNotExistsBean(t, &organization.OrgVerifiedDomain{OrgID: 3})
	})

	t.Run("add and verify", func(t *testing.T) {
		doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", verifiedDomainsURL), http.StatusOK).Body)
		assert.Contains(t, doc.Find(".org-setting-content").Text(), "No verified domains yet.")

		doc = NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", verifiedDomainsURL+"?domain=Company.COM"), http.StatusOK).Body)
		pending := doc.Find("#verified-domain-pending").Text()
		assert.Contains(t, pending, "_gitdepo-verify.company.com")
		assert.Contains(t, pending, org_service.DomainRecordValue(3, "company.com"))

		owner.MakeRequest(t, NewRequestWithValues(t, "POST", verifiedDomainsURL+"/verify", map[string]string{"domain": "company.com"}), http.StatusSeeOther)
		d := unittest.AssertExistsAndLoadBean(t, &organization.OrgVerifiedDomain{OrgID: 3, Domain: "company.com"})
		assert.Zero(t, d.VerifiedByAdminID)
	})

	t.Run("record missing", func(t *testing.T) {
		defer test.MockVariableValue(&org_service.LookupTXT, func(context.Context, string) ([]string, error) { return nil, nil })()
		resp := owner.MakeRequest(t, NewRequestWithValues(t, "POST", verifiedDomainsURL+"/verify", map[string]string{"domain": "missing.com"}), http.StatusSeeOther)
		assert.Equal(t, verifiedDomainsURL+"?domain=missing.com", test.RedirectURL(resp))
		assert.Contains(t, flashError(t, owner, test.RedirectURL(resp)), "not found yet")
		unittest.AssertNotExistsBean(t, &organization.OrgVerifiedDomain{Domain: "missing.com"})
	})

	t.Run("verify without DNS", func(t *testing.T) {
		defer test.MockVariableValue(&org_service.LookupTXT, func(context.Context, string) ([]string, error) { return nil, nil })()
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", verifiedDomainsURL+"/verify", map[string]string{"domain": "internal.example", "without_dns": "true"}), http.StatusForbidden)
		unittest.AssertNotExistsBean(t, &organization.OrgVerifiedDomain{Domain: "internal.example"})

		admin := loginUser(t, "user1")
		doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", verifiedDomainsURL+"?domain=internal.example"), http.StatusOK).Body)
		assert.Equal(t, 1, doc.Find(`button[name="without_dns"]`).Length())
		assert.Equal(t, 0, NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", verifiedDomainsURL+"?domain=internal.example"), http.StatusOK).Body).Find(`button[name="without_dns"]`).Length())

		admin.MakeRequest(t, NewRequestWithValues(t, "POST", verifiedDomainsURL+"/verify", map[string]string{"domain": "internal.example", "without_dns": "true"}), http.StatusSeeOther)
		d := unittest.AssertExistsAndLoadBean(t, &organization.OrgVerifiedDomain{OrgID: 3, Domain: "internal.example"})
		assert.EqualValues(t, 1, d.VerifiedByAdminID)

		// another organization can't take a verified domain, not even through a site admin
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org6/settings/verified_domains/verify", map[string]string{"domain": "company.com", "without_dns": "true"}), http.StatusSeeOther)
		assert.Contains(t, flashError(t, admin, "/org/org6/settings/verified_domains"), "already verified by another organization")
		unittest.AssertNotExistsBean(t, &organization.OrgVerifiedDomain{OrgID: 6})
	})

	t.Run("badge", func(t *testing.T) {
		doc := NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", "/org3"), http.StatusOK).Body)
		badges := doc.Find(".org-verified-domain").Text()
		assert.Contains(t, badges, "Verified: company.com")
		assert.Contains(t, badges, "Verified: internal.example")
	})

	t.Run("restriction", func(t *testing.T) {
		func() {
			defer test.MockVariableValue(&setting.OAuth2Client.RegisterEmailConfirm, false)()
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", verifiedDomainsURL+"/require", map[string]string{"require": "on"}), http.StatusSeeOther)
			assert.Contains(t, flashError(t, owner, verifiedDomainsURL), "email confirmation")
			assert.False(t, requireVerifiedDomain(t))
		}()

		owner.MakeRequest(t, NewRequestWithValues(t, "POST", verifiedDomainsURL+"/require", map[string]string{"require": "on"}), http.StatusSeeOther)
		assert.True(t, requireVerifiedDomain(t))
		// nobody qualifies yet: a warning lists the members, nobody is removed
		doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", verifiedDomainsURL), http.StatusOK).Body)
		warning := doc.Find("#verified-domain-non-qualifying").Text()
		assert.Contains(t, warning, "user2")
		assert.Contains(t, warning, "user4")
		unittest.AssertExistsAndLoadBean(t, &organization.OrgUser{OrgID: 3, UID: 4})
	})

	t.Run("removing the last domain turns the restriction off", func(t *testing.T) {
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", verifiedDomainsURL+"/remove", map[string]string{"domain": "company.com"}), http.StatusSeeOther)
		assert.True(t, requireVerifiedDomain(t))
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", verifiedDomainsURL+"/remove", map[string]string{"domain": "internal.example"}), http.StatusSeeOther)
		unittest.AssertNotExistsBean(t, &organization.OrgVerifiedDomain{OrgID: 3})
		assert.False(t, requireVerifiedDomain(t))

		owner.MakeRequest(t, NewRequestWithValues(t, "POST", verifiedDomainsURL+"/require", map[string]string{"require": "on"}), http.StatusSeeOther)
		assert.Contains(t, flashError(t, owner, verifiedDomainsURL), "Verify a domain first.")
		assert.False(t, requireVerifiedDomain(t))
	})
}

func TestOrgVerifiedDomainMembership(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Service.RegisterEmailConfirm, true)()
	defer test.MockVariableValue(&setting.OAuth2Client.RegisterEmailConfirm, true)()
	defer test.MockVariableValue(&setting.Service.AddMembersByInvitations, false)()
	ctx := t.Context()
	require.NoError(t, organization.AddVerifiedDomain(ctx, &organization.OrgVerifiedDomain{OrgID: 3, Domain: "company.com"}))
	require.NoError(t, org_service.SetVerifiedDomainRequired(ctx, unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 3}), true))
	addEmail := func(uid int64, email string, activated bool) {
		require.NoError(t, db.Insert(ctx, &user_model.EmailAddress{UID: uid, Email: email, LowerEmail: email, IsActivated: activated}))
	}
	isOrgMember := func(uid int64) bool {
		is, err := organization.IsOrganizationMember(ctx, 3, uid)
		require.NoError(t, err)
		return is
	}
	owner := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteOrganization)
	teamURL := "/org/org3/teams/team1"

	t.Run("web team add", func(t *testing.T) {
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", teamURL+"/action/add", map[string]string{"uname": "user5"}), http.StatusSeeOther)
		assert.Contains(t, flashError(t, owner, teamURL), "user5 can't join this organization")
		assert.False(t, isOrgMember(5))

		// an unactivated address doesn't count
		addEmail(5, "user5@company.com", false)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", teamURL+"/action/add", map[string]string{"uname": "user5"}), http.StatusSeeOther)
		assert.Contains(t, flashError(t, owner, teamURL), "user5 can't join this organization")
		assert.False(t, isOrgMember(5))

		addEmail(5, "user5@other.company.com", true) // no subdomains
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", teamURL+"/action/add", map[string]string{"uname": "user5"}), http.StatusSeeOther)
		assert.Contains(t, flashError(t, owner, teamURL), "user5 can't join this organization")
		assert.False(t, isOrgMember(5))
	})

	t.Run("web members add", func(t *testing.T) {
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/members/action/add", map[string]string{"uid": "2", "uname": "user5", "team_2": "on"}), http.StatusSeeOther)
		assert.Contains(t, flashError(t, owner, "/org/org3/members"), "user5 can't join this organization")
		assert.False(t, isOrgMember(5))
	})

	t.Run("API team add", func(t *testing.T) {
		MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/2/members/user5").AddTokenAuth(token), http.StatusForbidden)
		assert.False(t, isOrgMember(5))

		addEmail(5, "User5@Company.com", true)
		MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/2/members/user5").AddTokenAuth(token), http.StatusNoContent)
		assert.True(t, isOrgMember(5))
	})

	t.Run("existing members can join more teams", func(t *testing.T) {
		MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/7/members/user4").AddTokenAuth(token), http.StatusNoContent)
		unittest.AssertExistsAndLoadBean(t, &organization.TeamUser{TeamID: 7, UID: 4})
	})

	t.Run("invitation", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Service.AddMembersByInvitations, true)()
		// refused before an invitation is sent
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", teamURL+"/action/add", map[string]string{"uname": "user8"}), http.StatusSeeOther)
		assert.Contains(t, flashError(t, owner, teamURL), "user8 can't join this organization")
		unittest.AssertNotExistsBean(t, &organization.TeamInvite{TeamID: 2})

		// and when an invitation made before the restriction is accepted
		team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
		inviter := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		invited := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8})
		invite, err := organization.CreateTeamInviteForUser(ctx, inviter, invited, team)
		require.NoError(t, err)
		session := loginUser(t, "user8")
		session.MakeRequest(t, NewRequest(t, "POST", "/org/invite/"+invite.Token), http.StatusSeeOther)
		assert.Contains(t, flashError(t, session, "/org/invite/"+invite.Token), "user8 can't join this organization")
		assert.False(t, isOrgMember(8))

		addEmail(8, "user8@company.com", true)
		session.MakeRequest(t, NewRequest(t, "POST", "/org/invite/"+invite.Token), http.StatusSeeOther)
		assert.True(t, isOrgMember(8))
	})

	t.Run("user group sync skips", func(t *testing.T) {
		team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
		group := &organization.UserGroup{Name: "domain-sync", LowerName: "domain-sync"}
		require.NoError(t, usergroup.CreateGroup(ownActCtx(t), group))
		require.NoError(t, usergroup.LinkTeam(ownActCtx(t), group, team))
		skipped := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 10})
		added := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 12})
		addEmail(12, "user12@company.com", true)
		require.NoError(t, usergroup.AddMember(ownActCtx(t), group, skipped))
		require.NoError(t, usergroup.AddMember(ownActCtx(t), group, added))
		assert.False(t, isOrgMember(10))
		assert.True(t, isOrgMember(12))

		// login source (LDAP/OAuth) group mapping
		loginSource := createRemoteAuthSource(t, "domain-sync-source", "https://example.com", "")
		mapping := map[string]map[string][]string{"devs": {"org3": {"team1"}}}
		require.NoError(t, source.SyncGroupsToTeams(ctx, skipped, loginSource.ID, container.SetOf("devs"), mapping, true, nil, false))
		assert.False(t, isOrgMember(10))
	})

	t.Run("email confirmation turned off later", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Service.RegisterEmailConfirm, false)()
		addEmail(13, "user13@company.com", true)
		MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/2/members/user13").AddTokenAuth(token), http.StatusForbidden)
		assert.False(t, isOrgMember(13))
	})

	t.Run("org delete removes the domains and the flag", func(t *testing.T) {
		org := &organization.Organization{Name: "domain-org"}
		require.NoError(t, organization.CreateOrganization(ctx, org, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})))
		require.NoError(t, organization.AddVerifiedDomain(ctx, &organization.OrgVerifiedDomain{OrgID: org.ID, Domain: "deleted.example"}))
		require.NoError(t, org_service.SetVerifiedDomainRequired(ctx, org, true))
		require.NoError(t, org_service.DeleteOrganization(ctx, org, false))
		unittest.AssertNotExistsBean(t, &organization.OrgVerifiedDomain{OrgID: org.ID})
		unittest.AssertNotExistsBean(t, &user_model.Setting{UserID: org.ID, SettingKey: organization.SettingKeyRequireVerifiedDomain})
	})
}
