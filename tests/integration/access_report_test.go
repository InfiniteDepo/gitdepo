// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"testing"

	asymkey_model "forgejo.org/models/asymkey"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	perm_model "forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prepareAccessReport sets up org3/repo3 (private): user2 owns org3 and collaborates with write, user4 has it
// through team1, user5 is a write collaborator from outside the org who is also in team1 through the user group
// platform-devs synced by corp-ldap, and two deploy keys.
func prepareAccessReport(t *testing.T) *repo_model.Repository {
	t.Helper()
	ctx := db.DefaultContext
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})

	require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: 3, UserID: 5, Mode: perm_model.AccessModeWrite}))
	source := &auth_model.Source{Type: auth_model.LDAP, Name: "corp-ldap", IsActive: true}
	require.NoError(t, auth_model.CreateSource(ctx, source))
	group := &organization.UserGroup{Name: "platform-devs"}
	require.NoError(t, organization.InsertUserGroup(ctx, group))
	require.NoError(t, organization.InsertUserGroupMember(ctx, group.ID, 5, source.ID))
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	require.NoError(t, organization.InsertUserGroupTeam(ctx, group.ID, team, organization.LinkManual))
	require.NoError(t, db.Insert(ctx, &organization.TeamUser{OrgID: 3, TeamID: 2, UID: 5, Reason: organization.MembershipReasonAddedByUserGroup}))
	require.NoError(t, db.Insert(ctx, &asymkey_model.DeployKey{KeyID: 9001, RepoID: 3, Name: "prod-deploy", Fingerprint: "SHA256:prod", Mode: perm_model.AccessModeRead}))
	require.NoError(t, db.Insert(ctx, &asymkey_model.DeployKey{KeyID: 9002, RepoID: 3, Name: "ci-push", Fingerprint: "SHA256:ci", Mode: perm_model.AccessModeWrite}))
	require.NoError(t, access_model.RecalculateAccesses(ctx, repo))
	return repo
}

func accessRows(t *testing.T, session *TestSession, link string) *HTMLDoc {
	t.Helper()
	return NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body)
}

func apiAccessRows(t *testing.T, token, query string) []*api.AccessRow {
	t.Helper()
	var rows []*api.AccessRow
	DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3/access"+query).AddTokenAuth(token), http.StatusOK), &rows)
	return rows
}

func rowNames(rows []*api.AccessRow) []string {
	names := make([]string, 0, len(rows))
	for _, r := range rows {
		switch {
		case r.User != nil:
			names = append(names, r.User.UserName)
		case r.DeployKey != nil:
			names = append(names, r.DeployKey.Name)
		case r.Team != nil:
			names = append(names, "team:"+r.Team.Name)
		default:
			names = append(names, r.Type)
		}
	}
	return names
}

func TestRepoAccessOverview(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareAccessReport(t)
	link := "/org3/repo3/settings/access"

	t.Run("refused", func(t *testing.T) {
		MakeRequest(t, NewRequest(t, "GET", link), http.StatusSeeOther)
		loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound) // team member
		loginUser(t, "user5").MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound) // writer
	})

	t.Run("site admin", func(t *testing.T) {
		doc := accessRows(t, loginUser(t, "user1"), link)
		rows := doc.Find("table.access-report tbody tr")
		assert.Equal(t, 6, rows.Length(), "user1, user2, user4, user5 and two deploy keys")
		user5 := doc.Find(`table.access-report tbody tr[data-user="user5"]`)
		assert.Contains(t, user5.Text(), "team1")
		assert.Contains(t, user5.Text(), "platform-devs")
		assert.Contains(t, user5.Text(), "corp-ldap")
		user2 := doc.Find(`table.access-report tbody tr[data-user="user2"]`)
		assert.Contains(t, user2.Text(), "Owners")
		assert.Contains(t, doc.Find(`tr[data-user="user1"]`).Text(), "Site administrator")

		// AC5: deploy keys with their access
		assert.Contains(t, doc.Find(`tr[data-key="prod-deploy"]`).Text(), "Read")
		assert.Contains(t, doc.Find(`tr[data-key="ci-push"]`).Text(), "Write")
	})

	t.Run("org owner", func(t *testing.T) {
		doc := accessRows(t, loginUser(t, "user2"), link)
		assert.Contains(t, doc.Find(`tr[data-user="user5"]`).Text(), "platform-devs", "org owners see group names")
		assert.NotContains(t, doc.Find(`tr[data-user="user5"]`).Text(), "corp-ldap", "login sources only to site admins")
	})

	t.Run("pagination", func(t *testing.T) {
		session := loginUser(t, "user1")
		assert.Equal(t, 2, accessRows(t, session, link+"?limit=2").Find("table.access-report tbody tr").Length())
		assert.Equal(t, 2, accessRows(t, session, link+"?limit=2&page=3").Find("table.access-report tbody tr").Length())
		assert.Equal(t, 0, accessRows(t, session, link+"?limit=2&page=4").Find("table.access-report tbody tr").Length())
	})
}

// TestRepoAccessOverviewHidesInstanceRoles is F1: a repo admin who isn't a site admin sees no site admin or
// auditor by name, only one line.
func TestRepoAccessOverviewHidesInstanceRoles(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareAccessReport(t)
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET is_auditor = ? WHERE id = 8", true)
	require.NoError(t, err)

	doc := accessRows(t, loginUser(t, "user2"), "/org3/repo3/settings/access")
	assert.Equal(t, 0, doc.Find(`tr[data-user="user1"]`).Length())
	assert.Equal(t, 0, doc.Find(`tr[data-user="user8"]`).Length())
	assert.Equal(t, 1, doc.Find(`tr[data-type="instance_roles"]`).Length())

	rows := apiAccessRows(t, getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository), "")
	assert.NotContains(t, rowNames(rows), "user1")
	assert.NotContains(t, rowNames(rows), "user8")
	assert.Contains(t, rowNames(rows), "instance_roles")

	rows = apiAccessRows(t, getUserToken(t, "user1", auth_model.AccessTokenScopeReadRepository), "")
	assert.Contains(t, rowNames(rows), "user1")
	assert.Contains(t, rowNames(rows), "user8")
}

// TestRepoAccessOverviewOutsider is F2: a repo admin from outside the org sees teams as one row each, without
// their members, user groups or login sources.
func TestRepoAccessOverviewOutsider(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareAccessReport(t)
	ctx := db.DefaultContext
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: 3, UserID: 10, Mode: perm_model.AccessModeAdmin}))
	// user5 reads as a collaborator, and writes through team1, which an outsider must not learn
	_, err := db.GetEngine(ctx).Exec("UPDATE collaboration SET mode = ? WHERE repo_id = 3 AND user_id = 5", perm_model.AccessModeRead)
	require.NoError(t, err)
	require.NoError(t, access_model.RecalculateAccesses(ctx, repo))

	doc := accessRows(t, loginUser(t, "user10"), "/org3/repo3/settings/access")
	assert.Contains(t, doc.Find(`tr[data-user="user5"] td`).Eq(1).Text(), "Read")
	body := doc.Find("table.access-report").Text()
	assert.Equal(t, 0, doc.Find(`tr[data-user="user4"]`).Length(), "user4 has repo3 only through team1")
	assert.Equal(t, 1, doc.Find(`tr[data-user="user5"]`).Length(), "user5 is a collaborator")
	assert.Equal(t, 1, doc.Find(`tr[data-team="team1"]`).Length())
	assert.NotContains(t, body, "platform-devs")
	assert.NotContains(t, body, "corp-ldap")

	rows := apiAccessRows(t, getUserToken(t, "user10", auth_model.AccessTokenScopeReadRepository), "")
	assert.NotContains(t, rowNames(rows), "user4")
	assert.Contains(t, rowNames(rows), "team:team1")
	var persons []string
	for _, r := range rows {
		if r.Type == "person" {
			persons = append(persons, r.User.UserName)
		}
		if r.User != nil && r.User.UserName == "user5" {
			assert.Equal(t, "read", r.Access)
			assert.Equal(t, "read", r.Units["repo.code"])
			for _, p := range r.Paths {
				assert.True(t, p.Applied, p.Kind)
			}
		}
	}
	// N2: external-only can't tell the org members apart
	assert.ElementsMatch(t, persons, rowNames(apiAccessRows(t, getUserToken(t, "user10", auth_model.AccessTokenScopeReadRepository), "?external=true")))
	for _, r := range rows {
		for _, p := range r.Paths {
			assert.Empty(t, p.UserGroups)
		}
	}
}

func TestRepoAccessOverviewFilters(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareAccessReport(t)
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeReadRepository)

	bot := &user_model.User{Name: "release-bot", LowerName: "release-bot", Email: "release-bot@example.com", Type: user_model.UserTypeBot, IsActive: true}
	require.NoError(t, db.Insert(db.DefaultContext, bot))
	require.NoError(t, db.Insert(db.DefaultContext, &repo_model.Collaboration{RepoID: 3, UserID: bot.ID, Mode: perm_model.AccessModeWrite}))
	require.NoError(t, access_model.RecalculateUserAccess(db.DefaultContext, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}), bot.ID))

	assert.ElementsMatch(t, []string{"ci-push", "prod-deploy"}, rowNames(apiAccessRows(t, token, "?type=key")))
	assert.Equal(t, []string{"release-bot"}, rowNames(apiAccessRows(t, token, "?type=bot")))
	assert.ElementsMatch(t, []string{"user1", "user2", "user4", "user5"}, rowNames(apiAccessRows(t, token, "?type=person")))
	assert.ElementsMatch(t, []string{"user1", "user2"}, rowNames(apiAccessRows(t, token, "?mode=admin")))
	assert.NotContains(t, rowNames(apiAccessRows(t, token, "?mode=write")), "prod-deploy")
	assert.ElementsMatch(t, []string{"user1", "user2", "user4", "user5", "release-bot", "ci-push", "prod-deploy"}, rowNames(apiAccessRows(t, token, "?unit=repo.code")))
	assert.NotContains(t, rowNames(apiAccessRows(t, token, "?unit=repo.issues")), "prod-deploy")
	assert.ElementsMatch(t, []string{"user5", "release-bot"}, rowNames(apiAccessRows(t, token, "?external=true")))

	// inactive: user4 signed in 40 days ago, user5 yesterday, the others never
	defer timeutil.MockUnset()
	timeutil.MockSet(timeutil.TimeStampNow().AsTime())
	now := timeutil.TimeStampNow()
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET last_login_unix = ? WHERE id = 4", now.Add(-40*86400))
	require.NoError(t, err)
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET last_login_unix = ? WHERE id IN (1, 2, 5)", now.Add(-86400))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"user4", "release-bot"}, rowNames(apiAccessRows(t, token, "?inactive_days=30")))

	// N3: only site admins can filter by last sign-in; anyone can create an org and add any user to it
	ownerToken := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
	assert.Equal(t, rowNames(apiAccessRows(t, ownerToken, "")), rowNames(apiAccessRows(t, ownerToken, "?inactive_days=30")), "org owner")
	assert.Equal(t, 0, accessRows(t, loginUser(t, "user2"), "/org3/repo3/settings/access").Find(`input[name="inactive_days"]`).Length())
	require.NoError(t, db.Insert(db.DefaultContext, &repo_model.Collaboration{RepoID: 3, UserID: 10, Mode: perm_model.AccessModeAdmin}))
	require.NoError(t, access_model.RecalculateUserAccess(db.DefaultContext, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}), 10))
	outsiderToken := getUserToken(t, "user10", auth_model.AccessTokenScopeReadRepository)
	assert.Equal(t, rowNames(apiAccessRows(t, outsiderToken, "")), rowNames(apiAccessRows(t, outsiderToken, "?inactive_days=30")), "repo admin outside the org")
	assert.Equal(t, 0, accessRows(t, loginUser(t, "user10"), "/org3/repo3/settings/access").Find(`input[name="inactive_days"]`).Length())

	// the page filters the same way
	doc := accessRows(t, loginUser(t, "user1"), "/org3/repo3/settings/access?type=key")
	assert.Equal(t, 2, doc.Find("table.access-report tbody tr").Length())
	assert.Equal(t, 1, doc.Find(`input[name="inactive_days"]`).Length())
}

func TestAPIRepoAccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareAccessReport(t)

	rows := apiAccessRows(t, getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository), "")
	doc := accessRows(t, loginUser(t, "user2"), "/org3/repo3/settings/access")
	assert.Len(t, rows, doc.Find("table.access-report tbody tr").Length(), "same rows as the page")
	for _, r := range rows {
		if r.DeployKey != nil && r.DeployKey.Name == "ci-push" {
			assert.Equal(t, "write", r.Access)
			assert.Equal(t, map[string]string{"repo.code": "write"}, r.Units)
		}
		if r.User != nil && r.User.UserName == "user5" {
			assert.Equal(t, "write", r.Access)
			var kinds []string
			for _, p := range r.Paths {
				kinds = append(kinds, p.Kind)
			}
			assert.ElementsMatch(t, []string{"team", "collaborator"}, kinds)
		}
	}

	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3/access").AddTokenAuth(getUserToken(t, "user5", auth_model.AccessTokenScopeReadRepository)), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3/access"), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3/access").AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeReadUser)), http.StatusForbidden)
}

func TestAdminUserAccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareAccessReport(t)
	ctx := db.DefaultContext
	session := loginUser(t, "user1")

	// user5 is a site admin through a user group, user1 directly
	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/groups", &api.CreateUserGroupOption{Name: "admins", GrantsSiteAdmin: true}).AddTokenAuth(adminToken), http.StatusCreated)
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/admin/groups/admins/members/user5").AddTokenAuth(adminToken), http.StatusNoContent)
	require.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5}).IsAdmin)

	doc := accessRows(t, session, "/admin/users/5/access")
	assert.Contains(t, doc.Find(".site-admin-status").Text(), "admins")
	assert.Contains(t, doc.Find(".user-groups").Text(), "platform-devs")
	assert.Contains(t, doc.Find(".user-groups").Text(), "corp-ldap")
	assert.Contains(t, doc.Find(".user-teams").Text(), "team1")
	assert.Contains(t, doc.Find(".user-orgs").Text(), "org3")
	assert.Contains(t, doc.Find(`tr[data-repo="org3/repo3"]`).Text(), "team1")
	assert.Contains(t, doc.Find(`tr[data-repo="org3/repo3"]`).Text(), "Collaborator")

	doc = accessRows(t, session, "/admin/users/1/access")
	assert.Contains(t, doc.Find(".site-admin-status").Text(), "directly")

	// AC8: keys, tokens and OAuth grants, with last used
	_, err := db.GetEngine(ctx).Exec("UPDATE access_token SET updated_unix = ? WHERE uid = 2", 1700000000)
	require.NoError(t, err)
	doc = accessRows(t, session, "/admin/users/2/access")
	creds := doc.Find("table.user-credentials").Text()
	assert.Contains(t, creds, "user2@localhost")
	assert.Contains(t, creds, "Token A")
	assert.Contains(t, creds, "2023-11-14")
	doc = accessRows(t, session, "/admin/users/5/access")
	assert.Equal(t, 1, doc.Find(`table.user-credentials tr[data-kind="oauth2_grant"]`).Length())

	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/admin/users/5/access"), http.StatusForbidden)
}

func TestAPIAdminUserAccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareAccessReport(t)

	var ua api.UserAccess
	DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/users/user5/access").AddTokenAuth(getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin)), http.StatusOK), &ua)
	assert.False(t, ua.SiteAdmin)
	assert.Contains(t, ua.Orgs, "org7")
	assert.Equal(t, []string{"privated_org"}, ua.PrivateOrgs)
	require.Len(t, ua.UserGroups, 1)
	assert.Equal(t, "corp-ldap", ua.UserGroups[0].LoginSource)
	assert.Contains(t, rowNames(ua.Rows), "user5")
	var kinds []string
	for _, c := range ua.Credentials {
		kinds = append(kinds, c.Kind)
	}
	assert.ElementsMatch(t, []string{"ssh_key", "oauth2_grant"}, kinds)

	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/users/user5/access").AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeReadAdmin)), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/users/user5/access").AddTokenAuth(getUserToken(t, "user1", auth_model.AccessTokenScopeReadUser)), http.StatusForbidden)
}

func TestOrgMemberAccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareAccessReport(t)
	ctx := db.DefaultContext
	link := "/org/org3/members/user4/access"

	// user4 also collaborates on a repo of another user: it must not show
	require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm_model.AccessModeWrite}))

	owner := loginUser(t, "user2")
	doc := accessRows(t, owner, link)
	assert.Equal(t, 1, doc.Find(`tr[data-repo="org3/repo3"]`).Length())
	assert.Equal(t, 0, doc.Find(`tr[data-repo="user2/repo1"]`).Length())
	assert.Contains(t, doc.Find(".user-teams").Text(), "team1")
	before := doc.Find(".access-report").Text()

	// F3: a site admin and auditor member looks the same as an identical plain member
	_, err := db.GetEngine(ctx).Exec("UPDATE `user` SET is_admin = ?, is_auditor = ? WHERE id = 4", true, true)
	require.NoError(t, err)
	doc = accessRows(t, owner, link)
	assert.Equal(t, before, doc.Find(".access-report").Text())
	assert.Equal(t, 0, doc.Find(".site-admin-status").Length())
	assert.Equal(t, 0, doc.Find("table.user-credentials").Length())

	// user5 collaborates on repo3 and is in team1 through a group: owners see the group, not the login source
	doc = accessRows(t, owner, "/org/org3/members/user5/access")
	assert.Contains(t, doc.Find(".access-report").Text(), "platform-devs")
	assert.NotContains(t, doc.Find(".access-report").Text(), "corp-ldap")

	// someone with nothing in org3
	owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/members/user8/access"), http.StatusNotFound)
	// a member who isn't an owner
	loginUser(t, "user28").MakeRequest(t, NewRequest(t, "GET", "/org/org3/members/user2/access"), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "GET", link), http.StatusSeeOther)
}

func TestAccessReportWritesNothing(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	prepareAccessReport(t)
	count := func() string {
		var s string
		for _, table := range []string{"access", "collaboration", "team_user", "org_user", "user_group_user", "deploy_key", "access_token"} {
			n, err := db.GetEngine(db.DefaultContext).Table(table).Count()
			require.NoError(t, err)
			s += fmt.Sprintf("%s=%d ", table, n)
		}
		return s
	}
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization)
	before := count()
	session := loginUser(t, "user1")
	accessRows(t, session, "/org3/repo3/settings/access")
	accessRows(t, session, "/admin/users/5/access")
	accessRows(t, session, "/org/org3/members/user4/access")
	accessRows(t, session, "/org/org3/settings/access-report")
	accessRows(t, session, "/admin/access-reports")
	session.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/access-report?format=csv"), http.StatusOK)
	session.MakeRequest(t, NewRequest(t, "GET", "/admin/access-reports?format=json"), http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/access-report").AddTokenAuth(token), http.StatusOK)
	assert.Equal(t, before, count())
}
