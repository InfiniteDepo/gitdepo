// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	activities_model "forgejo.org/models/activities"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	project_model "forgejo.org/models/project"
	repo_model "forgejo.org/models/repo"
	system_model "forgejo.org/models/system"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/cache"
	"forgejo.org/modules/git"
	"forgejo.org/modules/json"
	"forgejo.org/modules/lfs"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	actions_service "forgejo.org/services/actions"
	issue_service "forgejo.org/services/issue"
	"forgejo.org/services/mailer/incoming"
	incoming_payload "forgejo.org/services/mailer/incoming/payload"
	migrations_allowlist "forgejo.org/services/migrations/allowlist"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetRepoUnitPolicy removes the stored policy: nothing stored is the behaviour before the policy existed
func resetRepoUnitPolicy(t *testing.T) {
	t.Helper()
	require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().RepoUnitPolicy.DynKey(): ""}))
	bumpSettingsRevision(t)
}

// denyRepoUnits makes the units Not allowed for all organizations except the exceptions (organization names), and
// returns a function that removes the policy again
func denyRepoUnits(t *testing.T, exceptions []string, units ...unit_model.Type) func() {
	t.Helper()
	changes := map[unit_model.Type]repo_service.UnitPolicyChange{}
	for _, u := range repo_model.PolicyUnitTypes() {
		c := repo_service.UnitPolicyChange{Allowed: true, OnDefault: slices.Contains(unit_model.DefaultRepoUnits, u)}
		if slices.Contains(units, u) {
			c.Allowed, c.OrgNames = false, exceptions
		}
		changes[u] = c
	}
	require.NoError(t, repo_service.SetUnitPolicy(db.DefaultContext, nil, changes))
	bumpSettingsRevision(t)
	return func() { resetRepoUnitPolicy(t) }
}

func repoUnitPolicyForm(allowed map[string]bool, orgs map[string]string) map[string]string {
	form := map[string]string{}
	for _, u := range repo_model.PolicyUnitTypes() {
		key := unit_model.Units[u].NameKey
		if a, ok := allowed[key]; !ok || a {
			form["allowed_"+key] = "on"
		}
		if o := orgs[key]; o != "" {
			form["orgs_"+key] = o
		}
		if slices.Contains(unit_model.DefaultRepoUnits, u) {
			form["default_"+key] = "on"
		}
	}
	return form
}

// A1, A2, A9: the admin page lists the 9 units, only site admins change them (not an org owner or a repo
// admin), the org names are checked, app.ini locks win (user repositories too), and the last change is shown
func TestRepoUnitPolicyAdminPage(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)

	admin := loginUser(t, "user1")
	doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repo-units"), http.StatusOK).Body)
	assert.Equal(t, 9, doc.Find("fieldset.repo-unit").Length())
	assert.Equal(t, 9, doc.Find(`input[name^="allowed_"][checked]`).Length())
	assert.Equal(t, 0, doc.Find(`fieldset.repo-unit[disabled]`).Length())

	// org owners, repo admins and other users can't read or change it
	isOwner, err := organization.IsOrganizationOwner(db.DefaultContext, 3, 2)
	require.NoError(t, err)
	require.True(t, isOwner, "user2 owns org3")
	user2Token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
	MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/collaborators/user5", &api.AddCollaboratorOption{Permission: new("admin")}).AddTokenAuth(user2Token), http.StatusNoContent)
	loginUser(t, "user5").MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings"), http.StatusOK) // a repo admin
	for _, name := range []string{"user2", "user5", "user4"} {
		s := loginUser(t, name)
		s.MakeRequest(t, NewRequest(t, "GET", "/admin/repo-units"), http.StatusForbidden)
		s.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/repo-units", repoUnitPolicyForm(map[string]bool{"repo.issues": false}, nil)), http.StatusForbidden)
	}
	MakeRequest(t, NewRequest(t, "GET", "/admin/repo-units"), http.StatusSeeOther)
	assert.Empty(t, setting.Config().RepoUnitPolicy.Value(db.DefaultContext).NotAllowed)

	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/repo-units", repoUnitPolicyForm(map[string]bool{"repo.issues": false}, map[string]string{"repo.wiki": "ORG3\norg17"})), http.StatusSeeOther)
	bumpSettingsRevision(t)
	p := setting.Config().RepoUnitPolicy.Value(db.DefaultContext)
	assert.Equal(t, []string{"repo.issues"}, p.NotAllowed)
	assert.Equal(t, []int64{3, 17}, p.OrgOverrides["repo.wiki"])
	assert.EqualValues(t, 1, p.UpdatedBy)
	doc = NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repo-units"), http.StatusOK).Body)
	assert.Contains(t, doc.Find(".admin-setting-content").Text(), "by user1")
	assert.Contains(t, doc.Find(".admin-setting-content").Text(), time.Unix(p.UpdatedUnix, 0).Format("2006-01-02"))
	assert.ElementsMatch(t, []string{"org3", "org17"}, strings.Split(doc.Find(`textarea[name="orgs_repo.wiki"]`).Text(), "\n"))

	// unknown, user and duplicate names are refused and nothing is saved
	for _, names := range []string{"no-such-org", "user2", "org3\nOrg3"} {
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/repo-units", repoUnitPolicyForm(nil, map[string]string{"repo.wiki": names})), http.StatusBadRequest)
		bumpSettingsRevision(t)
		assert.Equal(t, []string{"repo.issues"}, setting.Config().RepoUnitPolicy.Value(db.DefaultContext).NotAllowed, names)
	}

	t.Run("app.ini locks", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Repository.DefaultRepoUnits, []string{"repo.code", "repo.issues"})()
		disabled := unit_model.DisabledRepoUnitsGet()
		unit_model.DisabledRepoUnitsSet([]unit_model.Type{unit_model.TypeWiki})
		defer unit_model.DisabledRepoUnitsSet(disabled)

		doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repo-units"), http.StatusOK).Body)
		assert.Equal(t, 1, doc.Find(`fieldset.repo-unit[disabled][data-unit="repo.wiki"]`).Length())
		// the hard off applies to user repositories too
		loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/wiki"), http.StatusNotFound)
		assert.Equal(t, 0, doc.Find(`input[name^="default_"]:not([disabled])`).Length())

		form := repoUnitPolicyForm(nil, nil)
		for k := range form {
			if strings.HasPrefix(k, "default_") || strings.HasSuffix(k, "repo.wiki") {
				delete(form, k)
			}
		}
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/repo-units", form), http.StatusSeeOther)
		form["allowed_repo.wiki"] = "on"
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/repo-units", form), http.StatusBadRequest)
		delete(form, "allowed_repo.wiki")
		form["default_repo.projects"] = "on"
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/repo-units", form), http.StatusBadRequest)
	})
}

// A9: an organization deleted after it was listed leaves a stale ID that matches no other organization
func TestRepoUnitPolicyDeletedOrg(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)

	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteOrganization)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "unit-policy-gone"}).AddTokenAuth(token), http.StatusCreated)
	defer denyRepoUnits(t, []string{"unit-policy-gone"}, unit_model.TypeIssues)()
	gone := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "unit-policy-gone"})
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/orgs/unit-policy-gone").AddTokenAuth(token), http.StatusNoContent)
	bumpSettingsRevision(t)

	assert.Equal(t, []int64{gone.ID}, setting.Config().RepoUnitPolicy.Value(db.DefaultContext).OrgOverrides["repo.issues"])
	for _, id := range []int64{3, 17} {
		org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: id})
		assert.True(t, repo_model.HiddenUnits(db.DefaultContext, org).Contains(unit_model.TypeIssues))
	}
	doc := NewHTMLParser(t, loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", "/admin/repo-units"), http.StatusOK).Body)
	assert.Empty(t, doc.Find(`textarea[name="orgs_repo.issues"]`).Text())
}

// createUnitPolicyOrgRepo creates a public organization owned by user2 with an initialized public repository
func createUnitPolicyOrgRepo(t *testing.T, token, org, name string) *repo_model.Repository {
	t.Helper()
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: org}).AddTokenAuth(token), http.StatusCreated)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/"+org+"/repos", &api.CreateRepoOption{Name: name, AutoInit: true, Readme: "Default", DefaultBranch: "main"}).AddTokenAuth(token), http.StatusCreated)
	return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: org, LowerName: name})
}

// A3, A4, A8, A12: a Not allowed unit disappears from organization repositories everywhere, its data is kept and
// comes back; user repositories are not restricted
func TestRepoUnitPolicyHidesUnit(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)

	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteIssue, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeReadUser, auth_model.AccessTokenScopeReadNotification)
	other := loginUser(t, "user5")
	otherToken := getTokenForLoggedInUser(t, other, auth_model.AccessTokenScopeReadIssue, auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeReadNotification)
	repo := createUnitPolicyOrgRepo(t, token, "unit-policy-a", "hidden")
	repoAPI := "/api/v1/repos/unit-policy-a/hidden"

	// an issue with a feed entry, a notification and a milestone
	var apiIssue api.Issue
	DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", repoAPI+"/issues", &api.CreateIssueOption{Title: "unit policy issue"}).AddTokenAuth(token), http.StatusCreated), &apiIssue)
	issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: apiIssue.ID})
	notification := &activities_model.Notification{UserID: 5, RepoID: repo.ID, IssueID: issue.ID, Status: activities_model.NotificationStatusUnread, Source: activities_model.NotificationSourceIssue}
	unittest.AssertSuccessfulInsert(t, notification)
	MakeRequest(t, NewRequestWithJSON(t, "POST", repoAPI+"/milestones", &api.CreateMilestoneOption{Title: "unit policy milestone"}).AddTokenAuth(token), http.StatusCreated)
	issuesUnit := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: repo.ID, Type: unit_model.TypeIssues})

	issueURL := fmt.Sprintf("/unit-policy-a/hidden/issues/%d", issue.Index)
	visible := func(t *testing.T, want bool) {
		t.Helper()
		status := map[bool]int{true: http.StatusOK, false: http.StatusNotFound}[want]
		MakeRequest(t, NewRequest(t, "GET", "/unit-policy-a/hidden/issues"), status)
		MakeRequest(t, NewRequest(t, "GET", "/unit-policy-a/hidden/pulls"), status)
		MakeRequest(t, NewRequest(t, "GET", issueURL), status)
		session.MakeRequest(t, NewRequest(t, "GET", issueURL), status)
		MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("%s/issues/%d", repoAPI, issue.Index)).AddTokenAuth(token), status)
		MakeRequest(t, NewRequest(t, "GET", repoAPI+"/issues").AddTokenAuth(token), status)
		MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/notifications/threads/%d", notification.ID)).AddTokenAuth(otherToken), status)

		var apiRepo api.Repository
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", repoAPI).AddTokenAuth(token), http.StatusOK), &apiRepo)
		assert.Equal(t, want, apiRepo.HasIssues)
		units := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/unit-policy-a/hidden/settings/units"), http.StatusOK).Body)
		assert.Equal(t, want, units.Find(`input[name="enable_issues"]`).Length() == 1)

		// lists: API issue search (own and all public repositories), dashboard, milestones, feeds (API and RSS),
		// notifications (API and web)
		for _, tok := range []string{token, otherToken} {
			var found []*api.Issue
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/issues/search?limit=50").AddTokenAuth(tok), http.StatusOK), &found)
			assert.Equal(t, want, slices.ContainsFunc(found, func(i *api.Issue) bool { return i.ID == issue.ID }), "issue search")
		}
		assert.Equal(t, want, strings.Contains(session.MakeRequest(t, NewRequest(t, "GET", "/issues?type=created_by"), http.StatusOK).Body.String(), "unit policy issue"), "dashboard")
		assert.Equal(t, want, strings.Contains(session.MakeRequest(t, NewRequest(t, "GET", "/milestones"), http.StatusOK).Body.String(), "unit policy milestone"), "milestones")
		var feeds []*api.Activity
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/users/user2/activities/feeds?only-performed-by=true").AddTokenAuth(token), http.StatusOK), &feeds)
		assert.Equal(t, want, slices.ContainsFunc(feeds, func(a *api.Activity) bool { return a.OpType == "create_issue" && a.RepoID == repo.ID }), "feeds")
		assert.Equal(t, want, strings.Contains(MakeRequest(t, NewRequest(t, "GET", "/user2.rss"), http.StatusOK).Body.String(), "unit policy issue"), "rss")
		var notifications []*api.NotificationThread
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/notifications?all=true").AddTokenAuth(otherToken), http.StatusOK), &notifications)
		assert.Equal(t, want, slices.ContainsFunc(notifications, func(n *api.NotificationThread) bool { return n.ID == notification.ID }), "notifications")
		doc := NewHTMLParser(t, other.MakeRequest(t, NewRequest(t, "GET", "/notifications"), http.StatusOK).Body)
		assert.Equal(t, want, doc.Find(fmt.Sprintf("#notification_%d", notification.ID)).Length() == 1, "web notifications")
	}
	visible(t, true)

	defer denyRepoUnits(t, nil, unit_model.TypeIssues, unit_model.TypeExternalTracker, unit_model.TypePullRequests)()
	visible(t, false)

	// repo admins can't enable it: the web form ignores it, the API refuses; the row is untouched
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/unit-policy-a/hidden/settings/units", map[string]string{"enable_code": "on", "enable_issues": "on", "enable_pulls": "on"}), http.StatusSeeOther)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", repoAPI, &api.EditRepoOption{HasIssues: new(true)}).AddTokenAuth(token), http.StatusForbidden)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", repoAPI, &api.EditRepoOption{HasIssues: new(false), HasPullRequests: new(false)}).AddTokenAuth(token), http.StatusOK)
	assert.Equal(t, issuesUnit.Config, unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: repo.ID, Type: unit_model.TypeIssues}).Config)
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: repo.ID, Type: unit_model.TypePullRequests})
	visible(t, false)

	// nor can anyone write to it, by API or by email reply
	MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/issues/%d/comments", repoAPI, issue.Index), &api.CreateIssueCommentOption{Body: "hidden"}).AddTokenAuth(token), http.StatusNotFound)
	payload, err := incoming_payload.CreateReferencePayload(issue)
	require.NoError(t, err)
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, (&incoming.ReplyHandler{}).Handle(db.DefaultContext, &incoming.MailContent{Content: "reply to a hidden issue"}, user2, payload))
	unittest.AssertNotExistsBean(t, &issues_model.Comment{IssueID: issue.ID, Content: "reply to a hidden issue"})

	// nor do services: a comment made by code reaches no watcher by notification or mail
	recipients, restore := captureMail(t)
	user5 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	require.NoError(t, repo_model.WatchRepoExplicitly(db.DefaultContext, user5.ID, repo.ID, repo_model.WatchAllSelection))
	_, err = issue_service.CreateIssueComment(db.DefaultContext, user2, repo, issue, "made by code", nil)
	require.NoError(t, err)
	restore()
	assert.Empty(t, recipients())
	unittest.AssertNotExistsBean(t, &activities_model.Notification{UserID: 5, IssueID: issue.ID, Status: activities_model.NotificationStatusUnread, CommentID: unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: issue.ID, Content: "made by code"}).ID})

	// and a commit that closes it changes nothing
	closing := fmt.Sprintf("fixes #%d", issue.Index)
	createWorkflowFile(t, token, "unit-policy-a", "hidden", "closing.txt", getWorkflowCreateFileOptions(user2, "main", closing, "x"))
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: issue.ID}).IsClosed)
	unittest.AssertNotExistsBean(t, &issues_model.Comment{IssueID: issue.ID, Type: issues_model.CommentTypeCommitRef})

	// a user repository can still switch it off and on
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", &api.EditRepoOption{HasIssues: new(false)}).AddTokenAuth(token), http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/issues"), http.StatusNotFound)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", &api.EditRepoOption{HasIssues: new(true)}).AddTokenAuth(token), http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/issues/1"), http.StatusOK)

	// allowed again: the issue and the unit config are back
	resetRepoUnitPolicy(t)
	visible(t, true)
	assert.Equal(t, issuesUnit.Config, unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: repo.ID, Type: unit_model.TypeIssues}).Config)

	// control: the same closing commit works now
	createWorkflowFile(t, token, "unit-policy-a", "hidden", "closing2.txt", getWorkflowCreateFileOptions(user2, "main", closing, "x"))
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: issue.ID}).IsClosed)
}

// A3, A4: the same unit is Not allowed for one organization and allowed for another, both ways round
func TestRepoUnitPolicySelectedOrgs(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
	createUnitPolicyOrgRepo(t, token, "unit-policy-b", "other")

	// Not allowed by default, allowed for org3
	denyRepoUnits(t, []string{"org3"}, unit_model.TypePullRequests)
	session.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/pulls"), http.StatusOK)
	session.MakeRequest(t, NewRequest(t, "GET", "/unit-policy-b/other/pulls"), http.StatusNotFound)

	// allowed by default, Not allowed for org3
	changes := map[unit_model.Type]repo_service.UnitPolicyChange{unit_model.TypePullRequests: {Allowed: true, OrgNames: []string{"org3"}, OnDefault: true}}
	require.NoError(t, repo_service.SetUnitPolicy(db.DefaultContext, nil, changes))
	bumpSettingsRevision(t)
	session.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/pulls"), http.StatusNotFound)
	session.MakeRequest(t, NewRequest(t, "GET", "/unit-policy-b/other/pulls"), http.StatusOK)
	// user repositories are never restricted
	MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/pulls"), http.StatusOK)
}

// S2: project boards (repository and organization) don't show cards of hidden issues or pull requests
func TestRepoUnitPolicyProjectBoards(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)
	unittest.AssertSuccessfulInsert(t, &project_model.ProjectIssue{IssueID: 6, ProjectID: 2, ProjectColumnID: 5})              // org3/repo3 issue6
	unittest.AssertSuccessfulInsert(t, &project_model.ProjectIssue{IssueID: 12, ProjectID: 2, ProjectColumnID: 5, Sorting: 1}) // org3/repo3 pull6

	session := loginUser(t, "user2")
	cards := func(t *testing.T, page, title string, want bool) {
		t.Helper()
		assert.Equal(t, want, strings.Contains(session.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body.String(), title), page+" "+title)
	}
	cards(t, "/org3/repo3/projects/2", "issue6", true)
	cards(t, "/org3/repo3/projects/2", "pull6", true)
	cards(t, "/org3/-/projects/7", "a issue with a assignment", true)

	denyRepoUnits(t, nil, unit_model.TypeIssues)
	cards(t, "/org3/repo3/projects/2", "issue6", false)
	cards(t, "/org3/repo3/projects/2", "pull6", true)
	cards(t, "/org3/-/projects/7", "a issue with a assignment", false)

	denyRepoUnits(t, nil, unit_model.TypePullRequests)
	cards(t, "/org3/repo3/projects/2", "issue6", true)
	cards(t, "/org3/repo3/projects/2", "pull6", false)
}

// A11: hidden is decided by the current owner
func TestRepoUnitPolicyTransfer(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)
	defer denyRepoUnits(t, nil, unit_model.TypeIssues)()

	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})

	session := loginUser(t, "user2")
	repo3 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	session.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/issues/1"), http.StatusNotFound)
	require.NoError(t, repo_service.TransferOwnership(db.DefaultContext, admin, user2, repo3, nil))
	session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo3/issues/1"), http.StatusOK)

	repo1 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.NoError(t, repo_service.TransferOwnership(db.DefaultContext, admin, org3, repo1, nil))
	session.MakeRequest(t, NewRequest(t, "GET", "/org3/repo1/issues/1"), http.StatusNotFound)
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoUnit{RepoID: 1, Type: unit_model.TypeIssues})
}

// A7, A11: new repositories start without the units that are hidden or off by default, however they are created
func TestRepoUnitPolicyNewRepos(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer resetRepoUnitPolicy(t)
		defer test.MockVariableValue(&setting.Repository.EnablePushCreateOrg, true)()
		defer test.MockVariableValue(&setting.Migrations.AllowLocalNetworks, true)()
		defer test.MockVariableValue(&setting.Migrations.AllowUnencrypted, true)()
		require.NoError(t, migrations_allowlist.Init())

		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteUser)
		hasUnit := func(owner, name string, tp unit_model.Type) bool {
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: owner, LowerName: strings.ToLower(name)})
			return unittest.GetCount(t, &repo_model.RepoUnit{RepoID: repo.ID, Type: tp}) == 1
		}

		// nothing stored: today's defaults
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "unit-default"}).AddTokenAuth(token), http.StatusCreated)
		assert.True(t, hasUnit("user2", "unit-default", unit_model.TypeWiki))

		// Issues Not allowed for organizations, Wiki off for new repositories
		changes := map[unit_model.Type]repo_service.UnitPolicyChange{
			unit_model.TypeIssues: {Allowed: false, OnDefault: true},
			unit_model.TypeWiki:   {Allowed: true, OnDefault: false},
		}
		require.NoError(t, repo_service.SetUnitPolicy(db.DefaultContext, nil, changes))
		bumpSettingsRevision(t)

		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "unit-user"}).AddTokenAuth(token), http.StatusCreated)
		assert.True(t, hasUnit("user2", "unit-user", unit_model.TypeIssues))
		assert.False(t, hasUnit("user2", "unit-user", unit_model.TypeWiki))
		assert.True(t, hasUnit("user2", "unit-default", unit_model.TypeWiki), "existing repos don't change")

		created := []string{}
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: "unit-org"}).AddTokenAuth(token), http.StatusCreated)
		created = append(created, "unit-org")

		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user27/template1/generate", &api.GenerateRepoOption{Owner: "org3", Name: "unit-template", GitContent: true}).AddTokenAuth(token), http.StatusCreated)
		created = append(created, "unit-template")

		cloneURL := *u
		cloneURL.Path = "/user2/repo1.git"
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", &api.MigrateRepoOptions{CloneAddr: cloneURL.String(), RepoOwner: "org3", RepoName: "unit-migrate"}).AddTokenAuth(token), http.StatusCreated)
		created = append(created, "unit-migrate")

		tmpDir := t.TempDir()
		pushURL := *u
		pushURL.Path = "/org3/unit-push.git"
		pushURL.User = url.UserPassword("user2", userPassword)
		t.Run("InitTestRepository", doGitInitTestRepository(tmpDir, git.Sha1ObjectFormat))
		t.Run("AddRemote", doGitAddRemote(tmpDir, "origin", &pushURL))
		t.Run("PushCreate", doGitPushTestRepository(tmpDir, "origin", "master"))
		created = append(created, "unit-push")

		for _, name := range created {
			assert.False(t, hasUnit("org3", name, unit_model.TypeIssues), name)
			assert.True(t, hasUnit("org3", name, unit_model.TypeCode), name)
		}
		for _, name := range []string{"unit-org", "unit-template", "unit-migrate"} {
			assert.False(t, hasUnit("org3", name, unit_model.TypeWiki), name)
			assert.True(t, hasUnit("org3", name, unit_model.TypePullRequests), name)
		}

		// adopting files on disk
		require.NoError(t, git.InitRepository(t.Context(), repo_model.RepoPath("org3", "unit-adopt"), true, git.Sha1ObjectFormat.Name()))
		_, err := repo_service.AdoptRepository(db.DefaultContext, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}), repo_service.CreateRepoOptions{Name: "unit-adopt"})
		require.NoError(t, err)
		assert.False(t, hasUnit("org3", "unit-adopt", unit_model.TypeIssues))
		assert.False(t, hasUnit("org3", "unit-adopt", unit_model.TypeWiki))
		assert.True(t, hasUnit("org3", "unit-adopt", unit_model.TypeCode))

		// a fork into a restricted organization
		require.NoError(t, repo_service.SetUnitPolicy(db.DefaultContext, nil, map[unit_model.Type]repo_service.UnitPolicyChange{unit_model.TypePullRequests: {Allowed: false, OnDefault: true}}))
		bumpSettingsRevision(t)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/forks", &api.CreateForkOption{Organization: new("org3"), Name: new("unit-fork")}).AddTokenAuth(token), http.StatusAccepted)
		assert.False(t, hasUnit("org3", "unit-fork", unit_model.TypePullRequests))
		assert.True(t, hasUnit("org3", "unit-fork", unit_model.TypeCode))

		// migrating with a wiki into an organization whose Wiki is Not allowed: no wiki, no error
		require.NoError(t, repo_service.SetUnitPolicy(db.DefaultContext, nil, map[unit_model.Type]repo_service.UnitPolicyChange{unit_model.TypeWiki: {Allowed: false}}))
		bumpSettingsRevision(t)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", &api.MigrateRepoOptions{CloneAddr: cloneURL.String(), RepoOwner: "org3", RepoName: "unit-migrate-wiki", Wiki: true, Releases: true}).AddTokenAuth(token), http.StatusCreated)
		assert.False(t, hasUnit("org3", "unit-migrate-wiki", unit_model.TypeWiki))
		assert.True(t, hasUnit("org3", "unit-migrate-wiki", unit_model.TypeReleases))

		// app.ini DEFAULT_REPO_UNITS wins over the stored list
		defer test.MockVariableValue(&setting.Repository.DefaultRepoUnits, []string{"repo.code", "repo.wiki"})()
		defer test.MockProtect(&unit_model.DefaultRepoUnits)()
		unit_model.DefaultRepoUnits = []unit_model.Type{unit_model.TypeCode, unit_model.TypeWiki}
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "unit-ini"}).AddTokenAuth(token), http.StatusCreated)
		assert.True(t, hasUnit("user2", "unit-ini", unit_model.TypeWiki))
		assert.False(t, hasUnit("user2", "unit-ini", unit_model.TypeIssues))
	})
}

// A12, S1: git, hooks and Actions (triggers, runners, org runs pages, instance usage) refuse a hidden unit; Code is never hidden
func TestRepoUnitPolicyEntryPaths(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		defer resetRepoUnitPolicy(t)

		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

		// an org repository with a push and a schedule workflow
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: "unit-actions", AutoInit: true, Readme: "Default", DefaultBranch: "main"}).AddTokenAuth(token), http.StatusCreated)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: 3, Name: "unit-actions"})
		workflow := func(name string) string {
			return fmt.Sprintf("name: %s\non:\n  push:\n  schedule:\n    - cron: '* * * * *'\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n", name)
		}
		pushWorkflow := func(name string) {
			createWorkflowFile(t, token, "org3", "unit-actions", ".forgejo/workflows/"+name+".yml", getWorkflowCreateFileOptions(user2, "main", name, workflow(name)))
		}
		runs := func() int { return unittest.GetCount(t, &actions_model.ActionRun{RepoID: repo.ID}) }
		pushWorkflow("allowed")
		require.Equal(t, 1, runs())
		adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeAll)
		orgRuns := func(t *testing.T, want bool) {
			t.Helper()
			status := map[bool]int{true: http.StatusOK, false: http.StatusNotFound}[want]
			body := session.MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions"), status).Body.String()
			assert.Equal(t, want, strings.Contains(body, "unit-actions"))
			session.MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions/overview"), status)
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/actions/runs").AddTokenAuth(token), status)
			// site admins see the instance list without the hidden runs too
			assert.Equal(t, want, strings.Contains(MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/actions/runs").AddTokenAuth(adminToken), http.StatusOK).Body.String(), "unit-actions"))
		}
		orgRuns(t, true)

		runner := newMockRunner()
		var registration struct {
			Token string `json:"token"`
		}
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/actions/runners/registration-token").AddTokenAuth(token), http.StatusOK), &registration)
		runner.doRegister(t, "unit-policy-runner", registration.Token, []string{"ubuntu-latest"})

		deny := denyRepoUnits(t, nil, unit_model.TypeActions, unit_model.TypeWiki, unit_model.TypePullRequests, unit_model.TypeIssues, unit_model.TypeReleases, unit_model.TypeProjects, unit_model.TypePackages)

		// push and schedule triggers, runner pickup
		pushWorkflow("hidden")
		assert.Equal(t, 1, runs())
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE action_schedule_spec SET next = 1 WHERE repo_id = ?", repo.ID)
		require.NoError(t, err)
		require.NoError(t, actions_service.StartScheduleTasks(db.DefaultContext))
		assert.Equal(t, 1, runs())
		assert.Nil(t, runner.maybeFetchTask(t))

		orgRuns(t, false)

		// wiki.git over HTTP (fetch and push) and SSH
		MakeRequest(t, NewRequest(t, "GET", "/org3/repo3.wiki.git/info/refs?service=git-upload-pack").AddBasicAuth("user2"), http.StatusNotFound)
		wikiDir := t.TempDir()
		wikiURL := *u
		wikiURL.Path = "/org3/repo3.wiki.git"
		wikiURL.User = url.UserPassword("user2", userPassword)
		t.Run("InitWiki", doGitInitTestRepository(wikiDir, git.Sha1ObjectFormat))
		t.Run("AddWikiRemote", doGitAddRemote(wikiDir, "origin", &wikiURL))
		doGitPushTestRepositoryFail(t, wikiDir, "origin", "master")
		_, extra := private.ServCommand(t.Context(), 1, "org3", "repo3.wiki", 1, "", "git-upload-pack")
		require.Error(t, extra.Error)

		// AGit pushes need Pull requests
		extra = private.HookPreReceive(t.Context(), repoIDByName(t, "org3", "repo3"), private.HookOptions{
			UserID: 2, UserName: "user2", RefFullNames: []git.RefName{"refs/for/master/topic"},
			OldCommitIDs: []string{git.Sha1ObjectFormat.EmptyObjectID().String()}, NewCommitIDs: []string{"65f1bf27bc3bf70f64657658635e66094edbcb4d"},
		})
		assert.Equal(t, "User permission denied for creating pull-request.", extra.UserMsg)

		// Code and LFS are unaffected
		MakeRequest(t, NewRequest(t, "GET", "/org3/repo3.git/info/refs?service=git-upload-pack").AddBasicAuth("user2"), http.StatusOK)
		defer test.MockVariableValue(&setting.LFS.StartServer, true)()
		batch := &lfs.BatchRequest{Operation: "download", Objects: []lfs.Pointer{{Oid: strings.Repeat("a", 64), Size: 1}}}
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/org3/repo3.git/info/lfs/objects/batch", batch).AddBasicAuth("user2").
			SetHeader("Accept", lfs.AcceptHeader).SetHeader("Content-Type", lfs.MediaType), http.StatusOK)

		// allowed again: new pushes run, and the runner picks the jobs up again (as when a repository turns Actions
		// back on, runners are woken by the next new job)
		deny()
		pushWorkflow("again")
		assert.Equal(t, 4, runs()) // the push runs all three workflows
		runner.failAtTask(t, runner.fetchTask(t))
		orgRuns(t, true)

		// the instance usage and its top lists leave out repositories whose Actions are Not allowed
		usage := func() string {
			return MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/actions/usage?group_by=repo").AddTokenAuth(adminToken), http.StatusOK).Body.String()
		}
		var report api.ActionUsage
		require.NoError(t, json.Unmarshal([]byte(usage()), &report))
		require.True(t, slices.ContainsFunc(report.TopReposByFailures, func(e *api.ActionUsageEntry) bool { return e.Name == "org3/unit-actions" }))
		require.True(t, slices.ContainsFunc(report.Entries, func(e *api.ActionUsageEntry) bool { return e.Name == "org3/unit-actions" }))
		deny = denyRepoUnits(t, nil, unit_model.TypeActions)
		assert.NotContains(t, usage(), "org3/unit-actions")
		orgRuns(t, false)
		deny()
	})
}

// A6: Packages Not allowed for an organization close its registries, web and API pages, to site admins too
func TestRepoUnitPolicyPackages(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)

	token := getUserToken(t, "user2", auth_model.AccessTokenScopeWritePackage, auth_model.AccessTokenScopeReadOrganization)
	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWritePackage)
	file := "/api/packages/org3/generic/unit-policy/1.0/file.bin"
	MakeRequest(t, NewRequestWithBody(t, "PUT", file, bytes.NewReader([]byte{1})).AddTokenAuth(token), http.StatusCreated)
	var registryToken struct {
		Token string `json:"token"`
	}
	DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/v2/token").AddBasicAuth("user2"), http.StatusOK), &registryToken)
	registry := "Bearer " + registryToken.Token
	MakeRequest(t, NewRequest(t, "POST", "/v2/org3/unit-policy/blobs/uploads").AddTokenAuth(registry), http.StatusAccepted)

	defer denyRepoUnits(t, nil, unit_model.TypePackages)()
	for _, tok := range []string{token, adminToken} {
		MakeRequest(t, NewRequest(t, "GET", file).AddTokenAuth(tok), http.StatusNotFound)
		MakeRequest(t, NewRequestWithBody(t, "PUT", "/api/packages/org3/generic/unit-policy/2.0/file.bin", bytes.NewReader([]byte{1})).AddTokenAuth(tok), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/packages/org3").AddTokenAuth(tok), http.StatusNotFound)
	}
	MakeRequest(t, NewRequest(t, "POST", "/v2/org3/unit-policy/blobs/uploads").AddTokenAuth(registry), http.StatusNotFound)
	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org3/-/packages"), http.StatusNotFound)
	loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", "/org3/-/packages/generic/unit-policy/1.0"), http.StatusNotFound)
	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/packages"), http.StatusNotFound)
	MakeRequest(t, NewRequestWithBody(t, "PUT", "/api/packages/org3/maven/com/unitpolicy/app/1.0/app-1.0.jar", bytes.NewReader([]byte{1})).AddTokenAuth(token), http.StatusNotFound)
	// user packages are not restricted
	MakeRequest(t, NewRequestWithBody(t, "PUT", "/api/packages/user2/generic/unit-policy/1.0/file.bin", bytes.NewReader([]byte{1})).AddTokenAuth(token), http.StatusCreated)

	resetRepoUnitPolicy(t)
	MakeRequest(t, NewRequest(t, "GET", file).AddTokenAuth(token), http.StatusOK)
}

// A10: a stored policy that can't be parsed fails closed for organizations, and the admin page can replace it
func TestRepoUnitPolicyCorrupt(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)

	require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().RepoUnitPolicy.DynKey(): "{not json"}))
	bumpSettingsRevision(t)
	session := loginUser(t, "user2")
	session.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/issues"), http.StatusNotFound)
	session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/issues"), http.StatusOK)

	admin := loginUser(t, "user1")
	doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/repo-units"), http.StatusOK).Body)
	assert.Equal(t, 1, doc.Find(".ui.error.message").Length())
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/repo-units", repoUnitPolicyForm(nil, nil)), http.StatusSeeOther)
	bumpSettingsRevision(t)
	session.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/issues"), http.StatusOK)
}

// A3: loading the units of a list stays one query, whatever the policy
func TestRepoUnitPolicyLoadUnitsQueries(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer resetRepoUnitPolicy(t)

	var all repo_model.RepositoryList
	require.NoError(t, db.GetEngine(db.DefaultContext).Limit(30).Find(&all))
	for name, setPolicy := range map[string]func(){
		"empty":       func() {},
		"not allowed": func() { denyRepoUnits(t, []string{"org3"}, unit_model.TypeIssues, unit_model.TypeWiki) },
	} {
		t.Run(name, func(t *testing.T) {
			setPolicy()
			for _, n := range []int{1, len(all)} {
				repos := slices.Clone(all[:n])
				ctx := cache.WithCacheContext(db.DefaultContext)
				_ = repo_model.HiddenUnitCond(ctx, "a", "b") // warm up the settings and org_unit caches of the request
				assert.EqualValues(t, 1, stableQueryCount(t, func() {
					for _, r := range repos {
						r.Units = nil // every reading starts cold
					}
					require.NoError(t, repos.LoadUnits(ctx))
				}), "%d repos", n)
			}
		})
	}
}
