// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"maps"
	"net/http"
	"strings"
	"testing"

	actions_model "forgejo.org/models/actions"
	activities_model "forgejo.org/models/activities"
	asymkey_model "forgejo.org/models/asymkey"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/lfs"
	"forgejo.org/modules/private"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func enrolTOTP(t *testing.T, uid int64) {
	t.Helper()
	require.NoError(t, db.Insert(db.DefaultContext, &auth_model.TwoFactor{UID: uid}))
}

func unenrolTOTP(t *testing.T, uid int64) {
	t.Helper()
	_, err := db.DeleteByBean(db.DefaultContext, &auth_model.TwoFactor{UID: uid})
	require.NoError(t, err)
}

func postOrgTwoFactor(t *testing.T, session *TestSession, org string, values map[string]string, status int) string {
	t.Helper()
	form := map[string]string{"name": org, "visibility": "0", "require_two_factor_shown": "true"}
	maps.Copy(form, values)
	return session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/"+org+"/settings", form), status).Body.String()
}

// org3 (public) has the private repositories repo3 and repo5 and the public repo21; user2 owns it, user4 writes
// repo3 through team1 (id 2).
func TestOrgTwoFactorRequired(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := db.DefaultContext
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})

	// sessions and tokens are made before anyone enrols: the login form would ask for the second factor
	owner := loginUser(t, "user2")
	ownerToken := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeAll)
	member := loginUser(t, "user4")
	memberToken := getTokenForLoggedInUser(t, member, auth_model.AccessTokenScopeAll)
	readToken := getTokenForLoggedInUser(t, member, auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeReadIssue)
	// user 28 is in team12Creators, an admin team, given repo3; team1 may create repositories
	require.NoError(t, db.Insert(ctx, &organization.TeamRepo{OrgID: 3, TeamID: 12, RepoID: 3}))
	_, err := db.GetEngine(ctx).ID(2).Cols("can_create_org_repo").Update(&organization.Team{CanCreateOrgRepo: true})
	require.NoError(t, err)
	teamAdmin := loginUser(t, "user28")
	teamAdminToken := getTokenForLoggedInUser(t, teamAdmin, auth_model.AccessTokenScopeAll)

	// data of the member's that names repo3: a star, a notification, a subscription, a stopwatch, tracked time
	require.NoError(t, repo_model.StarRepo(ctx, 4, 3, true))
	require.NoError(t, db.Insert(ctx, &activities_model.Notification{UserID: 4, RepoID: 3, IssueID: 6, Status: activities_model.NotificationStatusUnread, Source: activities_model.NotificationSourceIssue}))
	require.NoError(t, db.Insert(ctx, &issues_model.IssueWatch{UserID: 4, IssueID: 6, IsWatching: true}))
	require.NoError(t, db.Insert(ctx, &issues_model.Stopwatch{UserID: 4, IssueID: 6}))
	require.NoError(t, db.Insert(ctx, &issues_model.TrackedTime{UserID: 4, IssueID: 6, Time: 60}))
	// an Actions run on repo3, seen in the org runs list by the owners team
	require.NoError(t, db.Insert(ctx, &repo_model.RepoUnit{RepoID: 3, Type: unit_model.TypeActions}))
	run := &actions_model.ActionRun{Title: "repo3-run", RepoID: 3, OwnerID: 3, WorkflowID: "w.yml", Index: 1, TriggerUserID: 2, Ref: "refs/heads/master", CommitSHA: "c2d72f548424103f01ee1dc02889c1e2bff816b0", Event: "push", Status: actions_model.StatusSuccess}
	require.NoError(t, db.Insert(ctx, run))

	// a package of org3, uploaded while the owner may still write
	MakeRequest(t, NewRequestWithBody(t, "PUT", "/api/packages/org3/generic/p/1.0/f.bin", bytes.NewReader([]byte{1})).AddTokenAuth(ownerToken), http.StatusCreated)

	// what names repo3 for the member, on web and API
	repo3Listed := func(t *testing.T) map[string]bool {
		t.Helper()
		in := func(req *RequestWrapper, session *TestSession) bool {
			t.Helper()
			var body string
			if session != nil {
				body = session.MakeRequest(t, req, http.StatusOK).Body.String()
			} else {
				body = MakeRequest(t, req, http.StatusOK).Body.String()
			}
			return strings.Contains(body, "org3/repo3")
		}
		contains := func(req *RequestWrapper, s string) bool {
			t.Helper()
			return strings.Contains(MakeRequest(t, req, http.StatusOK).Body.String(), s)
		}
		return map[string]bool{
			"web repo search":     in(NewRequest(t, "GET", "/repo/search?uid=4&q=repo3"), member),
			"web explore":         in(NewRequest(t, "GET", "/explore/repos?q=repo3"), member),
			"web team repos":      in(NewRequest(t, "GET", "/org/org3/teams/team1/repositories"), member),
			"web notifications":   in(NewRequest(t, "GET", "/notifications"), member),
			"web subscriptions":   in(NewRequest(t, "GET", "/notifications/subscriptions"), member),
			"api user repos":      in(NewRequest(t, "GET", "/api/v1/user/repos").AddTokenAuth(memberToken), nil),
			"api repo search":     in(NewRequest(t, "GET", "/api/v1/repos/search?uid=4&q=repo3").AddTokenAuth(memberToken), nil),
			"api team repos":      in(NewRequest(t, "GET", "/api/v1/teams/2/repos").AddTokenAuth(memberToken), nil),
			"api starred":         in(NewRequest(t, "GET", "/api/v1/user/starred").AddTokenAuth(memberToken), nil),
			"api notifications":   in(NewRequest(t, "GET", "/api/v1/notifications").AddTokenAuth(memberToken), nil),
			"api stopwatches":     contains(NewRequest(t, "GET", "/api/v1/user/stopwatches").AddTokenAuth(memberToken), `"repo_name":"repo3"`),
			"api tracked times":   contains(NewRequest(t, "GET", "/api/v1/user/times").AddTokenAuth(memberToken), `"issue_id":6,`),
			"api issues search":   in(NewRequest(t, "GET", "/api/v1/repos/issues/search?type=all").AddTokenAuth(memberToken), nil),
			"api read-only token": in(NewRequest(t, "GET", "/api/v1/repos/search?q=repo3").AddTokenAuth(readToken), nil),
		}
	}
	orgRunListed := func(t *testing.T) bool {
		t.Helper()
		body := MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/actions/runs").AddTokenAuth(ownerToken), http.StatusOK).Body.String()
		return strings.Contains(body, "repo3-run")
	}
	// the admin-team member, on the runs API, the runs page and the overview
	adminTeamSeesRun := func(t *testing.T) bool {
		t.Helper()
		fromAPI := strings.Contains(MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/actions/runs").AddTokenAuth(teamAdminToken), http.StatusOK).Body.String(), "repo3-run")
		fromWeb := strings.Contains(teamAdmin.MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions"), http.StatusOK).Body.String(), "repo3-run")
		assert.Equal(t, fromAPI, fromWeb)
		return fromAPI
	}
	memberAccess := func(t *testing.T, status int) {
		t.Helper()
		web := status // a blocked member gets the 403 page with the reason on the web
		if status == http.StatusNotFound {
			web = http.StatusForbidden
		}
		member.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3"), web)
		member.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/issues"), web)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3").AddTokenAuth(memberToken), status)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3/contents").AddTokenAuth(memberToken), status)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3/issues").AddTokenAuth(readToken), status)
		// git and LFS over HTTP, with the token as the password (a user with 2FA can't use theirs)
		for _, service := range []string{"git-upload-pack", "git-receive-pack"} {
			req := NewRequest(t, "GET", "/org3/repo3.git/info/refs?service="+service)
			req.SetBasicAuth("user4", memberToken)
			MakeRequest(t, req, status)
		}
		lfsReq := NewRequestWithJSON(t, "POST", "/org3/repo3.git/info/lfs/objects/batch", &lfs.BatchRequest{Operation: "download"})
		lfsReq.SetBasicAuth("user4", memberToken)
		lfsReq.Header.Set("Accept", lfs.MediaType)
		lfsReq.Header.Set("Content-Type", lfs.MediaType)
		// LFS answers 401 without access
		MakeRequest(t, lfsReq, map[int]int{http.StatusOK: http.StatusOK, http.StatusNotFound: http.StatusUnauthorized}[status])
		// public repositories are unaffected
		member.MakeRequest(t, NewRequest(t, "GET", "/org3/repo21"), http.StatusOK)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo21").AddTokenAuth(memberToken), http.StatusOK)
	}

	t.Run("flag off", func(t *testing.T) {
		memberAccess(t, http.StatusOK)
		for name, listed := range repo3Listed(t) {
			assert.True(t, listed, name)
		}
		assert.True(t, orgRunListed(t))
		assert.True(t, adminTeamSeesRun(t))
	})

	t.Run("turning it on", func(t *testing.T) {
		// the owner needs 2FA first
		body := postOrgTwoFactor(t, owner, "org3", map[string]string{"require_two_factor": "on", "require_two_factor_confirm": "on"}, http.StatusOK)
		assert.Contains(t, body, "you must enable two-factor authentication")
		assert.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).RequireTwoFactor)

		enrolTOTP(t, 2)
		// without confirmation: lists the members without 2FA, saves nothing
		body = postOrgTwoFactor(t, owner, "org3", map[string]string{"require_two_factor": "on", "full_name": "changed", "restrict_repo_visibility_change": "on", "private_fork_policy": "2"}, http.StatusOK)
		page := NewHTMLParser(t, bytes.NewBufferString(body))
		// the form is shown again as submitted
		assert.Equal(t, "changed", page.Find(`input[name="full_name"]`).AttrOr("value", ""))
		assert.Equal(t, 1, page.Find(`input[name="restrict_repo_visibility_change"][checked]`).Length())
		assert.Equal(t, 1, page.Find(`select[name="private_fork_policy"] option[value="2"][selected]`).Length())
		var members []string
		page.Find(".require-two-factor-members li a").Each(func(_ int, s *goquery.Selection) { members = append(members, s.Text()) })
		assert.Contains(t, members, "user4")
		assert.NotContains(t, members, "user2")
		assert.Equal(t, 1, page.Find(`input[name="require_two_factor_confirm"]`).Length())
		saved := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		assert.False(t, saved.RequireTwoFactor)
		assert.Equal(t, org3.FullName, saved.FullName)

		postOrgTwoFactor(t, owner, "org3", map[string]string{"require_two_factor": "on", "require_two_factor_confirm": "on", "restrict_repo_visibility_change": "on", "private_fork_policy": "2"}, http.StatusSeeOther)
		saved = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		assert.True(t, saved.RequireTwoFactor)
		assert.True(t, saved.RestrictRepoVisibilityChange)
		assert.Equal(t, 2, saved.PrivateForkPolicy)
		// saving again needs no confirmation
		postOrgTwoFactor(t, owner, "org3", map[string]string{"require_two_factor": "on"}, http.StatusSeeOther)
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).RequireTwoFactor)
		// a post without the checkbox at all keeps the setting
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings", map[string]string{"name": "org3", "visibility": "0"}), http.StatusSeeOther)
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).RequireTwoFactor)
	})

	t.Run("member without 2FA", func(t *testing.T) {
		memberAccess(t, http.StatusNotFound)
		for name, listed := range repo3Listed(t) {
			assert.False(t, listed, name)
		}
		// login and the 2FA setup page are not blocked
		member.MakeRequest(t, NewRequest(t, "GET", "/user/settings/security"), http.StatusOK)
		// an admin-team member sees no run of the hidden repository
		assert.False(t, adminTeamSeesRun(t))
		assert.NotContains(t, teamAdmin.MakeRequest(t, NewRequest(t, "GET", "/org/org3/actions/overview"), http.StatusOK).Body.String(), "repo3")
		// a team member who may create repositories can't
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: "blocked"}).AddTokenAuth(memberToken), http.StatusForbidden)
		// the org's public package stays readable, as for every signed-in user
		MakeRequest(t, NewRequest(t, "GET", "/api/packages/org3/generic/p/1.0/f.bin").AddTokenAuth(memberToken), http.StatusOK)
	})

	t.Run("owner without 2FA is no owner", func(t *testing.T) {
		unenrolTOTP(t, 2)
		for _, link := range []string{"/org/org3/settings", "/org/org3/settings/hooks", "/org/org3/settings/actions/runners", "/org/org3/teams/new", "/org/org3/members/user4/access"} {
			owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound)
		}
		postOrgTwoFactor(t, owner, "org3", map[string]string{}, http.StatusNotFound)
		for link, form := range map[string]map[string]string{
			"/org/org3/settings/hooks/forgejo/new":     {"payload_url": "http://example.com/hook", "content_type": "1", "events": "push_only", "active": "on"},
			"/org/org3/settings/actions/runners/new":   {"name": "blocked"},
			"/org/org3/teams/new":                      {"team_name": "blocked", "permission": "read"},
			"/org/org3/settings/actions/secrets":       {"name": "BLOCKED", "data": "x"},
			"/org/org3/settings/actions/variables/new": {"name": "BLOCKED", "data": "x"},
		} {
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", link, form), http.StatusNotFound)
		}
		// nor create, fork or migrate into the org on the web
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/repo/create", map[string]string{"uid": "3", "repo_name": "blocked"}), http.StatusForbidden)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/fork", map[string]string{"uid": "3", "repo_name": "blocked"}), http.StatusForbidden)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/repo/migrate", map[string]string{"uid": "3", "repo_name": "blocked", "clone_addr": "https://example.com/a.git", "service": "1"}), http.StatusForbidden)
		unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: 3, LowerName: "blocked"})
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/org3", map[string]string{"full_name": "x"}).AddTokenAuth(ownerToken), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/hooks").AddTokenAuth(ownerToken), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/actions/runners/registration-token").AddTokenAuth(ownerToken), http.StatusForbidden)
		refused := func(method, url string, v any) {
			t.Helper()
			MakeRequest(t, NewRequestWithJSON(t, method, url, v).AddTokenAuth(ownerToken), http.StatusForbidden)
		}
		refused("POST", "/api/v1/orgs/org3/teams", &api.CreateTeamOption{Name: "blocked", Permission: "read"})
		refused("POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: "blocked"})
		refused("POST", "/api/v1/repos/user2/repo1/forks", &api.CreateForkOption{Organization: new("org3")})
		refused("POST", "/api/v1/repos/migrate", &api.MigrateRepoOptions{CloneAddr: "https://example.com/a.git", RepoName: "blocked", RepoOwner: "org3"})
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/teams/1/members").AddTokenAuth(ownerToken), http.StatusOK) // own team
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/teams/7/members").AddTokenAuth(ownerToken), http.StatusForbidden)
		owner.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3"), http.StatusForbidden)
		owner.MakeRequest(t, NewRequest(t, "GET", "/user/settings/security"), http.StatusOK)
		assert.False(t, orgRunListed(t))
		// the owner may no longer write packages, reading the public org's stays
		MakeRequest(t, NewRequestWithBody(t, "PUT", "/api/packages/org3/generic/p/1.1/f.bin", bytes.NewReader([]byte{1})).AddTokenAuth(ownerToken), http.StatusUnauthorized)
		MakeRequest(t, NewRequest(t, "GET", "/api/packages/org3/generic/p/1.0/f.bin").AddTokenAuth(ownerToken), http.StatusOK)
	})

	t.Run("deploy keys are governed by their own key", func(t *testing.T) {
		key, err := asymkey_model.AddDeployKey(ctx, 3, "org-deploy", "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBGXEEzWmm1dxb+57RoK5KVCL0w2eNv9cqJX2AGGVlkFsVDhOXHzsadS3LTK4VlEbbrDMJdoti9yM8vclA8IeRacAAAAEc3NoOg== nocomment", false, 0)
		require.NoError(t, err)
		results, extra := private.ServCommand(ctx, key.KeyID, "org3", "repo3", perm.AccessModeWrite, "", "git-receive-pack")
		require.NoError(t, extra.Error)
		assert.Equal(t, int64(3), results.UserID)
		hook := private.HookPreReceive(ctx, repoIDByName(t, "org3", "repo3"), private.HookOptions{
			OldCommitIDs:   []string{git.Sha1ObjectFormat.EmptyObjectID().String()},
			NewCommitIDs:   []string{"2a47ca4b614a9f5a43abbd5ad851a54a616ffee6"},
			RefFullNames:   []git.RefName{git.RefNameFromBranch("deploy-key")},
			UserID:         results.UserID,
			DeployKeyKeyID: results.DeployKeyKeyID,
		})
		require.NoError(t, hook.Error)
	})

	t.Run("enrolling restores access", func(t *testing.T) {
		enrolTOTP(t, 2)
		enrolTOTP(t, 4)
		memberAccess(t, http.StatusOK)
		for name, listed := range repo3Listed(t) {
			assert.True(t, listed, name)
		}
		assert.True(t, orgRunListed(t))
		owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings"), http.StatusOK)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: "allowed"}).AddTokenAuth(ownerToken), http.StatusCreated)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/forks", &api.CreateForkOption{Organization: new("org3")}).AddTokenAuth(ownerToken), http.StatusAccepted)
	})

	t.Run("turning it off needs no confirmation", func(t *testing.T) {
		postOrgTwoFactor(t, owner, "org3", map[string]string{}, http.StatusSeeOther)
		assert.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).RequireTwoFactor)
	})
}
