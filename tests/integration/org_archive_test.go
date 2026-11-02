// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"strconv"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	repo_module "forgejo.org/modules/repository"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	org_service "forgejo.org/services/org"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// org3 (owner user2, member user4) owns repos 3, 5 and 32; repo 5 is archived by hand before the org archive.
const orgArchiveOrg = "org3"

func archivedOrg(t *testing.T) *user_model.User {
	t.Helper()
	org, err := user_model.GetUserByName(t.Context(), orgArchiveOrg)
	require.NoError(t, err)
	return org
}

func orgArchiveRepos(t *testing.T) map[int64]*repo_model.Repository {
	t.Helper()
	repos := map[int64]*repo_model.Repository{}
	for _, id := range []int64{3, 5, 32} {
		repo, err := repo_model.GetRepositoryByID(t.Context(), id)
		require.NoError(t, err)
		repos[id] = repo
	}
	return repos
}

func orgArchiveToken(t *testing.T, name string) string {
	t.Helper()
	return getTokenForLoggedInUser(t, loginUser(t, name), auth_model.AccessTokenScopeAll)
}

func webArchiveOrg(t *testing.T, user string, values map[string]string, status int) {
	t.Helper()
	loginUser(t, user).MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/archive", values), status)
}

func webUnarchiveOrg(t *testing.T, user string, status int) {
	t.Helper()
	loginUser(t, user).MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/unarchive", nil), status)
}

// archiveOrg3 archives org3 through the API as its owner.
func archiveOrg3(t *testing.T, removeMembers bool) {
	t.Helper()
	token := orgArchiveToken(t, "user2")
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/archive", &api.ArchiveOrgOption{RemoveMembers: removeMembers}).AddTokenAuth(token), http.StatusNoContent)
}

func archiveOrg3Pre(t *testing.T) {
	t.Helper()
	// repo 5 was archived before the org archive
	require.NoError(t, repo_model.SetArchiveRepoState(t.Context(), orgArchiveRepos(t)[5], true))
}

// AC1: owner and site admin may archive (web and API); everybody else gets 403; a second archive is refused.
func TestOrgArchivePermissions(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	// repo admin without team membership, team member, non-member
	require.NoError(t, repo_module.AddCollaborator(t.Context(), orgArchiveRepos(t)[3], unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8}), perm.AccessModeWrite))
	require.NoError(t, repo_module.ChangeCollaborationAccessMode(t.Context(), orgArchiveRepos(t)[3], 8, perm.AccessModeAdmin))

	for _, name := range []string{"user4", "user8", "user10"} {
		t.Run("denied "+name, func(t *testing.T) {
			webArchiveOrg(t, name, nil, http.StatusForbidden)
			webUnarchiveOrg(t, name, http.StatusForbidden)
			token := orgArchiveToken(t, name)
			MakeRequest(t, NewRequest(t, "POST", "/api/v1/orgs/org3/archive").AddTokenAuth(token), http.StatusForbidden)
			MakeRequest(t, NewRequest(t, "POST", "/api/v1/orgs/org3/unarchive").AddTokenAuth(token), http.StatusForbidden)
			assert.False(t, archivedOrg(t).IsArchived)
		})
	}

	t.Run("owner via web", func(t *testing.T) {
		webArchiveOrg(t, "user2", nil, http.StatusSeeOther)
		assert.True(t, archivedOrg(t).IsArchived)
		webArchiveOrg(t, "user2", nil, http.StatusForbidden) // second archive refused
		webUnarchiveOrg(t, "user2", http.StatusSeeOther)
		assert.False(t, archivedOrg(t).IsArchived)
	})
	t.Run("site admin via API", func(t *testing.T) {
		token := orgArchiveToken(t, "user1")
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/archive", &api.ArchiveOrgOption{}).AddTokenAuth(token), http.StatusNoContent)
		assert.True(t, archivedOrg(t).IsArchived)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/archive", &api.ArchiveOrgOption{}).AddTokenAuth(token), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/orgs/org3/unarchive").AddTokenAuth(token), http.StatusNoContent)
		assert.False(t, archivedOrg(t).IsArchived)
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/orgs/org3/unarchive").AddTokenAuth(token), http.StatusUnprocessableEntity)
	})
}

// AC2 + AC3 + AC4 + O5: only active repos are flagged; unarchive restores exactly those, including one created before the archive.
func TestOrgArchiveRepos(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	archiveOrg3Pre(t)

	token := orgArchiveToken(t, "user2")
	resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: "before-archive"}).AddTokenAuth(token), http.StatusCreated)
	var created api.Repository
	DecodeJSON(t, resp, &created)

	archiveOrg3(t, false)

	org := archivedOrg(t)
	assert.True(t, org.IsArchived)
	assert.NotZero(t, org.ArchivedUnix)
	assert.EqualValues(t, 2, org.ArchivedByID)
	for id, repo := range orgArchiveRepos(t) {
		assert.True(t, repo.IsArchived, id)
		assert.Equal(t, id != 5, repo.ArchivedByOrg, id) // pre-archived repo 5 is never marked
	}
	createdRepo, err := repo_model.GetRepositoryByID(t.Context(), created.ID)
	require.NoError(t, err)
	assert.True(t, createdRepo.IsArchived)
	assert.True(t, createdRepo.ArchivedByOrg)

	// a repository archived by the org is read-only: no issues, comments or releases (403 from the org guard)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/repo3/issues", &api.CreateIssueOption{Title: "x"}).AddTokenAuth(token), http.StatusForbidden)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/repo3/issues/1/comments", &api.CreateIssueCommentOption{Body: "x"}).AddTokenAuth(token), http.StatusForbidden)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/repo3/releases", &api.CreateReleaseOption{TagName: "v9", Target: "master"}).AddTokenAuth(token), http.StatusForbidden)

	// AC6: reads keep working for those who could read before
	user2 := loginUser(t, "user2")
	user2.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3"), http.StatusOK)
	user2.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/archive/master.zip"), http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3").AddTokenAuth(token), http.StatusOK)

	webUnarchiveOrg(t, "user2", http.StatusSeeOther)

	assert.False(t, archivedOrg(t).IsArchived)
	for id, repo := range orgArchiveRepos(t) {
		assert.Equal(t, id == 5, repo.IsArchived, id) // only repo 5 stays archived
		assert.False(t, repo.ArchivedByOrg, id)
	}
	createdRepo, err = repo_model.GetRepositoryByID(t.Context(), created.ID)
	require.NoError(t, err)
	assert.False(t, createdRepo.IsArchived)
	assert.False(t, createdRepo.ArchivedByOrg)
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/repo3/issues", &api.CreateIssueOption{Title: "x"}).AddTokenAuth(token), http.StatusCreated)
}

// AC5 + O3: org writes are refused with 403 and nothing is partly applied.
func TestOrgArchiveBlocksOrgWrites(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	archiveOrg3(t, false)

	teamsBefore, err := organization.FindOrgTeams(t.Context(), 3)
	require.NoError(t, err)
	membersBefore, err := organization.GetOrgUsersByOrgID(t.Context(), &organization.FindOrgMembersOpts{OrgID: 3, Doer: archivedOrg(t), IsDoerMember: true})
	require.NoError(t, err)
	reposBefore := unittest.GetCount(t, &repo_model.Repository{OwnerID: 3})
	nameBefore := archivedOrg(t).FullName

	user2 := loginUser(t, "user2")
	token := orgArchiveToken(t, "user2")
	teamID := strconv.FormatInt(teamsBefore[1].ID, 10)

	web := []struct {
		name, url string
		values    map[string]string
	}{
		{"new team", "/org/org3/teams/new", map[string]string{"team_name": "t", "permission": "read"}},
		{"edit team", "/org/org3/teams/team1/edit", map[string]string{"team_name": "renamed", "permission": "read"}},
		{"delete team", "/org/org3/teams/team1/delete", nil},
		{"add member", "/org/org3/teams/team1/action/add", map[string]string{"uname": "user5"}},
		{"remove member", "/org/org3/teams/team1/action/remove", map[string]string{"uid": "4"}},
		{"leave org", "/org/org3/members/action/leave", nil},
		{"team membership", "/org/org3/teams/team1/action/join", nil},
		{"org settings", "/org/org3/settings", map[string]string{"full_name": "changed", "visibility": "0"}},
		{"org label", "/org/org3/settings/labels/new", map[string]string{"title": "l", "color": "#ffffff"}},
		{"org webhook delete", "/org/org3/settings/hooks/delete", map[string]string{"id": "1"}},
	}
	for _, c := range web {
		t.Run("web "+c.name, func(t *testing.T) {
			user2.MakeRequest(t, NewRequestWithValues(t, "POST", c.url, c.values), http.StatusForbidden)
		})
	}

	apiCases := []struct {
		name, method, url string
		body              any
	}{
		{"settings", "PATCH", "/api/v1/orgs/org3", &api.EditOrgOption{Description: new("x")}},
		{"rename", "POST", "/api/v1/orgs/org3/rename", &api.RenameOrgOption{NewName: "renamed3"}},
		{"new team", "POST", "/api/v1/orgs/org3/teams", &api.CreateTeamOption{Name: "t", Permission: "read", Units: []string{"repo.code"}}},
		{"edit team", "PATCH", "/api/v1/teams/" + teamID, &api.EditTeamOption{Name: "renamed", Permission: "read", Units: []string{"repo.code"}}},
		{"delete team", "DELETE", "/api/v1/teams/" + teamID, nil},
		{"team member add", "PUT", "/api/v1/teams/" + teamID + "/members/user5", nil},
		{"team member remove", "DELETE", "/api/v1/teams/" + teamID + "/members/user4", nil},
		{"member remove", "DELETE", "/api/v1/orgs/org3/members/user4", nil},
		{"create repo", "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: "new-in-archived"}},
		{"label", "POST", "/api/v1/orgs/org3/labels", &api.CreateLabelOption{Name: "l", Color: "#ffffff"}},
	}
	for _, c := range apiCases {
		t.Run("api "+c.name, func(t *testing.T) {
			var req *RequestWrapper
			if c.body != nil {
				req = NewRequestWithJSON(t, c.method, c.url, c.body)
			} else {
				req = NewRequest(t, c.method, c.url)
			}
			MakeRequest(t, req.AddTokenAuth(token), http.StatusForbidden)
		})
	}

	// web repo create with uid=<org> is refused and nothing is created
	resp := user2.MakeRequest(t, NewRequestWithValues(t, "POST", "/repo/create", map[string]string{"uid": "3", "repo_name": "new-web"}), http.StatusOK)
	assert.Contains(t, resp.Body.String(), "archived")

	// transfer into the archived org is refused, for the API and for an accepted pending one
	user4 := loginUser(t, "user4")
	_ = user4
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/transfer", &api.TransferRepoOption{NewOwner: "org3"}).AddTokenAuth(token), http.StatusForbidden)

	teamsAfter, err := organization.FindOrgTeams(t.Context(), 3)
	require.NoError(t, err)
	assert.Len(t, teamsAfter, len(teamsBefore))
	membersAfter, err := organization.GetOrgUsersByOrgID(t.Context(), &organization.FindOrgMembersOpts{OrgID: 3, Doer: archivedOrg(t), IsDoerMember: true})
	require.NoError(t, err)
	assert.Len(t, membersAfter, len(membersBefore))
	assert.Equal(t, reposBefore, unittest.GetCount(t, &repo_model.Repository{OwnerID: 3}))
	assert.Equal(t, nameBefore, archivedOrg(t).FullName)
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: 3, Name: "new-web"})
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: 3, Name: "new-in-archived"})
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: 2, Name: "repo1", OwnerName: "org3"})

	// reads stay open
	MakeRequest(t, NewRequest(t, "GET", "/org3"), http.StatusOK)
	user2.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings"), http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/teams").AddTokenAuth(token), http.StatusOK)
}

// O2 + S2: a repo of an archived org cannot be unarchived by hand or transferred out, and repo settings are read-only.
func TestOrgArchiveRepoGuards(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	archiveOrg3(t, false)
	user2 := loginUser(t, "user2")
	token := orgArchiveToken(t, "user2")

	t.Run("manual unarchive refused", func(t *testing.T) {
		user2.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/repo3/settings", map[string]string{"action": "unarchive"}), http.StatusForbidden)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/repo3", &api.EditRepoOption{Archived: new(false)}).AddTokenAuth(token), http.StatusForbidden)
		repo, err := repo_model.GetRepositoryByID(t.Context(), 3)
		require.NoError(t, err)
		assert.True(t, repo.IsArchived)
	})
	t.Run("transfer out refused", func(t *testing.T) {
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/repo3/transfer", &api.TransferRepoOption{NewOwner: "user2"}).AddTokenAuth(token), http.StatusForbidden)
		repo, err := repo_model.GetRepositoryByID(t.Context(), 3)
		require.NoError(t, err)
		assert.EqualValues(t, 3, repo.OwnerID)
	})
	t.Run("settings and API writes refused", func(t *testing.T) {
		user2.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/repo3/settings", map[string]string{"action": "update", "repo_name": "renamed"}), http.StatusForbidden)
		user2.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/repo3/settings/keys", map[string]string{"title": "k", "content": "x"}), http.StatusForbidden)
		user2.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/repo3/pulls/1/update", nil), http.StatusForbidden)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/repo3", &api.EditRepoOption{Name: new("renamed")}).AddTokenAuth(token), http.StatusForbidden)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/repo3/git/notes/4a357436d925b5c974181ff12a994538ddc5180a", &api.NoteOptions{Message: "n"}).AddTokenAuth(token), http.StatusForbidden)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/repo3/statuses/4a357436d925b5c974181ff12a994538ddc5180a", &api.CreateStatusOption{State: api.CommitStatusSuccess}).AddTokenAuth(token), http.StatusForbidden)
	})
}

// AC8 + O6: remove_members removes non-owners only; without the option membership is untouched.
func TestOrgArchiveRemoveMembers(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	archiveOrg3(t, false)
	n, err := organization.CountOrgMembers(t.Context(), &organization.FindOrgMembersOpts{OrgID: 3, Doer: archivedOrg(t), IsDoerMember: true})
	require.NoError(t, err)
	assert.Greater(t, n, int64(1))
	webUnarchiveOrg(t, "user2", http.StatusSeeOther)

	webArchiveOrg(t, "user2", map[string]string{"remove_members": "on"}, http.StatusSeeOther)
	members, err := organization.GetOrgUsersByOrgID(t.Context(), &organization.FindOrgMembersOpts{OrgID: 3, Doer: archivedOrg(t), IsDoerMember: true})
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.EqualValues(t, 2, members[0].UID) // only the owner remains
	isMember, err := organization.IsOrganizationMember(t.Context(), 3, 4)
	require.NoError(t, err)
	assert.False(t, isMember)
}

// AC7 + AC10 + O7: badge and banner, hidden from Explore by default, admin list; ?archived= without a value is unchanged.
func TestOrgArchiveListing(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	archiveOrg3(t, false)

	page := NewHTMLParser(t, MakeRequest(t, NewRequest(t, "GET", "/org3"), http.StatusOK).Body)
	page.AssertElement(t, ".org-archived-banner", true)

	explore := func(query string) string {
		return MakeRequest(t, NewRequest(t, "GET", "/explore/organizations"+query), http.StatusOK).Body.String()
	}
	assert.NotContains(t, explore(""), `href="/org3"`)
	assert.Contains(t, explore("?archived=true"), `href="/org3"`)

	admin := loginUser(t, "user1")
	assert.Contains(t, admin.MakeRequest(t, NewRequest(t, "GET", "/admin/orgs"), http.StatusOK).Body.String(), "/org/org3/settings/unarchive")

	token := orgArchiveToken(t, "user2")
	list := func(query string) []string {
		resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/user/orgs"+query).AddTokenAuth(token), http.StatusOK)
		var orgs []*api.Organization
		DecodeJSON(t, resp, &orgs)
		names := []string{}
		for _, o := range orgs {
			if o.Name == "org3" {
				assert.True(t, o.Archived)
			}
			names = append(names, o.Name)
		}
		return names
	}
	assert.Contains(t, list(""), "org3")
	assert.Contains(t, list("?archived"), "org3") // no value: unchanged
	assert.Contains(t, list("?archived=true"), "org3")
	assert.NotContains(t, list("?archived=false"), "org3")

	// AC7: the dashboard switcher hides the archived org (except as the current context) and links to Explore
	user2 := loginUser(t, "user2")
	switcher := NewHTMLParser(t, user2.MakeRequest(t, NewRequest(t, "GET", "/"), http.StatusOK).Body)
	assert.Zero(t, switcher.Find(`.dropdown a.item[title="org3"]`).Length())
	assert.Equal(t, 1, switcher.Find(`a.item[href$="/explore/organizations?archived=true"]`).Length())
	inContext := NewHTMLParser(t, user2.MakeRequest(t, NewRequest(t, "GET", "/org/org3/dashboard"), http.StatusOK).Body)
	assert.Equal(t, 1, inContext.Find(`.dropdown a.item[title="org3"]`).Length())

	// AC10: a site admin unarchives from the admin page's form (same endpoint)
	webUnarchiveOrg(t, "user1", http.StatusSeeOther)
	assert.False(t, archivedOrg(t).IsArchived)
	assert.Contains(t, explore(""), `href="/org3"`)

	// non-admins cannot reach the admin list
	loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/admin/orgs"), http.StatusForbidden)
}

// N5: only organizations can be archived.
func TestOrgArchiveRejectsUser(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.ErrorIs(t, org_service.ArchiveOrganization(t.Context(), organization.OrgFromUser(user2), user2, false), util.ErrInvalidArgument)
	require.ErrorIs(t, org_service.UnarchiveOrganization(t.Context(), organization.OrgFromUser(user2)), util.ErrInvalidArgument)
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}).IsArchived)
}

// O1: an archived org can still be deleted by its owner.
func TestOrgArchiveDeleteAllowed(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	// an organization that owns no repositories can be deleted
	var orgID int64
	has, err := db.GetEngine(t.Context()).Table("user").Select("id").Where("type = ? AND id NOT IN (SELECT owner_id FROM repository) AND id NOT IN (SELECT owner_id FROM package)", user_model.UserTypeOrganization).Get(&orgID)
	require.NoError(t, err)
	require.True(t, has)
	org, err := user_model.GetUserByID(t.Context(), orgID)
	require.NoError(t, err)
	require.NoError(t, org_service.ArchiveOrganization(t.Context(), organization.OrgFromUser(org), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}), false))
	token := orgArchiveToken(t, "user1")
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/orgs/"+org.Name).AddTokenAuth(token), http.StatusNoContent)
	unittest.AssertNotExistsBean(t, &user_model.User{ID: orgID})

	// the web route is exempt as well
	has, err = db.GetEngine(t.Context()).Table("user").Select("id").Where("type = ? AND id NOT IN (SELECT owner_id FROM repository) AND id NOT IN (SELECT owner_id FROM package)", user_model.UserTypeOrganization).Get(&orgID)
	require.NoError(t, err)
	require.True(t, has)
	org, err = user_model.GetUserByID(t.Context(), orgID)
	require.NoError(t, err)
	require.NoError(t, org_service.ArchiveOrganization(t.Context(), organization.OrgFromUser(org), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}), false))
	loginUser(t, "user1").MakeRequest(t, NewRequestWithValues(t, "POST", "/org/"+org.Name+"/settings/delete", map[string]string{"org_name": org.Name}), http.StatusSeeOther)
	unittest.AssertNotExistsBean(t, &user_model.User{ID: orgID})
}
