// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"strconv"
	"testing"

	auth_model "forgejo.org/models/auth"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// org3's only owner is user2; user4 is a member that the tests make an admin collaborator of each repository.

func setOrgRepoPolicies(t *testing.T, restrict bool, forkPolicy int) {
	t.Helper()
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "org3"})
	org.RestrictRepoVisibilityChange, org.PrivateForkPolicy = restrict, forkPolicy
	require.NoError(t, user_model.UpdateUserCols(t.Context(), org, "restrict_repo_visibility_change", "private_fork_policy"))
}

// orgPolicyRepo creates org3/<name> as user2 and makes user4 an admin collaborator of it.
func orgPolicyRepo(t *testing.T, name string, private bool) *repo_model.Repository {
	t.Helper()
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeAll)
	admin := "admin"
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", &api.CreateRepoOption{Name: name, Private: private, AutoInit: true}).AddTokenAuth(token), http.StatusCreated)
	MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/"+name+"/collaborators/user4", &api.AddCollaboratorOption{Permission: &admin}).AddTokenAuth(token), http.StatusNoContent)
	return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", LowerName: name})
}

func orgPolicyToken(t *testing.T, user string) string {
	t.Helper()
	return getTokenForLoggedInUser(t, loginUser(t, user), auth_model.AccessTokenScopeAll)
}

// assertPolicyRefusedAPI checks a 403 that names the policy.
func assertPolicyRefusedAPI(t *testing.T, req *RequestWrapper, policy string) {
	t.Helper()
	resp := MakeRequest(t, req, http.StatusForbidden)
	var apiErr api.APIError
	DecodeJSON(t, resp, &apiErr)
	assert.Contains(t, apiErr.Message, policy)
}

// assertPolicyRefusedWeb checks that the page shows the translated error that names the policy.
func assertPolicyRefusedWeb(t *testing.T, user, url string, values map[string]string, label string) {
	t.Helper()
	resp := loginUser(t, user).MakeRequest(t, NewRequestWithValues(t, "POST", url, values), http.StatusOK)
	assert.Contains(t, NewHTMLParser(t, resp.Body).Find(".flash-error").Text(), "Blocked by the organization policy \""+label+"\"")
}

const (
	orgPolicyVisibilityLabel = "Only organization owners can change the visibility of repositories"
)

// AC1, AC8: the owner edits the policies on the web and through the API; non-owners can't.
func TestOrgRepoPolicySettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	loginUser(t, "user2").MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings", map[string]string{
		"name":                            "org3",
		"visibility":                      "0",
		"restrict_repo_visibility_change": "on",
		"private_fork_policy":             "2",
	}), http.StatusSeeOther)
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "org3"})
	assert.True(t, org.RestrictRepoVisibilityChange)
	assert.Equal(t, user_model.PrivateForkNone, org.PrivateForkPolicy)

	// an out-of-range fork policy is refused
	loginUser(t, "user2").MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings", map[string]string{
		"name": "org3", "visibility": "0", "private_fork_policy": "3",
	}), http.StatusOK)
	assert.Equal(t, user_model.PrivateForkNone, unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "org3"}).PrivateForkPolicy)

	f, org2 := false, "org"
	req := NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/org3", &api.EditOrgOption{RestrictRepoVisibilityChange: &f, PrivateForkPolicy: &org2}).AddTokenAuth(orgPolicyToken(t, "user2"))
	var apiOrg api.Organization
	DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &apiOrg)
	assert.False(t, apiOrg.RestrictRepoVisibilityChange)
	assert.Equal(t, "org", apiOrg.PrivateForkPolicy)
	org = unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "org3"})
	assert.False(t, org.RestrictRepoVisibilityChange)
	assert.Equal(t, user_model.PrivateForkOrg, org.PrivateForkPolicy)

	bad := "nobody"
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/org3", &api.EditOrgOption{PrivateForkPolicy: &bad}).AddTokenAuth(orgPolicyToken(t, "user2")), http.StatusUnprocessableEntity)

	// user4 is a member, not an owner
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/org3", &api.EditOrgOption{RestrictRepoVisibilityChange: &f}).AddTokenAuth(orgPolicyToken(t, "user4")), http.StatusForbidden)
	loginUser(t, "user4").MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings", map[string]string{
		"name": "org3", "visibility": "0",
	}), http.StatusNotFound)
	assert.Equal(t, user_model.PrivateForkOrg, unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "org3"}).PrivateForkPolicy)
}

// AC3, AC4 (scope change): delete and transfer of an organization repository stay owner-only, as before.
func TestOrgRepoDeleteTransferOwnerOnly(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	repo := orgPolicyRepo(t, "owner-only", false)
	// user28 is in team12, an admin team of org3
	MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/12/repos/org3/owner-only").AddTokenAuth(orgPolicyToken(t, "user2")), http.StatusNoContent)

	for _, user := range []string{"user4", "user28"} {
		session := loginUser(t, user)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/owner-only/settings", map[string]string{"action": "delete", "repo_name": "org3/owner-only"}), http.StatusNotFound)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/owner-only/settings", map[string]string{"action": "transfer", "repo_name": "org3/owner-only", "new_owner_name": user}), http.StatusNotFound)
		token := orgPolicyToken(t, user)
		MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/org3/owner-only").AddTokenAuth(token), http.StatusForbidden)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/owner-only/transfer", &api.TransferRepoOption{NewOwner: user}).AddTokenAuth(token), http.StatusForbidden)
	}
	assert.Equal(t, "org3", unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID}).OwnerName)

	// the owner transfers, a site admin deletes
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/owner-only/transfer", &api.TransferRepoOption{NewOwner: "org6"}).AddTokenAuth(orgPolicyToken(t, "user2")), http.StatusCreated)
	orgPolicyRepo(t, "owner-only2", false)
	loginUser(t, "user1").MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/owner-only2/settings", map[string]string{"action": "delete", "repo_name": "org3/owner-only2"}), http.StatusSeeOther)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/owner-only2").AddTokenAuth(orgPolicyToken(t, "user2")), http.StatusNotFound)
}

// AC11: the repo.private push option follows the visibility policy; deploy keys push as the organization and are refused.
func TestOrgRepoPolicyPushOption(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		setOrgRepoPolicies(t, true, user_model.PrivateForkAll)
		repo := orgPolicyRepo(t, "policy-push", false)
		keys := createProtectionTestDeployKeys(t, APITestContext{Username: "org3", Reponame: "policy-push", Token: orgPolicyToken(t, "user2")})

		preReceive := func(userID, deployKeyKeyID int64, options map[string]string) private.ResponseExtra {
			return private.HookPreReceive(t.Context(), repoIDByName(t, "org3", "policy-push"), private.HookOptions{UserID: userID, DeployKeyKeyID: deployKeyKeyID, GitPushOptions: options})
		}
		toPrivate := map[string]string{"repo.private": "true"}

		refused := preReceive(4, 0, toPrivate)
		assert.Equal(t, http.StatusForbidden, refused.StatusCode)
		assert.Contains(t, refused.UserMsg, "restrict_repo_visibility_change")
		// a deploy key has no permission of the organization it pushes as, so it can't change settings at all
		refused = preReceive(3, keys["listed"].keyID, toPrivate)
		assert.Equal(t, http.StatusForbidden, refused.StatusCode)
		assert.Contains(t, refused.UserMsg, "permission denied for changing repo settings")
		// unchanged visibility and other options pass
		require.NoError(t, preReceive(4, 0, map[string]string{"repo.private": "false", "repo.template": "true"}).Error)
		// the owner and a site admin can
		require.NoError(t, preReceive(2, 0, toPrivate).Error)
		require.NoError(t, preReceive(1, 0, toPrivate).Error)

		// and through a real HTTP push, which changes nothing
		dstPath := t.TempDir()
		u.Path = "org3/policy-push.git"
		u.User = url.UserPassword("user4", userPassword)
		doGitClone(dstPath, u)(t)
		doGitCreateBranch(dstPath, "push-option")(t)
		_, stderr, err := git.NewCommand(git.DefaultContext, "push", "-o", "repo.private=true", "origin", "push-option").RunStdString(&git.RunOpts{Dir: dstPath})
		require.Error(t, err)
		assert.Contains(t, stderr, "restrict_repo_visibility_change")
		assert.False(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID}).IsPrivate)
	})
}

// AC5, AC9: visibility, both directions, and the disabled controls.
func TestOrgRepoPolicyVisibility(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	setOrgRepoPolicies(t, true, user_model.PrivateForkAll)
	private := orgPolicyRepo(t, "policy-private", true)
	public := orgPolicyRepo(t, "policy-public", false)
	token := orgPolicyToken(t, "user4")
	yes, no := true, false

	assertPolicyRefusedWeb(t, "user4", "/org3/policy-private/settings", map[string]string{"action": "update", "repo_name": "policy-private"}, orgPolicyVisibilityLabel)
	assertPolicyRefusedWeb(t, "user4", "/org3/policy-public/settings", map[string]string{"action": "update", "repo_name": "policy-public", "private": "on"}, orgPolicyVisibilityLabel)
	assertPolicyRefusedAPI(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/policy-private", &api.EditRepoOption{Private: &no}).AddTokenAuth(token), "restrict_repo_visibility_change")
	assertPolicyRefusedAPI(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/policy-public", &api.EditRepoOption{Private: &yes}).AddTokenAuth(token), "restrict_repo_visibility_change")
	assert.True(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: private.ID}).IsPrivate)
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: public.ID}).IsPrivate)

	// other settings still change when the visibility doesn't
	desc := "changed"
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/policy-private", &api.EditRepoOption{Description: &desc, Private: &yes}).AddTokenAuth(token), http.StatusOK)
	loginUser(t, "user4").MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/policy-private/settings", map[string]string{"action": "update", "repo_name": "policy-private", "private": "true", "description": "web"}), http.StatusSeeOther)
	assert.Equal(t, "web", unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: private.ID}).Description)

	// the settings page disables the controls, with a note
	doc := NewHTMLParser(t, loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", "/org3/policy-private/settings"), http.StatusOK).Body)
	_, disabled := doc.Find(`input[name="private"][type="checkbox"]`).Attr("disabled")
	assert.True(t, disabled)
	assert.Equal(t, 1, doc.Find(".org-policy-note").Length())

	// the owner and a site admin see no restriction and can change it
	doc = NewHTMLParser(t, loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org3/policy-private/settings"), http.StatusOK).Body)
	assert.Equal(t, 0, doc.Find(".org-policy-note").Length())
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/policy-private", &api.EditRepoOption{Private: &no}).AddTokenAuth(orgPolicyToken(t, "user2")), http.StatusOK)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/policy-private", &api.EditRepoOption{Private: &yes}).AddTokenAuth(orgPolicyToken(t, "user1")), http.StatusOK)

	// policy off: the repo admin can
	setOrgRepoPolicies(t, false, user_model.PrivateForkAll)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/policy-private", &api.EditRepoOption{Private: &no}).AddTokenAuth(token), http.StatusOK)

	// AC7: a user-owned repository is never restricted, even with the flags set on the user's row
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	user2.RestrictRepoVisibilityChange = true
	require.NoError(t, user_model.UpdateUserCols(t.Context(), user2, "restrict_repo_visibility_change"))
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo2", &api.EditRepoOption{Private: &no}).AddTokenAuth(orgPolicyToken(t, "user2")), http.StatusOK)
}

// AC6: forks of private repositories.
func TestOrgRepoPolicyFork(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	private := orgPolicyRepo(t, "policy-fork", true)
	orgPolicyRepo(t, "policy-fork-public", false)
	token := orgPolicyToken(t, "user4")
	user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "user4"})
	forkName := func(s string) *api.CreateForkOption { return &api.CreateForkOption{Name: &s} }
	forkInto := func(org, s string) *api.CreateForkOption { return &api.CreateForkOption{Organization: &org, Name: &s} }
	forkButton := func(user, repo string) bool {
		doc := NewHTMLParser(t, loginUser(t, user).MakeRequest(t, NewRequest(t, "GET", "/org3/"+repo), http.StatusOK).Body)
		return doc.Find(`a[href$="/org3/`+repo+`/fork"]`).Length() > 0
	}
	require.True(t, forkButton("user4", "policy-fork"))

	// only into this organization: not into a personal account, on the web or the API
	setOrgRepoPolicies(t, false, user_model.PrivateForkOrg)
	assertPolicyRefusedAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/policy-fork/forks", forkName("f1")).AddTokenAuth(token), "private_fork_policy")
	// the web can't fork into the owner, so no target is left: the page and the post say so, and the button is gone
	assert.False(t, forkButton("user4", "policy-fork"))
	resp := loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", "/org3/policy-fork/fork"), http.StatusOK)
	assert.Contains(t, resp.Body.String(), "there are no valid owners")
	resp = loginUser(t, "user4").MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/policy-fork/fork", map[string]string{"uid": strconv.FormatInt(user4.ID, 10), "repo_name": "f1"}), http.StatusOK)
	assert.Contains(t, resp.Body.String(), "there are no valid owners")
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: user4.ID, LowerName: "f1"})
	// the API forks into the organization under a new name
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/policy-fork/forks", forkInto("org3", "policy-fork-in-org")).AddTokenAuth(orgPolicyToken(t, "user2")), http.StatusAccepted)
	unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", LowerName: "policy-fork-in-org", ForkID: private.ID})

	// none: owners included, site admins excepted; public repositories are never restricted
	setOrgRepoPolicies(t, false, user_model.PrivateForkNone)
	assertPolicyRefusedAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/policy-fork/forks", forkInto("org3", "f2")).AddTokenAuth(orgPolicyToken(t, "user2")), "private_fork_policy")
	assertPolicyRefusedAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/policy-fork/forks", forkName("f2")).AddTokenAuth(orgPolicyToken(t, "user2")), "private_fork_policy")
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/policy-fork/forks", forkName("admin-fork")).AddTokenAuth(orgPolicyToken(t, "user1")), http.StatusAccepted)
	assert.True(t, forkButton("user4", "policy-fork-public"))
	MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/policy-fork-public/forks", forkName("public-fork")).AddTokenAuth(token), http.StatusAccepted)

	// all: as today
	setOrgRepoPolicies(t, false, user_model.PrivateForkAll)
	testRepoFork(t, loginUser(t, "user4"), "org3", "policy-fork", "user4", "f3")
}

// The policies add no query to the repository page or its settings page while they allow the action.
func TestOrgRepoPolicyQueryCount(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	orgPolicyRepo(t, "policy-count", false)
	session := loginUser(t, "user4")
	count := func() (page, settings int64) {
		page = stableQueryCount(t, func() { session.MakeRequest(t, NewRequest(t, "GET", "/org3/policy-count"), http.StatusOK) })
		settings = stableQueryCount(t, func() { session.MakeRequest(t, NewRequest(t, "GET", "/org3/policy-count/settings"), http.StatusOK) })
		return page, settings
	}
	count() // warm up
	page, settings := count()
	// a public repository and policies that only bind private forks
	setOrgRepoPolicies(t, false, user_model.PrivateForkNone)
	page2, settings2 := count()
	assert.Equal(t, page, page2, "repository page")
	assert.Equal(t, settings, settings2, "settings page")
}

// #148 PR 2: the site floor in [repository] is the stricter of site and org, and an org owner can't loosen it.
func TestOrgRepoPolicySiteFloor(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	orgPolicyRepo(t, "floor-private", true)
	orgPolicyRepo(t, "floor-public", false)
	member, owner := orgPolicyToken(t, "user4"), orgPolicyToken(t, "user2")
	yes, no, all, none, org3 := true, false, "all", "none", "org3"
	storedOrg := func() *user_model.User { return unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "org3"}) }
	postSettings := func(values map[string]string) {
		values["name"], values["visibility"] = "org3", "0"
		loginUser(t, "user2").MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings", values), http.StatusSeeOther)
	}

	t.Run("visibility", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Repository.OrgRestrictVisibilityChange, true)()
		setOrgRepoPolicies(t, false, user_model.PrivateForkAll)

		// the org setting is off, the floor binds the repo admin on every path; the owner and a site admin pass
		assertPolicyRefusedAPI(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/floor-private", &api.EditRepoOption{Private: &no}).AddTokenAuth(member), "restrict_repo_visibility_change")
		assertPolicyRefusedWeb(t, "user4", "/org3/floor-public/settings", map[string]string{"action": "update", "repo_name": "floor-public", "private": "on"}, orgPolicyVisibilityLabel)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/floor-private", &api.EditRepoOption{Private: &no}).AddTokenAuth(owner), http.StatusOK)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/floor-private", &api.EditRepoOption{Private: &yes}).AddTokenAuth(orgPolicyToken(t, "user1")), http.StatusOK)

		// the API shows the effective value, and loosening it is a 422 that applies nothing
		var apiOrg api.Organization
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3").AddTokenAuth(owner), http.StatusOK), &apiOrg)
		assert.True(t, apiOrg.RestrictRepoVisibilityChange)
		desc := "floor description"
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/org3", &api.EditOrgOption{RestrictRepoVisibilityChange: &no, Description: &desc}).AddTokenAuth(owner), http.StatusUnprocessableEntity)
		assert.NotEqual(t, desc, storedOrg().Description)
		// a site admin passes the gate itself, but the API refuses to loosen the floor for them too
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/org3", &api.EditOrgOption{RestrictRepoVisibilityChange: &no}).AddTokenAuth(orgPolicyToken(t, "user1")), http.StatusUnprocessableEntity)
		// the same value as the floor is fine
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/org3", &api.EditOrgOption{RestrictRepoVisibilityChange: &yes, Description: &desc}).AddTokenAuth(owner), http.StatusOK)
		assert.Equal(t, desc, storedOrg().Description)

		// the settings page shows the checkbox on and disabled, with a note; the post keeps the stored value
		setOrgRepoPolicies(t, false, user_model.PrivateForkAll)
		doc := NewHTMLParser(t, loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings"), http.StatusOK).Body)
		box := doc.Find(`input[name="restrict_repo_visibility_change"]`)
		_, disabled := box.Attr("disabled")
		_, checked := box.Attr("checked")
		assert.True(t, disabled)
		assert.True(t, checked)
		assert.Equal(t, 1, doc.Find(".site-policy-floor").Length())
		setOrgRepoPolicies(t, true, user_model.PrivateForkAll)
		postSettings(map[string]string{})
		assert.True(t, storedOrg().RestrictRepoVisibilityChange)
	})

	t.Run("floor off: an owner can untick", func(t *testing.T) {
		setOrgRepoPolicies(t, true, user_model.PrivateForkAll)
		postSettings(map[string]string{})
		assert.False(t, storedOrg().RestrictRepoVisibilityChange)
		doc := NewHTMLParser(t, loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings"), http.StatusOK).Body)
		_, disabled := doc.Find(`input[name="restrict_repo_visibility_change"]`).Attr("disabled")
		assert.False(t, disabled)
		assert.Equal(t, 0, doc.Find(".site-policy-floor").Length())
	})

	t.Run("private forks", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Repository.OrgPrivateForkPolicy, user_model.PrivateForkNone)()
		setOrgRepoPolicies(t, false, user_model.PrivateForkAll)
		fork := func(s string) *api.CreateForkOption { return &api.CreateForkOption{Name: &s} }

		for _, tok := range []string{member, owner} {
			assertPolicyRefusedAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/floor-private/forks", fork("floor-fork")).AddTokenAuth(tok), "private_fork_policy")
		}
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/floor-public/forks", fork("floor-public-fork")).AddTokenAuth(member), http.StatusAccepted)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/floor-private/forks", fork("floor-admin-fork")).AddTokenAuth(orgPolicyToken(t, "user1")), http.StatusAccepted)

		// the API shows the effective policy; loosening it, even alongside a value that is allowed, is a 422 that applies nothing
		var apiOrg api.Organization
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3").AddTokenAuth(owner), http.StatusOK), &apiOrg)
		assert.Equal(t, "none", apiOrg.PrivateForkPolicy)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/org3", &api.EditOrgOption{RestrictRepoVisibilityChange: &yes, PrivateForkPolicy: &all}).AddTokenAuth(owner), http.StatusUnprocessableEntity)
		assert.False(t, storedOrg().RestrictRepoVisibilityChange)
		assert.Equal(t, user_model.PrivateForkAll, storedOrg().PrivateForkPolicy)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/org3", &api.EditOrgOption{PrivateForkPolicy: &none}).AddTokenAuth(owner), http.StatusOK)

		// the select keeps the options below the floor disabled, with the effective one selected
		doc := NewHTMLParser(t, loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings"), http.StatusOK).Body)
		assert.Equal(t, "2", doc.Find(`select[name="private_fork_policy"] option[selected]`).AttrOr("value", ""))
		_, lowDisabled := doc.Find(`select[name="private_fork_policy"] option[value="0"]`).Attr("disabled")
		_, floorDisabled := doc.Find(`select[name="private_fork_policy"] option[value="2"]`).Attr("disabled")
		assert.True(t, lowDisabled)
		assert.False(t, floorDisabled)
	})

	t.Run("fork floor org", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Repository.OrgPrivateForkPolicy, user_model.PrivateForkOrg)()
		setOrgRepoPolicies(t, false, user_model.PrivateForkAll)
		fork := func(s string) *api.CreateForkOption { return &api.CreateForkOption{Name: &s} }
		inOrg := func(s string) *api.CreateForkOption { return &api.CreateForkOption{Organization: &org3, Name: &s} }

		// into a user is refused, into the organization is allowed
		assertPolicyRefusedAPI(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/floor-private/forks", fork("floor-org-user")).AddTokenAuth(member), "private_fork_policy")
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/floor-private/forks", inOrg("floor-org-fork")).AddTokenAuth(owner), http.StatusAccepted)
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", LowerName: "floor-org-fork"})
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/floor-public/forks", fork("floor-org-public")).AddTokenAuth(owner), http.StatusAccepted)

		// the web form stores a value below the floor as the floor
		postSettings(map[string]string{"private_fork_policy": "0"})
		assert.Equal(t, user_model.PrivateForkOrg, storedOrg().PrivateForkPolicy)
		postSettings(map[string]string{"private_fork_policy": "2"})
		assert.Equal(t, user_model.PrivateForkNone, storedOrg().PrivateForkPolicy)
	})
}

// #148 PR 2: the repo.private push option follows the visibility floor (hook level; SSH can't run here).
func TestOrgRepoPolicySiteFloorPushOption(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.Repository.OrgRestrictVisibilityChange, true)()
	setOrgRepoPolicies(t, false, user_model.PrivateForkAll)
	orgPolicyRepo(t, "floor-push", false)
	preReceive := func(userID int64, options map[string]string) private.ResponseExtra {
		return private.HookPreReceive(t.Context(), repoIDByName(t, "org3", "floor-push"), private.HookOptions{UserID: userID, GitPushOptions: options})
	}
	toPrivate := map[string]string{"repo.private": "true"}

	refused := preReceive(4, toPrivate)
	assert.Equal(t, http.StatusForbidden, refused.StatusCode)
	assert.Contains(t, refused.UserMsg, "restrict_repo_visibility_change")
	require.NoError(t, preReceive(4, map[string]string{"repo.private": "false"}).Error) // unchanged
	require.NoError(t, preReceive(2, toPrivate).Error)                                  // owner
	require.NoError(t, preReceive(1, toPrivate).Error)                                  // site admin
}
