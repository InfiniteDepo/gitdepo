// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// apiResponse is the status, headers (without the date) and body of an API response.
func apiResponse(t *testing.T, method, path, token string) string {
	t.Helper()
	req := NewRequest(t, method, path)
	if method == "POST" {
		req = NewRequestWithJSON(t, method, path, &api.CreateIssueOption{Title: "x"})
	}
	if token != "" {
		req.AddTokenAuth(token)
	}
	resp := MakeRequest(t, req, NoExpectedStatus)
	header := resp.Header().Clone()
	header.Del("Date")
	return fmt.Sprintf("%d\n%v\n%s", resp.Code, header, resp.Body.String())
}

func TestAPIRepoGroupAddressing(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f, rootPub := prepareRepoGroupGit(t)
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteIssue, auth_model.AccessTokenScopeWriteUser)

	t.Run("project form", func(t *testing.T) {
		var repo api.Repository
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/PROJ/Priv/-").AddTokenAuth(token), http.StatusOK), &repo)
		assert.Equal(t, f.priv.ID, repo.ID)
		assert.Equal(t, "org3/proj/priv", repo.FullName)
		assert.Equal(t, "priv", repo.Name)
		require.NotNil(t, repo.Project)
		assert.Equal(t, api.ProjectMeta{ID: f.priv.GroupID, Name: "proj", FullName: "org3/proj", HTMLURL: setting.AppURL + "org3/proj"}, *repo.Project)
		assert.Equal(t, setting.AppURL+"api/v1/repos/org3/proj/priv/-", repo.URL)

		// the API URL of the repository works
		var again api.Repository
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", repo.URL).AddTokenAuth(token), http.StatusOK), &again)
		assert.Equal(t, repo.ID, again.ID)

		var issue api.Issue
		DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/proj/priv/-/issues", &api.CreateIssueOption{Title: "in a project"}).AddTokenAuth(token), http.StatusCreated), &issue)
		assert.Equal(t, "org3/proj/priv", issue.Repo.FullName)
		MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/org3/proj/priv/-/issues/%d", issue.Index)).AddTokenAuth(token), http.StatusOK)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/proj/priv/-/contents/README.md").AddTokenAuth(token), http.StatusOK)

		description := "changed by the API"
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/proj/priv/-", &api.EditRepoOption{Description: &description}).AddTokenAuth(token), http.StatusOK)
		assert.Equal(t, description, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: f.priv.ID}).Description)

		// the same writes by ID
		byID := fmt.Sprintf("/api/v1/repositories/%d", f.priv.ID)
		description = "changed by ID"
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", byID, &api.EditRepoOption{Description: &description}).AddTokenAuth(token), http.StatusOK)
		assert.Equal(t, apiResponse(t, "GET", "/api/v1/repos/org3/proj/priv/-", token), apiResponse(t, "GET", byID, token))
		assert.Equal(t, description, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: f.priv.ID}).Description)
		var issueByID api.Issue
		DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", byID+"/issues", &api.CreateIssueOption{Title: "by ID"}).AddTokenAuth(token), http.StatusCreated), &issueByID)
		assert.Equal(t, issue.Repo, issueByID.Repo)
		assert.Equal(t, issue.Index+1, issueByID.Index)

		MakeRequest(t, NewRequest(t, "PUT", "/api/v1/user/starred/org3/proj/pub/-").AddTokenAuth(token), http.StatusNoContent)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/user/starred/org3/proj/pub/-").AddTokenAuth(token), http.StatusNoContent)
	})

	t.Run("root form finds only root repositories", func(t *testing.T) {
		var repo api.Repository
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/pub").AddTokenAuth(token), http.StatusOK), &repo)
		assert.Equal(t, rootPub.ID, repo.ID)
		assert.Nil(t, repo.Project)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/priv").AddTokenAuth(token), http.StatusNotFound)
	})

	t.Run("by ID", func(t *testing.T) {
		for _, id := range []int64{f.priv.ID, rootPub.ID} {
			var repo api.Repository
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repositories/%d", id)).AddTokenAuth(token), http.StatusOK), &repo)
			assert.Equal(t, id, repo.ID)
			MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repositories/%d/issues", id)).AddTokenAuth(token), http.StatusOK)
		}
		// anonymous reads of a public repository, as by name
		MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repositories/%d", f.pub.ID)), http.StatusOK)
		MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repositories/%d", f.priv.ID)), http.StatusNotFound)

		defer test.MockVariableValue(&setting.Service.RequireSignInView, true)()
		assert.Equal(t, apiResponse(t, "GET", "/api/v1/repos/org3/pub", ""), apiResponse(t, "GET", fmt.Sprintf("/api/v1/repositories/%d", f.pub.ID), ""))
		assert.Equal(t, apiResponse(t, "GET", "/api/v1/repos/org3/pub", ""), apiResponse(t, "GET", "/api/v1/repos/org3/proj/pub/-", ""))
		MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repositories/%d", f.pub.ID)), http.StatusForbidden)
	})

	t.Run("leaf named like a route", func(t *testing.T) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		issues, err := repo_service.CreateRepository(db.DefaultContext, user2, f.org, repo_service.CreateRepoOptions{Name: "issues", GroupID: f.pub.GroupID})
		require.NoError(t, err)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/proj/issues/-").AddTokenAuth(token), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/repositories/%d", issues.ID)).AddTokenAuth(token), http.StatusOK)
	})
}

// A repository the viewer can't see answers exactly like one that doesn't exist, in the project form and by ID.
func TestAPIRepoGroupHiddenIsMissing(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := prepareRepoGroupWeb(t)
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	trashed, err := repo_service.CreateRepository(db.DefaultContext, user2, f.org, repo_service.CreateRepoOptions{Name: "gone", GroupID: f.pub.GroupID})
	require.NoError(t, err)
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = ?", trashed.ID)
	require.NoError(t, err)

	user5Token := getTokenForLoggedInUser(t, loginUser(t, "user5"), auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteIssue, auth_model.AccessTokenScopeReadOrganization)
	publicOnly := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteIssue, auth_model.AccessTokenScopeReadOrganization)
	specific := createFineGrainedRepoAccessToken(t, "user2", []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteIssue, auth_model.AccessTokenScopeReadOrganization}, []int64{f.priv.ID})

	for _, viewer := range []struct{ name, token string }{{"anonymous", ""}, {"non-member", user5Token}, {"public-only", publicOnly}, {"specific repos", specific}} {
		t.Run(viewer.name, func(t *testing.T) {
			for _, rest := range []string{"", "/issues"} {
				for _, method := range []string{"GET", "POST"} {
					if method == "POST" && rest == "" {
						continue
					}
					missing := apiResponse(t, method, "/api/v1/repos/org3/proj/nosuch/-"+rest, viewer.token)
					assert.Contains(t, missing, "404\n")
					paths := []string{
						"/api/v1/repos/nosuchorg/proj/pub/-", "/api/v1/repos/user2/proj/pub/-", "/api/v1/repos/org3/nosuch/pub/-",
						"/api/v1/repos/org3/secret/hid/-", fmt.Sprintf("/api/v1/repos/org3/proj/%s/-", trashed.Name),
						"/api/v1/repos/privated_org/pp/ppub/-",
						"/api/v1/repositories/999999", fmt.Sprintf("/api/v1/repositories/%d", f.hid.ID), fmt.Sprintf("/api/v1/repositories/%d", trashed.ID),
					}
					if viewer.token != specific {
						paths = append(paths, "/api/v1/repos/org3/proj/priv/-", fmt.Sprintf("/api/v1/repositories/%d", f.priv.ID))
					}
					for _, path := range paths {
						if viewer.name == "non-member" && path == "/api/v1/repos/privated_org/pp/ppub/-" {
							continue // user5 is a member of privated_org
						}
						assert.Equal(t, missing, apiResponse(t, method, path+rest, viewer.token), "%s %s%s", method, path, rest)
					}
				}
			}

			missing := apiResponse(t, "GET", "/api/v1/orgs/org3/projects/999999", viewer.token)
			assert.Contains(t, missing, "404\n")
			pp, err := repo_model.GetRepoGroupByName(db.DefaultContext, f.privOrg.ID, "pp")
			require.NoError(t, err)
			for _, id := range []int64{f.hid.GroupID, pp.ID} {
				assert.Equal(t, missing, apiResponse(t, "GET", fmt.Sprintf("/api/v1/orgs/org3/projects/%d", id), viewer.token))
				assert.Equal(t, missing, apiResponse(t, "GET", fmt.Sprintf("/api/v1/orgs/org3/projects/%d/repos", id), viewer.token))
			}
		})
	}
}

// A restricted token reaches a repository in a project by name exactly when it reaches it by ID.
func TestAPIRepoGroupTokens(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := prepareRepoGroupWeb(t)
	scopes := []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteIssue}
	all := getTokenForLoggedInUser(t, loginUser(t, "user2"), scopes...)
	publicOnly := getTokenForLoggedInUser(t, loginUser(t, "user2"), append([]auth_model.AccessTokenScope{auth_model.AccessTokenScopePublicOnly}, scopes...)...)
	specific := createFineGrainedRepoAccessToken(t, "user2", scopes, []int64{f.priv.ID})
	const jobToken = "8061e833a55f6fc0157c98b883e91fcfeeb1a71a" // a running task of user5/repo4

	check := func(t *testing.T, token string, repo *repo_model.Repository, readStatus int) {
		t.Helper()
		byName, byID := "/api/v1/repos/"+repo.FullName()+"/-", fmt.Sprintf("/api/v1/repositories/%d", repo.ID)
		for _, req := range []struct{ method, rest string }{{"GET", ""}, {"GET", "/issues"}, {"POST", "/issues"}} {
			name := apiResponse(t, req.method, byName+req.rest, token)
			id := apiResponse(t, req.method, byID+req.rest, token)
			if req.method == "GET" || name[:3] != "201" {
				assert.Equal(t, name, id, "%s %s%s", req.method, repo.FullName(), req.rest)
			} else { // each POST creates its own issue
				assert.Equal(t, name[:3], id[:3], "%s %s%s", req.method, repo.FullName(), req.rest)
			}
			if req.method == "GET" {
				assert.Equal(t, fmt.Sprint(readStatus), name[:3], "%s %s%s", req.method, repo.FullName(), req.rest)
			}
		}
	}
	for _, c := range []struct {
		name          string
		token         string
		pub, priv, hd int
	}{
		{"all access", all, 200, 200, 200},
		{"public only", publicOnly, 200, 404, 404},
		{"specific repos", specific, 200, 200, 404},
		{"job token of another repository", jobToken, 404, 404, 404},
	} {
		t.Run(c.name, func(t *testing.T) {
			check(t, c.token, f.pub, c.pub)
			check(t, c.token, f.priv, c.priv)
			check(t, c.token, f.hid, c.hd)
		})
	}

	t.Run("2FA-blocked member", func(t *testing.T) {
		// user2, an owner of org3 without two-factor authentication, read everything above
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET require_two_factor = ? WHERE id = 3", true)
		require.NoError(t, err)
		check(t, all, f.priv, http.StatusNotFound)
		check(t, all, f.pub, http.StatusOK)
	})
}

func TestAPIOrgProjects(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := prepareRepoGroupWeb(t)
	proj, secret := f.pub.GroupID, f.hid.GroupID
	owner := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeReadRepository)
	member := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeReadRepository)
	nonMember := getTokenForLoggedInUser(t, loginUser(t, "user5"), auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeReadRepository)
	publicOnly := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeReadRepository)
	specificScopes := []auth_model.AccessTokenScope{auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeReadRepository}
	specificHid := createFineGrainedRepoAccessToken(t, "user2", specificScopes, []int64{f.hid.ID})
	readOnly := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeReadOrganization)

	listed := func(t *testing.T, token string) []string {
		t.Helper()
		req := NewRequest(t, "GET", "/api/v1/orgs/org3/projects")
		if token != "" {
			req.AddTokenAuth(token)
		}
		var projects []*api.Project
		DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &projects)
		names := []string{}
		for _, p := range projects {
			names = append(names, p.Name)
		}
		return names
	}

	t.Run("read per viewer", func(t *testing.T) {
		assert.Equal(t, []string{"proj", "secret"}, listed(t, owner))
		assert.Equal(t, []string{"proj", "secret"}, listed(t, member))
		assert.Equal(t, []string{"proj"}, listed(t, nonMember))
		assert.Equal(t, []string{"proj"}, listed(t, ""))
		// a restricted token sees only the projects holding a repository it reaches, never through membership
		assert.Equal(t, []string{"proj"}, listed(t, publicOnly))
		assert.Equal(t, []string{"proj", "secret"}, listed(t, specificHid))
		specificPriv := createFineGrainedRepoAccessToken(t, "user2", specificScopes, []int64{f.priv.ID})
		assert.Equal(t, []string{"proj"}, listed(t, specificPriv))
		MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/orgs/org3/projects/%d", secret)).AddTokenAuth(specificPriv), http.StatusNotFound)

		var project api.Project
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/orgs/org3/projects/%d", proj)), http.StatusOK), &project)
		assert.Equal(t, "org3/proj", project.FullName)
		assert.Equal(t, setting.AppURL+"org3/proj", project.HTMLURL)
		assert.Equal(t, "the proj project", project.Description)

		repos := func(token string) []string {
			req := NewRequest(t, "GET", fmt.Sprintf("/api/v1/orgs/org3/projects/%d/repos", proj))
			if token != "" {
				req.AddTokenAuth(token)
			}
			var list []*api.Repository
			DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &list)
			names := []string{}
			for _, r := range list {
				names = append(names, r.FullName)
			}
			return names
		}
		assert.Equal(t, []string{"org3/proj/priv", "org3/proj/pub"}, repos(owner))
		assert.Equal(t, []string{"org3/proj/pub"}, repos(nonMember))
		assert.Equal(t, []string{"org3/proj/pub"}, repos(""))
		assert.Equal(t, []string{"org3/proj/pub"}, repos(publicOnly))
	})

	create := func(token, name string, status int) *RequestWrapper {
		req := NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/projects", &api.CreateProjectOption{Name: name, Description: "d"})
		if token != "" {
			req.AddTokenAuth(token)
		}
		MakeRequest(t, req, status)
		return req
	}

	t.Run("create", func(t *testing.T) {
		var project api.Project
		DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/projects", &api.CreateProjectOption{Name: "Fresh", Description: "new"}).AddTokenAuth(owner), http.StatusCreated), &project)
		assert.Equal(t, "org3/Fresh", project.FullName)

		// one answer for a name held by a public or private root repository, or a project
		var bodies []string
		for _, name := range []string{"repo21", "repo3", "proj"} { // org3/repo21 is public, org3/repo3 private
			resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/projects", &api.CreateProjectOption{Name: name}).AddTokenAuth(owner), http.StatusConflict)
			bodies = append(bodies, resp.Body.String())
		}
		assert.Equal(t, bodies[0], bodies[1])
		assert.Equal(t, bodies[0], bodies[2])

		create(owner, "..", http.StatusUnprocessableEntity)
		create(member, "x1", http.StatusForbidden)
		create(nonMember, "x2", http.StatusForbidden)
		create(publicOnly, "x3", http.StatusForbidden)
		create(specificHid, "x4", http.StatusForbidden)
		create(readOnly, "x5", http.StatusForbidden)
		create("", "x6", http.StatusUnauthorized)
		// a private organization the doer isn't in is not found
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/privated_org/projects", &api.CreateProjectOption{Name: "x7"}).AddTokenAuth(member), http.StatusNotFound)
		unittest.AssertNotExistsBean(t, &repo_model.RepoGroup{OwnerID: 3, LowerName: "x1"})
	})

	t.Run("owner check before the ID", func(t *testing.T) {
		for _, id := range []int64{proj, 999999} {
			assert.Equal(t, http.StatusForbidden, MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/orgs/org3/projects/%d", id)).AddTokenAuth(member), NoExpectedStatus).Code)
		}
		MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/orgs/org3/projects/999999").AddTokenAuth(owner), http.StatusNotFound)
	})

	t.Run("edit and delete", func(t *testing.T) {
		name, description := "proj2", "renamed"
		var project api.Project
		DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/orgs/org3/projects/%d", proj), &api.EditProjectOption{Name: &name, Description: &description}).AddTokenAuth(owner), http.StatusOK), &project)
		assert.Equal(t, "org3/proj2", project.FullName)
		assert.Equal(t, "renamed", project.Description)
		var repo api.Repository
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/proj2/pub/-"), http.StatusOK), &repo)
		assert.Equal(t, "org3/proj2/pub", repo.FullName)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/proj/pub/-"), http.StatusNotFound)

		taken := "secret"
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/orgs/org3/projects/%d", proj), &api.EditProjectOption{Name: &taken}).AddTokenAuth(owner), http.StatusConflict)

		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/orgs/org3/projects/%d", proj)).AddTokenAuth(owner), http.StatusConflict)
		fresh, err := repo_model.GetRepoGroupByName(db.DefaultContext, 3, "fresh")
		require.NoError(t, err)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/orgs/org3/projects/%d", fresh.ID)).AddTokenAuth(owner), http.StatusNoContent)
		MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/api/v1/orgs/org3/projects/%d", fresh.ID)).AddTokenAuth(owner), http.StatusNotFound)
	})

	t.Run("archived organization", func(t *testing.T) {
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET is_archived = ? WHERE id = 3", true)
		require.NoError(t, err)
		create(owner, "late", http.StatusForbidden)
		assert.Equal(t, []string{"proj2", "secret"}, listed(t, owner))
	})
}
