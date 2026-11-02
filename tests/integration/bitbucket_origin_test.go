// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"net/url"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// org3/repo3 is private: user2 owns org3, user5 can't read it.
func TestBitbucketOrigin(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := t.Context()
	require.NoError(t, db.Insert(ctx, &repo_model.BitbucketOrigin{RepoID: 3, ProjectKey: "PAY", Slug: "api", Server: "https://bb.example.com/bitbucket"}))
	_, err := db.Exec(ctx, "UPDATE repository SET original_service_type = ? WHERE id = 3", api.BitbucketDataCenterService)
	require.NoError(t, err)
	repo3 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})

	keywords := []string{
		"PAY/api",
		"https://bb.example.com/bitbucket/scm/pay/api.git",
		"https://bb.example.com/bitbucket/projects/PAY/repos/api/browse",
		"ssh://git@bb.example.com:7999/pay/api.git",
	}

	t.Run("search", func(t *testing.T) {
		apiSearch := func(t *testing.T, token, keyword string) []int64 {
			t.Helper()
			req := NewRequest(t, "GET", "/api/v1/repos/search?q="+url.QueryEscape(keyword))
			if token != "" {
				req.AddTokenAuth(token)
			}
			var result api.SearchResults
			DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &result)
			ids := []int64{}
			for _, r := range result.Data {
				ids = append(ids, r.ID)
			}
			return ids
		}
		owner := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
		other := getUserToken(t, "user5", auth_model.AccessTokenScopeReadRepository)
		ownerSession, otherSession, anonymous := loginUser(t, "user2"), loginUser(t, "user5"), emptyTestSession(t)
		for _, keyword := range keywords {
			assert.Contains(t, apiSearch(t, owner, keyword), int64(3), keyword)
			assert.NotContains(t, apiSearch(t, other, keyword), int64(3), keyword)
			assert.NotContains(t, apiSearch(t, "", keyword), int64(3), keyword)

			for _, page := range []string{"/explore/repos?q=", "/org3?q="} {
				u := page + url.QueryEscape(keyword)
				assert.Contains(t, ownerSession.MakeRequest(t, NewRequest(t, "GET", u), http.StatusOK).Body.String(), `href="/org3/repo3"`, u)
				assert.NotContains(t, otherSession.MakeRequest(t, NewRequest(t, "GET", u), http.StatusOK).Body.String(), `href="/org3/repo3"`, u)
				assert.NotContains(t, anonymous.MakeRequest(t, NewRequest(t, "GET", u), http.StatusOK).Body.String(), `href="/org3/repo3"`, u)
			}
		}
	})

	t.Run("repository home", func(t *testing.T) {
		session := loginUser(t, "user2")
		body := session.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3"), http.StatusOK).Body.String()
		assert.Contains(t, body, "Migrated from Bitbucket")
		assert.Contains(t, body, `href="https://bb.example.com/bitbucket/projects/PAY/repos/api/browse"`)
		assert.Contains(t, body, `id="bitbucket-origin-banner"`)
		assert.Contains(t, body, "git remote set-url origin "+repo3.CloneLink().HTTPS)

		// another page of the repository has the header but no lookup
		assert.NotContains(t, session.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/issues"), http.StatusOK).Body.String(), "Migrated from Bitbucket")
		// a repository without a row
		assert.NotContains(t, session.MakeRequest(t, NewRequest(t, "GET", "/org3/repo5"), http.StatusOK).Body.String(), "bitbucket-origin-banner")

		// a server that isn't a plain http(s) URL gets no link
		_, err := db.Exec(ctx, "UPDATE bitbucket_origin SET server = ? WHERE repo_id = 3", "javascript:alert(1)")
		require.NoError(t, err)
		body = session.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3"), http.StatusOK).Body.String()
		assert.Contains(t, body, "Migrated from Bitbucket")
		assert.NotContains(t, body, "javascript:alert")
		_, err = db.Exec(ctx, "UPDATE bitbucket_origin SET server = ? WHERE repo_id = 3", "https://bb.example.com/bitbucket")
		require.NoError(t, err)

		// a repository not imported from Bitbucket isn't looked up
		_, err = db.Exec(ctx, "UPDATE repository SET original_service_type = 0 WHERE id = 3")
		require.NoError(t, err)
		assert.NotContains(t, session.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3"), http.StatusOK).Body.String(), "bitbucket-origin-banner")
		_, err = db.Exec(ctx, "UPDATE repository SET original_service_type = ? WHERE id = 3", api.BitbucketDataCenterService)
		require.NoError(t, err)
	})

	t.Run("project home", func(t *testing.T) {
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		group, err := repo_model.CreateRepoGroup(ctx, org3, "payments", "")
		require.NoError(t, err)
		require.NoError(t, db.Insert(ctx, &repo_model.BitbucketOrigin{OwnerID: 3, GroupID: group.ID, ProjectKey: "PAY", Server: "https://bb.example.com/bitbucket"}))
		body := loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", group.Link("org3")), http.StatusOK).Body.String()
		assert.Contains(t, body, "Bitbucket key PAY")
	})

	t.Run("a transfer keeps the row", func(t *testing.T) {
		require.NoError(t, db.Insert(ctx, &repo_model.BitbucketOrigin{RepoID: 1, ProjectKey: "WEB", Slug: "site", Server: "https://bb.example.com/bitbucket"}))
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		require.NoError(t, repo_service.TransferOwnership(ctx, user2, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}), unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}), nil))
		repos, _, err := repo_model.SearchRepositoryByName(ctx, &repo_model.SearchRepoOptions{Keyword: "WEB/site", Actor: user2, Private: true})
		require.NoError(t, err)
		require.Len(t, repos, 1)
		assert.Equal(t, "org3", repos[0].OwnerName)
	})

	t.Run("purge removes the row", func(t *testing.T) {
		require.NoError(t, repo_service.DeleteRepositoryDirectly(ctx, 3, repo_service.DeleteRepositoryOpts{}))
		unittest.AssertNotExistsBean(t, &repo_model.BitbucketOrigin{RepoID: 3})
	})

	t.Run("organization delete removes its project rows", func(t *testing.T) {
		owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		org := &organization.Organization{Name: "bitbucket-import"}
		require.NoError(t, organization.CreateOrganization(ctx, org, owner))
		group, err := repo_model.CreateRepoGroup(ctx, org.AsUser(), "ops", "")
		require.NoError(t, err)
		require.NoError(t, db.Insert(ctx, &repo_model.BitbucketOrigin{OwnerID: org.ID, GroupID: group.ID, ProjectKey: "OPS", Server: "https://bb.example.com/bitbucket"}))
		require.NoError(t, org_service.DeleteOrganization(ctx, org, false))
		unittest.AssertNotExistsBean(t, &repo_model.BitbucketOrigin{OwnerID: org.ID})
		unittest.AssertExistsAndLoadBean(t, &repo_model.BitbucketOrigin{RepoID: 1})
	})
}
