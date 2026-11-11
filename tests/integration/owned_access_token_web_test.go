// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	perm_model "forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/timeutil"
	"forgejo.org/services/authz"
	"forgejo.org/tests"
	"forgejo.org/tests/forgery"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOwnedAccessTokenWeb(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	name := func() string { return fmt.Sprintf("web-token-%d", tokenCounter.Add(1)) }

	// follow answers a POST: a refusal is the page itself, a success redirects to the page that shows the value once
	follow := func(t *testing.T, resp *httptest.ResponseRecorder) *HTMLDoc {
		t.Helper()
		if resp.Code == http.StatusSeeOther {
			link, _, _ := strings.Cut(resp.Header().Get("Location"), "#")
			resp = session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
		}
		require.Equal(t, http.StatusOK, resp.Code)
		return NewHTMLParser(t, resp.Body)
	}
	// create posts the form and returns the page and the value shown once ("" when refused)
	create := func(t *testing.T, keysLink string, form map[string]string) (*HTMLDoc, string) {
		t.Helper()
		page := follow(t, session.MakeRequest(t, NewRequestWithValues(t, "POST", keysLink+"/tokens/new", form), NoExpectedStatus))
		return page, strings.TrimSpace(page.Find("#new-access-token-value").Text())
	}
	use := func(t *testing.T, path, token string) int {
		t.Helper()
		return MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), NoExpectedStatus).Code
	}

	t.Run("repository", func(t *testing.T) {
		link := "/user2/repo1/settings/keys"
		page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body)
		assert.Equal(t, 1, page.Find("#access-tokens-empty").Length())
		assert.Equal(t, "read", page.Find(`input[name="token_permission"][checked]`).AttrOr("value", ""))
		assert.Equal(t, "read:repository", page.Find(`#access-token-scope-repository option[selected]`).AttrOr("value", ""))
		assert.Equal(t, 0, page.Find(`#access-token-scope-organization option[value="write:organization"]`).Length())

		n := name()
		page, value := create(t, link, map[string]string{"token_name": n, "token_permission": "write", "token_scopes": "read:repository"})
		require.NotEmpty(t, value)
		assert.Contains(t, page.Find("#access-token-list").Text(), n)
		assert.Contains(t, page.Find("#access-token-list").Text(), "Never used")
		assert.Zero(t, page.Find("#access-token-list .text.green").Length(), "a token nobody used has no activity mark")
		tok := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{Name: n, OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 1})
		assert.Equal(t, perm_model.AccessModeWrite, tok.Mode)
		assert.EqualValues(t, 2, tok.CreatorID)
		assert.True(t, tok.ResourceAllRepos)
		assert.Equal(t, http.StatusOK, use(t, "/api/v1/repos/user2/repo1", value))
		assert.Equal(t, http.StatusNotFound, use(t, "/api/v1/repos/user2/repo2", value))

		// a refusal keeps what was entered and shows the value of nothing
		page, refused := create(t, link, map[string]string{"token_name": n, "token_permission": "admin", "token_scopes": "write:issue"})
		assert.Empty(t, refused)
		assert.Contains(t, page.Find("#access-token-error").Text(), n)
		assert.Equal(t, n, page.Find("#access-token-name").AttrOr("value", ""))
		assert.Equal(t, "admin", page.Find(`input[name="token_permission"][checked]`).AttrOr("value", ""))
		assert.Equal(t, "write:issue", page.Find(`#access-token-scope-issue option[selected]`).AttrOr("value", ""))
		// no scope is said under the Scopes field, not in the box above the form
		page, refused = create(t, link, map[string]string{"token_name": name(), "token_permission": "read"})
		assert.Empty(t, refused)
		assert.Equal(t, "Choose at least one scope.", strings.TrimSpace(page.Find("#access-token-scopes-error").Text()))
		assert.Zero(t, page.Find("#access-token-error").Length())
		for _, scope := range []string{"write:user", "write:admin", "write:organization", ""} {
			_, refused = create(t, link, map[string]string{"token_name": name(), "token_permission": "read", "token_scopes": scope})
			assert.Empty(t, refused, scope)
		}
		_, refused = create(t, link, map[string]string{"token_name": name(), "token_permission": "owner", "token_scopes": "read:repository"})
		assert.Empty(t, refused)

		// another repository's admin can't reach the page, the form or the revoke
		other := loginUser(t, "user4")
		other.MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound)
		other.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/tokens/new", map[string]string{"token_name": name(), "token_permission": "read", "token_scopes": "read:repository"}), http.StatusNotFound)
		other.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/tokens/delete", map[string]string{"id": fmt.Sprint(tok.ID)}), http.StatusNotFound)

		// a token of another repository is not found here
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo2/settings/keys/tokens/delete", map[string]string{"id": fmt.Sprint(tok.ID)}), http.StatusOK)
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: tok.ID})

		// rotate shows the new secret once, and the old one stops working
		resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/tokens/rotate", map[string]string{"id": fmt.Sprint(tok.ID)}), http.StatusSeeOther)
		assert.NotContains(t, resp.Body.String(), "new-access-token-value", "the POST answer holds no secret")
		page = follow(t, resp)
		rotated := strings.TrimSpace(page.Find("#new-access-token-value").Text())
		require.NotEmpty(t, rotated)
		// a reload shows nothing and rotates nothing; the secret was shown once
		for range 2 {
			reloaded := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body)
			assert.Zero(t, reloaded.Find("#new-access-token-value").Length())
			assert.Equal(t, http.StatusOK, use(t, "/api/v1/repos/user2/repo1", rotated))
		}
		assert.NotEqual(t, value, rotated)
		assert.Contains(t, page.Find("#new-access-token").Text(), "rotated")
		assert.Contains(t, page.Find("#access-token-list .last-rotated").Text(), "user2")
		assert.Equal(t, http.StatusUnauthorized, use(t, "/api/v1/repos/user2/repo1", value))
		assert.Equal(t, http.StatusOK, use(t, "/api/v1/repos/user2/repo1", rotated))
		other.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/tokens/rotate", map[string]string{"id": fmt.Sprint(tok.ID)}), http.StatusNotFound)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo2/settings/keys/tokens/rotate", map[string]string{"id": fmt.Sprint(tok.ID)}), http.StatusSeeOther)
		assert.Equal(t, http.StatusOK, use(t, "/api/v1/repos/user2/repo1", rotated), "another repository's page doesn't rotate it")

		session.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/tokens/delete", map[string]string{"id": fmt.Sprint(tok.ID)}), http.StatusOK)
		assert.NotZero(t, unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: tok.ID}).RevokedUnix, "revoked, kept for its name")
		assert.Equal(t, http.StatusUnauthorized, use(t, "/api/v1/repos/user2/repo1", rotated))
		page = NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body)
		assert.NotContains(t, page.Find("#access-token-list").Text(), n)
	})

	t.Run("organization", func(t *testing.T) {
		link := "/org/org3/settings/keys"
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		other := forgery.CreateRepository(t, org3, &forgery.CreateRepositoryOptions{Files: forgery.FilesInit{}})
		n := name()
		_, value := create(t, link, map[string]string{"token_name": n, "token_permission": "read", "token_scopes": "read:repository", "scope": "selected", "repo_ids": "3,3"})
		require.NotEmpty(t, value)
		assert.Equal(t, http.StatusOK, use(t, "/api/v1/repos/org3/repo3", value))
		assert.Equal(t, http.StatusNotFound, use(t, "/api/v1/repos/"+other.FullName(), value))
		tok := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{Name: n, OwnerType: auth_model.AccessTokenOwnerOrg, OwnerID: 3})
		assert.False(t, tok.ResourceAllRepos)

		// a repository of another owner, or none, is refused
		for _, ids := range []string{"1", "3,1", ""} {
			page, value := create(t, link, map[string]string{"token_name": name(), "token_permission": "read", "token_scopes": "read:repository", "scope": "selected", "repo_ids": ids})
			assert.Empty(t, value, ids)
			assert.Equal(t, 1, page.Find("#access-token-error").Length(), ids)
		}
		unittest.AssertNotExistsBean(t, &auth_model.AccessTokenResourceRepo{RepoID: 1})

		// the repository page lists it read-only
		page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/settings/keys"), http.StatusOK).Body)
		assert.Contains(t, page.Find("#covering-access-tokens").Text(), n)
		page = NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/"+other.FullName()+"/settings/keys"), http.StatusOK).Body)
		assert.NotContains(t, page.Find("#covering-access-tokens").Text(), n)

		// a member who isn't an owner can't reach it
		member := loginUser(t, "user4")
		member.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/tokens/new", map[string]string{"token_name": name(), "token_permission": "read", "token_scopes": "read:repository", "scope": "all"}), http.StatusNotFound)
	})

	t.Run("project", func(t *testing.T) {
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		group, err := repo_model.CreateRepoGroup(audit_model.WithSystem(db.DefaultContext, "test"), org3, "tokens-web", "")
		require.NoError(t, err)
		link := "/org3/tokens-web/-/settings/keys"
		page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body)
		assert.Contains(t, page.Find("#access-token-coverage").Text(), "tokens-web")
		assert.Equal(t, 0, page.Find(`#add-access-token-panel input[name="scope"]`).Length())

		n := name()
		// a project token covers its project whatever the form says
		_, value := create(t, link, map[string]string{"token_name": n, "token_permission": "read", "token_scopes": "read:repository", "scope": "selected", "repo_ids": "3"})
		require.NotEmpty(t, value)
		tok := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{Name: n, OwnerType: auth_model.AccessTokenOwnerProject, OwnerID: 3, GroupID: group.ID})
		assert.True(t, tok.ResourceAllRepos)
		assert.Equal(t, http.StatusNotFound, use(t, "/api/v1/repos/org3/repo3", value))

		// the organization's page doesn't see it, and its revoke doesn't find it
		page = NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/keys"), http.StatusOK).Body)
		assert.NotContains(t, page.Find("#access-token-list").Text(), n)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/keys/tokens/delete", map[string]string{"id": fmt.Sprint(tok.ID)}), http.StatusOK)
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: tok.ID})
		session.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/tokens/delete", map[string]string{"id": fmt.Sprint(tok.ID)}), http.StatusOK)
		assert.NotZero(t, unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: tok.ID}).RevokedUnix)
	})

	t.Run("the secret is shown once, on the page of its own owner", func(t *testing.T) {
		link := "/user2/repo1/settings/keys"
		n := name()
		resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/tokens/new", map[string]string{"token_name": n, "token_permission": "read", "token_scopes": "read:repository"}), http.StatusSeeOther)
		assert.NotContains(t, resp.Body.String(), "new-access-token-value")

		// another owner's page doesn't consume it and shows nothing
		for _, other := range []string{"/user2/repo2/settings/keys", "/org/org3/settings/keys"} {
			page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", other), http.StatusOK).Body)
			assert.Zero(t, page.Find("#new-access-token-value").Length(), other)
		}
		resp = session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
		assert.Equal(t, "no-store", resp.Header().Get("Cache-Control"))
		value := strings.TrimSpace(NewHTMLParser(t, resp.Body).Find("#new-access-token-value").Text())
		require.NotEmpty(t, value)
		assert.Equal(t, http.StatusOK, use(t, "/api/v1/repos/user2/repo1", value))
		assert.NotEqual(t, "no-store", session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Header().Get("Cache-Control"), "shown once")

		// a rotation between the POST and the page leaves nothing to show
		n = name()
		session.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/tokens/new", map[string]string{"token_name": n, "token_permission": "read", "token_scopes": "read:repository"}), http.StatusSeeOther)
		tok := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{Name: n, OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 1})
		_, err := authz.RotateOwnedAccessToken(audit_model.WithSystem(db.DefaultContext, "test"), auth_model.FindOwnedAccessTokensOptions{OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 1}, tok.ID, tok.TokenHash, optional.None[timeutil.TimeStamp](), 2)
		require.NoError(t, err)
		page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body)
		assert.Zero(t, page.Find("#new-access-token-value").Length())
	})

	t.Run("name filter", func(t *testing.T) {
		link := "/user2/repo2/settings/keys"
		for i := range 21 {
			_, value := create(t, link, map[string]string{"token_name": fmt.Sprintf("filter-%02d", i), "token_permission": "read", "token_scopes": "read:repository"})
			require.NotEmpty(t, value)
		}
		page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body)
		assert.Equal(t, 1, page.Find(`input[name="q"]`).Length())
		assert.Equal(t, 20, page.Find("#access-token-list .flex-item").Length())
		assert.Contains(t, page.Find("#access-token-list").Text(), "filter-20") // newest first
		page = NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link+"?q=FILTER-07"), http.StatusOK).Body)
		assert.Equal(t, 1, page.Find("#access-token-list .flex-item").Length())
	})
}
