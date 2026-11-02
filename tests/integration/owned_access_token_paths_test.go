// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/organization"
	perm_model "forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/json"
	"forgejo.org/modules/lfs"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/modules/timeutil"
	"forgejo.org/services/mailer"
	org_service "forgejo.org/services/org"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ownedTokenGitURL is the HTTP clone URL of repo with the token as the password.
func ownedTokenGitURL(u *url.URL, token string, repo *repo_model.Repository) *url.URL {
	c := *u
	c.Path = "/" + repo.FullName() + ".git"
	c.User = url.UserPassword("anything", token)
	return &c
}

// ownedTokenPush clones repo with the token, commits and pushes HEAD to branch.
func ownedTokenPush(t *testing.T, u *url.URL, token string, repo *repo_model.Repository, branch string) (string, error) {
	t.Helper()
	dst := t.TempDir()
	require.NoError(t, git.Clone(t.Context(), ownedTokenGitURL(u, token, repo).String(), dst, git.CloneRepoOptions{}))
	doGitSetRemoteURL(dst, "origin", ownedTokenGitURL(u, token, repo))(t)
	generateCommitWithNewData(t, 64, dst, "bot@example.com", "Bot", "data-")
	_, stderr, err := git.NewCommand(git.DefaultContext, "push", "origin").AddDynamicArguments("HEAD:refs/heads/" + branch).RunStdString(&git.RunOpts{Dir: dst})
	return stderr, err
}

// A repository inside a project (org/project/repo): tokens push to it, its Keys and tokens page and both API forms
// manage the repository's tokens, and everything is recorded.
func TestOwnedAccessTokenProjectRepository(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		sys := audit_model.WithSystem(db.DefaultContext, "test")
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		group, err := repo_model.CreateRepoGroup(sys, org3, "paths-proj", "")
		require.NoError(t, err)
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		leaf, err := repo_service.CreateRepository(db.DefaultContext, user2, org3, repo_service.CreateRepoOptions{
			Name: "leaf", IsPrivate: true, Readme: "Default", AutoInit: true, DefaultBranch: "main", GroupID: group.ID,
		})
		require.NoError(t, err)
		require.Equal(t, "org3/paths-proj/leaf", leaf.FullName())
		apiRepo := "/api/v1/repos/org3/paths-proj/leaf/-"
		owner := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		session := loginUser(t, "user2")
		use := func(path, token string) int {
			return MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), NoExpectedStatus).Code
		}

		t.Run("push with a project token", func(t *testing.T) {
			writer := newOwnedAccessToken(t, auth_model.AccessTokenOwnerProject, 3, group.ID, perm_model.AccessModeWrite, "write:repository")
			_, err := ownedTokenPush(t, u, writer.Token, leaf, "proj-pushed")
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, use(apiRepo+"/branches/proj-pushed", writer.Token), "the ref is there")
			unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: leaf.ID, Name: "proj-pushed"})

			reader := newOwnedAccessToken(t, auth_model.AccessTokenOwnerProject, 3, group.ID, perm_model.AccessModeRead, "write:repository")
			stderr, err := ownedTokenPush(t, u, reader.Token, leaf, "proj-read-only")
			require.Error(t, err)
			assert.Contains(t, stderr, "is not allowed to push")
			assert.Equal(t, http.StatusNotFound, use(apiRepo+"/branches/proj-read-only", writer.Token))

			// a token of another project doesn't reach it
			other, err := repo_model.CreateRepoGroup(sys, org3, "paths-other", "")
			require.NoError(t, err)
			foreign := newOwnedAccessToken(t, auth_model.AccessTokenOwnerProject, 3, other.ID, perm_model.AccessModeWrite, "write:repository")
			doGitCloneFail(ownedTokenGitURL(u, foreign.Token, leaf))(t)
			assert.Equal(t, http.StatusNotFound, use(apiRepo, foreign.Token))
		})

		t.Run("web page", func(t *testing.T) {
			link := "/org3/paths-proj/leaf/settings/keys"
			covering := newOwnedAccessToken(t, auth_model.AccessTokenOwnerProject, 3, group.ID, perm_model.AccessModeRead, "read:repository")
			page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body)
			assert.Contains(t, page.Find("#covering-access-tokens").Text(), covering.Name)

			session.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
			loginUser(t, "user8").MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound)

			since := auditMaxID(t)
			n := fmt.Sprintf("proj-web-%d", tokenCounter.Add(1))
			resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/tokens/new", map[string]string{"token_name": n, "token_permission": "write", "token_scopes": "read:repository"}), http.StatusSeeOther)
			tok := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{Name: n, OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: leaf.ID})
			e := auditOne(t, since, "credential.access_token.created")
			assert.Equal(t, tok.ID, e.TargetID)
			assert.Equal(t, leaf.ID, e.RepoID)
			page = NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", strings.TrimSuffix(resp.Header().Get("Location"), "#access-tokens")), http.StatusOK).Body)
			secret := strings.TrimSpace(page.Find("#new-access-token-value").Text())
			require.NotEmpty(t, secret)
			assert.Equal(t, http.StatusOK, use(apiRepo, secret))

			since = auditMaxID(t)
			resp = session.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/tokens/rotate", map[string]string{"id": fmt.Sprint(tok.ID)}), http.StatusSeeOther)
			assert.Equal(t, tok.ID, auditOne(t, since, "credential.access_token.rotated").TargetID)
			page = NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", strings.TrimSuffix(resp.Header().Get("Location"), "#access-tokens")), http.StatusOK).Body)
			rotated := strings.TrimSpace(page.Find("#new-access-token-value").Text())
			require.NotEmpty(t, rotated)
			assert.Equal(t, http.StatusUnauthorized, use(apiRepo, secret))
			assert.Equal(t, http.StatusOK, use(apiRepo, rotated))

			since = auditMaxID(t)
			session.MakeRequest(t, NewRequestWithValues(t, "POST", link+"/tokens/delete", map[string]string{"id": fmt.Sprint(tok.ID)}), http.StatusOK)
			assert.Equal(t, tok.ID, auditOne(t, since, "credential.access_token.deleted").TargetID)
			assert.NotZero(t, unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: tok.ID}).RevokedUnix)
			assert.Equal(t, http.StatusUnauthorized, use(apiRepo, rotated))
		})

		t.Run("API", func(t *testing.T) {
			for _, base := range []string{apiRepo + "/tokens", fmt.Sprintf("/api/v1/repositories/%d/tokens", leaf.ID)} {
				n := fmt.Sprintf("proj-api-%d", tokenCounter.Add(1))
				since := auditMaxID(t)
				var created api.AccessToken
				DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", base, api.CreateOwnedAccessTokenOption{Name: n, Scopes: []string{"read:repository"}, Permission: "read"}).AddTokenAuth(owner), http.StatusCreated), &created)
				e := auditOne(t, since, "credential.access_token.created")
				assert.Equal(t, created.ID, e.TargetID, base)
				assert.Equal(t, leaf.ID, e.RepoID, base)
				assert.Equal(t, http.StatusOK, use(apiRepo, created.Token), base)

				var list []*api.AccessToken
				DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(owner), http.StatusOK), &list)
				require.NotEmpty(t, list)
				assert.Equal(t, n, list[0].Name)

				since = auditMaxID(t)
				var rotated api.AccessToken
				DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/rotate", base, created.ID), api.RotateOwnedAccessTokenOption{}).AddTokenAuth(owner), http.StatusOK), &rotated)
				assert.Equal(t, created.ID, auditOne(t, since, "credential.access_token.rotated").TargetID, base)
				assert.Equal(t, http.StatusUnauthorized, use(apiRepo, created.Token), base)

				since = auditMaxID(t)
				MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", base, created.ID)).AddTokenAuth(owner), http.StatusNoContent)
				assert.Equal(t, created.ID, auditOne(t, since, "credential.access_token.deleted").TargetID, base)
				assert.Equal(t, http.StatusUnauthorized, use(apiRepo, rotated.Token), base)

				// someone without access to the repository, and a repository admin of nothing here
				MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(getUserToken(t, "user8", auth_model.AccessTokenScopeWriteRepository)), http.StatusNotFound)
				MakeRequest(t, NewRequest(t, "GET", base), http.StatusNotFound) // private: hidden is missing
			}
		})
	})
}

// The audit entries of the web pages and the API at each level, and of a token rotating itself.
func TestOwnedAccessTokenAudit(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	owner := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	group, err := repo_model.CreateRepoGroup(audit_model.WithSystem(db.DefaultContext, "test"), org3, "tokens-audit", "")
	require.NoError(t, err)

	levels := []struct {
		name    string
		link    string                     // the Keys and tokens page
		api     string                     // the API list route
		apiID   func(id int64) string      // the API route of one token
		scoped  func(e *audit_model.Entry) // what the entry names as its owner
		owner   auth_model.AccessTokenOwnerType
		ownerID int64
		groupID int64
	}{
		{
			name: "repository", link: "/org3/repo3/settings/keys", api: "/api/v1/repos/org3/repo3/tokens",
			apiID:  func(id int64) string { return fmt.Sprintf("/api/v1/repos/org3/repo3/tokens/%d", id) },
			scoped: func(e *audit_model.Entry) { assert.EqualValues(t, 3, e.RepoID) },
			owner:  auth_model.AccessTokenOwnerRepo, ownerID: 3,
		},
		{
			name: "organization", link: "/org/org3/settings/keys", api: "/api/v1/orgs/org3/tokens",
			apiID:  func(id int64) string { return fmt.Sprintf("/api/v1/orgs/org3/tokens/%d", id) },
			scoped: func(e *audit_model.Entry) { assert.EqualValues(t, 3, e.OwnerID); assert.Zero(t, e.GroupID) },
			owner:  auth_model.AccessTokenOwnerOrg, ownerID: 3,
		},
		{
			name: "project", link: "/org3/tokens-audit/-/settings/keys", api: fmt.Sprintf("/api/v1/orgs/org3/projects/%d/tokens", group.ID),
			apiID:  func(id int64) string { return fmt.Sprintf("/api/v1/orgs/org3/projects/%d/tokens/%d", group.ID, id) },
			scoped: func(e *audit_model.Entry) { assert.EqualValues(t, 3, e.OwnerID); assert.Equal(t, group.ID, e.GroupID) },
			owner:  auth_model.AccessTokenOwnerProject, ownerID: 3, groupID: group.ID,
		},
	}
	for _, l := range levels {
		t.Run(l.name+" web", func(t *testing.T) {
			n := fmt.Sprintf("audit-web-%d", tokenCounter.Add(1))
			since := auditMaxID(t)
			resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", l.link+"/tokens/new", map[string]string{"token_name": n, "token_permission": "read", "token_scopes": "read:repository", "scope": "all"}), http.StatusSeeOther)
			tok := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{Name: n, OwnerType: l.owner, OwnerID: l.ownerID, GroupID: l.groupID})
			e := auditOne(t, since, "credential.access_token.created")
			assert.Equal(t, tok.ID, e.TargetID)
			assert.Equal(t, n, e.TargetName)
			assert.Equal(t, audit_model.ActorUser, e.ActorType)
			assert.EqualValues(t, 2, e.ActorID)
			l.scoped(e)
			assert.Equal(t, "read", auditData(t, e)["after"].(map[string]any)["mode"])
			secret := strings.TrimSpace(NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", strings.TrimSuffix(resp.Header().Get("Location"), "#access-tokens")), http.StatusOK).Body).Find("#new-access-token-value").Text())
			assertNoSecretIn(t, since, secret)

			since = auditMaxID(t)
			session.MakeRequest(t, NewRequestWithValues(t, "POST", l.link+"/tokens/rotate", map[string]string{"id": fmt.Sprint(tok.ID)}), http.StatusSeeOther)
			e = auditOne(t, since, "credential.access_token.rotated")
			assert.Equal(t, tok.ID, e.TargetID)
			assert.EqualValues(t, 2, e.ActorID)
			assert.Equal(t, false, auditData(t, e)["self"])
			l.scoped(e)
			assertNoSecretIn(t, since, secret)

			since = auditMaxID(t)
			session.MakeRequest(t, NewRequestWithValues(t, "POST", l.link+"/tokens/delete", map[string]string{"id": fmt.Sprint(tok.ID)}), http.StatusOK)
			e = auditOne(t, since, "credential.access_token.deleted")
			assert.Equal(t, tok.ID, e.TargetID)
			assert.EqualValues(t, 2, e.ActorID)
			l.scoped(e)
		})

		t.Run(l.name+" API", func(t *testing.T) {
			since := auditMaxID(t)
			var created api.AccessToken
			DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", l.api, api.CreateOwnedAccessTokenOption{
				Name: fmt.Sprintf("audit-api-%d", tokenCounter.Add(1)), Scopes: []string{"read:repository"}, Permission: "read", SelfRotate: true,
			}).AddTokenAuth(owner), http.StatusCreated), &created)
			e := auditOne(t, since, "credential.access_token.created")
			assert.Equal(t, created.ID, e.TargetID)
			assert.EqualValues(t, 2, e.ActorID)
			l.scoped(e)

			// a token rotating itself records itself, not a user
			since = auditMaxID(t)
			var rotated api.AccessToken
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "POST", "/api/v1/tokens/self/rotate").AddTokenAuth(created.Token), http.StatusOK), &rotated)
			e = auditOne(t, since, "credential.access_token.rotated")
			assert.Equal(t, created.ID, e.TargetID)
			assert.Equal(t, true, auditData(t, e)["self"])
			assert.Equal(t, audit_model.CredentialAccessToken, e.CredentialType)
			assert.Equal(t, created.ID, e.CredentialID)
			l.scoped(e)
			assertNoSecretIn(t, since, created.Token, rotated.Token)

			since = auditMaxID(t)
			MakeRequest(t, NewRequest(t, "DELETE", l.apiID(created.ID)).AddTokenAuth(owner), http.StatusNoContent)
			e = auditOne(t, since, "credential.access_token.deleted")
			assert.Equal(t, created.ID, e.TargetID)
			l.scoped(e)
		})
	}
}

// Every refusal of the API, for each kind of caller and each kind of input.
func TestOwnedAccessTokenAPIRefusals(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	owner := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWritePackage)
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	group, err := repo_model.CreateRepoGroup(audit_model.WithSystem(db.DefaultContext, "test"), org3, "tokens-refusals", "")
	require.NoError(t, err)
	repoPath := "/api/v1/repos/org3/repo3/tokens"
	orgPath := "/api/v1/orgs/org3/tokens"
	projectPath := fmt.Sprintf("/api/v1/orgs/org3/projects/%d/tokens", group.ID)
	name := func() string { return fmt.Sprintf("refusal-%d", tokenCounter.Add(1)) }
	opts := func() api.CreateOwnedAccessTokenOption {
		return api.CreateOwnedAccessTokenOption{Name: name(), Scopes: []string{"read:repository"}, Permission: "read"}
	}
	post := func(t *testing.T, path, token string, o api.CreateOwnedAccessTokenOption, status int) {
		t.Helper()
		req := NewRequestWithJSON(t, "POST", path, o)
		if token != "" {
			req.AddTokenAuth(token)
		}
		MakeRequest(t, req, status)
	}
	ownedCount := func(t *testing.T) int64 {
		t.Helper()
		n, err := db.GetEngine(t.Context()).Where("owner_type <> ?", auth_model.AccessTokenOwnerUser).Count(new(auth_model.AccessToken))
		require.NoError(t, err)
		return n
	}

	t.Run("anonymous", func(t *testing.T) {
		before := ownedCount(t)
		victim := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, 3, 0, perm_model.AccessModeRead, "read:repository")
		before++
		for _, base := range []string{"/api/v1/repos/user2/repo1/tokens", orgPath, projectPath} {
			post(t, base, "", opts(), http.StatusUnauthorized)
			MakeRequest(t, NewRequest(t, "GET", base), http.StatusUnauthorized)
			MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", base, victim.ID)), http.StatusUnauthorized)
			MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/rotate", base, victim.ID), api.RotateOwnedAccessTokenOption{}), http.StatusUnauthorized)
		}
		// a private repository doesn't show that it has the route
		post(t, repoPath, "", opts(), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", repoPath), http.StatusNotFound)
		assert.Equal(t, before, ownedCount(t))
		assert.Zero(t, unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: victim.ID}).RevokedUnix)
	})

	t.Run("callers that may not manage tokens", func(t *testing.T) {
		before := ownedCount(t)
		// a collaborator with write but no admin, a member who isn't an owner, and a user who can't see the repository
		collaborator := getUserToken(t, "user4", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
		post(t, "/api/v1/repos/user5/repo4/tokens", collaborator, opts(), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user5/repo4/tokens").AddTokenAuth(collaborator), http.StatusForbidden)
		post(t, orgPath, collaborator, opts(), http.StatusForbidden)
		post(t, projectPath, collaborator, opts(), http.StatusForbidden)
		stranger := getUserToken(t, "user8", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
		post(t, repoPath, stranger, opts(), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", repoPath).AddTokenAuth(stranger), http.StatusNotFound)
		post(t, orgPath, stranger, opts(), http.StatusForbidden)
		assert.Equal(t, before, ownedCount(t))

		// a site admin manages the tokens of a repository they don't belong to
		admin := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteRepository)
		var created api.AccessToken
		DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/tokens", opts()).AddTokenAuth(admin), http.StatusCreated), &created)
		assert.Equal(t, "user1", created.CreatedBy)
		assert.EqualValues(t, 1, unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: created.ID}).CreatorID)
	})

	t.Run("credentials that may not manage tokens", func(t *testing.T) {
		before := ownedCount(t)
		publicOnly := getUserToken(t, "user2", auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
		victim := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, 3, 0, perm_model.AccessModeRead, "read:repository")
		before++
		for _, base := range []string{"/api/v1/repos/user2/repo1/tokens", orgPath, projectPath} {
			post(t, base, publicOnly, opts(), http.StatusForbidden)
			MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(publicOnly), http.StatusForbidden)
		}
		// a public-only token doesn't see a private repository at all
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", repoPath, victim.ID)).AddTokenAuth(publicOnly), http.StatusNotFound)
		publicVictim := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, 1, 0, perm_model.AccessModeRead, "read:repository")
		before++
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/repos/user2/repo1/tokens/%d", publicVictim.ID)).AddTokenAuth(publicOnly), http.StatusForbidden)
		MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/user2/repo1/tokens/%d/rotate", publicVictim.ID), api.RotateOwnedAccessTokenOption{}).AddTokenAuth(publicOnly), http.StatusForbidden)
		assert.Equal(t, before, ownedCount(t))
		assert.Zero(t, unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: victim.ID}).RevokedUnix)
		assert.Zero(t, unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: publicVictim.ID}).RevokedUnix)

		// a token of an organization or a repository, with admin on the repository, still can't manage tokens; a
		// project token doesn't even see a repository outside its project
		repoStatus := map[*auth_model.AccessToken]int{
			newOwnedAccessToken(t, auth_model.AccessTokenOwnerOrg, 3, 0, perm_model.AccessModeAdmin, "write:repository"):            http.StatusForbidden,
			newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, 3, 0, perm_model.AccessModeAdmin, "write:repository"):           http.StatusForbidden,
			newOwnedAccessToken(t, auth_model.AccessTokenOwnerProject, 3, group.ID, perm_model.AccessModeAdmin, "write:repository"): http.StatusNotFound,
		}
		before += int64(len(repoStatus))
		for tok, status := range repoStatus {
			post(t, repoPath, tok.Token, opts(), status)
			post(t, orgPath, tok.Token, opts(), http.StatusForbidden)
			post(t, projectPath, tok.Token, opts(), http.StatusForbidden)
		}
		assert.Equal(t, before, ownedCount(t))
	})

	t.Run("a token with less scope", func(t *testing.T) {
		before := ownedCount(t)
		readOnly := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeReadOrganization)
		post(t, repoPath, readOnly, opts(), http.StatusForbidden)
		post(t, orgPath, readOnly, opts(), http.StatusForbidden)
		post(t, projectPath, readOnly, opts(), http.StatusForbidden)
		noOrg := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		post(t, orgPath, noOrg, opts(), http.StatusForbidden)
		post(t, projectPath, noOrg, opts(), http.StatusForbidden)
		assert.Equal(t, before, ownedCount(t))
	})

	t.Run("invalid input", func(t *testing.T) {
		before := ownedCount(t)
		taken := opts()
		post(t, orgPath, owner, taken, http.StatusCreated)
		before++
		post(t, orgPath, owner, taken, http.StatusUnprocessableEntity)
		post(t, projectPath, owner, taken, http.StatusCreated) // the same name under another owner is free
		before++
		post(t, projectPath, owner, taken, http.StatusUnprocessableEntity)
		for _, base := range []string{orgPath, projectPath} {
			blank := opts()
			blank.Name = " "
			post(t, base, owner, blank, http.StatusUnprocessableEntity)
			long := opts()
			long.Name = strings.Repeat("n", 300)
			post(t, base, owner, long, http.StatusUnprocessableEntity)
			bad := opts()
			bad.Permission = "owner"
			post(t, base, owner, bad, http.StatusUnprocessableEntity)
			none := opts()
			none.Scopes = nil
			post(t, base, owner, none, http.StatusUnprocessableEntity)
		}
		assert.Equal(t, before, ownedCount(t))

		// package scopes belong to an organization token covering every repository
		pkg := func(o api.CreateOwnedAccessTokenOption) api.CreateOwnedAccessTokenOption {
			o.Scopes = []string{"read:package"}
			return o
		}
		post(t, repoPath, owner, pkg(opts()), http.StatusUnprocessableEntity)
		post(t, projectPath, owner, pkg(opts()), http.StatusUnprocessableEntity)
		selected := pkg(opts())
		selected.Repositories = []string{"repo3"}
		post(t, orgPath, owner, selected, http.StatusUnprocessableEntity)
		assert.Equal(t, before, ownedCount(t))
		post(t, orgPath, owner, pkg(opts()), http.StatusCreated)
	})

	t.Run("expiry", func(t *testing.T) {
		defer test.MockVariableValue(&setting.AccessTokenExpiry, setting.CredentialExpiryPolicy{Required: true, MaxLifetimeDays: 30})()
		before := ownedCount(t)
		at := func(d time.Duration) *time.Time {
			v := time.Now().Add(d)
			return &v
		}
		for _, base := range []string{repoPath, orgPath, projectPath} {
			none := opts() // required by the policy
			post(t, base, owner, none, http.StatusUnprocessableEntity)
			past := opts()
			past.ExpiresAt = at(-time.Hour)
			post(t, base, owner, past, http.StatusUnprocessableEntity)
			over := opts()
			over.ExpiresAt = at(90 * 24 * time.Hour)
			post(t, base, owner, over, http.StatusUnprocessableEntity)
		}
		assert.Equal(t, before, ownedCount(t))
		ok := opts()
		ok.ExpiresAt = at(10 * 24 * time.Hour)
		post(t, repoPath, owner, ok, http.StatusCreated)
		assert.Equal(t, before+1, ownedCount(t))
	})

	t.Run("rotate", func(t *testing.T) {
		tok := newOwnedAccessToken(t, auth_model.AccessTokenOwnerOrg, 3, 0, perm_model.AccessModeRead, "read:repository")
		project := newOwnedAccessToken(t, auth_model.AccessTokenOwnerProject, 3, group.ID, perm_model.AccessModeRead, "read:repository")
		rotate := func(path string, id int64, token string, status int) *api.AccessToken {
			t.Helper()
			resp := MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/rotate", path, id), api.RotateOwnedAccessTokenOption{}).AddTokenAuth(token), status)
			if status != http.StatusOK {
				return nil
			}
			var out api.AccessToken
			DecodeJSON(t, resp, &out)
			return &out
		}
		// the level decides: an organization token isn't found through the project or the repository
		rotate(projectPath, tok.ID, owner, http.StatusNotFound)
		rotate(repoPath, tok.ID, owner, http.StatusNotFound)
		rotate(orgPath, project.ID, owner, http.StatusNotFound)
		rotate(orgPath, tok.ID, getUserToken(t, "user4", auth_model.AccessTokenScopeWriteOrganization), http.StatusForbidden)

		since := auditMaxID(t)
		rotated := rotate(orgPath, tok.ID, owner, http.StatusOK)
		assert.NotEqual(t, tok.Token, rotated.Token)
		assert.Equal(t, http.StatusUnauthorized, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3").AddTokenAuth(tok.Token), NoExpectedStatus).Code)
		assert.Equal(t, http.StatusOK, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3").AddTokenAuth(rotated.Token), NoExpectedStatus).Code)
		assert.Equal(t, tok.ID, auditOne(t, since, "credential.access_token.rotated").TargetID)

		since = auditMaxID(t)
		rotated = rotate(projectPath, project.ID, owner, http.StatusOK)
		assert.Equal(t, project.ID, rotated.ID)
		assert.Equal(t, project.ID, auditOne(t, since, "credential.access_token.rotated").TargetID)

		// not after the credential that rotates it
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		short := &auth_model.AccessToken{UID: user2.ID, Name: name(), Scope: "write:repository,write:organization", ResourceAllRepos: true, ExpiresUnix: timeutil.TimeStamp(time.Now().Add(time.Hour).Unix())}
		require.NoError(t, auth_model.NewAccessToken(audit_model.WithSystem(db.DefaultContext, "test"), short, nil))
		hash := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: tok.ID}).TokenHash
		rotate(orgPath, tok.ID, short.Token, http.StatusUnprocessableEntity)
		assert.Equal(t, hash, unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: tok.ID}).TokenHash, "nothing was rotated")
	})
}

// LFS with a token of a repository: the mode decides, and another repository's token reaches nothing.
func TestOwnedAccessTokenLFS(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		if !setting.LFS.StartServer {
			t.Skip()
		}
		content := []byte("lfs by an access token")
		p, err := lfs.GeneratePointer(bytes.NewReader(content))
		require.NoError(t, err)
		batch := func(repo, op, token string) (int, *lfs.BatchResponse) {
			t.Helper()
			resp := MakeRequest(t, lfsRequest(t, "POST", "/"+repo+".git/info/lfs/objects/batch", &lfs.BatchRequest{Operation: op, Objects: []lfs.Pointer{p}}).withLFSAuth(token), NoExpectedStatus)
			var br lfs.BatchResponse
			if resp.Code == http.StatusOK {
				require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &br))
			}
			return resp.Code, &br
		}
		writer := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, 3, 0, perm_model.AccessModeWrite, "write:repository")
		reader := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, 3, 0, perm_model.AccessModeRead, "read:repository")
		foreign := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, 5, 0, perm_model.AccessModeWrite, "write:repository")

		status, br := batch("org3/repo3", "upload", writer.Token)
		require.Equal(t, http.StatusOK, status)
		upload := br.Objects[0].Actions["upload"]
		require.NotNil(t, upload)
		MakeRequest(t, NewRequestWithBody(t, "PUT", strings.TrimPrefix(upload.Href, setting.AppURL[:len(setting.AppURL)-1]), bytes.NewReader(content)).withLFSAuth(writer.Token), http.StatusOK)
		unittest.AssertExistsAndLoadBean(t, &git_model.LFSMetaObject{RepositoryID: 3, Pointer: p})

		status, br = batch("org3/repo3", "download", reader.Token)
		require.Equal(t, http.StatusOK, status)
		require.NotNil(t, br.Objects[0].Actions["download"])
		resp := MakeRequest(t, NewRequest(t, "GET", "/org3/repo3.git/info/lfs/objects/"+p.Oid).withLFSAuth(reader.Token), http.StatusOK)
		assert.Equal(t, content, resp.Body.Bytes())

		other := lfs.Pointer{Oid: "83de2e488b89a0aa1c97496b888120a28b0c1e15463a4adb8405578c540f36d4", Size: 6}
		status, _ = func() (int, *lfs.BatchResponse) {
			r := MakeRequest(t, lfsRequest(t, "POST", "/org3/repo3.git/info/lfs/objects/batch", &lfs.BatchRequest{Operation: "upload", Objects: []lfs.Pointer{other}}).withLFSAuth(reader.Token), NoExpectedStatus)
			return r.Code, nil
		}()
		assert.NotEqual(t, http.StatusOK, status, "a read token can't upload")
		unittest.AssertNotExistsBean(t, &git_model.LFSMetaObject{RepositoryID: 3, Pointer: other})

		status, _ = batch("org3/repo3", "download", foreign.Token)
		assert.NotEqual(t, http.StatusOK, status, "another repository's token")
		status, _ = batch("org3/repo3", "download", "")
		assert.NotEqual(t, http.StatusOK, status, "anonymous, the repository is private")

		// a revoked token is refused too
		require.NoError(t, auth_model.DeleteOwnedAccessToken(audit_model.WithSystem(db.DefaultContext, "test"),
			auth_model.FindOwnedAccessTokensOptions{OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 3}, reader.ID, 2))
		status, _ = batch("org3/repo3", "download", reader.Token)
		assert.NotEqual(t, http.StatusOK, status)
	})
}

// The expiry notice cron, run from the admin API: the right people get one mail per stage, and the notification
// setting decides who gets it.
func TestOwnedAccessTokenExpiryNoticeCron(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	require.NotNil(t, setting.MailService)
	type mail struct{ to, subject, body string }
	var sent []mail
	defer test.MockVariableValue(&mailer.SendAsync, func(msgs ...*mailer.Message) {
		for _, m := range msgs {
			sent = append(sent, mail{m.To, m.Subject, m.Body})
		}
	})()
	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	runCron := func(t *testing.T) []mail {
		t.Helper()
		sent = nil
		MakeRequest(t, NewRequest(t, "POST", "/api/v1/admin/cron/credential_expiry_notices").AddTokenAuth(adminToken), http.StatusNoContent)
		return sent
	}
	expiring := func(t *testing.T, ownerType auth_model.AccessTokenOwnerType, ownerID, groupID int64, in time.Duration) *auth_model.AccessToken {
		t.Helper()
		tok := newOwnedAccessToken(t, ownerType, ownerID, groupID, perm_model.AccessModeRead, "read:repository")
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE access_token SET expires_unix = ? WHERE id = ?", timeutil.TimeStampNow().AddDuration(in), tok.ID)
		require.NoError(t, err)
		return tok
	}
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	group, err := repo_model.CreateRepoGroup(audit_model.WithSystem(db.DefaultContext, "test"), org3, "tokens-cron", "")
	require.NoError(t, err)
	repoTok := expiring(t, auth_model.AccessTokenOwnerRepo, 1, 0, 3*24*time.Hour)
	orgTok := expiring(t, auth_model.AccessTokenOwnerOrg, 3, 0, 4*24*time.Hour)
	projectTok := expiring(t, auth_model.AccessTokenOwnerProject, 3, group.ID, 5*24*time.Hour)
	later := expiring(t, auth_model.AccessTokenOwnerOrg, 3, 0, 20*24*time.Hour)
	revoked := expiring(t, auth_model.AccessTokenOwnerRepo, 1, 0, 2*24*time.Hour)
	require.NoError(t, auth_model.DeleteOwnedAccessToken(audit_model.WithSystem(db.DefaultContext, "test"), auth_model.FindOwnedAccessTokensOptions{OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 1}, revoked.ID, 2))

	got := runCron(t)
	bySubject := map[string][]mail{}
	for _, m := range got {
		bySubject[m.subject] = append(bySubject[m.subject], m)
	}
	require.Len(t, bySubject["Access token "+repoTok.Name+" expires in 3 days"], 1, "%v", got)
	assert.Equal(t, `"User Two" <user2@example.com>`, bySubject["Access token "+repoTok.Name+" expires in 3 days"][0].to, "the administrator of user2/repo1")
	assert.Contains(t, bySubject["Access token "+repoTok.Name+" expires in 3 days"][0].body, "/user2/repo1/settings/keys")
	owners := bySubject["Access token "+orgTok.Name+" expires in 4 days"]
	require.NotEmpty(t, owners)
	var recipients []string
	for _, m := range owners {
		recipients = append(recipients, m.to)
		assert.Contains(t, m.body, "/org/org3/settings/keys")
	}
	assert.Contains(t, recipients, `"User Two" <user2@example.com>`, "an owner of org3")
	assert.NotContains(t, strings.Join(recipients, " "), "user4@example.com", "a member who isn't an owner")
	require.NotEmpty(t, bySubject["Access token "+projectTok.Name+" expires in 5 days"])
	assert.Contains(t, bySubject["Access token "+projectTok.Name+" expires in 5 days"][0].body, "/org3/tokens-cron/-/settings/keys")
	for _, m := range got {
		assert.NotContains(t, m.subject, later.Name, "more than a week away")
		assert.NotContains(t, m.subject, revoked.Name, "revoked")
		assert.NotContains(t, m.body, repoTok.Token, "no secret in the mail")
		assert.NotContains(t, m.body, orgTok.Token)
	}
	for _, id := range []int64{repoTok.ID, orgTok.ID, projectTok.ID} {
		unittest.AssertExistsAndLoadBean(t, &auth_model.CredentialExpiryNotice{Kind: "access_token", CredentialID: id, Stage: auth_model.ExpiryNoticeSoon})
	}
	unittest.AssertNotExistsBean(t, &auth_model.CredentialExpiryNotice{Kind: "access_token", CredentialID: later.ID})

	assert.Empty(t, runCron(t), "a second run sends nothing")

	// the last day brings the last-day notice, once
	_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE access_token SET expires_unix = ? WHERE id = ?", timeutil.TimeStampNow().AddDuration(3*time.Hour), repoTok.ID)
	require.NoError(t, err)
	got = runCron(t)
	require.Len(t, got, 1)
	assert.Equal(t, "Access token "+repoTok.Name+" expires within a day", got[0].subject)
	assert.Empty(t, runCron(t))

	// a user who turned the mail off through the settings page or the API gets none, and one who turns it on gets the next
	session := loginUser(t, "user2")
	page := session.MakeRequest(t, NewRequest(t, "GET", "/user/settings/notifications"), http.StatusOK).Body.String()
	assert.Contains(t, page, `name="event_credential_expiry"`)
	userToken := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteUser)
	put := func(on bool) {
		MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/user/settings/notifications", api.NotificationSettings{Preset: "custom", Events: map[string]bool{"credential_expiry": on}}).AddTokenAuth(userToken), http.StatusOK)
	}
	put(false)
	quiet := expiring(t, auth_model.AccessTokenOwnerRepo, 1, 0, 2*24*time.Hour)
	for _, m := range runCron(t) {
		assert.NotContains(t, m.subject, quiet.Name, "user2 turned the mail off, and is the only administrator of the repository")
	}
	put(true)
	loud := expiring(t, auth_model.AccessTokenOwnerRepo, 1, 0, 2*24*time.Hour)
	got = runCron(t)
	require.Len(t, got, 1)
	assert.Equal(t, "Access token "+loud.Name+" expires in 2 days", got[0].subject)

	// the same through the page: a Custom user without the event
	form := url.Values{"preference": {"custom"}}
	req := NewRequestWithBody(t, "POST", "/user/settings/notifications", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	session.MakeRequest(t, req, http.StatusSeeOther)
	s, err := user_model.LoadNotificationSettings(db.DefaultContext, []int64{2}, 0)
	require.NoError(t, err)
	assert.False(t, s[2].Enabled(user_model.NotifyEventCredentialExpiry))
	form.Set("event_credential_expiry", "on")
	req = NewRequestWithBody(t, "POST", "/user/settings/notifications", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	session.MakeRequest(t, req, http.StatusSeeOther)
	s, err = user_model.LoadNotificationSettings(db.DefaultContext, []int64{2}, 0)
	require.NoError(t, err)
	assert.True(t, s[2].Enabled(user_model.NotifyEventCredentialExpiry))
}

// Access tokens in the organization's access report through the API.
func TestOwnedAccessTokenAccessReportAPI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	orgTok := newOwnedAccessToken(t, auth_model.AccessTokenOwnerOrg, 3, 0, perm_model.AccessModeWrite, "write:repository")
	repoTok := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, 3, 0, perm_model.AccessModeRead, "read:repository")
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadOrganization)

	lines, report := jsonLines(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/access-report?type=token").AddTokenAuth(token), http.StatusOK))
	assert.Contains(t, lines, reportLine(orgTok.Name, "org3/repo5", "repo.code", "org_token", ""))
	assert.Contains(t, lines, reportLine(repoTok.Name, "org3/repo3", "repo.code", "repo_token", ""))
	assert.NotContains(t, lines, reportLine(repoTok.Name, "org3/repo5", "repo.code", "repo_token", ""))
	for _, l := range report {
		if l.Name == orgTok.Name {
			assert.Equal(t, []string{"write:repository"}, l.Scopes)
		}
	}
	// a revoked token is no longer a line
	require.NoError(t, auth_model.DeleteOwnedAccessToken(audit_model.WithSystem(db.DefaultContext, "test"), auth_model.FindOwnedAccessTokensOptions{OwnerType: auth_model.AccessTokenOwnerOrg, OwnerID: 3}, orgTok.ID, 2))
	lines, _ = jsonLines(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/access-report?type=token").AddTokenAuth(token), http.StatusOK))
	assert.NotContains(t, strings.Join(lines, "\n"), orgTok.Name)
}

// A token revoked between the moment a push was authenticated and its pre-receive hook can't finish the push, with
// or without a protection rule on the branch.
func TestOwnedAccessTokenPreReceiveRevoked(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	var branch api.Branch
	DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/branches/master").AddTokenAuth(getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)), http.StatusOK), &branch)
	head := branch.Commit.ID
	zero := git.Sha1ObjectFormat.EmptyObjectID().String()
	hook := func(botID int64, ref string) private.ResponseExtra {
		return private.HookPreReceive(t.Context(), repo.ID, private.HookOptions{
			UserID: botID, RefFullNames: []git.RefName{git.RefName(ref)}, OldCommitIDs: []string{zero}, NewCommitIDs: []string{head},
		})
	}
	pb := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "guarded"}
	require.NoError(t, git_model.UpdateProtectBranch(db.DefaultContext, repo, pb, git_model.WhitelistOptions{}))

	for _, ref := range []string{"refs/heads/revoked-open", "refs/heads/guarded"} {
		tok := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, repo.ID, 0, perm_model.AccessModeWrite, "write:repository")
		botID := user_model.AccessTokenBotID(tok.ID)
		require.NoError(t, auth_model.DeleteOwnedAccessToken(audit_model.WithSystem(db.DefaultContext, "test"),
			auth_model.FindOwnedAccessTokensOptions{OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: repo.ID}, tok.ID, 2))
		extra := hook(botID, ref)
		require.Error(t, extra.Error, ref)
		assert.Contains(t, extra.UserMsg, "The access token is no longer valid.", ref)

		// expired is refused the same way
		expired := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, repo.ID, 0, perm_model.AccessModeWrite, "write:repository")
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE access_token SET expires_unix = ? WHERE id = ?", timeutil.TimeStampNow().AddDuration(-time.Hour), expired.ID)
		require.NoError(t, err)
		extra = hook(user_model.AccessTokenBotID(expired.ID), ref)
		require.Error(t, extra.Error, ref)
		assert.Contains(t, extra.UserMsg, "The access token is no longer valid.", ref)
	}
}

// The create form of the Keys and tokens pages: the expiry policy, a package scope at the wrong level, a token that
// rotates itself, and who may open the page.
func TestOwnedAccessTokenWebForm(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	group, err := repo_model.CreateRepoGroup(audit_model.WithSystem(db.DefaultContext, "test"), org3, "tokens-form", "")
	require.NoError(t, err)
	pages := []struct {
		name      string
		link      string
		ownerType auth_model.AccessTokenOwnerType
		ownerID   int64
		groupID   int64
		extra     map[string]string
	}{
		{"repository", "/user2/repo1/settings/keys", auth_model.AccessTokenOwnerRepo, 1, 0, nil},
		{"organization", "/org/org3/settings/keys", auth_model.AccessTokenOwnerOrg, 3, 0, map[string]string{"scope": "all"}},
		{"project", "/org3/tokens-form/-/settings/keys", auth_model.AccessTokenOwnerProject, 3, group.ID, nil},
	}
	form := func(n string, extra map[string]string, kv ...string) map[string]string {
		f := map[string]string{"token_name": n, "token_permission": "read", "token_scopes": "read:repository"}
		maps.Copy(f, extra)
		for i := 0; i < len(kv); i += 2 {
			f[kv[i]] = kv[i+1]
		}
		return f
	}
	count := func(ownerType auth_model.AccessTokenOwnerType, ownerID, groupID int64) int64 {
		n, err := db.GetEngine(db.DefaultContext).Where("owner_type = ? AND owner_id = ? AND group_id = ?", ownerType, ownerID, groupID).Count(new(auth_model.AccessToken))
		require.NoError(t, err)
		return n
	}
	day := func(d int) string { return time.Now().AddDate(0, 0, d).Format("2006-01-02") }

	for _, p := range pages {
		t.Run(p.name, func(t *testing.T) {
			defer test.MockVariableValue(&setting.AccessTokenExpiry, setting.CredentialExpiryPolicy{Required: true, MaxLifetimeDays: 30})()
			before := count(p.ownerType, p.ownerID, p.groupID)
			refuse := func(f map[string]string) {
				t.Helper()
				resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", p.link+"/tokens/new", f), http.StatusOK)
				assert.Equal(t, 1, NewHTMLParser(t, resp.Body).Find("#access-token-error, #access-token-scopes-error").Length(), f["token_name"])
			}
			n := fmt.Sprintf("web-form-%d", tokenCounter.Add(1))
			refuse(form(n, p.extra, "token_expires_at", ""))         // required
			refuse(form(n, p.extra, "token_expires_at", day(-1)))    // past
			refuse(form(n, p.extra, "token_expires_at", day(90)))    // over the maximum
			refuse(form(n, p.extra, "token_expires_at", "tomorrow")) // not a date
			if p.ownerType != auth_model.AccessTokenOwnerOrg {       // an organization token covering every repository may have it
				refuse(form(n, p.extra, "token_expires_at", day(5), "token_scopes", "read:package"))
			}
			refuse(form(strings.Repeat("n", 300), p.extra, "token_expires_at", day(5)))
			refuse(form(n, p.extra, "token_expires_at", day(5), "token_description", strings.Repeat("d", 300)))
			assert.Equal(t, before, count(p.ownerType, p.ownerID, p.groupID), "nothing was created")

			session.MakeRequest(t, NewRequestWithValues(t, "POST", p.link+"/tokens/new", form(n, p.extra, "token_expires_at", day(5), "token_self_rotate", "on", "token_description", " nightly ")), http.StatusSeeOther)
			tok := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{Name: n, OwnerType: p.ownerType, OwnerID: p.ownerID, GroupID: p.groupID})
			assert.True(t, tok.SelfRotate)
			assert.Equal(t, "nightly", tok.Description)
			assert.InDelta(t, time.Now().AddDate(0, 0, 5).Unix(), int64(tok.ExpiresUnix), 2*24*3600, "the date, whatever the time zone")
			assert.Equal(t, before+1, count(p.ownerType, p.ownerID, p.groupID))
		})
	}

	t.Run("package scope on an organization token", func(t *testing.T) {
		n := fmt.Sprintf("web-package-%d", tokenCounter.Add(1))
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/keys/tokens/new", form(n, map[string]string{"scope": "all"}, "token_scopes", "read:package")), http.StatusSeeOther)
		assert.Equal(t, auth_model.AccessTokenScope("read:package"), unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{Name: n, OwnerType: auth_model.AccessTokenOwnerOrg, OwnerID: 3}).Scope)
		n = fmt.Sprintf("web-package-%d", tokenCounter.Add(1))
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/keys/tokens/new", form(n, map[string]string{"scope": "selected", "repo_ids": "3"}, "token_scopes", "read:package")), http.StatusOK)
		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{Name: n, OwnerType: auth_model.AccessTokenOwnerOrg, OwnerID: 3})
	})

	t.Run("who may open the pages", func(t *testing.T) {
		// a collaborator with write, a member who isn't an owner, a stranger and anonymous
		for _, c := range []struct {
			user, link string
		}{
			{"user4", "/user5/repo4/settings/keys"},
			{"user4", "/org/org3/settings/keys"},
			{"user4", "/org3/tokens-form/-/settings/keys"},
			{"user8", "/org3/repo3/settings/keys"},
		} {
			s := loginUser(t, c.user)
			s.MakeRequest(t, NewRequest(t, "GET", c.link), http.StatusNotFound)
			before, err := db.GetEngine(db.DefaultContext).Count(new(auth_model.AccessToken))
			require.NoError(t, err)
			s.MakeRequest(t, NewRequestWithValues(t, "POST", c.link+"/tokens/new", form("denied", map[string]string{"scope": "all"})), http.StatusNotFound)
			after, err := db.GetEngine(db.DefaultContext).Count(new(auth_model.AccessToken))
			require.NoError(t, err)
			assert.Equal(t, before, after, c.user+" "+c.link)
		}
		for _, link := range []string{"/user2/repo1/settings/keys", "/org/org3/settings/keys"} {
			resp := MakeRequest(t, NewRequest(t, "GET", link), http.StatusSeeOther)
			assert.Contains(t, resp.Header().Get("Location"), "/user/login")
			MakeRequest(t, NewRequestWithValues(t, "POST", link+"/tokens/new", form("denied", map[string]string{"scope": "all"})), http.StatusSeeOther)
		}
		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{Name: "denied"})

		// a site admin manages the tokens of any repository
		admin := loginUser(t, "user1")
		n := fmt.Sprintf("web-admin-%d", tokenCounter.Add(1))
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/repo3/settings/keys/tokens/new", form(n, nil)), http.StatusSeeOther)
		assert.EqualValues(t, 1, unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{Name: n, OwnerType: auth_model.AccessTokenOwnerRepo, OwnerID: 3}).CreatorID)
	})
}

// A token whose stored scopes are no longer allowed is not rotated, whichever way it is asked for.
func TestOwnedAccessTokenRotateRefusedForStoredScope(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")
	owner := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
	tok := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, 1, 0, perm_model.AccessModeRead, "read:repository")
	_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE access_token SET scope = 'all' WHERE id = ?", tok.ID)
	require.NoError(t, err)
	hash := unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: tok.ID}).TokenHash
	since := auditMaxID(t)

	MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/user2/repo1/tokens/%d/rotate", tok.ID), api.RotateOwnedAccessTokenOption{}).AddTokenAuth(owner), http.StatusUnprocessableEntity)
	resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/keys/tokens/rotate", map[string]string{"id": fmt.Sprint(tok.ID)}), http.StatusSeeOther)
	assert.Contains(t, resp.Header().Get("Location"), "/user2/repo1/settings/keys")
	page := NewHTMLParser(t, session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/keys"), http.StatusOK).Body)
	assert.Contains(t, page.Find(".flash-error").Text(), "scope")

	assert.Equal(t, hash, unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: tok.ID}).TokenHash, "nothing was rotated")
	assert.Empty(t, auditSince(t, since), "and nothing recorded")
}

// Deleting what a token belongs to deletes the token, and nothing else's.
func TestOwnedAccessTokenDeletedWithOwner(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	sys := audit_model.WithSystem(db.DefaultContext, "test")
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	use := func(path, token string) int {
		return MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), NoExpectedStatus).Code
	}

	t.Run("repository", func(t *testing.T) {
		repo, err := repo_service.CreateRepository(db.DefaultContext, user2, user2, repo_service.CreateRepoOptions{Name: "token-owner", Readme: "Default", AutoInit: true, DefaultBranch: "main"})
		require.NoError(t, err)
		tok := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, repo.ID, 0, perm_model.AccessModeRead, "read:repository")
		other := newOwnedAccessToken(t, auth_model.AccessTokenOwnerRepo, 1, 0, perm_model.AccessModeRead, "read:repository")
		assert.Equal(t, http.StatusOK, use("/api/v1/repos/user2/token-owner", tok.Token))
		require.NoError(t, repo_service.DeleteRepositoryPermanently(sys, user2, repo, false))
		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{ID: tok.ID})
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: other.ID})
		assert.Equal(t, http.StatusUnauthorized, use("/api/v1/repos/user2/repo1", tok.Token))
	})

	t.Run("project", func(t *testing.T) {
		org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
		group, err := repo_model.CreateRepoGroup(sys, org3, "token-owner-project", "")
		require.NoError(t, err)
		keep, err := repo_model.CreateRepoGroup(sys, org3, "token-keeper-project", "")
		require.NoError(t, err)
		tok := newOwnedAccessToken(t, auth_model.AccessTokenOwnerProject, 3, group.ID, perm_model.AccessModeRead, "read:repository")
		kept := newOwnedAccessToken(t, auth_model.AccessTokenOwnerProject, 3, keep.ID, perm_model.AccessModeRead, "read:repository")
		orgTok := newOwnedAccessToken(t, auth_model.AccessTokenOwnerOrg, 3, 0, perm_model.AccessModeRead, "read:repository")
		require.NoError(t, repo_service.DeleteRepoGroup(sys, org3, group))
		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{ID: tok.ID})
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: kept.ID})
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: orgTok.ID})
	})

	t.Run("organization", func(t *testing.T) {
		org := &organization.Organization{Name: "token-owner-org"}
		require.NoError(t, organization.CreateOrganization(db.DefaultContext, org, user2))
		group, err := repo_model.CreateRepoGroup(sys, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: org.ID}), "p", "")
		require.NoError(t, err)
		orgTok := newOwnedAccessToken(t, auth_model.AccessTokenOwnerOrg, org.ID, 0, perm_model.AccessModeRead, "read:repository")
		projectTok := newOwnedAccessToken(t, auth_model.AccessTokenOwnerProject, org.ID, group.ID, perm_model.AccessModeRead, "read:repository")
		other := newOwnedAccessToken(t, auth_model.AccessTokenOwnerOrg, 3, 0, perm_model.AccessModeRead, "read:repository")
		require.NoError(t, org_service.DeleteOrganization(sys, org, true))
		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{ID: orgTok.ID})
		unittest.AssertNotExistsBean(t, &auth_model.AccessToken{ID: projectTok.ID})
		unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: other.ID})
		assert.Equal(t, http.StatusUnauthorized, use("/api/v1/repos/org3/repo3", orgTok.Token))
	})
}
