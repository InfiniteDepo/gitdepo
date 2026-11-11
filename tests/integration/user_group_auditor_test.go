// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	asymkey_model "forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/lfs"
	"forgejo.org/modules/private"
	"forgejo.org/modules/storage"
	api "forgejo.org/modules/structs"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// orgMemberNames lists the members of an organization as the API returns them for the token.
func orgMemberNames(t *testing.T, link, token string) []string {
	t.Helper()
	var members []*api.User
	DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", link).AddTokenAuth(token), http.StatusOK), &members)
	names := make([]string, 0, len(members))
	for _, m := range members {
		names = append(names, m.UserName)
	}
	return names
}

// TestAuditorRole checks that a member of a user group granting the auditor role can read every repository and see
// private organizations, and that the role never lets them change anything.
func TestAuditorRole(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		ctx := db.DefaultContext

		// user2/repo1 has issues, pulls, releases, attachments and a wiki: make it private so that all of it is.
		repo1 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		repo1.IsPrivate = true
		require.NoError(t, repo_model.UpdateRepositoryCols(ctx, repo1, "is_private"))

		// user8 is in no organization and collaborates on nothing
		auditor := loginUser(t, "user8")
		auditor.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1"), http.StatusNotFound)
		auditor.MakeRequest(t, NewRequest(t, "GET", "/privated_org"), http.StatusNotFound)
		resp := auditor.MakeRequest(t, NewRequest(t, "GET", "/org/org3/members"), http.StatusOK)
		assert.NotContains(t, resp.Body.String(), `href="/user4"`, "user4 is a concealed member of org3")

		adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
		resp = MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/groups", &api.CreateUserGroupOption{
			Name:          "auditors",
			GrantsAuditor: true,
		}).AddTokenAuth(adminToken), http.StatusCreated)
		var apiGroup api.UserGroup
		DecodeJSON(t, resp, &apiGroup)
		assert.True(t, apiGroup.GrantsAuditor)
		MakeRequest(t, NewRequest(t, "PUT", "/api/v1/admin/groups/auditors/members/user8").AddTokenAuth(adminToken), http.StatusNoContent)
		user8 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8})
		assert.True(t, user8.IsAuditor)
		assert.False(t, user8.IsAdmin)

		group := unittest.AssertExistsAndLoadBean(t, &organization.UserGroup{LowerName: "auditors"})
		resp = loginUser(t, "user1").MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/admin/groups/%d", group.ID)), http.StatusOK)
		NewHTMLParser(t, resp.Body).AssertElement(t, `input[name="grants_auditor"][checked]`, true)

		t.Run("reads every repository", func(t *testing.T) {
			for _, link := range []string{
				"/user2/repo1",
				"/user2/repo1/src/branch/master/README.md",
				"/user2/repo1/raw/branch/master/README.md",
				"/user2/repo1/commits/branch/master",
				"/user2/repo1/issues",
				"/user2/repo1/issues/1",
				"/user2/repo1/pulls/2",
				"/user2/repo1/pulls/2/files",
				"/user2/repo1/releases",
				"/user2/repo1/wiki",
				"/org3/repo3",
				"/privated_org/private_repo_on_private_org",
			} {
				auditor.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
			}

			// an issue attachment of the private user2/repo2
			attachment := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12"
			_, err := storage.Attachments.Save(repo_model.AttachmentRelativePath(attachment), strings.NewReader("audit"), -1)
			require.NoError(t, err)
			auditor.MakeRequest(t, NewRequest(t, "GET", "/attachments/"+attachment), http.StatusOK)
		})

		t.Run("disabled units stay inaccessible", func(t *testing.T) {
			// user2/repo2 has no pull requests unit, privated_org/public_repo_on_private_org no releases unit
			auditor.MakeRequest(t, NewRequest(t, "GET", "/user2/repo2/pulls"), http.StatusNotFound)
			auditor.MakeRequest(t, NewRequest(t, "GET", "/privated_org/public_repo_on_private_org/releases"), http.StatusNotFound)
			attachment := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a21" // of a release of public_repo_on_private_org
			_, err := storage.Attachments.Save(repo_model.AttachmentRelativePath(attachment), strings.NewReader("audit"), -1)
			require.NoError(t, err)
			auditor.MakeRequest(t, NewRequest(t, "GET", "/attachments/"+attachment), http.StatusNotFound)
		})

		t.Run("sees private organizations, not their teams", func(t *testing.T) {
			resp := auditor.MakeRequest(t, NewRequest(t, "GET", "/privated_org"), http.StatusOK)
			assert.Contains(t, resp.Body.String(), "private_repo_on_private_org")
			auditor.MakeRequest(t, NewRequest(t, "GET", "/org/privated_org/members"), http.StatusOK)
			resp = auditor.MakeRequest(t, NewRequest(t, "GET", "/org/org3/members"), http.StatusOK)
			assert.Contains(t, resp.Body.String(), `href="/user4"`)
			resp = auditor.MakeRequest(t, NewRequest(t, "GET", "/explore/repos?q=private_repo_on_private_org"), http.StatusOK)
			assert.Contains(t, resp.Body.String(), "privated_org/private_repo_on_private_org")

			auditor.MakeRequest(t, NewRequest(t, "GET", "/org/privated_org/dashboard"), http.StatusNotFound)
			auditor.MakeRequest(t, NewRequest(t, "GET", "/org/org3/teams"), http.StatusNotFound)
		})

		t.Run("no settings or admin pages", func(t *testing.T) {
			for _, link := range []string{
				"/user2/repo1/settings",
				"/user2/repo1/settings/hooks",
				"/user2/repo1/settings/keys",
				"/user2/repo1/settings/actions/secrets",
				"/org/org3/settings",
				"/org/privated_org/settings",
			} {
				auditor.MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound)
			}
			auditor.MakeRequest(t, NewRequest(t, "GET", "/admin"), http.StatusForbidden)
		})

		countWrites := func() []int {
			return []int{
				unittest.GetCount(t, &issues_model.Comment{}),
				unittest.GetCount(t, &issues_model.Issue{}),
				unittest.GetCount(t, &repo_model.Star{UID: 8}),
				unittest.GetCount(t, &repo_model.Watch{UserID: 8}),
				unittest.GetCount(t, &repo_model.Repository{OwnerID: 8}),
			}
		}

		t.Run("web writes are refused", func(t *testing.T) {
			before := countWrites()
			for link, values := range map[string]map[string]string{
				"/user2/repo1/issues/new":               {"title": "audit"},
				"/user2/repo1/issues/1/comments":        {"content": "audit"},
				"/user2/repo1/issues/1/reactions/react": {"content": "+1"},
				"/user2/repo1/issues/1/watch":           {"watch": "1"},
				"/user2/repo1/action/star":              {},
				"/user2/repo1/action/watch":             {},
				"/user2/repo1/fork":                     {"uid": "8", "repo_name": "audit"},
				"/user2/repo1/_new/master/":             {"tree_path": "audit.txt", "content": "audit", "commit_choice": "direct"},
				"/user2/repo1/releases/new":             {"tag_name": "audit", "tag_target": "master", "title": "audit"},
				"/user2/repo1/wiki?action=_new":         {"title": "audit", "content": "audit"},
				"/user2/repo1/compare/master...branch2": {"title": "audit"},
				"/user2/repo1/pulls/2/merge":            {"do": "merge"},
			} {
				auditor.MakeRequest(t, NewRequestWithValues(t, "POST", link, values), http.StatusNotFound)
			}
			assert.Equal(t, before, countWrites())
		})

		token := getUserToken(t, "user8", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteIssue,
			auth_model.AccessTokenScopeWriteUser, auth_model.AccessTokenScopeReadOrganization)

		t.Run("API reads", func(t *testing.T) {
			for _, link := range []string{
				"/api/v1/repos/user2/repo1",
				"/api/v1/repos/user2/repo1/contents/README.md",
				"/api/v1/repos/user2/repo1/issues/1",
				"/api/v1/orgs/privated_org",
			} {
				MakeRequest(t, NewRequest(t, "GET", link).AddTokenAuth(token), http.StatusOK)
			}
			resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/search?q=private_repo_on_private_org").AddTokenAuth(token), http.StatusOK)
			var result api.SearchResults
			DecodeJSON(t, resp, &result)
			assert.Len(t, result.Data, 1)

			// user4 is a concealed member of org3
			assert.Contains(t, orgMemberNames(t, "/api/v1/orgs/org3/members", token), "user4")
			assert.NotContains(t, orgMemberNames(t, "/api/v1/orgs/org3/public_members", token), "user4")

			publicOnly := getUserToken(t, "user8", auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeReadRepository)
			resp = MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1").AddTokenAuth(publicOnly), NoExpectedStatus)
			assert.NotEqual(t, http.StatusOK, resp.Code)
		})

		t.Run("API writes are refused", func(t *testing.T) {
			before := countWrites()
			for _, req := range []*RequestWrapper{
				NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/issues", &api.CreateIssueOption{Title: "audit"}),
				NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/issues/1/comments", &api.CreateIssueCommentOption{Body: "audit"}),
				NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/issues/1/reactions", &api.EditReactionOption{Reaction: "+1"}),
				NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/forks", &api.CreateForkOption{}),
				NewRequest(t, "PUT", "/api/v1/user/starred/user2/repo1"),
				NewRequest(t, "PUT", "/api/v1/repos/user2/repo1/subscription"),
				NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/audit.txt", &api.CreateFileOptions{ContentBase64: "YXVkaXQ="}),
				NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", &api.EditRepoOption{}),
				NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1"),
			} {
				MakeRequest(t, req.AddTokenAuth(token), http.StatusNotFound)
			}
			assert.Equal(t, before, countWrites())
			unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		})

		t.Run("credentials held by others get no raise", func(t *testing.T) {
			oauthToken := createOAuth2Token(t, auditor, []auth_model.AccessTokenScope{auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeReadOrganization})
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3").AddTokenAuth(oauthToken), http.StatusNotFound)
			assert.NotContains(t, orgMemberNames(t, "/api/v1/orgs/org3/members", oauthToken), "user4")
		})

		t.Run("git clone, no push", func(t *testing.T) {
			withAuditor := func(path string) *url.URL {
				u := *u
				u.Path = path
				u.User = url.UserPassword("user8", userPassword)
				return &u
			}
			dstPath := filepath.Join(t.TempDir(), "repo1")
			doGitClone(dstPath, withAuditor("/user2/repo1.git"))(t)
			require.NoError(t, git.Clone(t.Context(), withAuditor("/user2/repo1.wiki.git").String(), t.TempDir(), git.CloneRepoOptions{}))
			doGitClone(filepath.Join(t.TempDir(), "repo3"), withAuditor("/org3/repo3.git"))(t)

			doGitAddSomeCommits(dstPath, "master")(t)
			doGitPushTestRepositoryFail(t, dstPath, "origin", "master")
			doGitPushTestRepositoryFail(t, dstPath, "origin", "HEAD:refs/for/master/audit")
			unittest.AssertNotExistsBean(t, &issues_model.PullRequest{HeadBranch: "audit", BaseRepoID: 1})
		})

		t.Run("ssh serv: upload-pack, no receive-pack", func(t *testing.T) {
			key, err := asymkey_model.AddPublicKey(audit_model.WithSystem(ctx, "test"), 8, "auditor", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINDRDoephkaFELacrNNe2fqAwedhRB1MKOpLEHlPuczO nocomment", 0, 0)
			require.NoError(t, err)
			_, extra := private.ServCommand(ctx, key.ID, "user2", "repo1", perm.AccessModeRead, "", "git-upload-pack", "")
			require.NoError(t, extra.Error)
			_, extra = private.ServCommand(ctx, key.ID, "user2", "repo1", perm.AccessModeWrite, "", "git-receive-pack", "")
			require.Error(t, extra.Error)
		})

		t.Run("LFS download, no upload", func(t *testing.T) {
			lfsRequest := func(operation string) *RequestWrapper {
				req := NewRequestWithJSON(t, "POST", "/user2/repo1.git/info/lfs/objects/batch", &lfs.BatchRequest{
					Operation: operation,
					Objects:   []lfs.Pointer{{Oid: "83de2e488b89a0aa1c97496b888120a28b0c1e15463a4adb8405578c540f36d4", Size: 6}},
				}).SetHeader("Accept", lfs.AcceptHeader).SetHeader("Content-Type", lfs.MediaType)
				req.Request.SetBasicAuth("user8", token)
				return req
			}
			MakeRequest(t, lfsRequest("download"), http.StatusOK)
			MakeRequest(t, lfsRequest("upload"), http.StatusUnauthorized)
		})

		t.Run("own permissions still apply", func(t *testing.T) {
			resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "audit-notes"}).AddTokenAuth(token), http.StatusCreated)
			var repo api.Repository
			DecodeJSON(t, resp, &repo)

			// a cross-reference to a repository read through the role is not recorded
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user8/audit-notes/issues", &api.CreateIssueOption{
				Title: "notes",
				Body:  "see user2/repo1#1",
			}).AddTokenAuth(token), http.StatusCreated)
			unittest.AssertNotExistsBean(t, &issues_model.Comment{IssueID: 1, PosterID: 8, Type: issues_model.CommentTypeIssueRef})
		})

		t.Run("leaving the group ends the role", func(t *testing.T) {
			MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/admin/groups/auditors/members/user8").AddTokenAuth(adminToken), http.StatusNoContent)
			assert.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 8}).IsAuditor)
			auditor.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1"), http.StatusNotFound)
			auditor.MakeRequest(t, NewRequest(t, "GET", "/privated_org"), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1").AddTokenAuth(token), http.StatusNotFound)
		})
	})
}
