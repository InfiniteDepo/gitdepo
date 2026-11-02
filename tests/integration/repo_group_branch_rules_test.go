// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/private"
	api "forgejo.org/modules/structs"
	"forgejo.org/services/forms"
	repo_service "forgejo.org/services/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Org owners manage the branch rules of a project on its settings page; the rules bind every repository of the
// project, together with the organization's and the repository's own rules, and nobody below an owner is exempt.
func TestRepoGroupBranchRules(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		f, rootPub := prepareRepoGroupGit(t)
		ctx := t.Context()
		owner := loginUser(t, "user2")
		member := loginUser(t, "user4")
		adminMember := loginUser(t, "user28") // team 12, admin, linked to the project below
		proj, err := repo_model.GetRepoGroupByName(db.DefaultContext, f.org.ID, "proj")
		require.NoError(t, err)
		secret, err := repo_model.GetRepoGroupByName(db.DefaultContext, f.org.ID, "secret")
		require.NoError(t, err)
		admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		require.NoError(t, repo_service.LinkTeamToRepoGroup(db.DefaultContext, admin, organization.OrgFromUser(f.org), 12, proj.ID))
		editLink := "/org3/proj/-/settings/branches/edit"

		t.Run("only owners manage the rules", func(t *testing.T) {
			for _, session := range []*TestSession{member, adminMember} {
				session.MakeRequest(t, NewRequest(t, "GET", editLink), http.StatusNotFound)
				session.MakeRequest(t, NewRequestWithValues(t, "POST", editLink, map[string]string{"rule_name": "main"}), http.StatusNotFound)
			}
			resp := owner.MakeRequest(t, NewRequest(t, "GET", editLink), http.StatusOK)
			assert.NotContains(t, resp.Body.String(), `name="apply_to_selected_repos"`, "a project rule covers the whole project")

			_, err := db.GetEngine(db.DefaultContext).ID(f.org.ID).Cols("is_archived").Update(&user_model.User{IsArchived: true})
			require.NoError(t, err)
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", editLink, map[string]string{"rule_name": "main"}), http.StatusForbidden)
			_, err = db.GetEngine(db.DefaultContext).ID(f.org.ID).Cols("is_archived").Update(&user_model.User{IsArchived: false})
			require.NoError(t, err)
			unittest.AssertNotExistsBean(t, &git_model.ProtectedBranch{GroupID: proj.ID})

			resp = owner.MakeRequest(t, NewRequestWithValues(t, "POST", editLink, map[string]string{
				"rule_name": "main", "required_approvals": "1", "apply_to_admins": "on",
			}), http.StatusSeeOther)
			assert.Equal(t, "/org3/proj/-/settings", resp.Header().Get("Location"))
			unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{RepoID: 0, OrgID: f.org.ID, GroupID: proj.ID, RuleName: "main"})
			resp = owner.MakeRequest(t, NewRequest(t, "GET", "/org3/proj/-/settings"), http.StatusOK)
			assert.Contains(t, resp.Body.String(), `data-url="/org3/proj/-/settings/branches/`)
		})
		rule := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{OrgID: f.org.ID, GroupID: proj.ID, RuleName: "main"})

		t.Run("rules of other levels are not found", func(t *testing.T) {
			orgRule := &git_model.ProtectedBranch{RuleName: "dev"}
			require.NoError(t, git_model.UpdateOrgProtectBranch(db.DefaultContext, f.org.ID, 0, orgRule, git_model.WhitelistOptions{}, nil))
			secretRule := &git_model.ProtectedBranch{RuleName: "dev"}
			require.NoError(t, git_model.UpdateOrgProtectBranch(db.DefaultContext, f.org.ID, secret.ID, secretRule, git_model.WhitelistOptions{}, nil))
			for _, id := range []int64{orgRule.ID, secretRule.ID} {
				owner.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/org3/proj/-/settings/branches/%d/delete", id)), http.StatusNotFound)
				owner.MakeRequest(t, NewRequestWithValues(t, "POST", editLink, map[string]string{"rule_id": strconv.FormatInt(id, 10), "rule_name": "x"}), http.StatusNotFound)
			}
			owner.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/org/org3/settings/branches/%d/delete", rule.ID)), http.StatusNotFound)
			member.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/org3/proj/-/settings/branches/%d/delete", rule.ID)), http.StatusNotFound)
			unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: rule.ID})
			require.NoError(t, git_model.DeleteOrgProtectedBranch(db.DefaultContext, f.org.ID, 0, orgRule.ID))
		})

		t.Run("the organization API never reaches a project rule", func(t *testing.T) {
			token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteOrganization)
			orgRule := &git_model.ProtectedBranch{RuleName: "main"}
			require.NoError(t, git_model.UpdateOrgProtectBranch(db.DefaultContext, f.org.ID, 0, orgRule, git_model.WhitelistOptions{}, nil))
			five := int64(5)
			var rules []*api.OrgBranchProtection
			DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/branch_protections").AddTokenAuth(token), http.StatusOK), &rules)
			names := []string{}
			for _, r := range rules {
				names = append(names, r.RuleName)
			}
			assert.Equal(t, []string{"main"}, names, "only the organization's own rule, not those of proj and secret")
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/orgs/org3/branch_protections/main", &api.EditOrgBranchProtectionOption{
				EditBranchProtectionOption: api.EditBranchProtectionOption{RequiredApprovals: &five},
			}).AddTokenAuth(token), http.StatusOK)
			MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/orgs/org3/branch_protections/main").AddTokenAuth(token), http.StatusNoContent)
			unittest.AssertNotExistsBean(t, &git_model.ProtectedBranch{ID: orgRule.ID})
			assert.EqualValues(t, 1, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: rule.ID}).RequiredApprovals)
		})

		t.Run("the repository settings list the project rule", func(t *testing.T) {
			resp := owner.MakeRequest(t, NewRequest(t, "GET", "/org3/proj/priv/settings/branches"), http.StatusOK)
			assert.Contains(t, resp.Body.String(), "Project proj")
		})

		t.Run("push", func(t *testing.T) {
			token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository)
			clone := *u
			clone.Path = "/org3/proj/pub.git"
			clone.User = url.UserPassword("user2", token)
			dir := t.TempDir()
			doGitClone(dir, &clone)(t)
			doGitAddSomeCommits(dir, "main")(t)
			assert.Contains(t, doGitPushTestRepositoryFail(t, dir, "origin", "main"), "protected branch")

			push := func(userID, repoID int64) private.ResponseExtra {
				return private.HookPreReceive(ctx, repoID, private.HookOptions{UserID: userID, OldCommitIDs: []string{git.Sha1ObjectFormat.EmptyObjectID().String()}, NewCommitIDs: []string{branchCommit(t, repoID)}, RefFullNames: []git.RefName{"refs/heads/main"}})
			}
			require.NoError(t, push(2, rootPub.ID).Error, "a root repository has no project rule")
			for _, userID := range []int64{2, 28} { // the owner, a project admin
				extra := push(userID, f.priv.ID)
				require.Error(t, extra.Error, userID)
				assert.Contains(t, extra.UserMsg, "protected branch", userID)
			}

			// the rule follows the repository
			priv := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: f.priv.ID})
			require.NoError(t, repo_service.MoveRepository(db.DefaultContext, admin, priv, 0))
			require.NoError(t, push(2, f.priv.ID).Error)
			require.NoError(t, repo_service.MoveRepository(db.DefaultContext, admin, priv, proj.ID))
			require.Error(t, push(2, f.priv.ID).Error)
		})

		t.Run("merge", func(t *testing.T) {
			token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository)
			call := func(method, path string, body any, status int) *httptest.ResponseRecorder {
				return MakeRequest(t, NewRequestWithJSON(t, method, "/api/v1/repos/org3/proj/priv/-"+path, body).AddTokenAuth(token), status)
			}
			call("POST", "/branches", &api.CreateBranchRepoOption{BranchName: "feat", OldBranchName: "main"}, http.StatusCreated)
			call("POST", "/contents/feat.txt", &api.CreateFileOptions{FileOptions: api.FileOptions{BranchName: "feat"}, ContentBase64: base64.StdEncoding.EncodeToString([]byte("feat"))}, http.StatusCreated)
			var pr api.PullRequest
			DecodeJSON(t, call("POST", "/pulls", &api.CreatePullRequestOption{Head: "feat", Base: "main", Title: "feat"}, http.StatusCreated), &pr)
			merge := func(session *TestSession, status int) *httptest.ResponseRecorder {
				token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
				req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/org3/proj/priv/-/pulls/%d/merge", pr.Index),
					&forms.MergePullRequestForm{Do: "merge", ForceMerge: true}).AddTokenAuth(token)
				return MakeRequest(t, req, status)
			}
			// with "apply to admins" nobody skips the required approval
			assert.Contains(t, merge(owner, http.StatusMethodNotAllowed).Body.String(), "Does not have enough approvals")
			_, err := db.GetEngine(db.DefaultContext).ID(rule.ID).Cols("apply_to_admins").Update(&git_model.ProtectedBranch{})
			require.NoError(t, err)
			// without it an owner may, a project admin still not
			assert.Contains(t, merge(adminMember, http.StatusMethodNotAllowed).Body.String(), "Does not have enough approvals")
			merge(owner, http.StatusOK)

			owner.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/org3/proj/-/settings/branches/%d/delete", rule.ID)), http.StatusOK)
			unittest.AssertNotExistsBean(t, &git_model.ProtectedBranch{ID: rule.ID})
		})

		t.Run("moving a repository in re-checks its pull requests", func(t *testing.T) {
			require.NoError(t, git_model.UpdateOrgProtectBranch(db.DefaultContext, f.org.ID, proj.ID,
				&git_model.ProtectedBranch{RuleName: "main", ProtectedFilePatterns: "secret.txt"}, git_model.WhitelistOptions{}, nil))
			repo, err := repo_service.CreateRepository(db.DefaultContext, admin, f.org, repo_service.CreateRepoOptions{
				Name: "moved", Readme: "Default", AutoInit: true, DefaultBranch: "main",
			})
			require.NoError(t, err)
			token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository)
			call := func(base, path string, body any, status int) *httptest.ResponseRecorder {
				return MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/"+base+path, body).AddTokenAuth(token), status)
			}
			call("org3/moved", "/branches", &api.CreateBranchRepoOption{BranchName: "feat", OldBranchName: "main"}, http.StatusCreated)
			call("org3/moved", "/contents/secret.txt", &api.CreateFileOptions{FileOptions: api.FileOptions{BranchName: "feat"}, ContentBase64: base64.StdEncoding.EncodeToString([]byte("s"))}, http.StatusCreated)
			var pr api.PullRequest
			DecodeJSON(t, call("org3/moved", "/pulls", &api.CreatePullRequestOption{Head: "feat", Base: "main", Title: "feat"}, http.StatusCreated), &pr)

			// no push after the move: the protected file is still found
			require.NoError(t, repo_service.MoveRepository(db.DefaultContext, admin, repo, proj.ID))
			resp := call("org3/proj/moved/-", fmt.Sprintf("/pulls/%d/merge", pr.Index), &forms.MergePullRequestForm{Do: "merge"}, http.StatusMethodNotAllowed)
			assert.Contains(t, resp.Body.String(), "Changed protected files")
		})
	})
}
