// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/perm"
	api "forgejo.org/modules/structs"
	"forgejo.org/services/forms"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// orgRuleEnv works on organization rules of org3, whose owner is user2. user4 is a member of org3,
// user5 and user8 are not.
type orgRuleEnv struct {
	t     *testing.T
	owner APITestContext
}

func newOrgRuleEnv(t *testing.T) *orgRuleEnv {
	return &orgRuleEnv{t: t, owner: NewAPITestContext(t, "user2", "", auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)}
}

// rule sends a request to /orgs/org3/branch_protections[/name] as ctx and decodes an OK answer.
func (e *orgRuleEnv) rule(ctx APITestContext, method, name string, body any, expected int) *api.OrgBranchProtection {
	e.t.Helper()
	link := "/api/v1/orgs/org3/branch_protections"
	if name != "" {
		link += "/" + url.PathEscape(name)
	}
	req := NewRequestWithJSON(e.t, method, link, body).AddTokenAuth(ctx.Token)
	resp := ctx.Session.MakeRequest(e.t, req, expected)
	if expected != http.StatusOK && expected != http.StatusCreated {
		return nil
	}
	var bp api.OrgBranchProtection
	DecodeJSON(e.t, resp, &bp)
	return &bp
}

// create creates an organization rule and deletes it when the test ends.
func (e *orgRuleEnv) create(opts api.CreateOrgBranchProtectionOption) {
	e.t.Helper()
	e.rule(e.owner, "POST", "", opts, http.StatusCreated)
	e.t.Cleanup(func() { e.rule(e.owner, "DELETE", opts.RuleName, nil, http.StatusNoContent) })
}

// repo creates org3/name with collaborators and returns a context for it.
func (e *orgRuleEnv) repo(name string, collaborators map[string]perm.AccessMode) APITestContext {
	e.t.Helper()
	bwRepo(e.t, name)
	ctx := e.owner
	ctx.Username, ctx.Reponame = "org3", name
	for user, mode := range collaborators {
		doAPIAddCollaborator(ctx, user, mode)(e.t)
	}
	return ctx
}

func (e *orgRuleEnv) repoRule(repo string, opts api.CreateBranchProtectionOption) {
	e.t.Helper()
	req := NewRequestWithJSON(e.t, "POST", fmt.Sprintf("/api/v1/repos/org3/%s/branch_protections", repo), opts).AddTokenAuth(e.owner.Token)
	e.owner.Session.MakeRequest(e.t, req, http.StatusCreated)
}

func userCtx(t *testing.T, user string, scopes ...auth_model.AccessTokenScope) APITestContext {
	return NewAPITestContext(t, user, "", scopes...)
}

// AC1 (API part), AC8, AC13: only owners manage organization rules, which only reference the organization.
func TestAPIOrgBranchProtection(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	e := newOrgRuleEnv(t)
	bwRepo(t, "obp-api")

	e.create(api.CreateOrgBranchProtectionOption{
		CreateBranchProtectionOption: api.CreateBranchProtectionOption{
			RuleName: "obp-api/*", EnablePush: true, EnablePushWhitelist: true, PushWhitelistUsernames: []string{"user4"},
			PushWhitelistTeams: []string{"team1"}, RequiredApprovals: 2, BlockOnIncompleteTasks: true,
			ApprovalRules: []*api.ApprovalRule{{Name: "Security", RequiredCount: 1, Usernames: []string{"user2"}}},
		},
		ApplyToSelectedRepos: true, Repos: []string{"obp-api"},
	})

	bp := e.rule(e.owner, "GET", "obp-api/*", nil, http.StatusOK)
	assert.Equal(t, []string{"user4"}, bp.PushWhitelistUsernames)
	assert.Equal(t, []string{"team1"}, bp.PushWhitelistTeams)
	assert.EqualValues(t, 2, bp.RequiredApprovals)
	assert.True(t, bp.BlockOnIncompleteTasks)
	assert.True(t, bp.ApplyToSelectedRepos)
	assert.Equal(t, []string{"obp-api"}, bp.Repos)
	require.Len(t, bp.ApprovalRules, 1)

	t.Run("List", func(t *testing.T) {
		req := NewRequest(t, "GET", "/api/v1/orgs/org3/branch_protections").AddTokenAuth(e.owner.Token)
		var list []*api.OrgBranchProtection
		DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &list)
		require.Len(t, list, 1)
		assert.Equal(t, "obp-api/*", list[0].RuleName)
	})

	t.Run("Edit", func(t *testing.T) {
		all := false
		approvals := int64(1)
		bp := e.rule(e.owner, "PATCH", "obp-api/*", api.EditOrgBranchProtectionOption{
			EditBranchProtectionOption: api.EditBranchProtectionOption{RequiredApprovals: &approvals},
			ApplyToSelectedRepos:       &all,
		}, http.StatusOK)
		assert.EqualValues(t, 1, bp.RequiredApprovals)
		assert.False(t, bp.ApplyToSelectedRepos)
		assert.Equal(t, []string{"user4"}, bp.PushWhitelistUsernames, "unset fields are kept")
		assert.Equal(t, []string{"obp-api"}, bp.Repos)
	})

	t.Run("Duplicate", func(t *testing.T) {
		e.rule(e.owner, "POST", "", api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "obp-api/*"}}, http.StatusForbidden)
	})

	t.Run("OnlyOwners", func(t *testing.T) {
		// user4 is a member of org3, user5 a repository admin, user8 not related
		bwRepoAdmin := e.owner
		bwRepoAdmin.Username, bwRepoAdmin.Reponame = "org3", "obp-api"
		doAPIAddCollaborator(bwRepoAdmin, "user5", perm.AccessModeAdmin)(t)
		for _, user := range []string{"user4", "user5", "user8"} {
			ctx := userCtx(t, user, auth_model.AccessTokenScopeWriteOrganization)
			e.rule(ctx, "GET", "", nil, http.StatusForbidden)
			e.rule(ctx, "GET", "obp-api/*", nil, http.StatusForbidden)
			e.rule(ctx, "POST", "", api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "x"}}, http.StatusForbidden)
			e.rule(ctx, "PATCH", "obp-api/*", api.EditOrgBranchProtectionOption{}, http.StatusForbidden)
			e.rule(ctx, "DELETE", "obp-api/*", nil, http.StatusForbidden)
		}
		readOnly := userCtx(t, "user2", auth_model.AccessTokenScopeReadOrganization)
		e.rule(readOnly, "GET", "obp-api/*", nil, http.StatusOK)
		e.rule(readOnly, "DELETE", "obp-api/*", nil, http.StatusForbidden)
	})

	t.Run("OtherOrgOwner", func(t *testing.T) {
		// user4 owns another organization, which doesn't make it an owner of org3's rules
		user4 := userCtx(t, "user4", auth_model.AccessTokenScopeWriteOrganization)
		req := NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "obp-other"}).AddTokenAuth(user4.Token)
		MakeRequest(t, req, http.StatusCreated)
		e.rule(user4, "PATCH", "obp-api/*", api.EditOrgBranchProtectionOption{}, http.StatusForbidden)
		e.rule(user4, "DELETE", "obp-api/*", nil, http.StatusForbidden)
		req = NewRequest(t, "DELETE", "/api/v1/orgs/obp-other/branch_protections/"+url.PathEscape("obp-api/*")).AddTokenAuth(user4.Token)
		MakeRequest(t, req, http.StatusNotFound)
		e.rule(e.owner, "GET", "obp-api/*", nil, http.StatusOK)
	})

	t.Run("Invalid", func(t *testing.T) {
		for name, opts := range map[string]api.CreateOrgBranchProtectionOption{
			"non-member user": {CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "x", MergeWhitelistUsernames: []string{"user5"}}},
			"other org team":  {CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "x", PushWhitelistTeams: []string{"review_team"}}},
			"deploy key":      {CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "x", DeleteAllowlistDeployKeyIDs: []int64{1}}},
			"deploy keys":     {CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "x", EnablePush: true, EnablePushWhitelist: true, PushWhitelistDeployKeys: true}},
			"other repo":      {CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "x"}, ApplyToSelectedRepos: true, Repos: []string{"repo1"}},
			"approver":        {CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "x", ApprovalRules: []*api.ApprovalRule{{Name: "a", RequiredCount: 1, Usernames: []string{"user5"}}}}},
		} {
			t.Run(name, func(t *testing.T) {
				e.rule(e.owner, "POST", "", opts, http.StatusUnprocessableEntity)
			})
		}
		e.rule(e.owner, "GET", "x", nil, http.StatusNotFound)
	})

	t.Run("DeletedTeam", func(t *testing.T) {
		req := NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/teams", &api.CreateTeamOption{Name: "obp-team", Permission: "write", Units: []string{"repo.code"}}).AddTokenAuth(e.owner.Token)
		var team api.Team
		DecodeJSON(t, MakeRequest(t, req, http.StatusCreated), &team)
		e.rule(e.owner, "PATCH", "obp-api/*", api.EditOrgBranchProtectionOption{EditBranchProtectionOption: api.EditBranchProtectionOption{PushWhitelistTeams: []string{"team1", "obp-team"}}}, http.StatusOK)

		MakeRequest(t, NewRequestf(t, "DELETE", "/api/v1/teams/%d", team.ID).AddTokenAuth(e.owner.Token), http.StatusNoContent)
		bp := e.rule(e.owner, "GET", "obp-api/*", nil, http.StatusOK)
		assert.Equal(t, []string{"team1"}, bp.PushWhitelistTeams)
		assert.True(t, bp.EnablePushWhitelist, "the rule keeps working")
	})
}

// AC3, AC4, AC5, AC12: pushes must pass the organization rule as well as the repository rule.
func TestOrgBranchProtectionPush(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newOrgRuleEnv(t)
		// pushes are allowed, deleting and force pushing are not
		e.create(api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "obp-*", EnablePush: true}})

		// AC5: a repository created after the rule is protected right away
		repo := e.repo("obp-push", map[string]perm.AccessMode{"user4": perm.AccessModeWrite, "user5": perm.AccessModeAdmin})
		httpURL := func(username string) *url.URL {
			userURL := *u
			userURL.Path = repo.GitPath()
			userURL.User = url.UserPassword(username, userPassword)
			return &userURL
		}
		user2, user4 := branchPusher{remote: httpURL("user2")}, branchPusher{remote: httpURL("user4")}
		dstPath := t.TempDir()
		doGitClone(dstPath, httpURL("user2"))(t)

		t.Run("NewRepoProtected", func(t *testing.T) {
			commitOnBranch(t, dstPath, "obp-new", "master", "obp-new.txt")
			_, err := user2.push(t, dstPath, "obp-new")
			require.NoError(t, err)
			stderr, err := user2.push(t, dstPath, "--delete", "obp-new")
			require.Error(t, err)
			assert.Contains(t, stderr, "protected from deletion")

			req := NewRequest(t, "GET", "/api/v1/repos/org3/obp-push/branches/obp-new").AddTokenAuth(repo.Token)
			var branch api.Branch
			DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &branch)
			assert.True(t, branch.Protected)
		})

		// must-fix 6: a repository rule allowing the pusher doesn't let it skip the organization rule
		t.Run("RepoAllowsOrgRefuses", func(t *testing.T) {
			e.repoRule("obp-push", api.CreateBranchProtectionOption{
				RuleName: "obp-both", EnablePush: true, DeleteAllowlistUsernames: []string{"user2"}, ForcePushAllowlistUsernames: []string{"user2"},
			})
			commitOnBranch(t, dstPath, "obp-both", "master", "obp-both-1.txt")
			first := gitHead(t, dstPath)
			doAddChangesToCheckout(dstPath, "obp-both-2.txt")(t)
			_, err := user2.push(t, dstPath, "obp-both")
			require.NoError(t, err)

			stderr, err := user2.push(t, dstPath, "--force", first+":refs/heads/obp-both")
			require.Error(t, err)
			assert.Contains(t, stderr, "protected from force push")
			stderr, err = user2.push(t, dstPath, "--delete", "obp-both")
			require.Error(t, err)
			assert.Contains(t, stderr, "protected from deletion")
		})

		// AC12: a push refused by the organization rule, and by the repository rule when the organization rule allows it
		t.Run("OrgRefusesPush", func(t *testing.T) {
			e.create(api.CreateOrgBranchProtectionOption{
				CreateBranchProtectionOption: api.CreateBranchProtectionOption{
					RuleName: "lock-*", EnablePush: true, EnablePushWhitelist: true, PushWhitelistUsernames: []string{"user2"},
				},
				ApplyToSelectedRepos: true, Repos: []string{"obp-push"},
			})
			commitOnBranch(t, dstPath, "lock-a", "master", "lock-a.txt")
			stderr, err := user4.push(t, dstPath, "lock-a")
			require.Error(t, err)
			assert.Contains(t, stderr, "Not allowed to push to protected branch lock-a")
			_, err = user2.push(t, dstPath, "lock-a")
			require.NoError(t, err)

			e.repoRule("obp-push", api.CreateBranchProtectionOption{RuleName: "lock-b", EnablePush: false})
			commitOnBranch(t, dstPath, "lock-b", "master", "lock-b.txt")
			stderr, err = user2.push(t, dstPath, "lock-b")
			require.Error(t, err)
			assert.Contains(t, stderr, "Not allowed to push to protected branch lock-b")
		})

		// AC3, AC9: updating a pull request pushes to its head branch, which must pass every matching rule
		t.Run("UpdatePullRequest", func(t *testing.T) {
			commitOnBranch(t, dstPath, "lock-c", "master", "lock-c.txt")
			_, err := user2.push(t, dstPath, "lock-c")
			require.NoError(t, err)
			e.repoRule("obp-push", api.CreateBranchProtectionOption{
				RuleName: "lock-c", EnablePush: true, EnablePushWhitelist: true, PushWhitelistUsernames: []string{"user4"},
			})
			pr, err := doAPICreatePullRequest(repo, "org3", "obp-push", "master", "lock-c")(t)
			require.NoError(t, err)

			writer := userCtx(t, "user4", auth_model.AccessTokenScopeWriteRepository)
			req := NewRequestf(t, "POST", "/api/v1/repos/org3/obp-push/pulls/%d/update", pr.Index).AddTokenAuth(writer.Token)
			MakeRequest(t, req, http.StatusForbidden)
		})

		// AC3: a repository admin can't change or delete the organization rule
		t.Run("RepoAdminCantChangeOrgRule", func(t *testing.T) {
			admin := userCtx(t, "user5", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
			link := "/api/v1/repos/org3/obp-push/branch_protections/" + url.PathEscape("obp-*")
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", link, api.EditBranchProtectionOption{}).AddTokenAuth(admin.Token), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "DELETE", link).AddTokenAuth(admin.Token), http.StatusNotFound)
			e.rule(admin, "DELETE", "obp-*", nil, http.StatusForbidden)
			e.rule(e.owner, "GET", "obp-*", nil, http.StatusOK)
		})

		// must-fix 1: a rename never moves a branch into or out of a protected name
		t.Run("Rename", func(t *testing.T) {
			e.repoRule("obp-push", api.CreateBranchProtectionOption{RuleName: "release/*", EnablePush: true})
			commitOnBranch(t, dstPath, "plain", "master", "plain.txt")
			_, err := user2.push(t, dstPath, "plain")
			require.NoError(t, err)

			writer := userCtx(t, "user4", auth_model.AccessTokenScopeWriteRepository)
			rename := func(from, to string, expected int) {
				t.Helper()
				req := NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/obp-push/branches/"+from, &api.UpdateBranchRepoOption{Name: to}).AddTokenAuth(writer.Token)
				MakeRequest(t, req, expected)
			}
			rename("plain", "release/1.0", http.StatusForbidden) // repository rule
			rename("plain", "obp-renamed", http.StatusForbidden) // organization rule
			rename("obp-new", "free", http.StatusForbidden)      // out of an organization rule
			rename("plain", "free", http.StatusNoContent)
		})

		// AC5: a transferred repository follows the rules of its new owner
		t.Run("Transfer", func(t *testing.T) {
			req := NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "obp-new-owner"}).AddTokenAuth(e.owner.Token)
			MakeRequest(t, req, http.StatusCreated)
			req = NewRequestWithJSON(t, "POST", "/api/v1/orgs/obp-new-owner/branch_protections", api.CreateOrgBranchProtectionOption{
				CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "master", EnablePush: false},
			}).AddTokenAuth(e.owner.Token)
			MakeRequest(t, req, http.StatusCreated)

			req = NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/obp-push/transfer", &api.TransferRepoOption{NewOwner: "obp-new-owner"}).AddTokenAuth(e.owner.Token)
			MakeRequest(t, req, http.StatusAccepted)

			moved := *httpURL("user2")
			moved.Path = "/obp-new-owner/obp-push.git"
			pusher := branchPusher{remote: &moved}
			_, err := pusher.push(t, dstPath, "--delete", "obp-new")
			require.NoError(t, err, "the rule of org3 doesn't apply anymore")

			commitOnBranch(t, dstPath, "master", "master", "obp-master.txt")
			stderr, err := pusher.push(t, dstPath, "master")
			require.Error(t, err)
			assert.Contains(t, stderr, "Not allowed to push to protected branch master")
		})
	})
}

// AC4, AC12, must-fix 2-4: a merge waits for the approvals and reviews of the organization rule.
func TestOrgBranchProtectionMerge(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		e := newOrgRuleEnv(t)
		repo := e.repo("obp-merge", map[string]perm.AccessMode{"user4": perm.AccessModeWrite, "user8": perm.AccessModeWrite, "user28": perm.AccessModeWrite})
		e.create(api.CreateOrgBranchProtectionOption{
			CreateBranchProtectionOption: api.CreateBranchProtectionOption{
				RuleName: "master", RequiredApprovals: 1, BlockOnRejectedReviews: true, BlockOnOfficialReviewRequests: true,
			},
			ApplyToSelectedRepos: true, Repos: []string{"obp-merge"},
		})

		user4 := NewAPITestContext(t, "user4", "obp-merge", auth_model.AccessTokenScopeWriteRepository)
		user8 := NewAPITestContext(t, "user8", "obp-merge", auth_model.AccessTokenScopeWriteRepository)
		user28 := NewAPITestContext(t, "user28", "obp-merge", auth_model.AccessTokenScopeWriteRepository)
		link := "/api/v1/repos/org3/obp-merge/pulls"
		changeFile := func(branch, newBranch, path string) {
			req := NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/obp-merge/contents", &api.ChangeFilesOptions{
				FileOptions: api.FileOptions{BranchName: branch, NewBranchName: newBranch, Message: "change"},
				Files:       []*api.ChangeFileOperation{create(path, path)},
			}).AddTokenAuth(repo.Token)
			MakeRequest(t, req, http.StatusCreated)
		}
		review := func(ctx APITestContext, index int64, event api.ReviewStateType) int64 {
			req := NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/reviews", link, index), &api.CreatePullReviewOptions{Event: event, Body: "review"}).AddTokenAuth(ctx.Token)
			var r api.PullReview
			DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &r)
			return r.ID
		}
		merge := func(index int64, expected int) string {
			req := NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/merge", link, index), &forms.MergePullRequestForm{Do: "merge"}).AddTokenAuth(repo.Token)
			return MakeRequest(t, req, expected).Body.String()
		}

		changeFile("master", "obp-head", "a.txt")
		pr, err := doAPICreatePullRequest(repo, "org3", "obp-merge", "master", "obp-head")(t)
		require.NoError(t, err)

		t.Run("NeedsApproval", func(t *testing.T) {
			assert.Contains(t, merge(pr.Index, http.StatusMethodNotAllowed), "Does not have enough approvals")
		})

		t.Run("AutoMergeWaits", func(t *testing.T) {
			req := NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/merge", link, pr.Index), &forms.MergePullRequestForm{Do: "merge", MergeWhenChecksSucceed: true}).AddTokenAuth(repo.Token)
			MakeRequest(t, req, http.StatusCreated)
			assert.False(t, doAPIGetPullRequest(repo, "org3", "obp-merge", pr.Index)(t).HasMerged)
			MakeRequest(t, NewRequestf(t, "DELETE", "%s/%d/merge", link, pr.Index).AddTokenAuth(repo.Token), http.StatusNoContent)
		})

		// must-fix 2: write access added by a repository admin doesn't make an outside collaborator an approver
		t.Run("OutsideCollaborator", func(t *testing.T) {
			review(user8, pr.Index, api.ReviewStateApproved)
			assert.Contains(t, merge(pr.Index, http.StatusMethodNotAllowed), "Does not have enough approvals")
		})

		// must-fix 3: a stale approval that isn't dismissed doesn't count when the rule dismisses stale approvals.
		// It is left stale by pushing before the rule dismisses.
		t.Run("StaleApproval", func(t *testing.T) {
			id := review(user4, pr.Index, api.ReviewStateApproved)
			changeFile("obp-head", "", "b.txt")
			// the push marks the review stale in the background
			assert.Eventually(t, func() bool {
				r, err := issues_model.GetReviewByID(db.DefaultContext, id)
				return err == nil && r.Stale
			}, 10*time.Second, 50*time.Millisecond)
			dismiss := true
			e.rule(e.owner, "PATCH", "master", api.EditOrgBranchProtectionOption{EditBranchProtectionOption: api.EditBranchProtectionOption{DismissStaleApprovals: &dismiss}}, http.StatusOK)
			assert.Contains(t, merge(pr.Index, http.StatusMethodNotAllowed), "Does not have enough approvals")
		})

		// must-fix 4: the latest review of each member counts
		t.Run("Rejection", func(t *testing.T) {
			review(user4, pr.Index, api.ReviewStateApproved)
			review(user28, pr.Index, api.ReviewStateRequestChanges)
			assert.Contains(t, merge(pr.Index, http.StatusMethodNotAllowed), "There are requested changes")
			review(user28, pr.Index, api.ReviewStateApproved)
		})

		// must-fix 4: a pending review request to a team of official reviewers blocks
		t.Run("TeamReviewRequest", func(t *testing.T) {
			MakeRequest(t, NewRequest(t, "PUT", "/api/v1/teams/2/repos/org3/obp-merge").AddTokenAuth(repo.Token), http.StatusNoContent)
			req := NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/requested_reviewers", link, pr.Index), &api.PullReviewRequestOptions{TeamReviewers: []string{"team1"}}).AddTokenAuth(repo.Token)
			MakeRequest(t, req, http.StatusCreated)
			assert.Contains(t, merge(pr.Index, http.StatusMethodNotAllowed), "There are official review requests")
			req = NewRequestWithJSON(t, "DELETE", fmt.Sprintf("%s/%d/requested_reviewers", link, pr.Index), &api.PullReviewRequestOptions{TeamReviewers: []string{"team1"}}).AddTokenAuth(repo.Token)
			MakeRequest(t, req, http.StatusNoContent)
		})

		// a pending or comment review doesn't answer a review request, only an approval or rejection does
		t.Run("UserReviewRequest", func(t *testing.T) {
			req := NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/requested_reviewers", link, pr.Index), &api.PullReviewRequestOptions{Reviewers: []string{"user28"}}).AddTokenAuth(repo.Token)
			MakeRequest(t, req, http.StatusCreated)
			assert.Contains(t, merge(pr.Index, http.StatusMethodNotAllowed), "There are official review requests")

			// a pending review keeps the request, and so does submitting it as a comment
			id := review(user28, pr.Index, api.ReviewStatePending)
			assert.Contains(t, merge(pr.Index, http.StatusMethodNotAllowed), "There are official review requests")
			req = NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/reviews/%d", link, pr.Index, id), &api.SubmitPullReviewOptions{Event: api.ReviewStateComment, Body: "comment"}).AddTokenAuth(user28.Token)
			MakeRequest(t, req, http.StatusOK)
			assert.Contains(t, merge(pr.Index, http.StatusMethodNotAllowed), "There are official review requests")

			review(user28, pr.Index, api.ReviewStateApproved)
		})

		t.Run("Merged", func(t *testing.T) {
			merge(pr.Index, http.StatusOK)
		})

		// AC4: auto merge goes ahead once the organization rule is satisfied
		t.Run("AutoMerge", func(t *testing.T) {
			changeFile("master", "obp-auto", "c.txt")
			pr, err := doAPICreatePullRequest(repo, "org3", "obp-merge", "master", "obp-auto")(t)
			require.NoError(t, err)
			req := NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/merge", link, pr.Index), &forms.MergePullRequestForm{Do: "merge", MergeWhenChecksSucceed: true}).AddTokenAuth(repo.Token)
			MakeRequest(t, req, http.StatusCreated)
			assert.False(t, doAPIGetPullRequest(repo, "org3", "obp-merge", pr.Index)(t).HasMerged)
			review(user4, pr.Index, api.ReviewStateApproved)
			assert.Eventually(t, func() bool {
				return doAPIGetPullRequest(repo, "org3", "obp-merge", pr.Index)(t).HasMerged
			}, 10*time.Second, 200*time.Millisecond)
		})

		// must-fix 10: each rule blocks on its own protected files
		t.Run("ProtectedFiles", func(t *testing.T) {
			patterns := "org-secret.txt"
			e.rule(e.owner, "PATCH", "master", api.EditOrgBranchProtectionOption{EditBranchProtectionOption: api.EditBranchProtectionOption{ProtectedFilePatterns: &patterns}}, http.StatusOK)
			e.repoRule("obp-merge", api.CreateBranchProtectionOption{RuleName: "master", ProtectedFilePatterns: "repo-secret.txt"})

			changeFile("master", "obp-files", "org-secret.txt")
			pr, err := doAPICreatePullRequest(repo, "org3", "obp-merge", "master", "obp-files")(t)
			require.NoError(t, err)
			review(user4, pr.Index, api.ReviewStateApproved)
			assert.Contains(t, merge(pr.Index, http.StatusMethodNotAllowed), "Changed protected files")
		})

		// Q1: the organization owner may force-merge a rule that doesn't apply to admins, a repository admin may not
		t.Run("AdminExemption", func(t *testing.T) {
			changeFile("master", "obp-force", "d.txt")
			pr, err := doAPICreatePullRequest(repo, "org3", "obp-merge", "master", "obp-force")(t)
			require.NoError(t, err)
			doAPIAddCollaborator(repo, "user5", perm.AccessModeAdmin)(t)
			user5 := NewAPITestContext(t, "user5", "obp-merge", auth_model.AccessTokenScopeWriteRepository)
			force := func(ctx APITestContext, expected int) {
				req := NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/%d/merge", link, pr.Index), &forms.MergePullRequestForm{Do: "merge", ForceMerge: true}).AddTokenAuth(ctx.Token)
				MakeRequest(t, req, expected)
			}
			force(user5, http.StatusMethodNotAllowed)
			force(repo, http.StatusOK)
		})
	})
}
