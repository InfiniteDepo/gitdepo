// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	auth_model "forgejo.org/models/auth"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	api "forgejo.org/modules/structs"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AC1: org owners manage organization rules on the organization settings pages, nobody else does.
func TestOrgBranchProtectionWeb(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	bwRepo(t, "obp-web")
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: "obp-web"})
	owner := loginUser(t, "user2")
	const editURL = "/org/org3/settings/branches/edit"
	rule := func(name string) *git_model.ProtectedBranch {
		bp := &git_model.ProtectedBranch{OrgID: 3, RuleName: name}
		if ok, err := unittest.LoadBeanIfExists(bp); err != nil || !ok {
			require.NoError(t, err)
			return nil
		}
		return bp
	}
	post := func(s *TestSession, link string, values map[string]string, expected int) {
		t.Helper()
		s.MakeRequest(t, NewRequestWithValues(t, "POST", link, values), expected)
	}

	t.Run("Create", func(t *testing.T) {
		owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/branches"), http.StatusOK)
		owner.MakeRequest(t, NewRequest(t, "GET", editURL), http.StatusOK)
		post(owner, editURL, map[string]string{
			"rule_name": "obp-web-*", "enable_push": "whitelist", "whitelist_users": "4", "whitelist_teams": "2",
			"required_approvals": "1", "apply_to_selected_repos": "on", "selected_repo_ids": strconv.FormatInt(repo.ID, 10),
		}, http.StatusSeeOther)

		bp := rule("obp-web-*")
		require.NotNil(t, bp)
		assert.True(t, bp.EnableWhitelist)
		assert.Equal(t, []int64{4}, bp.WhitelistUserIDs)
		assert.Equal(t, []int64{2}, bp.WhitelistTeamIDs)
		assert.EqualValues(t, 1, bp.RequiredApprovals)
		assert.True(t, bp.ApplyToSelectedRepos)
		ids, err := git_model.GetOrgProtectedBranchRuleRepoIDs(t.Context(), bp.ID)
		require.NoError(t, err)
		assert.Equal(t, []int64{repo.ID}, ids)

		resp := owner.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/branches"), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "obp-web-*")
		owner.MakeRequest(t, NewRequest(t, "GET", editURL+"?rule_name="+url.QueryEscape("obp-web-*")), http.StatusOK)
	})

	t.Run("Edit", func(t *testing.T) {
		bp := rule("obp-web-*")
		post(owner, editURL, map[string]string{
			"rule_id": strconv.FormatInt(bp.ID, 10), "rule_name": "obp-web-*", "required_approvals": "2",
		}, http.StatusSeeOther)
		bp = rule("obp-web-*")
		assert.EqualValues(t, 2, bp.RequiredApprovals)
		assert.False(t, bp.ApplyToSelectedRepos)
	})

	t.Run("Invalid", func(t *testing.T) {
		for name, values := range map[string]map[string]string{
			"non-member":  {"rule_name": "obp-bad", "enable_push": "whitelist", "whitelist_users": "5"},
			"other team":  {"rule_name": "obp-bad", "enable_push": "whitelist", "whitelist_teams": "3"},
			"other repo":  {"rule_name": "obp-bad", "apply_to_selected_repos": "on", "selected_repo_ids": "1"},
			"deploy keys": {"rule_name": "obp-bad", "enable_push": "whitelist", "whitelist_deploy_keys": "on"},
			"deploy key":  {"rule_name": "obp-bad", "delete_allowlist_deploy_key_ids": "1"},
		} {
			t.Run(name, func(t *testing.T) {
				post(owner, editURL, values, http.StatusSeeOther)
				assert.NotEmpty(t, bwFlash(owner))
				assert.Nil(t, rule("obp-bad"))
			})
		}
	})

	t.Run("OnlyOwners", func(t *testing.T) {
		id := strconv.FormatInt(rule("obp-web-*").ID, 10)
		for _, user := range []string{"user4", "user5"} {
			s := loginUser(t, user)
			s.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/branches"), http.StatusNotFound)
			s.MakeRequest(t, NewRequest(t, "GET", editURL), http.StatusNotFound)
			post(s, editURL, map[string]string{"rule_id": id, "rule_name": "obp-web-*"}, http.StatusNotFound)
			post(s, "/org/org3/settings/branches/"+id+"/delete", nil, http.StatusNotFound)
		}
		assert.NotNil(t, rule("obp-web-*"))
	})

	t.Run("OtherOrg", func(t *testing.T) {
		user4 := userCtx(t, "user4", auth_model.AccessTokenScopeWriteOrganization)
		req := NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "obp-web-other"}).AddTokenAuth(user4.Token)
		MakeRequest(t, req, http.StatusCreated)
		s := loginUser(t, "user4")
		bp := rule("obp-web-*")
		id := strconv.FormatInt(bp.ID, 10)
		post(s, "/org/obp-web-other/settings/branches/edit", map[string]string{"rule_id": id, "rule_name": "taken", "required_approvals": "5"}, http.StatusNotFound)
		post(s, "/org/obp-web-other/settings/branches/"+id+"/delete", nil, http.StatusNotFound)
		after := rule("obp-web-*")
		require.NotNil(t, after)
		assert.Equal(t, bp.RequiredApprovals, after.RequiredApprovals)
		unittest.AssertNotExistsBean(t, &git_model.ProtectedBranch{RuleName: "taken"})
	})

	// an archived organization's rules can't be changed
	t.Run("ArchivedOrg", func(t *testing.T) {
		bp := rule("obp-web-*")
		id := strconv.FormatInt(bp.ID, 10)
		archiveOrg3(t, false)
		post(owner, editURL, map[string]string{"rule_id": id, "rule_name": "obp-web-*", "required_approvals": "7"}, http.StatusForbidden)
		post(owner, "/org/org3/settings/branches/"+id+"/delete", nil, http.StatusForbidden)
		after := rule("obp-web-*")
		require.NotNil(t, after)
		assert.Equal(t, bp.RequiredApprovals, after.RequiredApprovals)
		webUnarchiveOrg(t, "user2", http.StatusSeeOther)
	})

	t.Run("Delete", func(t *testing.T) {
		post(owner, fmt.Sprintf("/org/org3/settings/branches/%d/delete", rule("obp-web-*").ID), nil, http.StatusOK)
		assert.Nil(t, rule("obp-web-*"))
	})
}

// AC6, AC12: the repository settings list the organization rules that apply, read-only.
func TestOrgBranchProtectionRepoSettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	e := newOrgRuleEnv(t)
	repo := e.repo("obp-web-repo", map[string]perm.AccessMode{"user5": perm.AccessModeAdmin})
	bwRepo(t, "obp-web-elsewhere")
	for _, branch := range []string{"obp-org-rule", "obp-unmatched"} {
		req := NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/obp-web-repo/branches", &api.CreateBranchRepoOption{BranchName: branch, OldRefName: "master"}).AddTokenAuth(repo.Token)
		MakeRequest(t, req, http.StatusCreated)
	}
	e.create(api.CreateOrgBranchProtectionOption{CreateBranchProtectionOption: api.CreateBranchProtectionOption{
		RuleName: "obp-org-rule", EnablePush: true, EnablePushWhitelist: true, PushWhitelistUsernames: []string{"user4"},
		ApprovalRules: []*api.ApprovalRule{{Name: "SecretApprovers", RequiredCount: 1, Usernames: []string{"user2"}}},
	}})
	e.create(api.CreateOrgBranchProtectionOption{
		CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "obp-org-elsewhere"},
		ApplyToSelectedRepos:         true, Repos: []string{"obp-web-elsewhere"},
	})
	id := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{OrgID: 3, RuleName: "obp-org-rule"}).ID

	resp := loginUser(t, "user5").MakeRequest(t, NewRequest(t, "GET", "/org3/obp-web-repo/settings/branches"), http.StatusOK)
	body := resp.Body.String()
	doc := NewHTMLParser(t, resp.Body)
	assert.Contains(t, body, "obp-org-rule")
	assert.Equal(t, 1, doc.Find(`a[href="/org/org3/settings/branches"]`).Length())
	assert.Contains(t, doc.Find(".org-protected-branches").Text(), "Organization")
	assert.NotContains(t, body, "rule_name=obp-org-rule")
	assert.NotContains(t, body, fmt.Sprintf("/settings/branches/%d/delete", id))
	assert.NotContains(t, body, "SecretApprovers", "the rule's settings stay private")
	assert.NotContains(t, body, "obp-org-elsewhere")

	// the branch list marks a branch protected by the organization rule only
	resp = loginUser(t, "user5").MakeRequest(t, NewRequest(t, "GET", "/org3/obp-web-repo/branches"), http.StatusOK)
	doc = NewHTMLParser(t, resp.Body)
	shield := func(branch string) int {
		return doc.Find(".flex-text-block").FilterFunction(func(_ int, s *goquery.Selection) bool {
			return s.Find("a.gt-ellipsis").Text() == branch
		}).Find(".octicon-shield-lock").Length()
	}
	assert.Equal(t, 1, shield("obp-org-rule"))
	assert.Equal(t, 0, shield("obp-unmatched"))
}

// AC6: the merge box, the approvals API and mergeable_reasons follow every matching rule.
func TestOrgBranchProtectionMergeBox(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	e := newOrgRuleEnv(t)
	repo := e.repo("obp-mb", map[string]perm.AccessMode{"user4": perm.AccessModeWrite, "user5": perm.AccessModeAdmin})
	e.create(api.CreateOrgBranchProtectionOption{
		CreateBranchProtectionOption: api.CreateBranchProtectionOption{RuleName: "master", RequiredApprovals: 2, BlockOnIncompleteTasks: true},
		ApplyToSelectedRepos:         true, Repos: []string{"obp-mb"},
	})

	req := NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/obp-mb/contents", &api.ChangeFilesOptions{
		FileOptions: api.FileOptions{BranchName: "master", NewBranchName: "obp-mb-head", Message: "change"},
		Files:       []*api.ChangeFileOperation{create("a.txt", "a")},
	}).AddTokenAuth(repo.Token)
	MakeRequest(t, req, http.StatusCreated)
	req = NewRequestWithJSON(t, "POST", "/api/v1/repos/org3/obp-mb/pulls", &api.CreatePullRequestOption{
		Head: "obp-mb-head", Base: "master", Title: "pr",
	}).AddTokenAuth(repo.Token)
	var pr api.PullRequest
	DecodeJSON(t, MakeRequest(t, req, http.StatusCreated), &pr)
	req = NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/org3/obp-mb/pulls/%d/tasks", pr.Index), &api.CreatePullTaskOption{Content: "a task"}).AddTokenAuth(repo.Token)
	MakeRequest(t, req, http.StatusCreated)

	approvals := func() map[string]*api.PullApprovalRule {
		req := NewRequestf(t, "GET", "/api/v1/repos/org3/obp-mb/pulls/%d/approvals", pr.Index).AddTokenAuth(repo.Token)
		var list []*api.PullApprovalRule
		DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &list)
		byName := map[string]*api.PullApprovalRule{}
		for _, r := range list {
			byName[r.Name] = r
		}
		return byName
	}
	page := func(user string) string {
		return loginUser(t, user).MakeRequest(t, NewRequestf(t, "GET", "/org3/obp-mb/pulls/%d", pr.Index), http.StatusOK).Body.String()
	}

	t.Run("OrgOnly", func(t *testing.T) {
		req := NewRequestf(t, "GET", "/api/v1/repos/org3/obp-mb/pulls/%d", pr.Index).AddTokenAuth(repo.Token)
		var got api.PullRequest
		DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &got)
		assert.Contains(t, got.MergeableReasons, "incomplete_tasks")

		def := approvals()["Default (organization)"]
		require.NotNil(t, def)
		assert.EqualValues(t, 2, def.Required)

		assert.Contains(t, page("user2"), "0 of 2 approvals granted")
	})

	t.Run("RepoAndOrg", func(t *testing.T) {
		e.repoRule("obp-mb", api.CreateBranchProtectionOption{
			RuleName: "master", ApprovalRules: []*api.ApprovalRule{{Name: "Security", RequiredCount: 1, Usernames: []string{"user4"}}},
		})
		got := approvals()
		require.Contains(t, got, "Security")
		require.Contains(t, got, "Default (organization)")

		req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/org3/obp-mb/pulls/%d/reviews", pr.Index), &api.CreatePullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(userCtx(t, "user4", auth_model.AccessTokenScopeWriteRepository).Token)
		MakeRequest(t, req, http.StatusOK)
		got = approvals()
		assert.True(t, got["Security"].Satisfied)
		assert.False(t, got["Default (organization)"].Satisfied)

		body := page("user5")
		assert.Contains(t, body, "1 of 2 approvals granted")
		assert.True(t, bwFlag(body, "canMergeNow", false), "a repository admin can't override the organization rule")
		assert.Contains(t, page("user2"), "1 of 2 approvals granted")
	})
}
