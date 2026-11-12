// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"forgejo.org/models"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/perm"
	pull_model "forgejo.org/models/pull"
	repo_model "forgejo.org/models/repo"
	unit_model "forgejo.org/models/unit"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/gitrepo"
	api "forgejo.org/modules/structs"
	"forgejo.org/services/forms"
	"forgejo.org/services/mergequeue"
	"forgejo.org/tests"
	"forgejo.org/tests/forgery"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// msRule saves the rule "main" (or the named rule) of repo through the settings form, as the owner.
func msRule(t *testing.T, s *TestSession, repo *repo_model.Repository, expected int, fields url.Values) {
	t.Helper()
	rule := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "main"}
	has, err := unittest.LoadBeanIfExists(rule)
	require.NoError(t, err)
	v := url.Values{"rule_name": {"main"}}
	if has {
		v.Set("rule_id", strconv.FormatInt(rule.ID, 10))
	}
	maps.Copy(v, fields)
	s.MakeRequest(t, NewRequestWithURLValues(t, "POST", fmt.Sprintf("/%s/settings/branches/edit", repo.FullName()), v), expected)
}

func msStored(t *testing.T, repo *repo_model.Repository) *git_model.ProtectedBranch {
	t.Helper()
	return unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "main"})
}

func TestMergeStyles(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		writer := forgery.CreateUser(t, nil)
		repo := forgery.CreateRepository(t, nil, &forgery.CreateRepositoryOptions{
			Files:         forgery.FilesInit{},
			Collaborators: map[*user_model.User]perm.AccessMode{writer: perm.AccessModeWrite},
		})
		forgery.EnableRepoUnits(t, repo, unit_model.TypeCode, unit_model.TypePullRequests)
		owner := repo.Owner
		session := loginUser(t, owner.Name)
		writerSession := loginUser(t, writer.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		statusCtx := APITestContext{Session: session, Token: token, Username: owner.Name, Reponame: repo.Name}
		gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
		require.NoError(t, err)
		defer gitRepo.Close()

		pulls := 0
		newPull := func(t *testing.T) *issues_model.PullRequest {
			t.Helper()
			pulls++
			branch := fmt.Sprintf("styles-%d", pulls)
			testNewFileToNewBranch(t, session, owner.Name, repo.Name, "main", branch, branch+".txt", branch)
			testPullCreate(t, session, owner.Name, repo.Name, true, "main", branch, branch)
			return unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, HeadBranch: branch})
		}
		index := func(pr *issues_model.PullRequest) string { return strconv.FormatInt(pr.Index, 10) }
		head := func(pr *issues_model.PullRequest) string {
			sha, err := gitRepo.GetRefCommitID(pr.GetGitRefName())
			require.NoError(t, err)
			return sha
		}
		merged := func(pr *issues_model.PullRequest) bool {
			return unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged
		}
		apiMerge := func(pr *issues_model.PullRequest, form forms.MergePullRequestForm, expected int) {
			t.Helper()
			MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/%s/pulls/%s/merge", repo.FullName(), index(pr)), &form).AddTokenAuth(token), expected)
		}
		page := func(pr *issues_model.PullRequest) string {
			return session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/%s/pulls/%s", repo.FullName(), index(pr))), http.StatusOK).Body.String()
		}
		lastComment := func(pr *issues_model.PullRequest, typ issues_model.CommentType) *issues_model.Comment {
			var cs []*issues_model.Comment
			require.NoError(t, db.GetEngine(t.Context()).Where("issue_id = ? AND `type` = ?", pr.IssueID, typ).Desc("id").Find(&cs))
			if len(cs) == 0 {
				return nil
			}
			return cs[0]
		}

		t.Run("Rule form and API validation", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			var auditID int64
			_, err := db.GetEngine(t.Context()).Table(new(audit_model.Entry)).Select("COALESCE(MAX(id), 0)").Get(&auditID)
			require.NoError(t, err)

			msRule(t, session, repo, http.StatusSeeOther, url.Values{"allowed_merge_styles": {"squash", "merge", "squash"}, "default_merge_style": {"squash"}})
			rule := msStored(t, repo)
			assert.Equal(t, []string{"merge", "squash"}, rule.AllowedMergeStyles, "fixed order, no duplicates")
			assert.Equal(t, "squash", rule.DefaultMergeStyle)
			session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/%s/settings/branches/edit?rule_name=main", repo.FullName())), http.StatusOK)

			// a refused form keeps the rule
			for name, v := range map[string]url.Values{
				"unknown style":        {"allowed_merge_styles": {"merge", "nope"}},
				"update-only style":    {"allowed_merge_styles": {"rebase-update-only"}},
				"default not allowed":  {"allowed_merge_styles": {"merge"}, "default_merge_style": {"squash"}},
				"default without list": {"default_merge_style": {"merge"}},
			} {
				t.Run(name, func(t *testing.T) {
					msRule(t, session, repo, http.StatusSeeOther, v)
					assert.NotEmpty(t, bwFlash(session))
					after := msStored(t, repo)
					assert.Equal(t, []string{"merge", "squash"}, after.AllowedMergeStyles)
					assert.Equal(t, "squash", after.DefaultMergeStyle)
				})
			}

			t.Run("Audit", func(t *testing.T) {
				msRule(t, session, repo, http.StatusSeeOther, url.Values{"allowed_merge_styles": {"merge", "squash"}, "default_merge_style": {"merge"}})
				var found bool
				for _, e := range auditSince(t, auditID) {
					if e.Action == "repo.branch_protection.updated" {
						found = true
						assert.Contains(t, e.Data, "default_merge_style")
					}
				}
				assert.True(t, found)
			})

			t.Run("API", func(t *testing.T) {
				link := fmt.Sprintf("/api/v1/repos/%s/branch_protections", repo.FullName())
				patch := func(body map[string]any, expected int) *api.BranchProtection {
					t.Helper()
					resp := MakeRequest(t, NewRequestWithJSON(t, "PATCH", link+"/main", body).AddTokenAuth(token), expected)
					if expected != http.StatusOK {
						return nil
					}
					var bp api.BranchProtection
					DecodeJSON(t, resp, &bp)
					return &bp
				}
				patch(map[string]any{"allowed_merge_styles": []string{"merge", "nope"}}, http.StatusUnprocessableEntity)
				patch(map[string]any{"default_merge_style": "rebase"}, http.StatusUnprocessableEntity) // not in [merge squash]
				MakeRequest(t, NewRequestWithJSON(t, "POST", link, map[string]any{"rule_name": "dev", "allowed_merge_styles": []string{"x"}}).AddTokenAuth(token), http.StatusUnprocessableEntity)
				MakeRequest(t, NewRequestWithJSON(t, "POST", link, map[string]any{"rule_name": "dev", "allowed_merge_styles": []string{"merge"}, "default_merge_style": "squash"}).AddTokenAuth(token), http.StatusUnprocessableEntity)
				unittest.AssertNotExistsBean(t, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "dev"})
				assert.Equal(t, []string{"merge", "squash"}, msStored(t, repo).AllowedMergeStyles)

				bp := patch(map[string]any{"allowed_merge_styles": []string{"squash"}, "default_merge_style": "squash"}, http.StatusOK)
				assert.Equal(t, []string{"squash"}, bp.AllowedMergeStyles)
				assert.Equal(t, "squash", bp.DefaultMergeStyle)
				bp = patch(map[string]any{"allowed_merge_styles": []string{}}, http.StatusUnprocessableEntity) // the default squash is no longer in the list
				require.Nil(t, bp)
				bp = patch(map[string]any{"allowed_merge_styles": []string{}, "default_merge_style": ""}, http.StatusOK)
				assert.Empty(t, bp.AllowedMergeStyles)
			})
		})

		t.Run("Every merge path", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			msRule(t, session, repo, http.StatusSeeOther, url.Values{"allowed_merge_styles": {"squash"}})

			pr := newPull(t)
			t.Run("Merge box offers only the effective set", func(t *testing.T) {
				body := page(pr)
				assert.Contains(t, body, "Branch rules limit the merge styles")
				assert.Regexp(t, `'name': 'merge',\s+'allowed':\s+false`, body)
				assert.Regexp(t, `'name': 'squash',\s+'allowed':\s+true`, body)
				assert.True(t, bwFlag(body, "canMergeNow", true))
				assert.Regexp(t, `'defaultMergeStyle': "squash"`, body)
			})
			t.Run("Web", func(t *testing.T) {
				testPullMergeForm(t, session, http.StatusBadRequest, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "merge"})
				testPullMergeForm(t, writerSession, http.StatusBadRequest, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "rebase"})
				assert.False(t, merged(pr))
			})
			t.Run("API, force and admin do not bypass", func(t *testing.T) {
				apiMerge(pr, forms.MergePullRequestForm{Do: "merge"}, http.StatusUnprocessableEntity)
				apiMerge(pr, forms.MergePullRequestForm{Do: "merge", ForceMerge: true}, http.StatusUnprocessableEntity)
				testPullMergeForm(t, session, http.StatusBadRequest, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "merge", "force_merge": "true"})
				assert.False(t, merged(pr))
			})
			t.Run("Manually merged is a style", func(t *testing.T) {
				testPullMergeForm(t, session, http.StatusBadRequest, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "manually-merged", "merge_commit_id": head(pr)})
				apiMerge(pr, forms.MergePullRequestForm{Do: "manually-merged", MergeCommitID: head(pr)}, http.StatusUnprocessableEntity)
				assert.False(t, merged(pr))
			})
			t.Run("Auto merge refuses at schedule", func(t *testing.T) {
				testPullMergeForm(t, session, http.StatusBadRequest, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "merge", "merge_when_checks_succeed": "true", "head_commit_id": head(pr)})
				unittest.AssertNotExistsBean(t, &pull_model.AutoMerge{PullID: pr.ID})
			})
			t.Run("The allowed style merges", func(t *testing.T) {
				testPullMergeForm(t, session, http.StatusOK, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "squash"})
				assert.True(t, merged(pr))
			})
		})

		t.Run("Auto merge cancels when the style is no longer allowed", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			fields := url.Values{"enable_status_check": {"true"}, "status_check_contexts": {"ci"}}
			fields["allowed_merge_styles"] = []string{"merge", "squash"}
			msRule(t, session, repo, http.StatusSeeOther, fields)
			pr := newPull(t)
			testPullMergeForm(t, session, http.StatusOK, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "merge", "merge_when_checks_succeed": "true", "head_commit_id": head(pr)})
			unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: pr.ID})

			fields["allowed_merge_styles"] = []string{"squash"}
			msRule(t, session, repo, http.StatusSeeOther, fields)
			setStatus(t, statusCtx, head(pr), api.CommitStatusSuccess)

			unittest.AssertNotExistsBean(t, &pull_model.AutoMerge{PullID: pr.ID})
			assert.False(t, merged(pr), "never merged with another style")
			c := lastComment(pr, issues_model.CommentTypePRUnScheduledToAutoMerge)
			require.NotNil(t, c)
			assert.Equal(t, "merge_style", c.AutoMergeInfo().Reason)
			assert.Contains(t, page(pr), "no longer allowed")
		})

		t.Run("Merge queue", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			fields := url.Values{
				"enable_status_check": {"true"}, "status_check_contexts": {"ci"},
				"require_merge_queue": {"true"}, "allowed_merge_styles": {"squash", "merge"},
			}
			msRule(t, session, repo, http.StatusSeeOther, fields)
			pr := newPull(t)
			setStatus(t, statusCtx, head(pr), api.CommitStatusSuccess)

			// not allowed: refused at Add, nothing queued
			apiQueue := func(style string, expected int) {
				t.Helper()
				MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/%s/pulls/%s/merge-queue", repo.FullName(), index(pr)), &forms.MergePullRequestForm{Do: style}).AddTokenAuth(token), expected)
			}
			apiQueue("rebase", http.StatusUnprocessableEntity)
			testPullMergeForm(t, session, http.StatusBadRequest, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "rebase"})
			assert.Nil(t, queueEntry(t, pr))

			// the queue's own style must be allowed too
			fields["merge_queue_merge_style"] = []string{"rebase"}
			msRule(t, session, repo, http.StatusSeeOther, fields)
			apiQueue("squash", http.StatusUnprocessableEntity)
			assert.Nil(t, queueEntry(t, pr))
			delete(fields, "merge_queue_merge_style")
			msRule(t, session, repo, http.StatusSeeOther, fields)

			testPullMergeForm(t, session, http.StatusOK, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "squash"})
			settleMergeQueues(t)
			require.NotNil(t, queueEntry(t, pr))

			// the rules change while queued: the next pass takes it out, it is never merged with another style
			fields["allowed_merge_styles"] = []string{"rebase"}
			msRule(t, session, repo, http.StatusSeeOther, fields)
			settleMergeQueues(t)
			assert.Nil(t, queueEntry(t, pr))
			c := lastComment(pr, issues_model.CommentTypePRRemovedFromMergeQueue)
			require.NotNil(t, c)
			assert.Equal(t, mergequeue.ReasonMergeStyle, c.AutoMergeInfo().Reason)
			assert.False(t, merged(pr))
			assert.Contains(t, page(pr), "no longer allowed")
		})

		t.Run("Without styles the repository setting applies", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			msRule(t, session, repo, http.StatusSeeOther, url.Values{})
			assert.Empty(t, msStored(t, repo).AllowedMergeStyles)
			forgery.EnableRepoUnit(t, repo, unit_model.TypePullRequests, &repo_model.PullRequestsConfig{AllowSquash: true, DefaultMergeStyle: repo_model.MergeStyleSquash})
			pr := newPull(t)
			testPullMergeForm(t, session, http.StatusBadRequest, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "merge"})
			assert.Regexp(t, `'defaultMergeStyle': "squash"`, page(pr))

			// a rule turns on a style the repository has off
			msRule(t, session, repo, http.StatusSeeOther, url.Values{"allowed_merge_styles": {"merge"}})
			resp := session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/%s/settings/branches/edit?rule_name=main", repo.FullName())), http.StatusOK)
			assert.Contains(t, resp.Body.String(), "is off in the Pull requests settings")
			testPullMergeForm(t, session, http.StatusOK, owner.Name, repo.Name, index(pr), optionsPullMerge{"do": "merge"})
			assert.True(t, merged(pr))
		})
	})
}

func queueEntry(t *testing.T, pr *issues_model.PullRequest) *pull_model.MergeQueueEntry {
	t.Helper()
	e, err := pull_model.GetMergeQueueEntryByPullID(t.Context(), pr.ID)
	require.NoError(t, err)
	return e
}

func TestMergeStylesStack(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user := forgery.CreateUser(t, nil)
		repo, prs := newPullStack(t, user, nil)
		forgery.EnableRepoUnits(t, repo, unit_model.TypeCode, unit_model.TypePullRequests)
		require.NoError(t, git_model.UpdateProtectBranch(t.Context(), repo, &git_model.ProtectedBranch{
			RepoID: repo.ID, RuleName: "main", AllowedMergeStyles: []string{"squash"}, DefaultMergeStyle: "squash",
		}, git_model.WhitelistOptions{}))

		_, err := mergeStack(t, user, repo, prs[2], repo_model.MergeStyleMerge, stackHeads(t, repo, prs...))
		require.Error(t, err)
		cause := requireStackMergeError(t, err, prs[0].Index)
		assert.True(t, models.IsErrInvalidMergeStyle(cause), "%v", cause)
		assertMerged(t, false, prs...)

		_, err = mergeStack(t, user, repo, prs[2], repo_model.MergeStyleSquash, stackHeads(t, repo, prs...))
		require.NoError(t, err)
		assertMerged(t, true, prs...)
	})
}

// the rules of the repository and its organization: the styles are the intersection
func TestMergeStylesLevels(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		name := bwRepo(t, "styles-levels")
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: name})
		owner := loginUser(t, "user2")
		repoRuleURL := fmt.Sprintf("/%s/settings/branches/edit", repo.FullName())
		post := func(link string, v url.Values) {
			t.Helper()
			owner.MakeRequest(t, NewRequestWithURLValues(t, "POST", link, v), http.StatusSeeOther)
		}
		post("/org/org3/settings/branches/edit", url.Values{"rule_name": {"master"}, "allowed_merge_styles": {"squash", "rebase"}, "default_merge_style": {"rebase"}})
		orgRule := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{OrgID: 3, RuleName: "master"})
		assert.Equal(t, []string{"rebase", "squash"}, orgRule.AllowedMergeStyles)
		assert.NotContains(t, bwFlash(owner), "share none", "no warning without another level")

		// the repository's rule shares nothing with the organization's: saved, with a warning naming the rule
		post(repoRuleURL, url.Values{"rule_name": {"master"}, "allowed_merge_styles": {"merge"}})
		assert.Contains(t, bwFlash(owner), "share none with the organization rule")
		assert.Contains(t, bwFlash(owner), "rebase, squash")
		repoRule := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "master"})

		pr := bwPR(t, owner, "org3", name, "master", "levels-1")
		for _, style := range []string{"merge", "squash", "rebase"} {
			resp := owner.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/org3/%s/pulls/%s/merge", name, pr), map[string]string{"do": style}), http.StatusBadRequest)
			assert.Contains(t, resp.Body.String(), "branch rules")
		}
		body := owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org3/%s/pulls/%s", name, pr)), http.StatusOK).Body.String()
		assert.Contains(t, body, "allow no merge style in common")
		assert.Contains(t, body, "repository rule")

		// widened: the intersection is squash, the default of the most specific rule (none) falls to the first allowed
		post(repoRuleURL, url.Values{"rule_id": {strconv.FormatInt(repoRule.ID, 10)}, "rule_name": {"master"}, "allowed_merge_styles": {"merge", "squash"}, "default_merge_style": {"merge"}})
		assert.NotContains(t, bwFlash(owner), "share none")
		body = owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org3/%s/pulls/%s", name, pr)), http.StatusOK).Body.String()
		assert.Regexp(t, `'defaultMergeStyle': "squash"`, body)
		assert.Regexp(t, `'name': 'rebase',\s+'allowed':\s+false`, body)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/org3/%s/pulls/%s/merge", name, pr), map[string]string{"do": "merge"}), http.StatusBadRequest)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/org3/%s/pulls/%s/merge", name, pr), map[string]string{"do": "squash"}), http.StatusOK)

		// the organization's form refuses what the repository's does
		post("/org/org3/settings/branches/edit", url.Values{"rule_id": {strconv.FormatInt(orgRule.ID, 10)}, "rule_name": {"master"}, "allowed_merge_styles": {"nope"}})
		assert.NotEmpty(t, bwFlash(owner))
		assert.Equal(t, []string{"rebase", "squash"}, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: orgRule.ID}).AllowedMergeStyles)
	})
}
