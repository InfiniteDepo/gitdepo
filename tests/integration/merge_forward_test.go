// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	activities_model "forgejo.org/models/activities"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	pull_model "forgejo.org/models/pull"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/gitrepo"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/forms"
	"forgejo.org/services/mergeforward"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeForward(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, _ *url.URL) {
		defer tests.PrintCurrentTest(t)()
		name := bwRepo(t, "mf-chain")
		owner := loginUser(t, "user2")
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "user2"})
		ctx := NewAPITestContext(t, "user2", name, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
		for _, b := range []string{"develop", "release/1.9", "release/1.10", "release/2.0"} {
			testAPICreateBranch(t, owner, "org3", name, "master", b, http.StatusCreated)
		}
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: name})
		// setModel sets the repository's branching model; change adjusts it before it is sent
		setModel := func(t *testing.T, mergeForward bool, change ...func(*api.EditRepoBranchingModelOption)) {
			t.Helper()
			opts := &api.EditRepoBranchingModelOption{
				DevelopmentBranch: "develop", ProductionBranch: "master", ReleasePrefixes: []string{"release/"}, MergeForward: mergeForward,
			}
			for _, f := range change {
				f(opts)
			}
			req := NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/"+name+"/branching-model", opts).AddTokenAuth(ctx.Token)
			ctx.Session.MakeRequest(t, req, http.StatusOK)
		}
		neverBypass := func(o *api.EditRepoBranchingModelOption) { o.MergeForwardNeverBypass = true }
		// pull opens a pull request into base from a new branch with one new file and returns it
		pull := func(t *testing.T, base, branch, file, content string) api.PullRequest {
			t.Helper()
			testAPICreateBranch(t, owner, "org3", name, base, branch, http.StatusCreated)
			require.NoError(t, createOrReplaceFileInBranch(user2, repo, file, branch, content))
			pr, err := doAPICreatePullRequest(ctx, "org3", name, base, branch)(t)
			require.NoError(t, err)
			return pr
		}
		merge := func(t *testing.T, pr api.PullRequest) {
			t.Helper()
			doAPIMergePullRequest(ctx, "org3", name, pr.Index)(t)
		}
		has := func(t *testing.T, branch, file string) bool {
			t.Helper()
			req := NewRequest(t, "GET", fmt.Sprintf("/api/v1/repos/org3/%s/contents/%s?ref=%s", name, file, url.QueryEscape(branch))).AddTokenAuth(ctx.Token)
			return ctx.Session.MakeRequest(t, req, NoExpectedStatus).Code == http.StatusOK
		}
		comments := func(pr api.PullRequest, typ issues_model.CommentType) []*issues_model.Comment {
			var list []*issues_model.Comment
			require.NoError(t, db.GetEngine(t.Context()).Where("issue_id = ? AND type = ?", issueIDOf(t, repo, pr.Index), typ).OrderBy("id").Find(&list))
			return list
		}

		t.Run("off", func(t *testing.T) {
			setModel(t, false)
			merge(t, pull(t, "release/1.9", "fix-off", "off.txt", "off"))
			assert.False(t, has(t, "release/1.10", "off.txt"))
			assert.False(t, has(t, "develop", "off.txt"))
		})

		t.Run("clean cascade", func(t *testing.T) {
			setModel(t, true)
			since := auditMaxID(t)
			pr := pull(t, "release/1.9", "fix-1", "fix1.txt", "fix")
			merge(t, pr)
			for _, b := range []string{"release/1.10", "release/2.0", "develop"} {
				assert.True(t, has(t, b, "fix1.txt"), b)
			}
			assert.False(t, has(t, "master", "fix1.txt"), "the default branch is not the development branch here")

			gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
			require.NoError(t, err)
			defer gitRepo.Close()
			head, err := gitRepo.GetBranchCommit("release/1.10")
			require.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("Automatic merge from release/1.9 -> release/1.10 (PR #%d)", pr.Index), strings.TrimSpace(head.Message()))
			assert.Equal(t, user2.NewGitSig().Name, head.Author.Name)
			assert.Equal(t, 2, head.ParentCount())

			list := comments(pr, issues_model.CommentTypePRMergedForward)
			require.Len(t, list, 1)
			info := list[0].MergeForwardInfo()
			require.Len(t, info.Steps, 3)
			assert.Equal(t, []string{"release/1.10", "release/2.0", "develop"}, []string{info.Steps[0].Branch, info.Steps[1].Branch, info.Steps[2].Branch})
			assert.Equal(t, head.ID.String(), info.Steps[0].SHA)
			assert.Equal(t, user2.ID, list[0].PosterID)

			entries := auditActions(t, since, "repo.branch.merged_forward")
			require.Len(t, entries, 3)
			assert.Equal(t, "release/1.10", entries[0].TargetName)
			assert.Equal(t, "release/1.9", auditData(t, entries[0])["from"])

			// the timeline renders the steps
			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org3/%s/pulls/%d", name, pr.Index)), http.StatusOK).Body)
			detail := doc.doc.Find(".merge-forward-detail").Text()
			for _, b := range []string{"release/1.10", "release/2.0", "develop"} {
				assert.Contains(t, detail, b)
			}
		})

		t.Run("a hotfix in the production branch reaches develop only", func(t *testing.T) {
			pr := pull(t, "master", "hotfix-1", "hotfix.txt", "fix")
			merge(t, pr)
			assert.True(t, has(t, "develop", "hotfix.txt"))
			assert.False(t, has(t, "release/2.0", "hotfix.txt"))
			list := comments(pr, issues_model.CommentTypePRMergedForward)
			require.Len(t, list, 1)
			assert.Equal(t, []issues_model.MergeForwardStep{{Branch: "develop", SHA: list[0].MergeForwardInfo().Steps[0].SHA}}, list[0].MergeForwardInfo().Steps)
		})

		t.Run("nothing to merge", func(t *testing.T) {
			yes := true
			req := NewRequestWithJSON(t, "PATCH", "/api/v1/repos/org3/"+name, &api.EditRepoOption{AllowFastForwardOnly: &yes}).AddTokenAuth(ctx.Token)
			ctx.Session.MakeRequest(t, req, http.StatusOK)
			// the change is in release/1.10, and through it in release/2.0 and develop, before it reaches release/1.9
			fix := pull(t, "release/1.10", "fix-2", "fix2.txt", "fix")
			merge(t, fix)
			require.True(t, has(t, "develop", "fix2.txt"))

			since := auditMaxID(t)
			pr, err := doAPICreatePullRequest(ctx, "org3", name, "release/1.9", "fix-2")(t)
			require.NoError(t, err)
			doAPIMergePullRequestForm(t, ctx, "org3", name, pr.Index, &forms.MergePullRequestForm{Do: string(repo_model.MergeStyleFastForwardOnly)})
			assert.True(t, has(t, "release/1.9", "fix2.txt"))
			assert.Empty(t, comments(pr, issues_model.CommentTypePRMergedForward))
			assert.Empty(t, comments(pr, issues_model.CommentTypePRMergeForwardStopped))
			assert.Empty(t, auditActions(t, since, "repo.branch.merged_forward"))
		})

		t.Run("conflict opens a pull request that continues", func(t *testing.T) {
			require.NoError(t, createOrReplaceFileInBranch(user2, repo, "conflict.txt", "release/2.0", "two"))
			since := auditMaxID(t)
			pr := pull(t, "release/1.9", "fix-3", "conflict.txt", "fix")
			merge(t, pr)
			assert.True(t, has(t, "release/1.10", "conflict.txt"))
			assert.False(t, has(t, "develop", "conflict.txt"))

			merged := comments(pr, issues_model.CommentTypePRMergedForward)
			require.Len(t, merged, 1)
			require.Len(t, merged[0].MergeForwardInfo().Steps, 1)
			stopped := comments(pr, issues_model.CommentTypePRMergeForwardStopped)
			require.Len(t, stopped, 1)
			assert.Equal(t, issues_model.MergeForwardInfo{Branch: "release/2.0", Reason: mergeforward.ReasonConflict}, stopped[0].MergeForwardInfo())

			branch := fmt.Sprintf("automerge/pr-%d/release/2.0", pr.Index)
			opened := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, HeadBranch: branch, BaseBranch: "release/2.0"})
			assert.Equal(t, opened.IssueID, stopped[0].RefIssueID)
			issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: opened.IssueID})
			assert.Equal(t, fmt.Sprintf("Automatic merge from release/1.10 -> release/2.0 (PR #%d)", pr.Index), issue.Title)
			require.NoError(t, issue.LoadAssignees(t.Context()))
			require.Len(t, issue.Assignees, 1)
			assert.Equal(t, user2.ID, issue.Assignees[0].ID)

			entries := auditActions(t, since, "repo.branch.merge_forward_stopped")
			require.Len(t, entries, 1)
			data := auditData(t, entries[0])
			assert.Equal(t, "conflict", data["reason"])
			assert.InDelta(t, float64(issue.Index), data["conflict_pull"], 0)

			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org3/%s/pulls/%d", name, pr.Index)), http.StatusOK).Body)
			assert.Contains(t, doc.doc.Find(".merge-forward-detail").Text(), "The merge has conflicts.")

			// resolve it the way release/2.0 has it, merge the pull request, and merging forward goes on to develop
			require.NoError(t, createOrReplaceFileInBranch(user2, repo, "conflict.txt", branch, "two"))
			merge(t, api.PullRequest{Index: issue.Index})
			assert.True(t, has(t, "develop", "conflict.txt"))
			cont := comments(api.PullRequest{Index: issue.Index}, issues_model.CommentTypePRMergedForward)
			require.Len(t, cont, 1)
			assert.Equal(t, "develop", cont[0].MergeForwardInfo().Steps[0].Branch)
		})

		t.Run("a step is an extension of the approved pull request", func(t *testing.T) {
			// develop takes no pushes and needs an approval and a status check: the merger may merge into it
			bwProtect(t, ctx, name, "develop", parameterProtectBranch{"required_approvals": "1", "enable_status_check": "true", "status_check_contexts": "ci"})
			pr := pull(t, "release/2.0", "fix-ext", "ext.txt", "fix")
			merge(t, pr)
			assert.True(t, has(t, "develop", "ext.txt"))
			merged := comments(pr, issues_model.CommentTypePRMergedForward)
			require.Len(t, merged, 1)
			assert.Equal(t, "develop", merged[0].MergeForwardInfo().Steps[0].Branch)

			// the hook takes a step only from the merger, into a branch of the chain, as a merge commit on top of it
			row := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{IssueID: issueIDOf(t, repo, pr.Index)})
			user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
			gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
			require.NoError(t, err)
			defer gitRepo.Close()
			head, err := gitRepo.GetBranchCommit("develop")
			require.NoError(t, err)
			parent, err := head.ParentID(0)
			require.NoError(t, err)
			for _, c := range []struct {
				name           string
				pusher         *user_model.User
				branch, oldSHA string
				allowed        bool
			}{
				{"the step", user2, "develop", parent.String(), true},
				{"another pusher", user4, "develop", parent.String(), false},
				{"a branch outside the chain", user2, "release/1.9", parent.String(), false},
				{"not on top of the branch", user2, "develop", head.ID.String(), false},
			} {
				allowed, err := mergeforward.AllowsStep(t.Context(), repo, row.ID, c.pusher, c.branch, c.oldSHA, head.ID.String(), nil)
				require.NoError(t, err)
				assert.Equal(t, c.allowed, allowed, c.name)
			}
		})

		t.Run("the merge allow list still applies", func(t *testing.T) {
			bwProtect(t, ctx, name, "develop", parameterProtectBranch{"enable_merge_whitelist": "true", "merge_whitelist_users": "4"})
			pr := pull(t, "release/2.0", "fix-mwl", "mwl.txt", "fix")
			merge(t, pr)
			assert.False(t, has(t, "develop", "mwl.txt"))
			stopped := comments(pr, issues_model.CommentTypePRMergeForwardStopped)
			require.Len(t, stopped, 1)
			assert.Equal(t, mergeforward.ReasonRefused, stopped[0].MergeForwardInfo().Reason)
		})

		t.Run("protected files are never bypassed", func(t *testing.T) {
			bwProtect(t, ctx, name, "develop", parameterProtectBranch{"protected_file_patterns": "*.lock"})
			pr := pull(t, "release/2.0", "fix-lock", "deps.lock", "fix")
			merge(t, pr)
			assert.False(t, has(t, "develop", "deps.lock"))
			require.Len(t, comments(pr, issues_model.CommentTypePRMergeForwardStopped), 1)
		})

		t.Run("a branch rule refuses a step when it never bypasses", func(t *testing.T) {
			setModel(t, true, neverBypass)
			bwProtect(t, ctx, name, "develop", parameterProtectBranch{})
			pr := pull(t, "release/2.0", "fix-4", "fix4.txt", "fix")
			merge(t, pr)
			assert.False(t, has(t, "develop", "fix4.txt"))
			stopped := comments(pr, issues_model.CommentTypePRMergeForwardStopped)
			require.Len(t, stopped, 1)
			assert.Equal(t, issues_model.MergeForwardInfo{Branch: "develop", Reason: mergeforward.ReasonRefused}, stopped[0].MergeForwardInfo())
			unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, HeadBranch: fmt.Sprintf("automerge/pr-%d/develop", pr.Index), BaseBranch: "develop"})
		})

		t.Run("a pull request title rule refuses the follow-up pull request", func(t *testing.T) {
			setModel(t, true, neverBypass)
			setPRTitleRule(t, repo.ID, git_model.PushRule{PRTitleRegex: `^ABC-\d+ `, PRTitleBranches: "develop"})
			defer setPRTitleRule(t, repo.ID, git_model.PushRule{})
			since := auditMaxID(t)
			pr := pull(t, "release/2.0", "fix-5", "fix5.txt", "fix")
			merge(t, pr)
			stopped := comments(pr, issues_model.CommentTypePRMergeForwardStopped)
			require.Len(t, stopped, 1)
			assert.Equal(t, issues_model.MergeForwardInfo{Branch: "develop", Reason: mergeforward.ReasonRefused, PullFailed: true}, stopped[0].MergeForwardInfo())
			assert.Zero(t, stopped[0].RefIssueID)
			entries := auditActions(t, since, "repo.branch.merge_forward_stopped")
			require.Len(t, entries, 1)
			assert.Equal(t, true, auditData(t, entries[0])["pull_failed"])
			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org3/%s/pulls/%d", name, pr.Index)), http.StatusOK).Body)
			assert.Contains(t, doc.doc.Find(".merge-forward-detail").Text(), "No pull request could be opened for it")
		})

		// mergedWithoutCascade merges a pull request into release/1.10 with merging forward off and turns it on again
		mergedWithoutCascade := func(t *testing.T, branch, file string) (api.PullRequest, *issues_model.PullRequest) {
			t.Helper()
			setModel(t, false)
			pr := pull(t, "release/1.10", branch, file, "fix")
			merge(t, pr)
			setModel(t, true)
			return pr, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{IssueID: issueIDOf(t, repo, pr.Index)})
		}

		t.Run("a pull request marked as merged manually is not merged forward", func(t *testing.T) {
			pr, row := mergedWithoutCascade(t, "fix-6", "fix6.txt")
			_, err := db.GetEngine(t.Context()).Exec("UPDATE pull_request SET status = ? WHERE id = ?", issues_model.PullRequestStatusManuallyMerged, row.ID)
			require.NoError(t, err)
			ran, err := mergeforward.Run(t.Context(), row.ID)
			require.NoError(t, err)
			assert.True(t, ran)
			assert.False(t, has(t, "release/2.0", "fix6.txt"))
			assert.Empty(t, comments(pr, issues_model.CommentTypePRMergedForward))
			assert.Empty(t, comments(pr, issues_model.CommentTypePRMergeForwardStopped))

			// the same pull request merged here is merged forward
			_, err = db.GetEngine(t.Context()).Exec("UPDATE pull_request SET status = ? WHERE id = ?", row.Status, row.ID)
			require.NoError(t, err)
			_, err = mergeforward.Run(t.Context(), row.ID)
			require.NoError(t, err)
			assert.True(t, has(t, "release/2.0", "fix6.txt"))
		})

		t.Run("a merger without write access stops it", func(t *testing.T) {
			pr, row := mergedWithoutCascade(t, "fix-7", "fix7.txt")
			user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
			_, err := db.GetEngine(t.Context()).Exec("UPDATE pull_request SET merger_id = ? WHERE id = ?", user4.ID, row.ID)
			require.NoError(t, err)
			_, err = mergeforward.Run(t.Context(), row.ID)
			require.NoError(t, err)
			assert.False(t, has(t, "release/2.0", "fix7.txt"))
			stopped := comments(pr, issues_model.CommentTypePRMergeForwardStopped)
			require.Len(t, stopped, 1)
			assert.Equal(t, issues_model.MergeForwardInfo{Branch: "release/2.0", Reason: mergeforward.ReasonMerger}, stopped[0].MergeForwardInfo())
			assert.False(t, has(t, fmt.Sprintf("automerge/pr-%d/release/2.0", pr.Index), "fix7.txt"))
			// the author of the pull request is told
			unittest.AssertExistsAndLoadBean(t, &activities_model.Notification{UserID: user2.ID, IssueID: row.IssueID, CommentID: stopped[0].ID})
		})

		t.Run("a target that moves during a step is retried", func(t *testing.T) {
			pr, row := mergedWithoutCascade(t, "fix-move", "fixmove.txt")
			moved := false
			defer test.MockVariableValue(&mergeforward.BeforeStepPush, func(_ context.Context, target string) {
				if target == "release/2.0" && !moved {
					moved = true
					require.NoError(t, createOrReplaceFileInBranch(user2, repo, "moved.txt", "release/2.0", "moved"))
				}
			})()
			_, err := mergeforward.Run(t.Context(), row.ID)
			require.NoError(t, err)
			assert.True(t, moved)
			for _, b := range []string{"release/2.0", "develop"} {
				assert.True(t, has(t, b, "fixmove.txt"), b)
				assert.True(t, has(t, b, "moved.txt"), b)
			}
			list := comments(pr, issues_model.CommentTypePRMergedForward)
			require.Len(t, list, 1)
			assert.Len(t, list[0].MergeForwardInfo().Steps, 2)
			assert.Empty(t, comments(pr, issues_model.CommentTypePRMergeForwardStopped))
		})

		t.Run("a target that keeps moving stops it", func(t *testing.T) {
			pr, row := mergedWithoutCascade(t, "fix-moving", "fixmoving.txt")
			moves := 0
			defer test.MockVariableValue(&mergeforward.BeforeStepPush, func(_ context.Context, target string) {
				if target == "release/2.0" {
					moves++
					require.NoError(t, createOrReplaceFileInBranch(user2, repo, "moving.txt", "release/2.0", strconv.Itoa(moves)))
				}
			})()
			_, err := mergeforward.Run(t.Context(), row.ID)
			require.NoError(t, err)
			assert.Equal(t, 3, moves, "every attempt is retried")
			assert.False(t, has(t, "release/2.0", "fixmoving.txt"))
			stopped := comments(pr, issues_model.CommentTypePRMergeForwardStopped)
			require.Len(t, stopped, 1)
			assert.Equal(t, "release/2.0", stopped[0].MergeForwardInfo().Branch)
			assert.Equal(t, mergeforward.ReasonError, stopped[0].MergeForwardInfo().Reason)
		})

		t.Run("a second cascade waits for the running one", func(t *testing.T) {
			first, firstRow := mergedWithoutCascade(t, "fix-first", "fixfirst.txt")
			// the second one is merged into release/1.9, so the first cascade, from release/1.10, doesn't carry it
			setModel(t, false)
			second := pull(t, "release/1.9", "fix-second", "fixsecond.txt", "fix")
			merge(t, second)
			setModel(t, true)
			secondRow := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{IssueID: issueIDOf(t, repo, second.Index)})
			called := false
			defer test.MockVariableValue(&mergeforward.BeforeStepPush, func(ctx context.Context, target string) {
				if called {
					return
				}
				called = true
				ran, err := mergeforward.Run(ctx, secondRow.ID)
				require.NoError(t, err)
				assert.False(t, ran, "the queue retries it")
			})()
			_, err := mergeforward.Run(t.Context(), firstRow.ID)
			require.NoError(t, err)
			require.True(t, called)
			assert.True(t, has(t, "develop", "fixfirst.txt"))
			assert.Empty(t, comments(first, issues_model.CommentTypePRMergeForwardStopped))
			require.Len(t, comments(first, issues_model.CommentTypePRMergedForward), 1)
			assert.False(t, has(t, "release/1.10", "fixsecond.txt"))
			assert.Empty(t, comments(second, issues_model.CommentTypePRMergedForward))

			// the retry runs once the first one is done
			ran, err := mergeforward.Run(t.Context(), secondRow.ID)
			require.NoError(t, err)
			assert.True(t, ran)
			assert.True(t, has(t, "develop", "fixsecond.txt"))
			require.Len(t, comments(second, issues_model.CommentTypePRMergedForward), 1)
		})

		skipped := func(t *testing.T, pr api.PullRequest, by *user_model.User) {
			t.Helper()
			list := comments(pr, issues_model.CommentTypePRMergeForwardSkipped)
			require.Len(t, list, 1)
			assert.Equal(t, by.ID, list[0].PosterID)
			assert.Equal(t, "release/2.0", list[0].MergeForwardInfo().Branch)
			assert.Empty(t, comments(pr, issues_model.CommentTypePRMergedForward))
		}

		t.Run("don't merge forward", func(t *testing.T) {
			setModel(t, true)
			since := auditMaxID(t)
			pr := pull(t, "release/1.10", "fix-skip", "skip.txt", "fix")
			no := false
			doAPIMergePullRequestForm(t, ctx, "org3", name, pr.Index, &forms.MergePullRequestForm{Do: "merge", MergeForward: &no})
			assert.True(t, has(t, "release/1.10", "skip.txt"))
			assert.False(t, has(t, "release/2.0", "skip.txt"))
			skipped(t, pr, user2)
			entries := auditActions(t, since, "repo.branch.merge_forward_skipped")
			require.Len(t, entries, 1)
			assert.Equal(t, "release/1.10", entries[0].TargetName)
			assert.Equal(t, user2.ID, entries[0].ActorID)

			doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org3/%s/pulls/%d", name, pr.Index)), http.StatusOK).Body)
			assert.Contains(t, doc.doc.Find(".timeline").Text(), "chose not to merge this forward into release/2.0")
		})

		t.Run("don't merge forward in the merge box", func(t *testing.T) {
			pr := pull(t, "release/1.10", "fix-skip-web", "skipweb.txt", "fix")
			page := owner.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org3/%s/pulls/%d", name, pr.Index)), http.StatusOK).Body.String()
			assert.Contains(t, strings.ReplaceAll(page, " ", ""), "'canSkipMergeForward':true")
			testPullMergeForm(t, owner, http.StatusOK, "org3", name, strconv.FormatInt(pr.Index, 10), optionsPullMerge{"do": "merge", "skip_merge_forward": "on"})
			assert.True(t, has(t, "release/1.10", "skipweb.txt"))
			assert.False(t, has(t, "release/2.0", "skipweb.txt"))
			skipped(t, pr, user2)
		})

		t.Run("only those who may change the model may skip", func(t *testing.T) {
			write := "write"
			req := NewRequestWithJSON(t, "PUT", fmt.Sprintf("/api/v1/repos/org3/%s/collaborators/user4", name), &api.AddCollaboratorOption{Permission: &write}).AddTokenAuth(ctx.Token)
			ctx.Session.MakeRequest(t, req, http.StatusNoContent)
			user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
			ctx4 := NewAPITestContext(t, "user4", name, auth_model.AccessTokenScopeWriteRepository)
			no := false

			pr := pull(t, "release/1.10", "fix-skip-4", "skip4.txt", "fix")
			page := loginUser(t, "user4").MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org3/%s/pulls/%d", name, pr.Index)), http.StatusOK).Body.String()
			assert.Contains(t, strings.ReplaceAll(page, " ", ""), "'canSkipMergeForward':false")
			ctx4.ExpectedCode = http.StatusForbidden
			doAPIMergePullRequestForm(t, ctx4, "org3", name, pr.Index, &forms.MergePullRequestForm{Do: "merge", MergeForward: &no})
			assert.False(t, has(t, "release/1.10", "skip4.txt"), "nothing is merged")

			setModel(t, true, func(o *api.EditRepoBranchingModelOption) { o.MergeForwardAnyoneMaySkip = true })
			ctx4.ExpectedCode = http.StatusOK
			doAPIMergePullRequestForm(t, ctx4, "org3", name, pr.Index, &forms.MergePullRequestForm{Do: "merge", MergeForward: &no})
			assert.False(t, has(t, "release/2.0", "skip4.txt"))
			skipped(t, pr, user4)
			setModel(t, true)
		})

		t.Run("an organization that enforces the model", func(t *testing.T) {
			setModel(t, false)
			org3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "org3"})
			require.NoError(t, branchworkflow.SetOrgModel(t.Context(), org3, &repo_model.BranchingModel{DevelopmentBranch: "develop", ProductionBranch: "master", ReleasePrefixes: []string{"release/"}, MergeForward: true}, true))
			defer func() { require.NoError(t, branchworkflow.SetOrgModel(t.Context(), org3, nil, false)) }()
			pr := pull(t, "release/1.10", "fix-org", "org.txt", "fix")
			merge(t, pr)
			assert.True(t, has(t, "release/2.0", "org.txt"), "the repository's own model is not used while the organization enforces one")

			// only an owner of the organization may skip it then: user4 may not even with write access
			pr = pull(t, "release/1.10", "fix-org-skip", "orgskip.txt", "fix")
			ctx4 := NewAPITestContext(t, "user4", name, auth_model.AccessTokenScopeWriteRepository)
			ctx4.ExpectedCode = http.StatusForbidden
			no := false
			doAPIMergePullRequestForm(t, ctx4, "org3", name, pr.Index, &forms.MergePullRequestForm{Do: "merge", MergeForward: &no})
			doAPIMergePullRequestForm(t, ctx, "org3", name, pr.Index, &forms.MergePullRequestForm{Do: "merge", MergeForward: &no})
			assert.False(t, has(t, "release/2.0", "orgskip.txt"))
		})

		t.Run("an auto merge keeps don't merge forward", func(t *testing.T) {
			setModel(t, true)
			req := NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/org3/%s/branch_protections", name), &api.CreateBranchProtectionOption{
				RuleName: "release/1.10", EnablePush: true, EnableStatusCheck: true, StatusCheckContexts: []string{"ci"},
			}).AddTokenAuth(ctx.Token)
			ctx.Session.MakeRequest(t, req, http.StatusCreated)
			pr := pull(t, "release/1.10", "fix-auto", "auto.txt", "fix")
			no := false
			ctx.ExpectedCode = http.StatusCreated
			doAPIMergePullRequestForm(t, ctx, "org3", name, pr.Index, &forms.MergePullRequestForm{Do: "merge", MergeWhenChecksSucceed: true, MergeForward: &no})
			ctx.ExpectedCode = 0
			row := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{IssueID: issueIDOf(t, repo, pr.Index)})
			unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: row.ID, SkipMergeForward: true})

			// a passing check merges it
			req = NewRequestWithJSON(t, "POST", fmt.Sprintf("/api/v1/repos/org3/%s/statuses/%s", name, pr.Head.Sha), &api.CreateStatusOption{State: api.CommitStatusSuccess, Context: "ci"}).AddTokenAuth(ctx.Token)
			ctx.Session.MakeRequest(t, req, http.StatusCreated)
			assert.True(t, has(t, "release/1.10", "auto.txt"))
			assert.False(t, has(t, "release/2.0", "auto.txt"))
			skipped(t, pr, user2)
		})
	})
}

func issueIDOf(t *testing.T, repo *repo_model.Repository, index int64) int64 {
	t.Helper()
	return unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{RepoID: repo.ID, Index: index}).ID
}
