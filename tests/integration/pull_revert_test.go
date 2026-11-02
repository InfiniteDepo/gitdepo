// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/services/forms"
	repo_service "forgejo.org/services/repository"
	files_service "forgejo.org/services/repository/files"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// revertTestRepo creates a repository with a merged two-commit pull request #1 (feature -> main)
// and returns it with the base branch tip from before the merge.
func revertTestRepo(t *testing.T, ctx APITestContext, name string, style repo_model.MergeStyle) (*repo_model.Repository, string) {
	t.Helper()
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repo, err := repo_service.CreateRepository(db.DefaultContext, user2, user2, repo_service.CreateRepoOptions{
		Name:          name,
		AutoInit:      true,
		Readme:        "Default",
		DefaultBranch: "main",
	})
	require.NoError(t, err)

	revertTestCommit(t, repo, "main", "feature", "create", "a.txt", "a\n")
	revertTestCommit(t, repo, "feature", "feature", "update", "README.md", "changed by the PR\n")
	_, err = doAPICreatePullRequest(ctx, "user2", name, "main", "feature")(t)
	require.NoError(t, err)

	if style != repo_model.MergeStyleFastForwardOnly {
		// Move the base branch so that rebases really rewrite the PR's commits.
		revertTestCommit(t, repo, "main", "main", "create", "before.txt", "before\n")
	}
	premerge, err := gitrepo.GetBranchCommitID(db.DefaultContext, repo, "main")
	require.NoError(t, err)
	doAPIMergePullRequestForm(t, ctx, "user2", name, 1, &forms.MergePullRequestForm{Do: string(style)})

	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, Index: 1})
	assert.True(t, pr.HasMerged)
	assert.Equal(t, premerge, pr.MergedBaseCommitID)
	return repo, premerge
}

func revertTestCommit(t *testing.T, repo *repo_model.Repository, oldBranch, newBranch, op, path, content string) {
	t.Helper()
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	file := &files_service.ChangeRepoFile{Operation: op, TreePath: path, ContentReader: strings.NewReader(content)}
	if op == "update" {
		gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
		require.NoError(t, err)
		defer gitRepo.Close()
		commit, err := gitRepo.GetBranchCommit(oldBranch)
		require.NoError(t, err)
		entry, err := commit.GetTreeEntryByPath(path)
		require.NoError(t, err)
		file.SHA = entry.ID.String()
	}
	_, err := files_service.ChangeRepoFiles(git.DefaultContext, repo, user2, &files_service.ChangeRepoFilesOptions{
		Files:     []*files_service.ChangeRepoFile{file},
		OldBranch: oldBranch,
		NewBranch: newBranch,
		Message:   op + " " + path,
	})
	require.NoError(t, err)
}

func revertTestURL(name string, index int) string {
	return fmt.Sprintf("/api/v1/repos/user2/%s/pulls/%d/revert", name, index)
}

func TestPullRevert(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		ctx := NewAPITestContext(t, "user2", "", auth_model.AccessTokenScopeWriteRepository)

		for _, style := range []repo_model.MergeStyle{
			repo_model.MergeStyleMerge,
			repo_model.MergeStyleSquash,
			repo_model.MergeStyleRebase,
			repo_model.MergeStyleRebaseMerge,
			repo_model.MergeStyleFastForwardOnly,
		} {
			t.Run(string(style), func(t *testing.T) {
				name := "revert-" + string(style)
				repo, premerge := revertTestRepo(t, ctx, name, style)
				// A later, unrelated change must survive the revert.
				revertTestCommit(t, repo, "main", "main", "create", "later.txt", "later\n")

				page := NewHTMLParser(t, ctx.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/"+name+"/pulls/1"), http.StatusOK).Body)
				assert.Equal(t, 1, page.Find("#revert-pull-request").Length())

				resp := ctx.Session.MakeRequest(t, NewRequest(t, "POST", revertTestURL(name, 1)).AddTokenAuth(ctx.Token), http.StatusCreated)
				var revert api.PullRequest
				DecodeJSON(t, resp, &revert)
				assert.Equal(t, "revert-1-feature", revert.Head.Ref)
				assert.Equal(t, "main", revert.Base.Ref)
				assert.Equal(t, `Revert "create a pr from feature to main"`, revert.Title)
				assert.Contains(t, revert.Body, "This reverts #1.")

				// The revert branch is the pre-merge tree plus the later change, nothing else.
				diff, _, err := git.NewCommand(t.Context(), "diff", "--name-only").AddDynamicArguments(premerge, "revert-1-feature").RunStdString(&git.RunOpts{Dir: repo.RepoPath()})
				require.NoError(t, err)
				assert.Equal(t, "later.txt", strings.TrimSpace(diff))

				// The original PR links to the revert.
				revertPR := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, Index: revert.Index})
				orig := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, Index: 1})
				unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{Type: issues_model.CommentTypePullRef, IssueID: orig.IssueID, RefIssueID: revertPR.IssueID})
				unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{Type: issues_model.CommentTypeRevertOpened, IssueID: orig.IssueID, RefIssueID: revertPR.IssueID})
				// Merging a pull request that is no revert adds no "reverted" entry.
				unittest.AssertNotExistsBean(t, &issues_model.Comment{Type: issues_model.CommentTypeReverted})

				// Reverting again: the branch exists.
				ctx.Session.MakeRequest(t, NewRequest(t, "POST", revertTestURL(name, 1)).AddTokenAuth(ctx.Token), http.StatusConflict)
			})
		}

		t.Run("web", func(t *testing.T) {
			repo, _ := revertTestRepo(t, ctx, "revert-web", repo_model.MergeStyleSquash)
			// The revert title must stay within the 255 runes allowed for issue titles.
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE issue SET name = ? WHERE repo_id = ? AND `index` = 1", strings.Repeat("x", 255), repo.ID)
			require.NoError(t, err)

			resp := ctx.Session.MakeRequest(t, NewRequest(t, "POST", "/user2/revert-web/pulls/1/revert"), http.StatusSeeOther)
			assert.Equal(t, "/user2/revert-web/pulls/2", test.RedirectURL(resp))
			revertPR := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, Index: 2, HeadBranch: "revert-1-feature"})
			require.NoError(t, revertPR.LoadIssue(db.DefaultContext))
			assert.Equal(t, `Revert "`+strings.Repeat("x", 243)+`..."`, revertPR.Issue.Title)

			// The original pull request's timeline links to the revert when it is opened and merged.
			timeline := func(index int) string {
				page := NewHTMLParser(t, ctx.Session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/user2/revert-web/pulls/%d", index)), http.StatusOK).Body)
				return page.Find(`.timeline-item:has(a[href="/user2/revert-web/pulls/2"])`).Text()
			}
			assert.Contains(t, timeline(1), "opened a revert of this pull request")
			assert.NotContains(t, timeline(1), "reverted this pull request")

			doAPIMergePullRequest(ctx, "user2", "revert-web", 2)(t)
			assert.Contains(t, timeline(1), "reverted this pull request")
			orig := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, Index: 1})
			unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{Type: issues_model.CommentTypeReverted, IssueID: orig.IssueID, RefIssueID: revertPR.IssueID})
			// The revert pull request itself gets neither entry.
			body := ctx.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/revert-web/pulls/2"), http.StatusOK).Body.String()
			assert.NotContains(t, body, "opened a revert of this pull request")
			assert.NotContains(t, body, "reverted this pull request")
		})

		t.Run("conflict", func(t *testing.T) {
			repo, _ := revertTestRepo(t, ctx, "revert-conflict", repo_model.MergeStyleMerge)
			revertTestCommit(t, repo, "main", "main", "update", "README.md", "changed again later\n")

			resp := ctx.Session.MakeRequest(t, NewRequest(t, "POST", revertTestURL("revert-conflict", 1)).AddTokenAuth(ctx.Token), http.StatusConflict)
			var apiErr api.APIError
			DecodeJSON(t, resp, &apiErr)
			assert.Contains(t, apiErr.Message, "can't be reverted automatically because later changes conflict")
			assert.Contains(t, apiErr.Message, "git switch -c revert-1-feature origin/main")
			assert.Contains(t, apiErr.Message, "git revert -m 1 ")

			assert.False(t, git.IsBranchExist(t.Context(), repo.RepoPath(), "revert-1-feature"))
			unittest.AssertNotExistsBean(t, &issues_model.PullRequest{BaseRepoID: repo.ID, Index: 2})

			ctx.Session.MakeRequest(t, NewRequest(t, "POST", "/user2/revert-conflict/pulls/1/revert"), http.StatusSeeOther)
			assert.False(t, git.IsBranchExist(t.Context(), repo.RepoPath(), "revert-1-feature"))
		})

		t.Run("not revertable", func(t *testing.T) {
			repo, _ := revertTestRepo(t, ctx, "revert-legacy", repo_model.MergeStyleRebase)
			// A multi-commit rebase merged before the base tip was recorded can't be reverted safely.
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE pull_request SET merged_base_commit_id = '' WHERE base_repo_id = ?", repo.ID)
			require.NoError(t, err)

			page := NewHTMLParser(t, ctx.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/revert-legacy/pulls/1"), http.StatusOK).Body)
			assert.Equal(t, 0, page.Find("#revert-pull-request").Length())
			ctx.Session.MakeRequest(t, NewRequest(t, "POST", revertTestURL("revert-legacy", 1)).AddTokenAuth(ctx.Token), http.StatusUnprocessableEntity)

			// An open pull request can't be reverted either.
			revertTestCommit(t, repo, "main", "open", "create", "open.txt", "open\n")
			_, err = doAPICreatePullRequest(ctx, "user2", "revert-legacy", "main", "open")(t)
			require.NoError(t, err)
			ctx.Session.MakeRequest(t, NewRequest(t, "POST", revertTestURL("revert-legacy", 2)).AddTokenAuth(ctx.Token), http.StatusUnprocessableEntity)
		})

		t.Run("permissions", func(t *testing.T) {
			repo, _ := revertTestRepo(t, ctx, "revert-perm", repo_model.MergeStyleMerge)

			// user4 can read the public repository but not write to it.
			user4 := NewAPITestContext(t, "user4", "", auth_model.AccessTokenScopeWriteRepository)
			page := NewHTMLParser(t, user4.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/revert-perm/pulls/1"), http.StatusOK).Body)
			assert.Equal(t, 0, page.Find("#revert-pull-request").Length())
			user4.Session.MakeRequest(t, NewRequest(t, "POST", revertTestURL("revert-perm", 1)).AddTokenAuth(user4.Token), http.StatusForbidden)
			user4.Session.MakeRequest(t, NewRequest(t, "POST", "/user2/revert-perm/pulls/1/revert"), http.StatusNotFound)
			MakeRequest(t, NewRequest(t, "POST", "/user2/revert-perm/pulls/1/revert"), http.StatusNotFound)

			// Archived repositories can't be changed.
			require.NoError(t, repo_model.SetArchiveRepoState(db.DefaultContext, repo, true))
			page = NewHTMLParser(t, ctx.Session.MakeRequest(t, NewRequest(t, "GET", "/user2/revert-perm/pulls/1"), http.StatusOK).Body)
			assert.Equal(t, 0, page.Find("#revert-pull-request").Length())
			ctx.Session.MakeRequest(t, NewRequest(t, "POST", revertTestURL("revert-perm", 1)).AddTokenAuth(ctx.Token), http.StatusLocked)

			assert.False(t, git.IsBranchExist(t.Context(), repo.RepoPath(), "revert-1-feature"))
		})
	})
}
