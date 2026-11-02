// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/services/automerge"
	"forgejo.org/services/forms"
	"forgejo.org/tests"
	"forgejo.org/tests/forgery"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (c *conversationCheckPR) topLevelComment(t *testing.T, session *TestSession, content string) *issues_model.Comment {
	t.Helper()
	session.MakeRequest(t, NewRequestWithValues(t, "POST", c.link()+"/comments", map[string]string{"content": content}), http.StatusOK)
	return unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: c.pr.IssueID, Type: issues_model.CommentTypeComment, Content: content})
}

func (c *conversationCheckPR) webCreateTask(t *testing.T, session *TestSession, content string, commentID int64, expectedStatus int) {
	t.Helper()
	session.MakeRequest(t, NewRequestWithValues(t, "POST", c.link()+"/tasks/new", map[string]string{
		"content":    content,
		"comment_id": strconv.FormatInt(commentID, 10),
	}), expectedStatus)
}

func (c *conversationCheckPR) apiCreateTask(t *testing.T, token, content string, expectedStatus int) *api.PullTask {
	t.Helper()
	resp := MakeRequest(t, NewRequestWithJSON(t, "POST", c.apiLink()+"/tasks", &api.CreatePullTaskOption{Content: content}).AddTokenAuth(token), expectedStatus)
	if expectedStatus != http.StatusCreated {
		return nil
	}
	var task api.PullTask
	DecodeJSON(t, resp, &task)
	return &task
}

func (c *conversationCheckPR) apiSetTaskStatus(t *testing.T, token string, id int64, status string, expectedStatus int) {
	t.Helper()
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("%s/tasks/%d", c.apiLink(), id), &api.EditPullTaskOption{Status: status}).AddTokenAuth(token), expectedStatus)
}

func (c *conversationCheckPR) apiDeleteTask(t *testing.T, token string, id int64, expectedStatus int) {
	t.Helper()
	MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/tasks/%d", c.apiLink(), id)).AddTokenAuth(token), expectedStatus)
}

func taskDone(t *testing.T, id int64) bool {
	t.Helper()
	return unittest.AssertExistsAndLoadBean(t, &issues_model.PullTask{ID: id}).IsDone
}

// AC6: anyone who can comment adds tasks from a top-level comment, from a diff comment and standalone;
// others get 403 and no control.
func TestPullTaskCreate(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		reader := forgery.CreateUser(t, nil)
		blocked := forgery.CreateUser(t, nil)
		c := prepareConversationCheckPR(t, nil)
		readerSession := loginUser(t, reader.Name)
		readerToken := getTokenForLoggedInUser(t, readerSession, auth_model.AccessTokenScopeWriteRepository)

		topLevel := c.topLevelComment(t, readerSession, "please add a test")
		diff := c.codeComment(t, readerSession, "and handle the empty case", http.StatusOK)

		resp := readerSession.MakeRequest(t, NewRequest(t, "GET", c.link()), http.StatusOK)
		doc := NewHTMLParser(t, resp.Body)
		assert.Equal(t, 1, doc.Find(`#pull-tasks form[action$="/tasks/new"]`).Length())
		assert.Equal(t, 1, doc.Find(fmt.Sprintf(`.create-pull-task input[name="comment_id"][value="%d"]`, topLevel.ID)).Length())
		assert.Equal(t, 1, doc.Find(fmt.Sprintf(`.create-pull-task input[name="comment_id"][value="%d"]`, diff.ID)).Length())

		c.webCreateTask(t, readerSession, "add a test", topLevel.ID, http.StatusSeeOther)
		c.webCreateTask(t, readerSession, "handle the empty case", diff.ID, http.StatusSeeOther)
		c.webCreateTask(t, readerSession, "update the changelog", 0, http.StatusSeeOther)
		apiTask := c.apiCreateTask(t, readerToken, "bump the version", http.StatusCreated)
		assert.Equal(t, "open", apiTask.Status)
		assert.Equal(t, reader.ID, apiTask.Creator.ID)
		assert.Equal(t, c.repo.Owner.ID, apiTask.Assignee.ID)

		for content, commentID := range map[string]int64{"add a test": topLevel.ID, "handle the empty case": diff.ID, "update the changelog": 0} {
			task := unittest.AssertExistsAndLoadBean(t, &issues_model.PullTask{IssueID: c.pr.IssueID, Content: content})
			assert.Equal(t, commentID, task.CommentID)
			assert.Equal(t, reader.ID, task.CreatorID)
			assert.Equal(t, c.repo.Owner.ID, task.AssigneeID, "assigned to the PR poster")
			assert.False(t, task.IsDone)
		}

		t.Run("invalid input", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			other := forgery.CreateIssue(t, c.repo.Owner, c.repo, "other", "")
			otherComment, err := issues_model.CreateComment(t.Context(), &issues_model.CreateCommentOptions{
				Type: issues_model.CommentTypeComment, Doer: c.repo.Owner, Repo: c.repo, Issue: other, Content: "elsewhere",
			})
			require.NoError(t, err)
			c.webCreateTask(t, readerSession, "foreign comment", otherComment.ID, http.StatusNotFound)
			c.webCreateTask(t, readerSession, strings.Repeat("é", 256), 0, http.StatusSeeOther)
			unittest.AssertNotExistsBean(t, &issues_model.PullTask{IssueID: c.pr.IssueID, Content: strings.Repeat("é", 256)})
			c.webCreateTask(t, readerSession, strings.Repeat("é", 255), 0, http.StatusSeeOther)
			unittest.AssertExistsAndLoadBean(t, &issues_model.PullTask{IssueID: c.pr.IssueID, Content: strings.Repeat("é", 255)})
			c.apiCreateTask(t, readerToken, strings.Repeat("x", 256), http.StatusUnprocessableEntity)
		})

		t.Run("blocked by the owner", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			blockedSession := loginUser(t, blocked.Name)
			blockedToken := getTokenForLoggedInUser(t, blockedSession, auth_model.AccessTokenScopeWriteRepository)
			BlockUser(t, c.repo.Owner, blocked)
			c.webCreateTask(t, blockedSession, "blocked task", 0, http.StatusForbidden)
			c.apiCreateTask(t, blockedToken, "blocked task", http.StatusForbidden)
			resp := blockedSession.MakeRequest(t, NewRequest(t, "GET", c.link()), http.StatusOK)
			assert.Zero(t, NewHTMLParser(t, resp.Body).Find(`form[action$="/tasks/new"]`).Length())
		})

		t.Run("locked", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()
			require.NoError(t, c.pr.LoadIssue(t.Context()))
			require.NoError(t, issues_model.LockIssue(t.Context(), &issues_model.IssueLockOptions{Doer: c.repo.Owner, Issue: c.pr.Issue}))
			c.webCreateTask(t, readerSession, "locked task", 0, http.StatusForbidden)
			c.apiCreateTask(t, readerToken, "locked task", http.StatusForbidden)
			resp := readerSession.MakeRequest(t, NewRequest(t, "GET", c.link()), http.StatusOK)
			assert.Zero(t, NewHTMLParser(t, resp.Body).Find(`form[action$="/tasks/new"]`).Length())
			unittest.AssertNotExistsBean(t, &issues_model.PullTask{IssueID: c.pr.IssueID, Content: "locked task"})
		})
	})
}

// AC7, AC9: the PR author, the creator and writers change the status; the creator and admins delete.
func TestPullTaskPermissions(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		author := forgery.CreateUser(t, nil)
		writer := forgery.CreateUser(t, nil)
		admin := forgery.CreateUser(t, nil)
		creator := forgery.CreateUser(t, nil)
		other := forgery.CreateUser(t, nil)
		c := prepareConversationCheckPR(t, map[*user_model.User]perm.AccessMode{
			author: perm.AccessModeWrite,
			writer: perm.AccessModeWrite,
			admin:  perm.AccessModeAdmin,
		}, author)
		token := func(user *user_model.User) string {
			return getTokenForLoggedInUser(t, loginUser(t, user.Name), auth_model.AccessTokenScopeWriteRepository)
		}
		authorToken, writerToken, adminToken, creatorToken, otherToken := token(author), token(writer), token(admin), token(creator), token(other)

		first := c.apiCreateTask(t, creatorToken, "first", http.StatusCreated)
		second := c.apiCreateTask(t, creatorToken, "second", http.StatusCreated)
		assert.Equal(t, author.ID, first.Assignee.ID)

		resp := MakeRequest(t, NewRequest(t, "GET", c.apiLink()+"/tasks").AddTokenAuth(otherToken), http.StatusOK)
		var tasks []*api.PullTask
		DecodeJSON(t, resp, &tasks)
		require.Len(t, tasks, 2)
		assert.Equal(t, "first", tasks[0].Content)

		// status
		c.apiSetTaskStatus(t, otherToken, first.ID, "done", http.StatusForbidden)
		assert.False(t, taskDone(t, first.ID))
		c.apiSetTaskStatus(t, creatorToken, first.ID, "done", http.StatusOK)
		assert.True(t, taskDone(t, first.ID))
		c.apiSetTaskStatus(t, authorToken, first.ID, "open", http.StatusOK)
		assert.False(t, taskDone(t, first.ID))
		c.apiSetTaskStatus(t, writerToken, first.ID, "done", http.StatusOK)
		assert.True(t, taskDone(t, first.ID))
		c.apiSetTaskStatus(t, writerToken, first.ID, "finished", http.StatusUnprocessableEntity)
		loginUser(t, other.Name).MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("%s/tasks/%d/status", c.link(), first.ID), map[string]string{"done": "false"}), http.StatusForbidden)
		loginUser(t, author.Name).MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("%s/tasks/%d/status", c.link(), first.ID), map[string]string{"done": "false"}), http.StatusSeeOther)
		assert.False(t, taskDone(t, first.ID))

		// a creator blocked by the owner can no longer change their task
		blockedCreator := forgery.CreateUser(t, nil)
		blockedTask := c.apiCreateTask(t, token(blockedCreator), "blocked creator's task", http.StatusCreated)
		c.apiSetTaskStatus(t, adminToken, blockedTask.ID, "done", http.StatusOK)
		BlockUser(t, c.repo.Owner, blockedCreator)
		blockedSession := loginUser(t, blockedCreator.Name)
		c.apiSetTaskStatus(t, getTokenForLoggedInUser(t, blockedSession, auth_model.AccessTokenScopeWriteRepository), blockedTask.ID, "open", http.StatusForbidden)
		blockedSession.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("%s/tasks/%d/status", c.link(), blockedTask.ID), map[string]string{"done": "false"}), http.StatusForbidden)
		assert.True(t, taskDone(t, blockedTask.ID))
		resp = blockedSession.MakeRequest(t, NewRequest(t, "GET", c.link()), http.StatusOK)
		assert.Zero(t, NewHTMLParser(t, resp.Body).Find(fmt.Sprintf(`form[action$="/tasks/%d/status"]`, blockedTask.ID)).Length())

		// delete
		c.apiDeleteTask(t, otherToken, first.ID, http.StatusForbidden)
		c.apiDeleteTask(t, authorToken, first.ID, http.StatusForbidden)
		c.apiDeleteTask(t, writerToken, first.ID, http.StatusForbidden)
		loginUser(t, author.Name).MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("%s/tasks/%d/delete", c.link(), first.ID)), http.StatusForbidden)
		unittest.AssertExistsAndLoadBean(t, &issues_model.PullTask{ID: first.ID})
		c.apiDeleteTask(t, adminToken, first.ID, http.StatusNoContent)
		unittest.AssertNotExistsBean(t, &issues_model.PullTask{ID: first.ID})
		loginUser(t, creator.Name).MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("%s/tasks/%d/delete", c.link(), second.ID)), http.StatusSeeOther)
		unittest.AssertNotExistsBean(t, &issues_model.PullTask{ID: second.ID})

		// a task of another pull request is not found
		otherPR := prepareConversationCheckPR(t, nil)
		foreign := otherPR.apiCreateTask(t, token(otherPR.repo.Owner), "foreign", http.StatusCreated)
		c.apiSetTaskStatus(t, adminToken, foreign.ID, "done", http.StatusNotFound)
		c.apiDeleteTask(t, adminToken, foreign.ID, http.StatusNotFound)
	})
}

// AC8: the header and the merge box show the progress, the sidebar lists the tasks, and the timeline
// records created, done, reopened and deleted, with the task text escaped.
func TestPullTaskTimelineAndPanel(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		c := prepareConversationCheckPR(t, nil)
		session := loginUser(t, c.repo.Owner.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)

		first := c.apiCreateTask(t, token, "<b>bold</b> task", http.StatusCreated)
		c.apiCreateTask(t, token, "second task", http.StatusCreated)
		third := c.apiCreateTask(t, token, "third task", http.StatusCreated)
		c.apiSetTaskStatus(t, token, first.ID, "done", http.StatusOK)
		c.apiSetTaskStatus(t, token, third.ID, "done", http.StatusOK)
		c.apiSetTaskStatus(t, token, third.ID, "open", http.StatusOK)
		c.apiDeleteTask(t, token, third.ID, http.StatusNoContent)

		for typ, count := range map[issues_model.CommentType]int{
			issues_model.CommentTypePullTaskCreated:  3,
			issues_model.CommentTypePullTaskDone:     2,
			issues_model.CommentTypePullTaskReopened: 1,
			issues_model.CommentTypePullTaskDeleted:  1,
		} {
			assert.Equal(t, count, unittest.GetCount(t, &issues_model.Comment{IssueID: c.pr.IssueID, Type: typ}), typ.String())
		}

		resp := session.MakeRequest(t, NewRequest(t, "GET", c.link()), http.StatusOK)
		body := resp.Body.String()
		assert.NotContains(t, body, "<b>bold</b>")
		assert.Contains(t, body, "&lt;b&gt;bold&lt;/b&gt; task")
		doc := NewHTMLParser(t, resp.Body)
		assert.Equal(t, "Tasks: 1 of 2 done", strings.TrimSpace(doc.Find(".issue-title-meta .pull-tasks-progress").Text()))
		assert.Equal(t, "Tasks: 1 of 2 done", strings.TrimSpace(doc.Find(".merge.box .pull-tasks-progress").Text()))
		assert.Equal(t, 2, doc.Find("#pull-tasks .pull-task").Length())
		assert.Equal(t, 1, doc.Find("#pull-tasks .pull-task.done").Length())
		assert.Equal(t, 7, doc.Find(".timeline-item .pull-task-content").Length())
	})
}

// AC10, AC12, AC13: open tasks block web, API and auto-merge only with the option on; the last task
// done lets the pending auto-merge through.
func TestPullTaskMergeCheck(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		c := prepareConversationCheckPR(t, nil)
		owner := c.repo.Owner
		session := loginUser(t, owner.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		task := c.apiCreateTask(t, token, "add a test", http.StatusCreated)

		// with the option off, open tasks don't block
		c.protect(t, git_model.ProtectedBranch{})
		assert.Empty(t, c.mergeableReasons(t, token))

		c.protect(t, git_model.ProtectedBranch{BlockOnIncompleteTasks: true})
		assert.Equal(t, []string{"incomplete_tasks"}, c.mergeableReasons(t, token))

		resp := session.MakeRequest(t, NewRequest(t, "GET", c.link()), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "This pull request has tasks that are not done.")

		testPullMergeForm(t, session, http.StatusBadRequest, owner.Name, c.repo.Name, strconv.FormatInt(c.pr.Index, 10), optionsPullMerge{"do": "merge"})
		MakeRequest(t, NewRequestWithJSON(t, "POST", c.apiLink()+"/merge", &forms.MergePullRequestForm{Do: "merge"}).AddTokenAuth(token), http.StatusMethodNotAllowed)
		scheduled, err := automerge.ScheduleAutoMerge(db.DefaultContext, owner, c.pr, repo_model.MergeStyleMerge, "auto merge", false, 0, 0, "")
		require.NoError(t, err)
		assert.True(t, scheduled)
		automerge.StartPRCheckAndAutoMerge(db.DefaultContext, c.pr)
		assert.False(t, c.hasMerged(t))

		c.apiSetTaskStatus(t, token, task.ID, "done", http.StatusOK)
		assert.True(t, c.hasMerged(t))
	})
}

// AC13: with the option off, a PR with an open task merges as before.
func TestPullTaskOptionsOffUnchanged(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		c := prepareConversationCheckPR(t, nil)
		session := loginUser(t, c.repo.Owner.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		c.apiCreateTask(t, token, "never done", http.StatusCreated)
		c.protect(t, git_model.ProtectedBranch{})
		testPullMerge(t, session, c.repo.Owner.Name, c.repo.Name, strconv.FormatInt(c.pr.Index, 10), repo_model.MergeStyleMerge, false)
		assert.True(t, c.hasMerged(t))
	})
}

// AC11: repo admins merge past open tasks only when ApplyToAdmins is off.
func TestPullTaskMergeCheckApplyToAdmins(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		admin := forgery.CreateUser(t, nil)
		c := prepareConversationCheckPR(t, map[*user_model.User]perm.AccessMode{admin: perm.AccessModeAdmin})
		token := getTokenForLoggedInUser(t, loginUser(t, admin.Name), auth_model.AccessTokenScopeWriteRepository)
		c.apiCreateTask(t, token, "open task", http.StatusCreated)
		merge := &forms.MergePullRequestForm{Do: "merge", ForceMerge: true}

		c.protect(t, git_model.ProtectedBranch{BlockOnIncompleteTasks: true, ApplyToAdmins: true})
		MakeRequest(t, NewRequestWithJSON(t, "POST", c.apiLink()+"/merge", merge).AddTokenAuth(token), http.StatusMethodNotAllowed)
		assert.False(t, c.hasMerged(t))

		c.protect(t, git_model.ProtectedBranch{BlockOnIncompleteTasks: true})
		MakeRequest(t, NewRequestWithJSON(t, "POST", c.apiLink()+"/merge", merge).AddTokenAuth(token), http.StatusOK)
		assert.True(t, c.hasMerged(t))
	})
}

// AC10: the option is saved and shown in the web form and in the API.
func TestPullTaskMergeCheckOption(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		c := prepareConversationCheckPR(t, nil)
		session := loginUser(t, c.repo.Owner.Name)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)

		session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/%s/settings/branches/edit", c.repo.FullName()), map[string]string{
			"rule_name":                 "main",
			"block_on_incomplete_tasks": "on",
		}), http.StatusSeeOther)
		resp := session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/%s/settings/branches/edit?rule_name=main", c.repo.FullName())), http.StatusOK)
		NewHTMLParser(t, resp.Body).AssertElementChecked(t, `input[name="block_on_incomplete_tasks"]`)

		branchLink := fmt.Sprintf("/api/v1/repos/%s/branch_protections/main", c.repo.FullName())
		resp = MakeRequest(t, NewRequest(t, "GET", branchLink).AddTokenAuth(token), http.StatusOK)
		var bp api.BranchProtection
		DecodeJSON(t, resp, &bp)
		assert.True(t, bp.BlockOnIncompleteTasks)
		resp = MakeRequest(t, NewRequestWithJSON(t, "PATCH", branchLink, &api.EditBranchProtectionOption{BlockOnIncompleteTasks: new(false)}).AddTokenAuth(token), http.StatusOK)
		DecodeJSON(t, resp, &bp)
		assert.False(t, bp.BlockOnIncompleteTasks)
	})
}
