// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"errors"
	"net/http"

	issues_model "forgejo.org/models/issues"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/services/automerge"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
)

// getPullTaskIssue returns the pull request of the URL, or writes a response.
func getPullTaskIssue(ctx *context.Context) *issues_model.Issue {
	issue := GetActionIssue(ctx)
	if ctx.Written() {
		return nil
	}
	if !issue.IsPull {
		ctx.NotFound("not a pull request", nil)
		return nil
	}
	return issue
}

// getPullTask returns the task of the URL on the pull request, or writes a response.
func getPullTask(ctx *context.Context, issue *issues_model.Issue) *issues_model.PullTask {
	task, err := issues_model.GetPullTaskByID(ctx, issue.ID, ctx.ParamsInt64(":id"))
	if err != nil {
		ctx.NotFoundOrServerError("GetPullTaskByID", func(err error) bool { return errors.Is(err, util.ErrNotExist) }, err)
		return nil
	}
	return task
}

// CreatePullTask adds a task to a pull request, standalone or from a comment
func CreatePullTask(ctx *context.Context) {
	issue := getPullTaskIssue(ctx)
	if issue == nil {
		return
	}
	if ctx.HasError() {
		ctx.Flash.Error(ctx.GetErrMsg())
		ctx.Redirect(issue.Link())
		return
	}
	if !issues_model.CanCreatePullTask(ctx, ctx.Doer, issue, ctx.Repo.Permission) {
		ctx.Error(http.StatusForbidden)
		return
	}
	form := web.GetForm(ctx).(*forms.PullTaskForm)
	if _, err := issues_model.CreatePullTask(ctx, ctx.Doer, issue, form.Content, form.CommentID); err != nil {
		ctx.NotFoundOrServerError("CreatePullTask", func(err error) bool { return errors.Is(err, util.ErrNotExist) }, err)
		return
	}
	ctx.Redirect(issue.Link() + "#pull-tasks")
}

// UpdatePullTaskStatus marks a task of a pull request done or reopens it
func UpdatePullTaskStatus(ctx *context.Context) {
	issue := getPullTaskIssue(ctx)
	if issue == nil {
		return
	}
	task := getPullTask(ctx, issue)
	if task == nil {
		return
	}
	if !issues_model.CanChangePullTaskStatus(ctx, ctx.Doer, issue, task, ctx.Repo.Permission) {
		ctx.Error(http.StatusForbidden)
		return
	}
	done := ctx.FormBool("done")
	if err := issues_model.SetPullTaskDone(ctx, ctx.Doer, issue, task, done); err != nil {
		ctx.ServerError("SetPullTaskDone", err)
		return
	}
	if done {
		// an open task could have blocked a pending auto merge
		automerge.StartPRCheckAndAutoMerge(ctx, issue.PullRequest)
	}
	ctx.Redirect(issue.Link() + "#pull-tasks")
}

// DeletePullTask deletes a task of a pull request
func DeletePullTask(ctx *context.Context) {
	issue := getPullTaskIssue(ctx)
	if issue == nil {
		return
	}
	task := getPullTask(ctx, issue)
	if task == nil {
		return
	}
	if !issues_model.CanDeletePullTask(ctx.Doer, task, ctx.Repo.Permission) {
		ctx.Error(http.StatusForbidden)
		return
	}
	if err := issues_model.DeletePullTask(ctx, ctx.Doer, issue, task); err != nil {
		ctx.ServerError("DeletePullTask", err)
		return
	}
	automerge.StartPRCheckAndAutoMerge(ctx, issue.PullRequest)
	ctx.Redirect(issue.Link() + "#pull-tasks")
}
