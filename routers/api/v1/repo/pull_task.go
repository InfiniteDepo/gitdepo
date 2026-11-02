// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"errors"
	"net/http"

	issues_model "forgejo.org/models/issues"
	"forgejo.org/modules/log"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/services/automerge"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

// getPullTaskIssue returns the pull request of the URL, or writes a response.
func getPullTaskIssue(ctx *context.APIContext) *issues_model.Issue {
	issue, err := issues_model.GetIssueByIndex(ctx, ctx.Repo().Repository.ID, ctx.ParamsInt64(":index"))
	if err != nil {
		ctx.NotFoundOrServerError("GetIssueByIndex", issues_model.IsErrIssueNotExist, err)
		return nil
	}
	if !issue.IsPull {
		ctx.NotFound()
		return nil
	}
	issue.Repo = ctx.Repo().Repository
	return issue
}

// getPullTask returns the task of the URL on the pull request, or writes a response.
func getPullTask(ctx *context.APIContext, issue *issues_model.Issue) *issues_model.PullTask {
	task, err := issues_model.GetPullTaskByID(ctx, issue.ID, ctx.ParamsInt64(":id"))
	if err != nil {
		ctx.NotFoundOrServerError("GetPullTaskByID", func(err error) bool { return errors.Is(err, util.ErrNotExist) }, err)
		return nil
	}
	return task
}

// ListPullTasks lists the tasks of a pull request
func ListPullTasks(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/pulls/{index}/tasks repository repoListPullTasks
	// ---
	// summary: List the tasks of a pull request
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// - name: index
	//   in: path
	//   description: index of the pull request
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/PullTaskList"
	//   "404":
	//     "$ref": "#/responses/notFound"

	issue := getPullTaskIssue(ctx)
	if issue == nil {
		return
	}
	tasks, err := issues_model.FindPullTasks(ctx, issue.ID)
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	apiTasks := make([]*api.PullTask, len(tasks))
	for i, task := range tasks {
		apiTasks[i] = convert.ToAPIPullTask(ctx, task, ctx.Doer())
	}
	ctx.JSON(http.StatusOK, apiTasks)
}

// CreatePullTask adds a task to a pull request
func CreatePullTask(ctx *context.APIContext) {
	// swagger:operation POST /repos/{owner}/{repo}/pulls/{index}/tasks repository repoCreatePullTask
	// ---
	// summary: Add a task to a pull request, standalone or from one of its comments
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// - name: index
	//   in: path
	//   description: index of the pull request
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/CreatePullTaskOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/PullTask"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	issue := getPullTaskIssue(ctx)
	if issue == nil {
		return
	}
	if !issues_model.CanCreatePullTask(ctx, ctx.Doer(), issue, ctx.Repo().Permission) {
		ctx.Error(http.StatusForbidden, "CanCreatePullTask", "You cannot add tasks to this pull request.")
		return
	}
	form := web.GetForm(ctx).(*api.CreatePullTaskOption)
	task, err := issues_model.CreatePullTask(ctx, ctx.Doer(), issue, form.Content, form.CommentID)
	if err != nil {
		ctx.NotFoundOrServerError("CreatePullTask", func(err error) bool { return errors.Is(err, util.ErrNotExist) }, err)
		return
	}
	ctx.JSON(http.StatusCreated, convert.ToAPIPullTask(ctx, task, ctx.Doer()))
}

// EditPullTask marks a task of a pull request done or reopens it
func EditPullTask(ctx *context.APIContext) {
	// swagger:operation PATCH /repos/{owner}/{repo}/pulls/{index}/tasks/{id} repository repoEditPullTask
	// ---
	// summary: Mark a task of a pull request done or reopen it
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// - name: index
	//   in: path
	//   description: index of the pull request
	//   type: integer
	//   format: int64
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the task
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/EditPullTaskOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/PullTask"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	issue := getPullTaskIssue(ctx)
	if issue == nil {
		return
	}
	task := getPullTask(ctx, issue)
	if task == nil {
		return
	}
	if !issues_model.CanChangePullTaskStatus(ctx, ctx.Doer(), issue, task, ctx.Repo().Permission) {
		ctx.Error(http.StatusForbidden, "CanChangePullTaskStatus", "You cannot change this task.")
		return
	}
	done := web.GetForm(ctx).(*api.EditPullTaskOption).Status == "done"
	if err := issues_model.SetPullTaskDone(ctx, ctx.Doer(), issue, task, done); err != nil {
		ctx.InternalServerError(err)
		return
	}
	if done {
		startPullTaskAutoMerge(ctx, issue)
	}
	ctx.JSON(http.StatusOK, convert.ToAPIPullTask(ctx, task, ctx.Doer()))
}

// DeletePullTask deletes a task of a pull request
func DeletePullTask(ctx *context.APIContext) {
	// swagger:operation DELETE /repos/{owner}/{repo}/pulls/{index}/tasks/{id} repository repoDeletePullTask
	// ---
	// summary: Delete a task of a pull request
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// - name: index
	//   in: path
	//   description: index of the pull request
	//   type: integer
	//   format: int64
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the task
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	issue := getPullTaskIssue(ctx)
	if issue == nil {
		return
	}
	task := getPullTask(ctx, issue)
	if task == nil {
		return
	}
	if !issues_model.CanDeletePullTask(ctx.Doer(), task, ctx.Repo().Permission) {
		ctx.Error(http.StatusForbidden, "CanDeletePullTask", "You cannot delete this task.")
		return
	}
	if err := issues_model.DeletePullTask(ctx, ctx.Doer(), issue, task); err != nil {
		ctx.InternalServerError(err)
		return
	}
	startPullTaskAutoMerge(ctx, issue)
	ctx.Status(http.StatusNoContent)
}

// startPullTaskAutoMerge re-runs a pending auto merge an open task could have blocked.
func startPullTaskAutoMerge(ctx *context.APIContext, issue *issues_model.Issue) {
	if err := issue.LoadPullRequest(ctx); err != nil {
		log.Error("LoadPullRequest: %v", err)
		return
	}
	automerge.StartPRCheckAndAutoMerge(ctx, issue.PullRequest)
}
