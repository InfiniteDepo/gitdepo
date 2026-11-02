// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"errors"
	"net/http"

	"forgejo.org/models"
	issues_model "forgejo.org/models/issues"
	pull_model "forgejo.org/models/pull"
	quota_model "forgejo.org/models/quota"
	repo_model "forgejo.org/models/repo"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	asymkey_service "forgejo.org/services/asymkey"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	"forgejo.org/services/forms"
	issue_service "forgejo.org/services/issue"
	"forgejo.org/services/mergeforward"
	"forgejo.org/services/mergequeue"
	pull_service "forgejo.org/services/pull"
)

func toMergeQueueEntry(ctx *context.APIContext, v *mergequeue.ViewEntry) *api.MergeQueueEntry {
	e := &api.MergeQueueEntry{
		Position:               v.Position,
		Number:                 v.Pull.Index,
		Title:                  v.Pull.Issue.Title,
		State:                  v.State,
		MergeStyle:             string(v.MergeStyle),
		DeleteBranchAfterMerge: v.DeleteBranch,
		HeadSHA:                v.HeadCommitID,
		TestSHA:                v.TempCommitID,
		EnqueuedBy:             convert.ToUser(ctx, v.EnqueuedBy, ctx.Doer()),
		EnqueuedAt:             v.EnqueuedUnix.AsTime(),
	}
	if v.StartedUnix != 0 {
		t := v.StartedUnix.AsTime()
		e.StartedAt = &t
	}
	return e
}

// ListMergeQueue lists the merge queue of a branch
func ListMergeQueue(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/merge-queue/{branch} repository repoListMergeQueue
	// ---
	// summary: List the merge queue of a branch, in order
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
	// - name: branch
	//   in: path
	//   description: the branch the pull requests merge into
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/MergeQueueEntryList"
	//   "404":
	//     "$ref": "#/responses/notFound"

	view, rule, err := mergequeue.View(ctx, ctx.Repo().Repository, ctx.Params("*"))
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	if rule == nil {
		ctx.NotFound()
		return
	}
	list := make([]*api.MergeQueueEntry, 0, len(view))
	for _, v := range view {
		list = append(list, toMergeQueueEntry(ctx, v))
	}
	ctx.JSON(http.StatusOK, list)
}

// AddToMergeQueue adds a pull request to the merge queue of its base branch
func AddToMergeQueue(ctx *context.APIContext) {
	// swagger:operation POST /repos/{owner}/{repo}/pulls/{index}/merge-queue repository repoAddToMergeQueue
	// ---
	// summary: Add a pull request to the merge queue of its base branch
	// description: The base branch must have a branch protection rule that requires a merge queue. The queue tests
	//   the pull request on top of the branch and the pull requests ahead of it and merges it once the required
	//   status checks pass there. The merge title and message fields are ignored; the merge message is the title and
	//   description of the pull request.
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
	//   schema:
	//     $ref: "#/definitions/MergePullRequestOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/MergeQueueEntry"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "405":
	//     "$ref": "#/responses/error"
	//   "409":
	//     "$ref": "#/responses/error"
	//   "413":
	//     "$ref": "#/responses/quotaExceeded"
	//   "422":
	//     "$ref": "#/responses/validationError"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"

	pr, ok := pullForMergeQueue(ctx)
	if !ok {
		return
	}
	addToMergeQueue(ctx, web.GetForm(ctx).(*forms.MergePullRequestForm), pr)
}

func addToMergeQueue(ctx *context.APIContext, form *forms.MergePullRequestForm, pr *issues_model.PullRequest) {
	if form.SkipsMergeForward() {
		allowed, err := mergeforward.MaySkip(ctx, ctx.Doer(), ctx.Repo().Permission, ctx.Repo().Repository, pr.BaseBranch)
		if err != nil {
			ctx.InternalServerError(err)
			return
		} else if !allowed {
			ctx.Error(http.StatusForbidden, "MergeForward", "not allowed to merge without merging forward")
			return
		}
	}
	err := mergequeue.Add(ctx, ctx.Doer(), &ctx.Repo().Permission, pr, mergequeue.AddOptions{
		Style:        repo_model.MergeStyle(form.Do),
		ExpectedHead: form.HeadCommitID,
		DeleteBranch: form.DeleteBranchAfterMerge,
		SkipForward:  form.SkipsMergeForward(),
		Force:        form.ForceMerge,
	})
	switch {
	case err == nil:
	case errors.Is(err, util.ErrPermissionDenied):
		ctx.Error(http.StatusForbidden, "AddToMergeQueue", "user may not add the pull request to the merge queue")
		return
	case errors.Is(err, mergequeue.ErrNotRequired):
		ctx.Error(http.StatusMethodNotAllowed, "AddToMergeQueue", "the base branch has no merge queue")
		return
	case errors.As(err, &quota_model.ErrPersonalRepoLimit{}):
		ctx.Error(http.StatusRequestEntityTooLarge, "AddToMergeQueue", err)
		return
	case errors.As(err, &pull_model.ErrAlreadyInMergeQueue{}):
		ctx.Error(http.StatusConflict, "AddToMergeQueue", "the pull request is already in the merge queue")
		return
	case models.IsErrSHADoesNotMatch(err):
		ctx.Error(http.StatusConflict, "AddToMergeQueue", "the head of the pull request is not head_commit_id")
		return
	case models.IsErrInvalidMergeStyle(err):
		ctx.Error(http.StatusUnprocessableEntity, "AddToMergeQueue", "the merge queue can't merge with this merge style")
		return
	default:
		mergeCheckError(ctx, pr, err)
		return
	}
	view, _, err := mergequeue.View(ctx, ctx.Repo().Repository, pr.BaseBranch)
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	for _, v := range view {
		if v.PullID == pr.ID {
			ctx.JSON(http.StatusCreated, toMergeQueueEntry(ctx, v))
			return
		}
	}
	// a pass removed it meanwhile
	ctx.Error(http.StatusConflict, "AddToMergeQueue", "the pull request left the merge queue at once, see its timeline")
}

// RemoveFromMergeQueue takes a pull request out of the merge queue
func RemoveFromMergeQueue(ctx *context.APIContext) {
	// swagger:operation DELETE /repos/{owner}/{repo}/pulls/{index}/merge-queue repository repoRemoveFromMergeQueue
	// ---
	// summary: Remove a pull request from the merge queue
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
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     "$ref": "#/responses/error"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"

	pr, ok := pullForMergeQueue(ctx)
	if !ok {
		return
	}
	if err := mergequeue.Remove(ctx, ctx.Doer(), ctx.Repo().Permission, pr); err != nil {
		switch {
		case errors.Is(err, util.ErrPermissionDenied):
			ctx.Error(http.StatusForbidden, "RemoveFromMergeQueue", "user may not remove the pull request from the merge queue")
		case errors.Is(err, mergequeue.ErrNotQueued):
			ctx.NotFound()
		case errors.Is(err, mergequeue.ErrMerging):
			ctx.Error(http.StatusConflict, "RemoveFromMergeQueue", "the pull request is being merged")
		default:
			ctx.InternalServerError(err)
		}
		return
	}
	ctx.Status(http.StatusNoContent)
}

func pullForMergeQueue(ctx *context.APIContext) (*issues_model.PullRequest, bool) {
	pr, err := issues_model.GetPullRequestByIndex(ctx, ctx.Repo().Repository.ID, ctx.ParamsInt64(":index"))
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.InternalServerError(err)
		}
		return nil, false
	}
	if err := pr.LoadIssue(ctx); err != nil {
		ctx.InternalServerError(err)
		return nil, false
	}
	pr.Issue.Repo = ctx.Repo().Repository
	return pr, true
}

// mergeCheckError answers a refused CheckPullMergeable
func mergeCheckError(ctx *context.APIContext, pr *issues_model.PullRequest, err error) {
	if errors.Is(err, pull_service.ErrIsClosed) {
		ctx.NotFound()
	} else if errors.Is(err, pull_service.ErrUserNotAllowedToMerge) {
		ctx.Error(http.StatusMethodNotAllowed, "Merge", "User not allowed to merge PR")
	} else if errors.Is(err, pull_service.ErrHasMerged) {
		ctx.Error(http.StatusMethodNotAllowed, "PR already merged", "")
	} else if errors.Is(err, pull_service.ErrIsWorkInProgress) {
		ctx.Error(http.StatusMethodNotAllowed, "PR is a work in progress", "Work in progress PRs cannot be merged")
	} else if message, ok := issue_service.PRTitleRuleMessage(ctx.Locale, err); ok {
		ctx.Error(http.StatusMethodNotAllowed, "PRTitleRule", message)
	} else if errors.Is(err, pull_service.ErrNotMergeableState) {
		ctx.Error(http.StatusMethodNotAllowed, "PR not in mergeable state", "Please try again later")
	} else if models.IsErrDisallowedToMerge(err) {
		ctx.Error(http.StatusMethodNotAllowed, "PR is not ready to be merged", err)
	} else if asymkey_service.IsErrWontSign(err) {
		ctx.Error(http.StatusMethodNotAllowed, "Protected branch "+pr.BaseBranch+" requires signed commits but this merge would not be signed", err)
	} else {
		ctx.InternalServerError(err)
	}
}
