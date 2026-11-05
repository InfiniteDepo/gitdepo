// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"errors"
	"net/http"
	"slices"

	actions_model "forgejo.org/models/actions"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	actions_service "forgejo.org/services/actions"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
)

// maxReviewJobs is how many jobs one review request names.
const maxReviewJobs = 100

// runOfRepo returns the run of the path, which must belong to the repository; it answers the request itself if not.
func runOfRepo(ctx *context.APIContext) *actions_model.ActionRun {
	run, err := actions_model.GetRunByID(ctx, ctx.ParamsInt64(":run_id"))
	if err != nil {
		if errors.Is(err, util.ErrNotExist) {
			ctx.Error(http.StatusNotFound, "GetRunById", err)
		} else {
			ctx.Error(http.StatusInternalServerError, "GetRunByID", err)
		}
		return nil
	}
	if ctx.Repo().Repository.ID != run.RepoID {
		ctx.Error(http.StatusNotFound, "GetRunById", util.ErrNotExist)
		return nil
	}
	return run
}

// toActionDeployments converts the deployments of the run for doer.
func toActionDeployments(ctx *context.APIContext, run *actions_model.ActionRun, ds []*actions_model.ActionDeployment) ([]*api.ActionDeployment, error) {
	jobs, err := actions_model.GetRunJobsByRunID(ctx, run.ID)
	if err != nil {
		return nil, err
	}
	envs := map[int64]*actions_model.ActionEnvironment{}
	counts := map[int64]*api.ActionDeploymentReviewers{}
	users := map[int64]*user_model.User{}
	out := make([]*api.ActionDeployment, 0, len(ds))
	for _, d := range ds {
		item := &api.ActionDeployment{
			ID: d.ID, JobID: d.JobID, Attempt: d.Attempt, Status: d.Status.String(), Reason: d.Reason,
			ReviewComment: d.ReviewComment, Created: d.Created.AsTime(), Reviewers: &api.ActionDeploymentReviewers{},
		}
		if i := slices.IndexFunc(jobs, func(j *actions_model.ActionRunJob) bool { return j.ID == d.JobID }); i >= 0 {
			item.JobName = jobs[i].Name
		}
		if d.ReleaseAfterUnix > 0 {
			t := d.ReleaseAfterUnix.AsTime()
			item.ReleaseAfter = &t
		}
		if d.ReviewedBy != 0 {
			u, ok := users[d.ReviewedBy]
			if !ok {
				if u, err = user_model.GetPossibleUserByID(ctx, d.ReviewedBy); err != nil && !user_model.IsErrUserNotExist(err) {
					return nil, err
				}
				users[d.ReviewedBy] = u
			}
			if u != nil {
				item.ReviewedBy = convert.ToUser(ctx, u, ctx.Doer())
			}
			t := d.ReviewedUnix.AsTime()
			item.ReviewedAt = &t
		}
		env, ok := envs[d.EnvironmentID]
		if !ok {
			if env, err = actions_model.GetRepoEnvironmentByID(ctx, run.RepoID, d.EnvironmentID); err != nil && !errors.Is(err, actions_model.ErrEnvironmentNotFound) {
				return nil, err
			}
			envs[d.EnvironmentID] = env // nil for a deleted environment
			if env != nil {
				rs, err := actions_model.FindEnvironmentReviewers(ctx, env.ID)
				if err != nil {
					return nil, err
				}
				counts[env.ID] = &api.ActionDeploymentReviewers{}
				for _, r := range rs {
					if r.TeamID > 0 {
						counts[env.ID].Teams++
					} else {
						counts[env.ID].Users++
					}
				}
			}
		}
		if env != nil {
			item.Environment = env.Name
			item.Reviewers.Users, item.Reviewers.Teams = counts[env.ID].Users, counts[env.ID].Teams
		}
		if can, err := actions_service.CanReviewDeployment(ctx, ctx.Doer(), run, d); err != nil {
			if !errors.Is(err, actions_model.ErrEnvironmentNotFound) {
				return nil, err
			}
		} else {
			item.Reviewers.CanReview = can
		}
		out = append(out, item)
	}
	return out, nil
}

// ListActionRunDeployments lists the deployments of a workflow run.
func ListActionRunDeployments(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/actions/runs/{run_id}/deployments repository ListActionRunDeployments
	// ---
	// summary: List the deployments of a workflow run
	// description: >
	//   The deployments of the jobs of the run that name an environment, those that wait for a review and the past
	//   ones, for every attempt of a job.
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
	// - name: run_id
	//   in: path
	//   description: ID of the workflow run
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/ActionDeploymentList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	run := runOfRepo(ctx)
	if run == nil {
		return
	}
	ds, err := actions_model.FindRunDeployments(ctx, run.ID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "FindRunDeployments", err)
		return
	}
	items, err := toActionDeployments(ctx, run, ds)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "toActionDeployments", err)
		return
	}
	ctx.JSON(http.StatusOK, items)
}

// ReviewActionRunDeployments approves or rejects the deployments of a workflow run that wait for a review.
func ReviewActionRunDeployments(ctx *context.APIContext) {
	// swagger:operation POST /repos/{owner}/{repo}/actions/runs/{run_id}/deployments/review repository ReviewActionRunDeployments
	// ---
	// summary: Approve or reject the deployments of a workflow run that wait for a review
	// description: >
	//   Only a reviewer listed by the environment, or a member of a listed team, who can read the repository's Actions
	//   may review; site administrators have no exception. One approval releases a job once its wait timer is due,
	//   one rejection fails it. Nothing changes unless every named deployment can be reviewed.
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
	// - name: run_id
	//   in: path
	//   description: ID of the workflow run
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/ReviewDeploymentsOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/ActionDeploymentList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	run := runOfRepo(ctx)
	if run == nil {
		return
	}
	form := web.GetForm(ctx).(*api.ReviewDeploymentsOption)
	if form.State != "approved" && form.State != "rejected" {
		ctx.Error(http.StatusUnprocessableEntity, "state", "state must be approved or rejected")
		return
	}
	if len(form.JobIDs) > maxReviewJobs {
		ctx.Error(http.StatusUnprocessableEntity, "job_ids", "too many jobs")
		return
	}
	ds, err := actions_service.ReviewDeployments(ctx, ctx.Doer(), run, slices.Compact(slices.Sorted(slices.Values(form.JobIDs))), form.State == "approved", form.Comment)
	switch {
	case errors.Is(err, util.ErrPermissionDenied):
		ctx.Error(http.StatusForbidden, "ReviewDeployments", err)
		return
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Error(http.StatusUnprocessableEntity, "ReviewDeployments", err)
		return
	case errors.Is(err, util.ErrNotExist):
		ctx.Error(http.StatusNotFound, "ReviewDeployments", err)
		return
	case err != nil:
		ctx.Error(http.StatusInternalServerError, "ReviewDeployments", err)
		return
	}
	items, err := toActionDeployments(ctx, run, ds)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "toActionDeployments", err)
		return
	}
	ctx.JSON(http.StatusOK, items)
}
