// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"errors"
	"net/http"
	"slices"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
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

// deploymentData holds what the deployments of a page refer to, loaded with one query per table.
type deploymentData struct {
	jobs  map[int64]*actions_model.ActionRunJob
	runs  map[int64]*actions_model.ActionRun
	envs  map[int64]*actions_model.ActionEnvironment
	users map[int64]*user_model.User
}

func loadDeploymentData(ctx *context.APIContext, ds []*actions_model.ActionDeployment) (*deploymentData, error) {
	var jobIDs, runIDs, envIDs, userIDs []int64
	for _, d := range ds {
		jobIDs, runIDs, envIDs = append(jobIDs, d.JobID), append(runIDs, d.RunID), append(envIDs, d.EnvironmentID)
		userIDs = append(userIDs, d.TriggerUserID, d.ReviewedBy)
	}
	data := &deploymentData{}
	var err error
	if data.jobs, err = db.GetByIDs(ctx, "id", slices.Compact(slices.Sorted(slices.Values(jobIDs))), &actions_model.ActionRunJob{}); err != nil {
		return nil, err
	}
	if data.runs, err = db.GetByIDs(ctx, "id", slices.Compact(slices.Sorted(slices.Values(runIDs))), &actions_model.ActionRun{}); err != nil {
		return nil, err
	}
	if data.envs, err = db.GetByIDs(ctx, "id", slices.Compact(slices.Sorted(slices.Values(envIDs))), &actions_model.ActionEnvironment{}); err != nil {
		return nil, err
	}
	userIDs = slices.DeleteFunc(slices.Compact(slices.Sorted(slices.Values(userIDs))), func(id int64) bool { return id == 0 })
	if data.users, err = user_model.GetUsersByIDsWithBots(ctx, userIDs); err != nil {
		return nil, err
	}
	return data, nil
}

// toActionDeployment converts what every list of deployments shows of d. Everything is read from the repository of
// the request: a run, job or environment of another repository is left out.
func (data *deploymentData) toActionDeployment(ctx *context.APIContext, d *actions_model.ActionDeployment) *api.ActionDeployment {
	repo := ctx.Repo().Repository
	item := &api.ActionDeployment{
		ID: d.ID, JobID: d.JobID, Attempt: d.Attempt, Status: d.Status.String(), Reason: d.Reason,
		ReviewComment: d.ReviewComment, Created: d.Created.AsTime(), RunID: d.RunID, Ref: d.Ref, CommitSHA: d.CommitSHA,
		EnvironmentURL: d.URL,
	}
	if job, ok := data.jobs[d.JobID]; ok && job.RepoID == repo.ID {
		item.JobName = job.Name
	}
	if run, ok := data.runs[d.RunID]; ok && run.RepoID == repo.ID {
		run.Repo = repo
		item.RunURL = run.HTMLURL()
	}
	if env, ok := data.envs[d.EnvironmentID]; ok && env.RepoID == repo.ID { // missing for a deleted environment
		item.Environment = env.Name
	}
	if d.ReleaseAfterUnix > 0 {
		t := d.ReleaseAfterUnix.AsTime()
		item.ReleaseAfter = &t
	}
	if d.TriggerUserID != 0 {
		_, u := user_model.GetUserFromMap(d.TriggerUserID, data.users)
		item.TriggeredBy = convert.ToUser(ctx, u, ctx.Doer())
	}
	if d.ReviewedBy != 0 {
		_, u := user_model.GetUserFromMap(d.ReviewedBy, data.users)
		item.ReviewedBy = convert.ToUser(ctx, u, ctx.Doer())
		t := d.ReviewedUnix.AsTime()
		item.ReviewedAt = &t
	}
	return item
}

// toActionDeployments converts the deployments of the run for doer. What the doer may review is decided by the same
// checker as the review itself, over the deployments that can be reviewed now; the environments and their reviewers
// are loaded once.
func toActionDeployments(ctx *context.APIContext, run *actions_model.ActionRun, ds []*actions_model.ActionDeployment) ([]*api.ActionDeployment, error) {
	data, err := loadDeploymentData(ctx, ds)
	if err != nil {
		return nil, err
	}
	checker, err := actions_service.NewReviewChecker(ctx, ctx.Doer(), run)
	if err != nil {
		return nil, err
	}
	reviewable, err := actions_model.FindReviewableDeployments(ctx, run.ID, actions_service.ReviewCutoff())
	if err != nil {
		return nil, err
	}
	out := make([]*api.ActionDeployment, 0, len(ds))
	for _, d := range ds {
		item := data.toActionDeployment(ctx, d)
		item.Reviewers = &api.ActionDeploymentReviewers{}
		env, reviewers, err := checker.Environment(ctx, d.EnvironmentID)
		if err != nil {
			return nil, err
		}
		if env != nil { // nil for a deleted environment
			for _, r := range reviewers {
				if r.TeamID > 0 {
					item.Reviewers.Teams++
				} else {
					item.Reviewers.Users++
				}
			}
		}
		if slices.ContainsFunc(reviewable, func(r *actions_model.ActionDeployment) bool { return r.ID == d.ID }) {
			if item.Reviewers.CanReview, err = checker.May(ctx, d); err != nil {
				return nil, err
			}
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
	//   may review; site administrators have no exception, and neither does a request made under sudo or with an OAuth2
	//   grant or an authorized integration (use the reviewer's own access token or session). The jobs to review must be
	//   named. One approval releases a job once its wait timer is due,
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
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"

	run := runOfRepo(ctx)
	if run == nil {
		return
	}
	form := web.GetForm(ctx).(*api.ReviewDeploymentsOption)
	if form.State != "approved" && form.State != "rejected" {
		ctx.Error(http.StatusUnprocessableEntity, "state", "state must be approved or rejected")
		return
	}
	if len(form.JobIDs) == 0 || len(form.JobIDs) > maxReviewJobs {
		ctx.Error(http.StatusUnprocessableEntity, "job_ids", "name between 1 and 100 jobs")
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
