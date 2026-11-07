// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"errors"
	"maps"
	"net/http"
	"slices"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/routers/api/v1/utils"
	actions_service "forgejo.org/services/actions"
	"forgejo.org/services/context"
)

// refPolicies are the API names of the ref policies of an environment, by their value.
var refPolicies = []string{
	actions_model.EnvironmentRefAny:               "any",
	actions_model.EnvironmentRefProtectedBranches: "protected_branches",
	actions_model.EnvironmentRefPatterns:          "patterns",
}

// environmentScope returns the owner and repository of the environments of the request: those of the repository,
// or those of the organization on the organization routes.
func environmentScope(ctx *context.APIContext) (ownerID, repoID int64) {
	if ctx.Repo() != nil && ctx.Repo().Repository != nil {
		return 0, ctx.Repo().Repository.ID
	}
	return ctx.Org().Organization.ID, 0
}

// environmentOfRepo returns the environment of the path, looked up by name (ignoring case) in the repository or
// organization of the request; it answers the request itself if there is none. An organization environment a
// repository inherits is not one of the repository's own: it is changed only on the organization routes.
func environmentOfRepo(ctx *context.APIContext) *actions_model.ActionEnvironment {
	ownerID, repoID := environmentScope(ctx)
	env, err := actions_model.GetEnvironmentByName(ctx, ownerID, repoID, ctx.Params("environment"))
	if errors.Is(err, actions_model.ErrEnvironmentNotFound) {
		ctx.NotFound()
		return nil
	} else if err != nil {
		ctx.InternalServerError(err)
		return nil
	}
	return env
}

// toActionEnvironments converts environments of the repository or organization of the request (with the
// organization environments a repository inherits), with one query for each of their reviewers, the reviewers'
// users and teams, the secret and variable counts of each scope and the last deployments.
func toActionEnvironments(ctx *context.APIContext, envs []*actions_model.ActionEnvironment) ([]*api.ActionEnvironment, error) {
	_, repoID := environmentScope(ctx)
	var ids, orgIDs []int64
	var orgID int64
	for _, e := range envs {
		ids = append(ids, e.ID)
		if e.RepoID == 0 {
			orgID = e.OwnerID
			orgIDs = append(orgIDs, e.ID)
		}
	}
	reviewers, err := actions_model.FindReviewersOfEnvironments(ctx, ids)
	if err != nil {
		return nil, err
	}
	var userIDs, teamIDs []int64
	for _, rs := range reviewers {
		for _, r := range rs {
			if r.TeamID > 0 {
				teamIDs = append(teamIDs, r.TeamID)
			} else {
				userIDs = append(userIDs, r.UserID)
			}
		}
	}
	users, err := user_model.GetUsersByIDsWithBots(ctx, slices.Compact(slices.Sorted(slices.Values(userIDs))))
	if err != nil {
		return nil, err
	}
	teams, err := db.GetByIDs(ctx, "id", slices.Compact(slices.Sorted(slices.Values(teamIDs))), &org_model.Team{})
	if err != nil {
		return nil, err
	}
	secrets, variables := map[int64]int64{}, map[int64]int64{}
	if repoID != 0 {
		if secrets, variables, err = actions_model.CountEnvironmentSecretsAndVariables(ctx, 0, repoID, ids); err != nil {
			return nil, err
		}
	}
	if len(orgIDs) > 0 {
		orgSecrets, orgVariables, err := actions_model.CountEnvironmentSecretsAndVariables(ctx, orgID, 0, orgIDs)
		if err != nil {
			return nil, err
		}
		maps.Copy(secrets, orgSecrets)
		maps.Copy(variables, orgVariables)
	}
	last := map[int64]*actions_model.ActionDeployment{}
	var data *actions_service.DeploymentData
	if repoID != 0 {
		if last, err = actions_model.FindLastDeployments(ctx, repoID, ids); err != nil {
			return nil, err
		}
		if data, err = actions_service.LoadDeploymentData(ctx, ctx.Doer(), repoID, slices.Collect(maps.Values(last))); err != nil {
			return nil, err
		}
	}

	out := make([]*api.ActionEnvironment, 0, len(envs))
	for _, e := range envs {
		item := &api.ActionEnvironment{
			ID: e.ID, Name: e.Name, RefPolicy: refPolicies[e.RefPolicy], RefPatterns: []*api.ActionEnvironmentRefPattern{},
			WaitTimer: e.WaitTimerMinutes, PreventSelfReview: e.PreventSelfReview, Reviewers: []*api.ActionEnvironmentReviewer{},
			ReviewsRequired: e.ReviewsRequired, RunnerLabels: e.RunnerLabels, AllowedWorkflows: e.AllowedWorkflows,
			CreatedByWorkflow: e.CreatedByWorkflow, SecretsCount: secrets[e.ID], VariablesCount: variables[e.ID],
			Inherited: repoID != 0 && e.RepoID == 0, Created: e.Created.AsTime(), Updated: e.Updated.AsTime(),
		}
		for _, p := range e.RefPatterns {
			item.RefPatterns = append(item.RefPatterns, &api.ActionEnvironmentRefPattern{Type: p.Type, Pattern: p.Pattern})
		}
		for _, r := range reviewers[e.ID] {
			if r.TeamID > 0 {
				name := ""
				if team, ok := teams[r.TeamID]; ok {
					name = team.Name
				}
				item.Reviewers = append(item.Reviewers, &api.ActionEnvironmentReviewer{Type: "team", ID: r.TeamID, Name: name})
			} else {
				_, u := user_model.GetUserFromMap(r.UserID, users)
				item.Reviewers = append(item.Reviewers, &api.ActionEnvironmentReviewer{Type: "user", ID: r.UserID, Name: u.Name})
			}
		}
		if d, ok := last[e.ID]; ok {
			item.LastDeployment = toActionDeployment(ctx, data, d)
		}
		out = append(out, item)
	}
	return out, nil
}

// ListActionEnvironments lists the environments of a repository
func ListActionEnvironments(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/actions/environments repository repoListActionEnvironments
	// ---
	// summary: List the deployment environments of a repository with their protection rules
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repository
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repository
	//   type: string
	//   required: true
	// - name: page
	//   in: query
	//   description: page number of results to return (1-based)
	//   type: integer
	// - name: limit
	//   in: query
	//   description: page size of results
	//   type: integer
	// responses:
	//   "200":
	//     "$ref": "#/responses/ActionEnvironmentList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	var envs []*actions_model.ActionEnvironment
	var count int64
	var err error
	if ownerID, repoID := environmentScope(ctx); repoID != 0 {
		envs, count, err = actions_model.FindEnvironmentsOfRepo(ctx, repoID, utils.GetListOptions(ctx))
	} else {
		envs, count, err = actions_model.FindEnvironments(ctx, ownerID, 0, utils.GetListOptions(ctx))
	}
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	items, err := toActionEnvironments(ctx, envs)
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	ctx.SetTotalCountHeader(count)
	ctx.JSON(http.StatusOK, items)
}

// GetActionEnvironment gets an environment of a repository
func GetActionEnvironment(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/actions/environments/{environment} repository repoGetActionEnvironment
	// ---
	// summary: Get a deployment environment of a repository with its protection rules
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repository
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repository
	//   type: string
	//   required: true
	// - name: environment
	//   in: path
	//   description: name of the environment, matched ignoring case
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/ActionEnvironment"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	env := environmentOfRepo(ctx)
	if env == nil {
		return
	}
	items, err := toActionEnvironments(ctx, []*actions_model.ActionEnvironment{env})
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	ctx.JSON(http.StatusOK, items[0])
}

// CreateOrUpdateActionEnvironment creates an environment of a repository or replaces its rules
func CreateOrUpdateActionEnvironment(ctx *context.APIContext) {
	// swagger:operation PUT /repos/{owner}/{repo}/actions/environments/{environment} repository repoCreateOrUpdateActionEnvironment
	// ---
	// summary: Create a deployment environment of a repository, or replace the protection rules of the one with that name
	// description: >
	//   The body is the whole set of rules and every field is required (a field left out is a 422): an empty list, 0
	//   or false sets no rule, so an empty reviewers list removes them and the jobs that wait for a review are
	//   released. An environment whose name differs only in case is the
	//   same environment and keeps its name. Every change is recorded in the audit log. Only a person's own
	//   credential changes the rules: a request under sudo, with an OAuth2 grant or with an authorized integration is a
	//   403. An unknown reviewer, or one the caller can't see, is a 422; so is an invalid rule.
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repository
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repository
	//   type: string
	//   required: true
	// - name: environment
	//   in: path
	//   description: name of the environment, matched ignoring case
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/CreateOrUpdateEnvironmentOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/ActionEnvironment"
	//   "201":
	//     "$ref": "#/responses/ActionEnvironment"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"
	//   "422":
	//     "$ref": "#/responses/validationError"

	form := web.GetForm(ctx).(*api.CreateOrUpdateEnvironmentOption)
	// every rule is required: a field left out would remove a rule the client may not know about
	if form.RefPolicy == "" || form.RefPatterns == nil || form.WaitTimer == nil || form.PreventSelfReview == nil ||
		form.Reviewers == nil || form.RunnerLabels == nil || form.AllowedWorkflows == nil {
		ctx.Error(http.StatusUnprocessableEntity, "CreateOrUpdateEnvironmentOption", "every rule is required: ref_policy, ref_patterns, wait_timer, prevent_self_review, reviewers, runner_labels and allowed_workflows")
		return
	}
	env := &actions_model.ActionEnvironment{
		Name: ctx.Params("environment"), WaitTimerMinutes: *form.WaitTimer,
		PreventSelfReview: *form.PreventSelfReview, RunnerLabels: form.RunnerLabels, AllowedWorkflows: form.AllowedWorkflows,
	}
	env.OwnerID, env.RepoID = environmentScope(ctx)
	if env.RefPolicy = slices.Index(refPolicies, form.RefPolicy); env.RefPolicy < 0 {
		ctx.Error(http.StatusUnprocessableEntity, "ref_policy", "ref_policy must be any, protected_branches or patterns")
		return
	}
	for _, p := range form.RefPatterns {
		if p == nil {
			ctx.Error(http.StatusUnprocessableEntity, "ref_patterns", "invalid ref pattern")
			return
		}
		env.RefPatterns = append(env.RefPatterns, actions_model.EnvironmentRefPattern{Type: p.Type, Pattern: p.Pattern})
	}
	var userIDs, teamIDs []int64
	for _, r := range form.Reviewers {
		switch {
		case r != nil && r.Type == "user":
			userIDs = append(userIDs, r.ID)
		case r != nil && r.Type == "team":
			teamIDs = append(teamIDs, r.ID)
		default:
			ctx.Error(http.StatusUnprocessableEntity, "reviewers", "a reviewer has the type user or team")
			return
		}
	}

	created, err := actions_service.SaveEnvironment(ctx, ctx.Doer(), env, userIDs, teamIDs)
	switch {
	case errors.Is(err, util.ErrPermissionDenied):
		ctx.Error(http.StatusForbidden, "SaveEnvironment", err)
		return
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Error(http.StatusUnprocessableEntity, "SaveEnvironment", err)
		return
	case errors.Is(err, util.ErrNotExist): // deleted by a concurrent request
		ctx.NotFound()
		return
	case err != nil:
		ctx.InternalServerError(err)
		return
	}
	stored, err := actions_model.GetEnvironmentByID(ctx, env.OwnerID, env.RepoID, env.ID)
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	items, err := toActionEnvironments(ctx, []*actions_model.ActionEnvironment{stored})
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	if created {
		ctx.JSON(http.StatusCreated, items[0])
	} else {
		ctx.JSON(http.StatusOK, items[0])
	}
}

// DeleteActionEnvironment deletes an environment of a repository
func DeleteActionEnvironment(ctx *context.APIContext) {
	// swagger:operation DELETE /repos/{owner}/{repo}/actions/environments/{environment} repository repoDeleteActionEnvironment
	// ---
	// summary: Delete a deployment environment of a repository with its secrets, variables and reviewers
	// description: >
	//   Its deployments stay as history. The jobs that wait for it, or were released by it and no runner took yet,
	//   fail. A workflow that names the environment again creates it without rules. Only a person's own credential
	//   deletes it: a request under sudo, with an OAuth2 grant or with an authorized integration is a 403.
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repository
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repository
	//   type: string
	//   required: true
	// - name: environment
	//   in: path
	//   description: name of the environment, matched ignoring case
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"

	env := environmentOfRepo(ctx)
	if env == nil {
		return
	}
	if err := actions_service.DeleteEnvironment(ctx, env); errors.Is(err, util.ErrPermissionDenied) {
		ctx.Error(http.StatusForbidden, "DeleteEnvironment", err)
		return
	} else if errors.Is(err, util.ErrNotExist) {
		ctx.NotFound()
		return
	} else if err != nil {
		ctx.InternalServerError(err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

// ListActionDeployments lists the deployments of a repository
func ListActionDeployments(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/actions/deployments repository repoListActionDeployments
	// ---
	// summary: List the deployments of a repository, newest first
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repository
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repository
	//   type: string
	//   required: true
	// - name: environment
	//   in: query
	//   description: only the deployments to the environment of that name (ignoring case)
	//   type: string
	// - name: page
	//   in: query
	//   description: page number of results to return (1-based)
	//   type: integer
	// - name: limit
	//   in: query
	//   description: page size of results
	//   type: integer
	// responses:
	//   "200":
	//     "$ref": "#/responses/ActionDeploymentList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"

	repoID := ctx.Repo().Repository.ID
	var environmentID int64
	if name := ctx.FormString("environment"); name != "" {
		env, err := actions_model.ResolveEnvironment(ctx, repoID, name)
		if errors.Is(err, actions_model.ErrEnvironmentNotFound) {
			ctx.SetTotalCountHeader(0)
			ctx.JSON(http.StatusOK, []*api.ActionDeployment{})
			return
		} else if err != nil {
			ctx.InternalServerError(err)
			return
		}
		environmentID = env.ID
	}
	ds, count, err := actions_model.FindRepoDeployments(ctx, repoID, actions_model.DeploymentFilter{EnvironmentID: environmentID}, utils.GetListOptions(ctx))
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	data, err := actions_service.LoadDeploymentData(ctx, ctx.Doer(), repoID, ds)
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	items := make([]*api.ActionDeployment, 0, len(ds))
	for _, d := range ds {
		items = append(items, toActionDeployment(ctx, data, d))
	}
	ctx.SetTotalCountHeader(count)
	ctx.JSON(http.StatusOK, items)
}

// The secrets and variables of an environment: the bodies of the repository's routes, on the environment of the path.

// ListActionEnvironmentSecrets lists the secrets of an environment
func ListActionEnvironmentSecrets(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/actions/environments/{environment}/secrets repository repoListActionEnvironmentSecrets
	// ---
	// summary: List the secrets of a deployment environment (never their values)
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repository
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repository
	//   type: string
	//   required: true
	// - name: environment
	//   in: path
	//   description: name of the environment, matched ignoring case
	//   type: string
	//   required: true
	// - name: page
	//   in: query
	//   description: page number of results to return (1-based)
	//   type: integer
	// - name: limit
	//   in: query
	//   description: page size of results
	//   type: integer
	// responses:
	//   "200":
	//     "$ref": "#/responses/SecretList"
	//   "404":
	//     "$ref": "#/responses/notFound"
	if env := environmentOfRepo(ctx); env != nil {
		listRepoSecrets(ctx, env.ID)
	}
}

// CreateOrUpdateActionEnvironmentSecret creates or updates a secret of an environment
func CreateOrUpdateActionEnvironmentSecret(ctx *context.APIContext) {
	// swagger:operation PUT /repos/{owner}/{repo}/actions/environments/{environment}/secrets/{secretname} repository updateRepoEnvironmentSecret
	// ---
	// summary: Create or update a secret of a deployment environment
	// description: >
	//   An invalid name is a 400, as for the secrets of a repository. Only a person's own credential changes the
	//   secrets of an environment: a request under sudo, with an OAuth2 grant or with an authorized integration is a 403.
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repository
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repository
	//   type: string
	//   required: true
	// - name: environment
	//   in: path
	//   description: name of the environment, matched ignoring case
	//   type: string
	//   required: true
	// - name: secretname
	//   in: path
	//   description: name of the secret
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/CreateOrUpdateSecretOption"
	// responses:
	//   "201":
	//     description: response when creating a secret
	//   "204":
	//     description: response when updating a secret
	//   "400":
	//     "$ref": "#/responses/error"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"
	if env := environmentOfRepo(ctx); env != nil {
		putRepoSecret(ctx, env.ID)
	}
}

// DeleteActionEnvironmentSecret deletes a secret of an environment
func DeleteActionEnvironmentSecret(ctx *context.APIContext) {
	// swagger:operation DELETE /repos/{owner}/{repo}/actions/environments/{environment}/secrets/{secretname} repository deleteRepoEnvironmentSecret
	// ---
	// summary: Delete a secret of a deployment environment
	// description: >
	//   An invalid name is a 400, as for the secrets of a repository. Only a person's own credential changes the
	//   secrets of an environment: a request under sudo, with an OAuth2 grant or with an authorized integration is a 403.
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repository
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repository
	//   type: string
	//   required: true
	// - name: environment
	//   in: path
	//   description: name of the environment, matched ignoring case
	//   type: string
	//   required: true
	// - name: secretname
	//   in: path
	//   description: name of the secret
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     description: response when deleting a secret
	//   "400":
	//     "$ref": "#/responses/error"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"
	if env := environmentOfRepo(ctx); env != nil {
		deleteRepoSecret(ctx, env.ID)
	}
}

// ListActionEnvironmentVariables lists the variables of an environment
func ListActionEnvironmentVariables(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/actions/environments/{environment}/variables repository getRepoEnvironmentVariablesList
	// ---
	// summary: List the variables of a deployment environment
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repository
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repository
	//   type: string
	//   required: true
	// - name: environment
	//   in: path
	//   description: name of the environment, matched ignoring case
	//   type: string
	//   required: true
	// - name: page
	//   in: query
	//   description: page number of results to return (1-based)
	//   type: integer
	// - name: limit
	//   in: query
	//   description: page size of results
	//   type: integer
	// responses:
	//   "200":
	//     "$ref": "#/responses/VariableList"
	//   "400":
	//     "$ref": "#/responses/error"
	//   "404":
	//     "$ref": "#/responses/notFound"
	if env := environmentOfRepo(ctx); env != nil {
		listRepoVariables(ctx, env.ID)
	}
}

// GetActionEnvironmentVariable gets a variable of an environment
func GetActionEnvironmentVariable(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/actions/environments/{environment}/variables/{variablename} repository getRepoEnvironmentVariable
	// ---
	// summary: Get a variable of a deployment environment
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repository
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repository
	//   type: string
	//   required: true
	// - name: environment
	//   in: path
	//   description: name of the environment, matched ignoring case
	//   type: string
	//   required: true
	// - name: variablename
	//   in: path
	//   description: name of the variable
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/ActionVariable"
	//   "400":
	//     "$ref": "#/responses/error"
	//   "404":
	//     "$ref": "#/responses/notFound"
	if env := environmentOfRepo(ctx); env != nil {
		getRepoVariable(ctx, env.ID)
	}
}

// CreateActionEnvironmentVariable creates a variable of an environment
func CreateActionEnvironmentVariable(ctx *context.APIContext) {
	// swagger:operation POST /repos/{owner}/{repo}/actions/environments/{environment}/variables/{variablename} repository createRepoEnvironmentVariable
	// ---
	// summary: Create a variable of a deployment environment
	// description: >
	//   An invalid name is a 400, as for the variables of a repository. Only a person's own credential changes the
	//   variables of an environment: a request under sudo, with an OAuth2 grant or with an authorized integration is a 403.
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repository
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repository
	//   type: string
	//   required: true
	// - name: environment
	//   in: path
	//   description: name of the environment, matched ignoring case
	//   type: string
	//   required: true
	// - name: variablename
	//   in: path
	//   description: name of the variable
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/CreateVariableOption"
	// responses:
	//   "204":
	//     description: response when creating a variable
	//   "400":
	//     "$ref": "#/responses/error"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"
	//   "409":
	//     description: a variable of that name exists
	if env := environmentOfRepo(ctx); env != nil {
		createRepoVariable(ctx, env.ID)
	}
}

// UpdateActionEnvironmentVariable updates a variable of an environment
func UpdateActionEnvironmentVariable(ctx *context.APIContext) {
	// swagger:operation PUT /repos/{owner}/{repo}/actions/environments/{environment}/variables/{variablename} repository updateRepoEnvironmentVariable
	// ---
	// summary: Update a variable of a deployment environment
	// description: >
	//   An invalid name is a 400, as for the variables of a repository. Only a person's own credential changes the
	//   variables of an environment: a request under sudo, with an OAuth2 grant or with an authorized integration is a 403.
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repository
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repository
	//   type: string
	//   required: true
	// - name: environment
	//   in: path
	//   description: name of the environment, matched ignoring case
	//   type: string
	//   required: true
	// - name: variablename
	//   in: path
	//   description: name of the variable
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/UpdateVariableOption"
	// responses:
	//   "204":
	//     description: response when updating a variable
	//   "400":
	//     "$ref": "#/responses/error"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"
	//   "409":
	//     description: a variable of the new name exists
	if env := environmentOfRepo(ctx); env != nil {
		updateRepoVariable(ctx, env.ID)
	}
}

// DeleteActionEnvironmentVariable deletes a variable of an environment
func DeleteActionEnvironmentVariable(ctx *context.APIContext) {
	// swagger:operation DELETE /repos/{owner}/{repo}/actions/environments/{environment}/variables/{variablename} repository deleteRepoEnvironmentVariable
	// ---
	// summary: Delete a variable of a deployment environment
	// description: >
	//   An invalid name is a 400, as for the variables of a repository. Only a person's own credential changes the
	//   variables of an environment: a request under sudo, with an OAuth2 grant or with an authorized integration is a 403.
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repository
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repository
	//   type: string
	//   required: true
	// - name: environment
	//   in: path
	//   description: name of the environment, matched ignoring case
	//   type: string
	//   required: true
	// - name: variablename
	//   in: path
	//   description: name of the variable
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     description: response when deleting a variable
	//   "400":
	//     "$ref": "#/responses/error"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"
	if env := environmentOfRepo(ctx); env != nil {
		deleteRepoVariable(ctx, env.ID)
	}
}
