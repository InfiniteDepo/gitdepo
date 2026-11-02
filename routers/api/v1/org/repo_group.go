// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"errors"
	"net/http"

	"forgejo.org/models/db"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/optional"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/services/auth"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	repo_service "forgejo.org/services/repository"

	"xorm.io/builder"
)

// projectNameTaken is the one answer for a name held by any repository (of any visibility, or trashed) or project.
const projectNameTaken = "the name is not available"

// projectRepoSearchOptions are the options of the organization's repository lists in the API.
func projectRepoSearchOptions(ctx *context.APIContext) *repo_model.SearchRepoOptions {
	return &repo_model.SearchRepoOptions{
		OwnerID:              ctx.Org().Organization.ID,
		Collaborate:          optional.Some(false),
		Private:              ctx.IsSigned() && !ctx.PublicOnly(),
		Actor:                ctx.Doer(),
		AuditorView:          auth.IsHeldByUser(ctx.Authentication()),
		AuthorizationReducer: ctx.Reducer(),
	}
}

// visibleProjectCond is the web's rule (VisibleRepoGroupCond) for the projects of the organization. A token limited
// to public or specific repositories sees only the projects holding a repository it reaches, never through
// membership.
func visibleProjectCond(ctx *context.APIContext) builder.Cond {
	cond := repo_model.VisibleRepoGroupCond(ctx.Doer()).And(builder.Eq{"`repo_group`.owner_id": ctx.Org().Organization.ID})
	if !utils.IsOrgWideToken(ctx) {
		cond = cond.And(builder.In("`repo_group`.id", builder.Select("group_id").From("repository").
			Where(repo_model.SearchRepositoryCondition(projectRepoSearchOptions(ctx)))))
	}
	return cond
}

// visibleProject returns the project `{id}` if the doer may see it; otherwise it answers the plain 404.
func visibleProject(ctx *context.APIContext) *repo_model.RepoGroup {
	group := new(repo_model.RepoGroup)
	has, err := db.GetEngine(ctx).Where(visibleProjectCond(ctx)).And(builder.Eq{"`repo_group`.id": ctx.ParamsInt64(":id")}).Get(group)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "visibleProject", err)
		return nil
	} else if !has {
		ctx.NotFound()
		return nil
	}
	return group
}

// ownedProject returns the project `{id}` for a write by an organization owner; reqOrgOwnership ran before, so
// someone else can't probe IDs.
func ownedProject(ctx *context.APIContext) *repo_model.RepoGroup {
	if !orgWideToken(ctx) {
		return nil
	}
	group, err := repo_model.GetRepoGroupByID(ctx, ctx.Org().Organization.ID, ctx.ParamsInt64(":id"))
	if errors.Is(err, repo_model.ErrRepoGroupNotExist) {
		ctx.NotFound()
		return nil
	} else if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetRepoGroupByID", err)
		return nil
	}
	return group
}

func projectWriteError(ctx *context.APIContext, err error) {
	switch {
	case repo_model.IsErrRepoAlreadyExist(err), repo_model.IsErrRepoFilesAlreadyExist(err):
		ctx.Error(http.StatusConflict, "", projectNameTaken)
	case errors.Is(err, repo_model.ErrRepoGroupNotEmpty):
		ctx.Error(http.StatusConflict, "", "the project still holds repositories")
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Error(http.StatusUnprocessableEntity, "", err.Error())
	default:
		ctx.Error(http.StatusInternalServerError, "", err)
	}
}

// ListProjects lists the organization's projects the doer can see
func ListProjects(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/projects organization orgListProjects
	// ---
	// summary: List the organization's projects the doer can see
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: q
	//   in: query
	//   description: part of the project name
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
	//     "$ref": "#/responses/ProjectList"
	//   "404":
	//     "$ref": "#/responses/notFound"

	listOptions := utils.GetListOptions(ctx)
	groups, count, err := repo_model.FindRepoGroups(ctx, visibleProjectCond(ctx), 0, ctx.FormTrim("q"), listOptions)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "FindRepoGroups", err)
		return
	}
	projects := make([]*api.Project, 0, len(groups))
	for _, group := range groups {
		projects = append(projects, convert.ToProject(group, ctx.Org().Organization.Name))
	}
	ctx.SetLinkHeader(int(count), listOptions.PageSize)
	ctx.SetTotalCountHeader(count)
	ctx.JSON(http.StatusOK, projects)
}

// GetProject gets a project of the organization
func GetProject(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/projects/{id} organization orgGetProject
	// ---
	// summary: Get a project of the organization
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/Project"
	//   "404":
	//     "$ref": "#/responses/notFound"

	if group := visibleProject(ctx); group != nil {
		ctx.JSON(http.StatusOK, convert.ToProject(group, ctx.Org().Organization.Name))
	}
}

// ListProjectRepos lists the repositories of a project the doer can see
func ListProjectRepos(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/projects/{id}/repos organization orgListProjectRepos
	// ---
	// summary: List the repositories of a project the doer can see
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
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
	//     "$ref": "#/responses/RepositoryList"
	//   "404":
	//     "$ref": "#/responses/notFound"

	group := visibleProject(ctx)
	if group == nil {
		return
	}
	opts := projectRepoSearchOptions(ctx)
	opts.GroupID = group.ID
	opts.ListOptions = utils.GetListOptions(ctx)
	opts.OrderBy = db.SearchOrderByAlphabetically
	repos, count, err := repo_model.SearchRepository(ctx, opts)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "SearchRepository", err)
		return
	}
	if err := repos.LoadAttributes(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadAttributes", err)
		return
	}
	apiRepos := make([]*api.Repository, 0, len(repos))
	for _, repo := range repos {
		permission, err := access_model.GetUserRepoPermissionWithReducer(ctx, repo, ctx.Doer(), ctx.Reducer())
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "GetUserRepoPermissionWithReducer", err)
			return
		}
		if permission.HasAccess() {
			apiRepos = append(apiRepos, convert.ToRepo(ctx, repo, permission))
		}
	}
	ctx.SetLinkHeader(int(count), opts.PageSize)
	ctx.SetTotalCountHeader(count)
	ctx.JSON(http.StatusOK, apiRepos)
}

// CreateProject creates a project in the organization
func CreateProject(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/projects organization orgCreateProject
	// ---
	// summary: Create a project in the organization
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/CreateProjectOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/Project"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     "$ref": "#/responses/conflict"
	//   "422":
	//     "$ref": "#/responses/validationError"

	if !orgWideToken(ctx) {
		return
	}
	form := web.GetForm(ctx).(*api.CreateProjectOption)
	org := ctx.Org().Organization.AsUser()
	group, err := repo_model.CreateRepoGroup(ctx, org, form.Name, form.Description)
	if err != nil {
		projectWriteError(ctx, err)
		return
	}
	ctx.JSON(http.StatusCreated, convert.ToProject(group, org.Name))
}

// EditProject renames a project or changes its description
func EditProject(ctx *context.APIContext) {
	// swagger:operation PATCH /orgs/{org}/projects/{id} organization orgEditProject
	// ---
	// summary: Rename a project or change its description
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/EditProjectOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/Project"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     "$ref": "#/responses/conflict"
	//   "422":
	//     "$ref": "#/responses/validationError"

	group := ownedProject(ctx)
	if group == nil {
		return
	}
	form := web.GetForm(ctx).(*api.EditProjectOption)
	org := ctx.Org().Organization.AsUser()
	if form.Name != nil && *form.Name != group.Name {
		if err := repo_service.RenameRepoGroup(ctx, org, group, *form.Name); err != nil {
			projectWriteError(ctx, err)
			return
		}
	}
	if form.Description != nil && *form.Description != group.Description {
		group.Description = *form.Description
		if err := repo_model.UpdateRepoGroupDescription(ctx, group); err != nil {
			ctx.Error(http.StatusInternalServerError, "UpdateRepoGroupDescription", err)
			return
		}
	}
	ctx.JSON(http.StatusOK, convert.ToProject(group, org.Name))
}

// DeleteProject deletes an empty project
func DeleteProject(ctx *context.APIContext) {
	// swagger:operation DELETE /orgs/{org}/projects/{id} organization orgDeleteProject
	// ---
	// summary: Delete a project that holds no repositories, trashed ones included
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the project
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
	//     "$ref": "#/responses/conflict"

	group := ownedProject(ctx)
	if group == nil {
		return
	}
	if err := repo_service.DeleteRepoGroup(ctx, ctx.Org().Organization.AsUser(), group); err != nil {
		projectWriteError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}
