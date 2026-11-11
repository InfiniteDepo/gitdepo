// Copyright 2016 The Gogs Authors. All rights reserved.
// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"errors"
	"net/http"

	"forgejo.org/models"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	repo_module "forgejo.org/modules/repository"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	pull_service "forgejo.org/services/pull"
	repo_service "forgejo.org/services/repository"
)

// GetBranch get a branch of a repository
func GetBranch(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/branches/{branch} repository repoGetBranch
	// ---
	// summary: Retrieve a specific branch from a repository, including its effective branch protection
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
	//   description: branch to get
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/Branch"
	//   "404":
	//     "$ref": "#/responses/notFound"

	branchName := ctx.Params("*")

	branch, err := ctx.Repo().GitRepo.GetBranch(branchName)
	if err != nil {
		if git.IsErrBranchNotExist(err) {
			ctx.NotFound(err)
		} else {
			ctx.Error(http.StatusInternalServerError, "GetBranch", err)
		}
		return
	}

	c, err := branch.GetCommit()
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetCommit", err)
		return
	}

	branchProtection, err := git_model.GetMatchedProtectedBranchRules(ctx, ctx.Repo().Repository.ID, branchName)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetBranchProtection", err)
		return
	}

	br, err := convert.ToBranch(ctx, ctx.Repo().Repository, branch.Name, c, branchProtection, ctx.Doer(), ctx.IsUserRepoAdmin())
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "convert.ToBranch", err)
		return
	}

	ctx.JSON(http.StatusOK, br)
}

// DeleteBranch get a branch of a repository
func DeleteBranch(ctx *context.APIContext) {
	// swagger:operation DELETE /repos/{owner}/{repo}/branches/{branch} repository repoDeleteBranch
	// ---
	// summary: Delete a specific branch from a repository
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
	//   description: branch to delete
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/error"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     "$ref": "#/responses/error"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"
	if ctx.Repo().Repository.IsEmpty {
		ctx.Error(http.StatusNotFound, "", "Git Repository is empty.")
		return
	}

	if ctx.Repo().Repository.IsMirror {
		ctx.Error(http.StatusForbidden, "", "Git Repository is a mirror.")
		return
	}

	branchName := ctx.Params("*")

	// check whether branches of this repository has been synced
	totalNumOfBranches, err := db.Count[git_model.Branch](ctx, git_model.FindBranchOptions{
		RepoID:          ctx.Repo().Repository.ID,
		IsDeletedBranch: optional.Some(false),
	})
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "CountBranches", err)
		return
	}
	if totalNumOfBranches == 0 { // sync branches immediately because non-empty repository should have at least 1 branch
		_, err = repo_module.SyncRepoBranches(ctx, ctx.Repo().Repository.ID, 0)
		if err != nil {
			ctx.ServerError("SyncRepoBranches", err)
			return
		}
	}

	if err := repo_service.DeleteBranch(ctx, ctx.Doer(), ctx.Repo().Repository, ctx.Repo().GitRepo, branchName, ""); err != nil {
		switch {
		case git.IsErrBranchNotExist(err):
			ctx.NotFound(err)
		case errors.Is(err, repo_service.ErrBranchIsDefault):
			ctx.Error(http.StatusForbidden, "DefaultBranch", errors.New("can not delete default branch"))
		case errors.Is(err, git_model.ErrBranchIsProtected):
			ctx.Error(http.StatusForbidden, "IsProtectedBranch", errors.New("branch protected"))
		case errors.Is(err, repo_service.ErrBranchHasNewCommits):
			ctx.Error(http.StatusConflict, "BranchMoved", errors.New("the branch was pushed to meanwhile and was not deleted"))
		default:
			ctx.Error(http.StatusInternalServerError, "DeleteBranch", err)
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

// DeleteBranches deletes several branches of a repository, named or picked by filters, and reports each one
func DeleteBranches(ctx *context.APIContext) {
	// swagger:operation POST /repos/{owner}/{repo}/branches/delete repository repoDeleteBranches
	// ---
	// summary: Delete several branches, named or picked by filters
	// description: Names up to 100 branches, or picks the first 100 that match the filters. The default, development, production, release and protected branches, branches of the merge queue and branches used by open pull requests are kept, and so is a branch that was pushed to since it was read. A kept branch does not stop the others. Every deleted branch can be restored from the deleted branches.
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
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/DeleteBranchesOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/DeleteBranchesResult"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"
	repo := ctx.Repo().Repository
	if repo.IsEmpty {
		ctx.Error(http.StatusNotFound, "", "Git Repository is empty.")
		return
	}
	if repo.IsMirror {
		ctx.Error(http.StatusForbidden, "", "Git Repository is a mirror.")
		return
	}
	opt := web.GetForm(ctx).(*api.DeleteBranchesOption)

	// check whether branches of this repository has been synced
	total, err := db.Count[git_model.Branch](ctx, git_model.FindBranchOptions{RepoID: repo.ID, IsDeletedBranch: optional.Some(false)})
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "CountBranches", err)
		return
	}
	if total == 0 {
		if _, err := repo_module.SyncRepoBranches(ctx, repo.ID, 0); err != nil {
			ctx.ServerError("SyncRepoBranches", err)
			return
		}
	}

	var selected []repo_service.SelectedBranch
	more := false
	if len(opt.Names) > 0 {
		names, err := repo_service.CheckSelectedBranchNames(opt.Names, repo_service.MaxDeleteSelectedBranchesAPI)
		if err != nil {
			ctx.Error(http.StatusUnprocessableEntity, "", err)
			return
		}
		for _, n := range names {
			selected = append(selected, repo_service.SelectedBranch{Name: n})
		}
	} else {
		filter := repo_service.BranchFilter{
			Keyword: opt.Keyword, Type: opt.Type, Untyped: opt.Untyped, State: opt.Merged, Into: opt.MergedInto,
			StaleDays: opt.StaleDays, PushedBy: opt.PushedBy,
		}
		if !filter.IsSet() && filter.Type == "" && !filter.Untyped {
			ctx.Error(http.StatusUnprocessableEntity, "", "name the branches or give a filter")
			return
		}
		model, err := branchworkflow.GetEffectiveModel(ctx, repo)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "GetEffectiveModel", err)
			return
		}
		q, err := filter.Query(ctx, repo, ctx.Repo().GitRepo, model)
		if err != nil {
			if errors.Is(err, util.ErrInvalidArgument) {
				ctx.Error(http.StatusUnprocessableEntity, "", err)
			} else {
				ctx.Error(http.StatusInternalServerError, "BranchFilter.Query", err)
			}
			return
		}
		found, err := repo_service.FindDeletableBranches(ctx, repo, q, repo_service.MaxDeleteSelectedBranchesAPI)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "FindDeletableBranches", err)
			return
		}
		selected, more = found.Branches, found.Total > len(found.Branches)
	}

	results, err := repo_service.DeleteSelectedBranches(ctx, ctx.Doer(), repo, ctx.Repo().GitRepo, selected)
	if err != nil {
		if results == nil {
			ctx.Error(http.StatusInternalServerError, "DeleteSelectedBranches", err)
			return
		}
		log.Error("DeleteBranches: %-v: %v", repo, err) // the branches are deleted and audited one by one; only the summary failed
	}
	res := api.DeleteBranchesResult{Deleted: []string{}, Kept: []api.KeptBranch{}, More: more}
	for _, r := range results {
		if r.Reason == "" {
			res.Deleted = append(res.Deleted, r.Name)
		} else {
			res.Kept = append(res.Kept, api.KeptBranch{Name: r.Name, Reason: r.Reason})
		}
	}
	ctx.JSON(http.StatusOK, res)
}

// CreateBranch creates a branch for a user's repository
func CreateBranch(ctx *context.APIContext) {
	// swagger:operation POST /repos/{owner}/{repo}/branches repository repoCreateBranch
	// ---
	// summary: Create a branch
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
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/CreateBranchRepoOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/Branch"
	//   "403":
	//     description: The branch is archived or a mirror.
	//   "404":
	//     description: The old branch does not exist.
	//   "409":
	//     description: The branch with the same name already exists.
	//   "413":
	//     "$ref": "#/responses/quotaExceeded"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"

	if ctx.Repo().Repository.IsEmpty {
		ctx.Error(http.StatusNotFound, "", "Git Repository is empty.")
		return
	}

	if ctx.Repo().Repository.IsMirror {
		ctx.Error(http.StatusForbidden, "", "Git Repository is a mirror.")
		return
	}

	opt := web.GetForm(ctx).(*api.CreateBranchRepoOption)

	var oldCommit *git.Commit
	var err error

	if len(opt.OldRefName) > 0 {
		oldCommit, err = ctx.Repo().GitRepo.GetCommit(opt.OldRefName)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "GetCommit", err)
			return
		}
	} else if len(opt.OldBranchName) > 0 { //nolint:staticcheck
		if ctx.Repo().GitRepo.IsBranchExist(opt.OldBranchName) { //nolint:staticcheck
			oldCommit, err = ctx.Repo().GitRepo.GetBranchCommit(opt.OldBranchName) //nolint:staticcheck
			if err != nil {
				ctx.Error(http.StatusInternalServerError, "GetBranchCommit", err)
				return
			}
		} else {
			ctx.Error(http.StatusNotFound, "", "The old branch does not exist")
			return
		}
	} else {
		oldCommit, err = ctx.Repo().GitRepo.GetBranchCommit(ctx.Repo().Repository.DefaultBranch)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "GetBranchCommit", err)
			return
		}
	}

	err = repo_service.CreateNewBranchFromCommit(ctx, ctx.Doer(), ctx.Repo().Repository, ctx.Repo().GitRepo, oldCommit.ID.String(), opt.BranchName)
	if err != nil {
		if git_model.IsErrBranchNotExist(err) {
			ctx.Error(http.StatusNotFound, "", "The old branch does not exist")
		} else if models.IsErrTagAlreadyExists(err) {
			ctx.Error(http.StatusConflict, "", "The branch with the same tag already exists.")
		} else if git_model.IsErrBranchAlreadyExists(err) || git.IsErrPushOutOfDate(err) {
			ctx.Error(http.StatusConflict, "", "The branch already exists.")
		} else if git_model.IsErrBranchNameConflict(err) {
			ctx.Error(http.StatusConflict, "", "The branch with the same name already exists.")
		} else if git_model.IsErrBranchNameReserved(err) {
			ctx.Error(http.StatusUnprocessableEntity, "", "The branch name is reserved.")
		} else if refused, ok := errors.AsType[branchworkflow.ErrBranchTypeRequired](err); ok {
			ctx.Error(http.StatusUnprocessableEntity, "", refused.Text(ctx.Locale))
		} else {
			ctx.Error(http.StatusInternalServerError, "CreateNewBranchFromCommit", err)
		}
		return
	}

	branch, err := ctx.Repo().GitRepo.GetBranch(opt.BranchName)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetBranch", err)
		return
	}

	commit, err := branch.GetCommit()
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetCommit", err)
		return
	}

	branchProtection, err := git_model.GetMatchedProtectedBranchRules(ctx, ctx.Repo().Repository.ID, branch.Name)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetBranchProtection", err)
		return
	}

	br, err := convert.ToBranch(ctx, ctx.Repo().Repository, branch.Name, commit, branchProtection, ctx.Doer(), ctx.IsUserRepoAdmin())
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "convert.ToBranch", err)
		return
	}

	ctx.JSON(http.StatusCreated, br)
}

// ListBranches list all the branches of a repository
func ListBranches(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/branches repository repoListBranches
	// ---
	// summary: List a repository's branches
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
	//     "$ref": "#/responses/BranchList"

	var totalNumOfBranches int64
	var apiBranches []*api.Branch

	listOptions := utils.GetListOptions(ctx)

	if !ctx.Repo().Repository.IsEmpty {
		if ctx.Repo().GitRepo == nil {
			ctx.Error(http.StatusInternalServerError, "Load git repository failed", nil)
			return
		}

		branchOpts := git_model.FindBranchOptions{
			ListOptions:     listOptions,
			RepoID:          ctx.Repo().Repository.ID,
			IsDeletedBranch: optional.Some(false),
		}
		var err error
		totalNumOfBranches, err = db.Count[git_model.Branch](ctx, branchOpts)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "CountBranches", err)
			return
		}
		if totalNumOfBranches == 0 { // sync branches immediately because non-empty repository should have at least 1 branch
			totalNumOfBranches, err = repo_module.SyncRepoBranches(ctx, ctx.Repo().Repository.ID, 0)
			if err != nil {
				ctx.ServerError("SyncRepoBranches", err)
				return
			}
		}

		rules, err := git_model.FindProtectedBranchRulesForRepo(ctx, ctx.Repo().Repository)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "FindMatchedProtectedBranchRules", err)
			return
		}

		branches, err := db.Find[git_model.Branch](ctx, branchOpts)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "GetBranches", err)
			return
		}

		apiBranches = make([]*api.Branch, 0, len(branches))
		for i := range branches {
			c, err := ctx.Repo().GitRepo.GetBranchCommit(branches[i].Name)
			if err != nil {
				// Skip if this branch doesn't exist anymore.
				if git.IsErrNotExist(err) {
					totalNumOfBranches--
					continue
				}
				ctx.Error(http.StatusInternalServerError, "GetCommit", err)
				return
			}

			branchProtection := rules.GetMatched(branches[i].Name)
			apiBranch, err := convert.ToBranch(ctx, ctx.Repo().Repository, branches[i].Name, c, branchProtection, ctx.Doer(), ctx.IsUserRepoAdmin())
			if err != nil {
				ctx.Error(http.StatusInternalServerError, "convert.ToBranch", err)
				return
			}
			apiBranches = append(apiBranches, apiBranch)
		}
	} else {
		apiBranches = make([]*api.Branch, 0)
	}

	ctx.SetLinkHeader(int(totalNumOfBranches), listOptions.PageSize)
	ctx.SetTotalCountHeader(totalNumOfBranches)
	ctx.JSON(http.StatusOK, apiBranches)
}

// UpdateBranch updates a repository's branch.
func UpdateBranch(ctx *context.APIContext) {
	// swagger:operation PATCH /repos/{owner}/{repo}/branches/{branch} repository repoUpdateBranch
	// ---
	// summary: Update a branch
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
	// - name: branch
	//   in: path
	//   description: name of the branch
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/UpdateBranchRepoOption"
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	opt := web.GetForm(ctx).(*api.UpdateBranchRepoOption)

	oldName := ctx.Params("*")
	repo := ctx.Repo().Repository

	if repo.IsEmpty {
		ctx.Error(http.StatusNotFound, "", "Git Repository is empty.")
		return
	}

	if repo.IsMirror {
		ctx.Error(http.StatusForbidden, "", "Git Repository is a mirror.")
		return
	}

	msg, err := repo_service.RenameBranch(ctx, repo, ctx.Doer(), ctx.Repo().GitRepo, oldName, opt.Name)
	if errors.Is(err, git_model.ErrBranchIsProtected) {
		ctx.Error(http.StatusForbidden, "", "The branch or the new branch name is protected.")
		return
	} else if git_model.IsErrBranchNameReserved(err) {
		ctx.Error(http.StatusUnprocessableEntity, "", "The branch name is reserved.")
		return
	} else if refused, ok := errors.AsType[branchworkflow.ErrBranchTypeRequired](err); ok {
		ctx.Error(http.StatusUnprocessableEntity, "", refused.Text(ctx.Locale))
		return
	} else if err != nil {
		ctx.Error(http.StatusInternalServerError, "RenameBranch", err)
		return
	}
	if msg == "target_exist" {
		ctx.Error(http.StatusUnprocessableEntity, "", "Cannot rename a branch using the same name or rename to a branch that already exists.")
		return
	}
	if msg == "from_not_exist" {
		ctx.Error(http.StatusNotFound, "", "Branch doesn't exist.")
		return
	}
	if msg == "push_rule" {
		ctx.Error(http.StatusUnprocessableEntity, "", "The new branch name does not match the repository's push rule.")
		return
	}

	ctx.Status(http.StatusNoContent)
}

// GetBranchProtection gets a branch protection
func GetBranchProtection(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/branch_protections/{name} repository repoGetBranchProtection
	// ---
	// summary: Get a specific branch protection for the repository
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
	// - name: name
	//   in: path
	//   description: name of protected branch
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/BranchProtection"
	//   "404":
	//     "$ref": "#/responses/notFound"

	repo := ctx.Repo().Repository
	bpName := ctx.Params(":name")
	bp, err := git_model.GetProtectedBranchRuleByName(ctx, repo.ID, bpName)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetProtectedBranchByID", err)
		return
	}
	if bp == nil || bp.RepoID != repo.ID {
		ctx.NotFound()
		return
	}

	ctx.JSON(http.StatusOK, convert.ToBranchProtection(ctx, bp, repo))
}

// ListBranchProtections list branch protections for a repo
func ListBranchProtections(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/branch_protections repository repoListBranchProtection
	// ---
	// summary: List branch protections for a repository
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
	// responses:
	//   "200":
	//     "$ref": "#/responses/BranchProtectionList"

	repo := ctx.Repo().Repository
	bps, err := git_model.FindRepoProtectedBranchRules(ctx, repo.ID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetProtectedBranches", err)
		return
	}
	apiBps := make([]*api.BranchProtection, len(bps))
	for i := range bps {
		apiBps[i] = convert.ToBranchProtection(ctx, bps[i], repo)
	}

	ctx.JSON(http.StatusOK, apiBps)
}

// CreateBranchProtection creates a branch protection for a repo
func CreateBranchProtection(ctx *context.APIContext) {
	// swagger:operation POST /repos/{owner}/{repo}/branch_protections repository repoCreateBranchProtection
	// ---
	// summary: Create a branch protections for a repository
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
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/CreateBranchProtectionOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/BranchProtection"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"

	form := web.GetForm(ctx).(*api.CreateBranchProtectionOption)
	repo := ctx.Repo().Repository

	ruleName := form.RuleName
	if ruleName == "" {
		ruleName = form.BranchName //nolint
	}
	if len(ruleName) == 0 {
		ctx.Error(http.StatusBadRequest, "both rule_name and branch_name are empty", "both rule_name and branch_name are empty")
		return
	}

	isPlainRule := !git_model.IsRuleNameSpecial(ruleName)
	var isBranchExist bool
	if isPlainRule {
		isBranchExist = ctx.Repo().GitRepo.IsBranchExist(ruleName)
	}

	protectBranch, err := git_model.GetProtectedBranchRuleByName(ctx, repo.ID, ruleName)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetProtectBranchOfRepoByName", err)
		return
	} else if protectBranch != nil {
		ctx.Error(http.StatusForbidden, "Create branch protection", "Branch protection already exist")
		return
	}

	protectBranch, opts, ok := BranchProtectionFromCreateOption(ctx, repo.Owner, ruleName, form)
	if !ok {
		return
	}
	protectBranch.RepoID = repo.ID
	err = git_model.UpdateProtectBranch(ctx, repo, protectBranch, opts)
	if errors.Is(err, util.ErrInvalidArgument) {
		ctx.Error(http.StatusUnprocessableEntity, "Invalid approval rule", err)
		return
	} else if err != nil {
		ctx.Error(http.StatusInternalServerError, "UpdateProtectBranch", err)
		return
	}

	if isBranchExist {
		if err = pull_service.CheckPRsForBaseBranch(ctx, ctx.Repo().Repository, ruleName); err != nil {
			ctx.Error(http.StatusInternalServerError, "CheckPRsForBaseBranch", err)
			return
		}
	} else {
		if !isPlainRule {
			if ctx.Repo().GitRepo == nil {
				ctx.Repo().GitRepo, err = gitrepo.OpenRepository(ctx, ctx.Repo().Repository)
				if err != nil {
					ctx.Error(http.StatusInternalServerError, "OpenRepository", err)
					return
				}
				defer func() {
					ctx.Repo().GitRepo.Close()
					ctx.Repo().GitRepo = nil
				}()
			}
			// FIXME: since we only need to recheck files protected rules, we could improve this
			matchedBranches, err := git_model.FindAllMatchedBranches(ctx, ctx.Repo().Repository.ID, ruleName)
			if err != nil {
				ctx.Error(http.StatusInternalServerError, "FindAllMatchedBranches", err)
				return
			}

			for _, branchName := range matchedBranches {
				if err = pull_service.CheckPRsForBaseBranch(ctx, ctx.Repo().Repository, branchName); err != nil {
					ctx.Error(http.StatusInternalServerError, "CheckPRsForBaseBranch", err)
					return
				}
			}
		}
	}

	// Reload from db to get all whitelists
	bp, err := git_model.GetProtectedBranchRuleByName(ctx, ctx.Repo().Repository.ID, ruleName)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetProtectedBranchByID", err)
		return
	}
	if bp == nil || bp.RepoID != ctx.Repo().Repository.ID {
		ctx.Error(http.StatusInternalServerError, "New branch protection not found", err)
		return
	}

	ctx.JSON(http.StatusCreated, convert.ToBranchProtection(ctx, bp, repo))
}

// EditBranchProtection edits a branch protection for a repo
func EditBranchProtection(ctx *context.APIContext) {
	// swagger:operation PATCH /repos/{owner}/{repo}/branch_protections/{name} repository repoEditBranchProtection
	// ---
	// summary: Edit a branch protections for a repository. Only fields that are set will be changed
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
	// - name: name
	//   in: path
	//   description: name of protected branch
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/EditBranchProtectionOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/BranchProtection"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"
	form := web.GetForm(ctx).(*api.EditBranchProtectionOption)
	repo := ctx.Repo().Repository
	bpName := ctx.Params(":name")
	protectBranch, err := git_model.GetProtectedBranchRuleByName(ctx, repo.ID, bpName)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetProtectedBranchByID", err)
		return
	}
	if protectBranch == nil || protectBranch.RepoID != repo.ID {
		ctx.NotFound()
		return
	}

	opts, ok := ApplyEditBranchProtectionOption(ctx, repo.Owner, protectBranch, form)
	if !ok {
		return
	}
	err = git_model.UpdateProtectBranch(ctx, repo, protectBranch, opts)
	if errors.Is(err, util.ErrInvalidArgument) {
		ctx.Error(http.StatusUnprocessableEntity, "Invalid approval rule", err)
		return
	} else if err != nil {
		ctx.Error(http.StatusInternalServerError, "UpdateProtectBranch", err)
		return
	}

	isPlainRule := !git_model.IsRuleNameSpecial(bpName)
	var isBranchExist bool
	if isPlainRule {
		isBranchExist = ctx.Repo().GitRepo.IsBranchExist(bpName)
	}

	if isBranchExist {
		if err = pull_service.CheckPRsForBaseBranch(ctx, ctx.Repo().Repository, bpName); err != nil {
			ctx.Error(http.StatusInternalServerError, "CheckPrsForBaseBranch", err)
			return
		}
	} else {
		if !isPlainRule {
			if ctx.Repo().GitRepo == nil {
				ctx.Repo().GitRepo, err = gitrepo.OpenRepository(ctx, ctx.Repo().Repository)
				if err != nil {
					ctx.Error(http.StatusInternalServerError, "OpenRepository", err)
					return
				}
				defer func() {
					ctx.Repo().GitRepo.Close()
					ctx.Repo().GitRepo = nil
				}()
			}

			// FIXME: since we only need to recheck files protected rules, we could improve this
			matchedBranches, err := git_model.FindAllMatchedBranches(ctx, ctx.Repo().Repository.ID, protectBranch.RuleName)
			if err != nil {
				ctx.Error(http.StatusInternalServerError, "FindAllMatchedBranches", err)
				return
			}

			for _, branchName := range matchedBranches {
				if err = pull_service.CheckPRsForBaseBranch(ctx, ctx.Repo().Repository, branchName); err != nil {
					ctx.Error(http.StatusInternalServerError, "CheckPrsForBaseBranch", err)
					return
				}
			}
		}
	}

	// Reload from db to ensure get all whitelists
	bp, err := git_model.GetProtectedBranchRuleByName(ctx, repo.ID, bpName)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetProtectedBranchBy", err)
		return
	}
	if bp == nil || bp.RepoID != ctx.Repo().Repository.ID {
		ctx.Error(http.StatusInternalServerError, "New branch protection not found", err)
		return
	}

	ctx.JSON(http.StatusOK, convert.ToBranchProtection(ctx, bp, repo))
}

// DeleteBranchProtection deletes a branch protection for a repo
func DeleteBranchProtection(ctx *context.APIContext) {
	// swagger:operation DELETE /repos/{owner}/{repo}/branch_protections/{name} repository repoDeleteBranchProtection
	// ---
	// summary: Delete a specific branch protection for the repository
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
	// - name: name
	//   in: path
	//   description: name of protected branch
	//   type: string
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "404":
	//     "$ref": "#/responses/notFound"

	repo := ctx.Repo().Repository
	bpName := ctx.Params(":name")
	bp, err := git_model.GetProtectedBranchRuleByName(ctx, repo.ID, bpName)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetProtectedBranchByID", err)
		return
	}
	if bp == nil || bp.RepoID != repo.ID {
		ctx.NotFound()
		return
	}

	if err := git_model.DeleteProtectedBranch(ctx, ctx.Repo().Repository, bp.ID); err != nil {
		ctx.Error(http.StatusInternalServerError, "DeleteProtectedBranch", err)
		return
	}

	ctx.Status(http.StatusNoContent)
}

// BranchProtectionFromCreateOption builds a new rule without RepoID and its allow-lists from form,
// looking teams up in owner. On error it writes the response and returns false.
func BranchProtectionFromCreateOption(ctx *context.APIContext, owner *user_model.User, ruleName string, form *api.CreateBranchProtectionOption) (*git_model.ProtectedBranch, git_model.WhitelistOptions, bool) {
	var opts git_model.WhitelistOptions
	lists := []struct {
		usernames, teams []string
		userIDs, teamIDs *[]int64
	}{
		{form.PushWhitelistUsernames, form.PushWhitelistTeams, &opts.UserIDs, &opts.TeamIDs},
		{form.MergeWhitelistUsernames, form.MergeWhitelistTeams, &opts.MergeUserIDs, &opts.MergeTeamIDs},
		{form.ApprovalsWhitelistUsernames, form.ApprovalsWhitelistTeams, &opts.ApprovalsUserIDs, &opts.ApprovalsTeamIDs},
		{form.DeleteAllowlistUsernames, form.DeleteAllowlistTeams, &opts.DeleteUserIDs, &opts.DeleteTeamIDs},
		{form.ForcePushAllowlistUsernames, form.ForcePushAllowlistTeams, &opts.ForcePushUserIDs, &opts.ForcePushTeamIDs},
	}
	for _, l := range lists {
		var ok bool
		if *l.userIDs, *l.teamIDs, ok = getAllowlistIDs(ctx, owner, l.usernames, l.teams, nil, nil); !ok {
			return nil, opts, false
		}
	}
	opts.DeployKeyIDs = form.PushWhitelistDeployKeyIDs
	opts.DeleteDeployKeyIDs = form.DeleteAllowlistDeployKeyIDs
	opts.ForcePushDeployKeyIDs = form.ForcePushAllowlistDeployKeyIDs

	var ok bool
	if opts.ApprovalRules, ok = approvalRulesFromAPI(ctx, owner, form.ApprovalRules); !ok {
		return nil, opts, false
	}

	var requiredApprovals int64
	if form.RequiredApprovals > 0 {
		requiredApprovals = form.RequiredApprovals
	}
	pb := &git_model.ProtectedBranch{
		RuleName:                       ruleName,
		CanPush:                        form.EnablePush,
		EnableWhitelist:                form.EnablePush && form.EnablePushWhitelist,
		EnableMergeWhitelist:           form.EnableMergeWhitelist,
		WhitelistDeployKeys:            form.EnablePush && form.EnablePushWhitelist && form.PushWhitelistDeployKeys,
		EnableStatusCheck:              form.EnableStatusCheck,
		StatusCheckContexts:            form.StatusCheckContexts,
		EnableApprovalsWhitelist:       form.EnableApprovalsWhitelist,
		RequiredApprovals:              requiredApprovals,
		BlockOnRejectedReviews:         form.BlockOnRejectedReviews,
		BlockOnOfficialReviewRequests:  form.BlockOnOfficialReviewRequests,
		DismissStaleApprovals:          form.DismissStaleApprovals,
		IgnoreStaleApprovals:           form.IgnoreStaleApprovals,
		IgnorePusherApprovals:          form.IgnorePusherApprovals,
		RequireSignedCommits:           form.RequireSignedCommits,
		ProtectedFilePatterns:          form.ProtectedFilePatterns,
		UnprotectedFilePatterns:        form.UnprotectedFilePatterns,
		BlockOnOutdatedBranch:          form.BlockOnOutdatedBranch,
		ApplyToAdmins:                  form.ApplyToAdmins,
		BlockOnUnresolvedConversations: form.BlockOnUnresolvedConversations,
		IgnoreOutdatedConversations:    form.IgnoreOutdatedConversations,
		BlockOnIncompleteTasks:         form.BlockOnIncompleteTasks,
		RequireMergeQueue:              form.RequireMergeQueue,
		MergeQueueMergeStyle:           form.MergeQueueMergeStyle,
		MergeQueueBuildConcurrency:     form.MergeQueueBuildConcurrency,
		MergeQueueMinGroupSize:         form.MergeQueueMinGroupSize,
		MergeQueueMaxGroupSize:         form.MergeQueueMaxGroupSize,
		MergeQueueWaitMinutes:          form.MergeQueueWaitMinutes,
		MergeQueueCheckTimeoutMinutes:  form.MergeQueueCheckTimeoutMinutes,
	}
	if err := pb.ValidateMergeQueue(); err != nil {
		ctx.Error(http.StatusUnprocessableEntity, "ValidateMergeQueue", err)
		return nil, opts, false
	}
	return pb, opts, true
}

// ApplyEditBranchProtectionOption changes protectBranch by the fields set in form and returns its allow-lists,
// looking teams up in owner. On error it writes the response and returns false.
func ApplyEditBranchProtectionOption(ctx *context.APIContext, owner *user_model.User, protectBranch *git_model.ProtectedBranch, form *api.EditBranchProtectionOption) (git_model.WhitelistOptions, bool) {
	if form.EnablePush != nil {
		if !*form.EnablePush {
			protectBranch.CanPush = false
			protectBranch.EnableWhitelist = false
			protectBranch.WhitelistDeployKeys = false
		} else {
			protectBranch.CanPush = true
			if form.EnablePushWhitelist != nil {
				if !*form.EnablePushWhitelist {
					protectBranch.EnableWhitelist = false
					protectBranch.WhitelistDeployKeys = false
				} else {
					protectBranch.EnableWhitelist = true
					if form.PushWhitelistDeployKeys != nil {
						protectBranch.WhitelistDeployKeys = *form.PushWhitelistDeployKeys
					}
				}
			}
		}
	}
	setIfNotNil := func(dst, src *bool) {
		if src != nil {
			*dst = *src
		}
	}
	setIfNotNil(&protectBranch.EnableMergeWhitelist, form.EnableMergeWhitelist)
	setIfNotNil(&protectBranch.EnableStatusCheck, form.EnableStatusCheck)
	if form.StatusCheckContexts != nil {
		protectBranch.StatusCheckContexts = form.StatusCheckContexts
	}
	if form.RequiredApprovals != nil && *form.RequiredApprovals >= 0 {
		protectBranch.RequiredApprovals = *form.RequiredApprovals
	}
	setIfNotNil(&protectBranch.EnableApprovalsWhitelist, form.EnableApprovalsWhitelist)
	setIfNotNil(&protectBranch.BlockOnRejectedReviews, form.BlockOnRejectedReviews)
	setIfNotNil(&protectBranch.BlockOnOfficialReviewRequests, form.BlockOnOfficialReviewRequests)
	setIfNotNil(&protectBranch.DismissStaleApprovals, form.DismissStaleApprovals)
	setIfNotNil(&protectBranch.IgnoreStaleApprovals, form.IgnoreStaleApprovals)
	setIfNotNil(&protectBranch.IgnorePusherApprovals, form.IgnorePusherApprovals)
	setIfNotNil(&protectBranch.RequireSignedCommits, form.RequireSignedCommits)
	if form.ProtectedFilePatterns != nil {
		protectBranch.ProtectedFilePatterns = *form.ProtectedFilePatterns
	}
	if form.UnprotectedFilePatterns != nil {
		protectBranch.UnprotectedFilePatterns = *form.UnprotectedFilePatterns
	}
	setIfNotNil(&protectBranch.BlockOnOutdatedBranch, form.BlockOnOutdatedBranch)
	setIfNotNil(&protectBranch.BlockOnUnresolvedConversations, form.BlockOnUnresolvedConversations)
	setIfNotNil(&protectBranch.IgnoreOutdatedConversations, form.IgnoreOutdatedConversations)
	setIfNotNil(&protectBranch.BlockOnIncompleteTasks, form.BlockOnIncompleteTasks)
	setIfNotNil(&protectBranch.ApplyToAdmins, form.ApplyToAdmins)
	setIfNotNil(&protectBranch.RequireMergeQueue, form.RequireMergeQueue)
	if form.MergeQueueMergeStyle != nil {
		protectBranch.MergeQueueMergeStyle = *form.MergeQueueMergeStyle
	}
	for _, f := range []struct{ dst, src *int }{
		{&protectBranch.MergeQueueBuildConcurrency, form.MergeQueueBuildConcurrency},
		{&protectBranch.MergeQueueMinGroupSize, form.MergeQueueMinGroupSize},
		{&protectBranch.MergeQueueMaxGroupSize, form.MergeQueueMaxGroupSize},
		{&protectBranch.MergeQueueWaitMinutes, form.MergeQueueWaitMinutes},
		{&protectBranch.MergeQueueCheckTimeoutMinutes, form.MergeQueueCheckTimeoutMinutes},
	} {
		if f.src != nil {
			*f.dst = *f.src
		}
	}
	if err := protectBranch.ValidateMergeQueue(); err != nil {
		ctx.Error(http.StatusUnprocessableEntity, "ValidateMergeQueue", err)
		return git_model.WhitelistOptions{}, false
	}

	opts := git_model.WhitelistOptions{
		DeployKeyIDs:          protectBranch.WhitelistDeployKeyIDs,
		DeleteDeployKeyIDs:    protectBranch.DeleteAllowlistDeployKeyIDs,
		ForcePushDeployKeyIDs: protectBranch.ForcePushAllowlistDeployKeyIDs,
	}
	lists := []struct {
		usernames, teams       []string
		curUserIDs, curTeamIDs []int64
		userIDs, teamIDs       *[]int64
	}{
		{form.PushWhitelistUsernames, form.PushWhitelistTeams, protectBranch.WhitelistUserIDs, protectBranch.WhitelistTeamIDs, &opts.UserIDs, &opts.TeamIDs},
		{form.MergeWhitelistUsernames, form.MergeWhitelistTeams, protectBranch.MergeWhitelistUserIDs, protectBranch.MergeWhitelistTeamIDs, &opts.MergeUserIDs, &opts.MergeTeamIDs},
		{form.ApprovalsWhitelistUsernames, form.ApprovalsWhitelistTeams, protectBranch.ApprovalsWhitelistUserIDs, protectBranch.ApprovalsWhitelistTeamIDs, &opts.ApprovalsUserIDs, &opts.ApprovalsTeamIDs},
		{form.DeleteAllowlistUsernames, form.DeleteAllowlistTeams, protectBranch.DeleteAllowlistUserIDs, protectBranch.DeleteAllowlistTeamIDs, &opts.DeleteUserIDs, &opts.DeleteTeamIDs},
		{form.ForcePushAllowlistUsernames, form.ForcePushAllowlistTeams, protectBranch.ForcePushAllowlistUserIDs, protectBranch.ForcePushAllowlistTeamIDs, &opts.ForcePushUserIDs, &opts.ForcePushTeamIDs},
	}
	for _, l := range lists {
		var ok bool
		if *l.userIDs, *l.teamIDs, ok = getAllowlistIDs(ctx, owner, l.usernames, l.teams, l.curUserIDs, l.curTeamIDs); !ok {
			return opts, false
		}
	}
	if form.PushWhitelistDeployKeyIDs != nil {
		opts.DeployKeyIDs = form.PushWhitelistDeployKeyIDs
	}
	if form.DeleteAllowlistDeployKeyIDs != nil {
		opts.DeleteDeployKeyIDs = form.DeleteAllowlistDeployKeyIDs
	}
	if form.ForcePushAllowlistDeployKeyIDs != nil {
		opts.ForcePushDeployKeyIDs = form.ForcePushAllowlistDeployKeyIDs
	}

	if form.ApprovalRules != nil {
		var ok bool
		if opts.ApprovalRules, ok = approvalRulesFromAPI(ctx, owner, form.ApprovalRules); !ok {
			return opts, false
		}
	}
	return opts, true
}

// getAllowlistIDs resolves the user and team names, keeping userIDs or teamIDs for a nil list. The token identities
// of userIDs stay when the user names are replaced: names can't name them.
// Teams are looked up in owner. On error it writes the response and returns false.
func getAllowlistIDs(ctx *context.APIContext, owner *user_model.User, usernames, teams []string, userIDs, teamIDs []int64) ([]int64, []int64, bool) {
	var err error
	if usernames != nil {
		tokenIDs := user_model.TokenIDsOnly(userIDs)
		if userIDs, err = user_model.GetUserIDsByNames(ctx, usernames, false); err != nil {
			if user_model.IsErrUserNotExist(err) {
				ctx.Error(http.StatusUnprocessableEntity, "User does not exist", err)
			} else {
				ctx.Error(http.StatusInternalServerError, "GetUserIDsByNames", err)
			}
			return nil, nil, false
		}
		userIDs = append(userIDs, tokenIDs...)
	}
	if teams != nil && owner.IsOrganization() {
		if teamIDs, err = organization.GetTeamIDsByNames(ctx, owner.ID, teams, false); err != nil {
			if organization.IsErrTeamNotExist(err) {
				ctx.Error(http.StatusUnprocessableEntity, "Team does not exist", err)
			} else {
				ctx.Error(http.StatusInternalServerError, "GetTeamIDsByNames", err)
			}
			return nil, nil, false
		}
	}
	return userIDs, teamIDs, true
}

// approvalRulesFromAPI resolves the names of the approval rules, teams in owner. On error it writes the response and returns false.
func approvalRulesFromAPI(ctx *context.APIContext, owner *user_model.User, rules []*api.ApprovalRule) ([]*git_model.ApprovalRule, bool) {
	resolved, err := pull_service.ApprovalRulesFromAPI(ctx, owner, rules)
	switch {
	case user_model.IsErrUserNotExist(err):
		ctx.Error(http.StatusUnprocessableEntity, "User does not exist", err)
	case organization.IsErrTeamNotExist(err), errors.Is(err, util.ErrInvalidArgument):
		ctx.Error(http.StatusUnprocessableEntity, "Invalid approval rule", err)
	case err != nil:
		ctx.Error(http.StatusInternalServerError, "ApprovalRulesFromAPI", err)
	}
	return resolved, err == nil
}
