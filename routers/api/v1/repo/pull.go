// Copyright 2016 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"cmp"
	stdCtx "context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"forgejo.org/models"
	activities_model "forgejo.org/models/activities"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	access_model "forgejo.org/models/perm/access"
	pull_model "forgejo.org/models/pull"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/git"
	"forgejo.org/modules/gitrepo"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/routers/api/v1/utils"
	asymkey_service "forgejo.org/services/asymkey"
	"forgejo.org/services/automerge"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	"forgejo.org/services/forms"
	"forgejo.org/services/gitdiff"
	issue_service "forgejo.org/services/issue"
	"forgejo.org/services/mergeforward"
	"forgejo.org/services/mergequeue"
	notify_service "forgejo.org/services/notify"
	pull_service "forgejo.org/services/pull"
	repo_service "forgejo.org/services/repository"
	files_service "forgejo.org/services/repository/files"
)

// ListPullRequests returns a list of all PRs
func ListPullRequests(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/pulls repository repoListPullRequests
	// ---
	// summary: List a repo's pull requests. If a pull request is selected but fails to be retrieved for any reason, it will be a null value in the list of results.
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: Owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: Name of the repo
	//   type: string
	//   required: true
	// - name: state
	//   in: query
	//   description: State of pull request
	//   type: string
	//   enum: [open, closed, all]
	//   default: open
	// - name: sort
	//   in: query
	//   description: Type of sort
	//   type: string
	//   enum: [oldest, recentupdate, recentclose, leastupdate, mostcomment, leastcomment, priority]
	// - name: milestone
	//   in: query
	//   description: ID of the milestone
	//   type: integer
	//   format: int64
	// - name: labels
	//   in: query
	//   description: Label IDs
	//   type: array
	//   collectionFormat: multi
	//   items:
	//     type: integer
	//     format: int64
	// - name: poster
	//   in: query
	//   description: Filter by pull request author
	//   type: string
	// - name: base
	//   in: query
	//   description: Filter by base branch name
	//   type: string
	// - name: head
	//   in: query
	//   description: Filter by head branch name
	//   type: string
	// - name: page
	//   in: query
	//   description: Page number of results to return (1-based)
	//   type: integer
	//   minimum: 1
	//   default: 1
	// - name: limit
	//   in: query
	//   description: Page size of results
	//   type: integer
	//   minimum: 0
	// responses:
	//   "200":
	//     "$ref": "#/responses/PullRequestList"
	//   "400":
	//     "$ref": "#/responses/error"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "500":
	//     "$ref": "#/responses/error"

	labelIDs, err := base.StringsToInt64s(ctx.FormStrings("labels"))
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "PullRequests", err)
		return
	}
	var posterID int64
	if posterStr := ctx.FormString("poster"); posterStr != "" {
		poster, err := user_model.GetUserByName(ctx, posterStr)
		if err != nil {
			if user_model.IsErrUserNotExist(err) {
				ctx.Error(http.StatusBadRequest, "Poster not found", err)
			} else {
				ctx.Error(http.StatusInternalServerError, "GetUserByName", err)
			}
			return
		}
		posterID = poster.ID
	}
	listOptions := utils.GetListOptions(ctx)
	prs, maxResults, err := issues_model.PullRequests(ctx, ctx.Repo().Repository.ID, &issues_model.PullRequestsOptions{
		ListOptions: listOptions,
		State:       ctx.FormTrim("state"),
		SortType:    ctx.FormTrim("sort"),
		Labels:      labelIDs,
		MilestoneID: ctx.FormInt64("milestone"),
		PosterID:    posterID,
		BaseBranch:  ctx.FormTrim("base"),
		HeadBranch:  ctx.FormTrim("head"),
	})
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "PullRequests", err)
		return
	}

	apiPrs := make([]*api.PullRequest, len(prs))
	// NOTE: load repository first, so that issue.Repo will be filled with pr.BaseRepo
	if err := prs.LoadRepositories(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadRepositories", err)
		return
	}
	issueList, err := prs.LoadIssues(ctx)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadIssues", err)
		return
	}

	if err := issueList.LoadLabels(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadLabels", err)
		return
	}
	if err := issueList.LoadPosters(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadPoster", err)
		return
	}
	if err := issueList.LoadAttachments(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadAttachments", err)
		return
	}
	if err := issueList.LoadMilestones(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadMilestones", err)
		return
	}
	if err := issueList.LoadAssignees(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadAssignees", err)
		return
	}

	for i := range prs {
		apiPrs[i] = convert.ToAPIPullRequest(ctx, prs[i], ctx.Doer())
	}

	ctx.SetLinkHeader(int(maxResults), listOptions.PageSize)
	ctx.SetTotalCountHeader(maxResults)
	ctx.JSON(http.StatusOK, &apiPrs)
}

// GetPullRequest returns a single PR based on index
func GetPullRequest(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/pulls/{index} repository repoGetPullRequest
	// ---
	// summary: Get a pull request
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
	//   description: index of the pull request to get
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/PullRequest"
	//   "404":
	//     "$ref": "#/responses/notFound"

	pr, err := issues_model.GetPullRequestByIndex(ctx, ctx.Repo().Repository.ID, ctx.ParamsInt64(":index"))
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetPullRequestByIndex", err)
		}
		return
	}

	if err = pr.LoadBaseRepo(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadBaseRepo", err)
		return
	}
	if err = pr.LoadHeadRepo(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadHeadRepo", err)
		return
	}
	apiPR := convert.ToAPIPullRequest(ctx, pr, ctx.Doer())
	pbs, err := git_model.GetMatchedProtectedBranchRules(ctx, pr.BaseRepoID, pr.BaseBranch)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetMatchedProtectedBranchRules", err)
		return
	}
	if slices.ContainsFunc(pbs, func(pb *git_model.ProtectedBranch) bool {
		return issues_model.MergeBlockedByUnresolvedConversations(ctx, pb, pr)
	}) {
		apiPR.MergeableReasons = append(apiPR.MergeableReasons, "unresolved_conversations")
	}
	if slices.ContainsFunc(pbs, func(pb *git_model.ProtectedBranch) bool {
		return issues_model.MergeBlockedByIncompleteTasks(ctx, pb, pr)
	}) {
		apiPR.MergeableReasons = append(apiPR.MergeableReasons, "incomplete_tasks")
	}
	ctx.JSON(http.StatusOK, apiPR)
}

// GetPullRequest returns a single PR based on index
func GetPullRequestByBaseHead(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/pulls/{base}/{head} repository repoGetPullRequestByBaseHead
	// ---
	// summary: Get a pull request by base and head
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
	// - name: base
	//   in: path
	//   description: base of the pull request to get
	//   type: string
	//   required: true
	// - name: head
	//   in: path
	//   description: head of the pull request to get
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/PullRequest"
	//   "404":
	//     "$ref": "#/responses/notFound"

	var headRepoID int64
	var headBranch string
	head := ctx.Params("*")
	if strings.Contains(head, ":") {
		split := strings.SplitN(head, ":", 2)
		headBranch = split[1]
		var owner, group, name string
		if strings.Contains(split[0], "/") {
			split = strings.Split(split[0], "/")
			if len(split) > 3 {
				ctx.NotFound()
				return
			}
			owner, name = split[0], split[len(split)-1]
			if len(split) == 3 {
				group = split[1]
			}
		} else {
			owner = split[0]
			name = ctx.Repo().Repository.Name
			if strings.EqualFold(owner, ctx.Repo().Repository.OwnerName) { // forks live at the root of their owner
				group = ctx.Repo().Repository.GroupName
			}
		}
		repo, err := repo_model.GetRepositoryByRef(ctx, owner, group, name)
		if err != nil {
			if repo_model.IsErrRepoNotExist(err) {
				ctx.NotFound()
			} else {
				ctx.Error(http.StatusInternalServerError, "GetRepositoryByRef", err)
			}
			return
		}
		headRepoID = repo.ID
	} else {
		headRepoID = ctx.Repo().Repository.ID
		headBranch = head
	}

	pr, err := issues_model.GetPullRequestByBaseHeadInfo(ctx, ctx.Repo().Repository.ID, headRepoID, ctx.Params(":base"), headBranch)
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetPullRequestByBaseHeadInfo", err)
		}
		return
	}

	if err = pr.LoadBaseRepo(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadBaseRepo", err)
		return
	}
	if err = pr.LoadHeadRepo(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadHeadRepo", err)
		return
	}
	ctx.JSON(http.StatusOK, convert.ToAPIPullRequest(ctx, pr, ctx.Doer()))
}

// DownloadPullDiffOrPatch render a pull's raw diff or patch
func DownloadPullDiffOrPatch(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/pulls/{index}.{diffType} repository repoDownloadPullDiffOrPatch
	// ---
	// summary: Get a pull request diff or patch
	// produces:
	// - text/plain
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
	//   description: index of the pull request to get
	//   type: integer
	//   format: int64
	//   required: true
	// - name: diffType
	//   in: path
	//   description: whether the output is diff or patch
	//   type: string
	//   enum: [diff, patch]
	//   required: true
	// - name: binary
	//   in: query
	//   description: whether to include binary file changes. if true, the diff is applicable with `git apply`
	//   type: boolean
	// responses:
	//   "200":
	//     "$ref": "#/responses/string"
	//   "404":
	//     "$ref": "#/responses/notFound"
	pr, err := issues_model.GetPullRequestByIndex(ctx, ctx.Repo().Repository.ID, ctx.ParamsInt64(":index"))
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.InternalServerError(err)
		}
		return
	}
	var patch bool
	if ctx.Params(":diffType") == "diff" {
		patch = false
	} else {
		patch = true
	}

	binary := ctx.FormBool("binary")

	if err := pull_service.DownloadDiffOrPatch(ctx, pr, ctx, patch, binary); err != nil {
		ctx.InternalServerError(err)
		return
	}
}

// CreatePullRequest does what it says
func CreatePullRequest(ctx *context.APIContext) {
	// swagger:operation POST /repos/{owner}/{repo}/pulls repository repoCreatePullRequest
	// ---
	// summary: Create a pull request
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
	//     "$ref": "#/definitions/CreatePullRequestOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/PullRequest"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     "$ref": "#/responses/error"
	//   "413":
	//     "$ref": "#/responses/quotaExceeded"
	//   "422":
	//     "$ref": "#/responses/validationError"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"

	form := *web.GetForm(ctx).(*api.CreatePullRequestOption)
	if form.Base == "" {
		// the base repository's model decides, from the name of the head branch
		target, err := branchworkflow.ResolveTarget(ctx, ctx.Repo().Repository, form.Head[strings.LastIndex(form.Head, ":")+1:])
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "ResolveTarget", err)
			return
		}
		form.Base = target.Branch
		if form.Head == form.Base {
			ctx.Error(http.StatusUnprocessableEntity, "BaseHeadSame", fmt.Sprintf("The branching model targets %s, the head branch itself: name a base", form.Base))
			return
		}
	}
	if form.Head == form.Base {
		ctx.Error(http.StatusUnprocessableEntity, "BaseHeadSame",
			"Invalid PullRequest: There are no changes between the head and the base")
		return
	}

	var (
		repo        = ctx.Repo().Repository
		labelIDs    []int64
		milestoneID int64
	)

	// Get repo/branch information
	headRepo, headGitRepo, _, baseBranch, headBranch := parseCompareInfo(ctx, form)
	if ctx.Written() {
		return
	}
	defer headGitRepo.Close()

	// the head of a pull request from another repository is copied into the base repository
	if baseRepo := ctx.Repo().Repository; headRepo.ID != baseRepo.ID && !ctx.CheckPersonalRepoLimit(baseRepo.OwnerID, baseRepo.OwnerName) {
		return
	}

	// Check if another PR exists with the same targets
	existingPr, err := issues_model.GetUnmergedPullRequest(ctx, headRepo.ID, ctx.Repo().Repository.ID, headBranch, baseBranch, issues_model.PullRequestFlowGithub)
	if err != nil {
		if !issues_model.IsErrPullRequestNotExist(err) {
			ctx.Error(http.StatusInternalServerError, "GetUnmergedPullRequest", err)
			return
		}
	} else {
		err = issues_model.ErrPullRequestAlreadyExists{
			ID:         existingPr.ID,
			IssueID:    existingPr.Index,
			HeadRepoID: existingPr.HeadRepoID,
			BaseRepoID: existingPr.BaseRepoID,
			HeadBranch: existingPr.HeadBranch,
			BaseBranch: existingPr.BaseBranch,
		}
		ctx.Error(http.StatusConflict, "GetUnmergedPullRequest", err)
		return
	}

	if len(form.Labels) > 0 {
		labels, err := issues_model.GetLabelsInRepoByIDs(ctx, ctx.Repo().Repository.ID, form.Labels)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "GetLabelsInRepoByIDs", err)
			return
		}

		labelIDs = make([]int64, 0, len(labels))
		for _, label := range labels {
			labelIDs = append(labelIDs, label.ID)
		}

		if ctx.Repo().Owner.IsOrganization() {
			orgLabels, err := issues_model.GetLabelsInOrgByIDs(ctx, ctx.Repo().Owner.ID, form.Labels)
			if err != nil {
				ctx.Error(http.StatusInternalServerError, "GetLabelsInOrgByIDs", err)
				return
			}

			orgLabelIDs := make([]int64, 0, len(orgLabels))
			for _, orgLabel := range orgLabels {
				orgLabelIDs = append(orgLabelIDs, orgLabel.ID)
			}
			labelIDs = append(labelIDs, orgLabelIDs...)
		}
	}

	if form.Milestone > 0 {
		milestone, err := issues_model.GetMilestoneByRepoID(ctx, ctx.Repo().Repository.ID, form.Milestone)
		if err != nil {
			if issues_model.IsErrMilestoneNotExist(err) {
				ctx.NotFound()
			} else {
				ctx.Error(http.StatusInternalServerError, "GetMilestoneByRepoID", err)
			}
			return
		}

		milestoneID = milestone.ID
	}

	var deadlineUnix timeutil.TimeStamp
	if form.Deadline != nil {
		deadlineUnix = timeutil.TimeStamp(form.Deadline.Unix())
	}

	prIssue := &issues_model.Issue{
		RepoID:       repo.ID,
		Title:        form.Title,
		PosterID:     ctx.Doer().ID,
		Poster:       ctx.Doer(),
		MilestoneID:  milestoneID,
		IsPull:       true,
		Content:      form.Body,
		DeadlineUnix: deadlineUnix,
	}
	pr := &issues_model.PullRequest{
		HeadRepoID: headRepo.ID,
		BaseRepoID: repo.ID,
		HeadBranch: headBranch,
		BaseBranch: baseBranch,
		HeadRepo:   headRepo,
		BaseRepo:   repo,
		Type:       issues_model.PullRequestGitea,
	}

	// Get all assignee IDs
	assigneeIDs, err := issues_model.MakeIDsFromAPIAssigneesToAdd(ctx, form.Assignee, form.Assignees)
	if err != nil {
		if user_model.IsErrUserNotExist(err) {
			ctx.Error(http.StatusUnprocessableEntity, "", fmt.Sprintf("Assignee does not exist: [name: %s]", err))
		} else {
			ctx.Error(http.StatusInternalServerError, "AddAssigneeByName", err)
		}
		return
	}
	// Check if the passed assignees is assignable
	for _, aID := range assigneeIDs {
		assignee, err := user_model.GetUserByID(ctx, aID)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "GetUserByID", err)
			return
		}

		valid, err := access_model.CanBeAssigned(ctx, assignee, repo, true)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "canBeAssigned", err)
			return
		}
		if !valid {
			ctx.Error(http.StatusUnprocessableEntity, "canBeAssigned", repo_model.ErrUserDoesNotHaveAccessToRepo{UserID: aID, RepoName: repo.Name})
			return
		}
	}

	if err := pull_service.NewPullRequest(ctx, repo, prIssue, labelIDs, []string{}, pr, assigneeIDs); err != nil {
		if errors.Is(err, user_model.ErrBlockedByUser) {
			ctx.Error(http.StatusForbidden, "BlockedByUser", err)
			return
		} else if repo_model.IsErrUserDoesNotHaveAccessToRepo(err) {
			ctx.Error(http.StatusBadRequest, "UserDoesNotHaveAccessToRepo", err)
			return
		} else if message, ok := issue_service.PRTitleRuleMessage(ctx.Locale, err); ok {
			ctx.Error(http.StatusUnprocessableEntity, "PRTitleRule", message)
			return
		} else if git_model.IsErrBranchesEqual(err) {
			ctx.Error(http.StatusUnprocessableEntity, "BaseHeadSame", "Invalid PullRequest: There are no changes between the head and the base")
			return
		}
		ctx.Error(http.StatusInternalServerError, "NewPullRequest", err)
		return
	}

	log.Trace("Pull request created: %d/%d", repo.ID, prIssue.ID)
	ctx.JSON(http.StatusCreated, convert.ToAPIPullRequest(ctx, pr, ctx.Doer()))
}

// EditPullRequest does what it says
func EditPullRequest(ctx *context.APIContext) {
	// swagger:operation PATCH /repos/{owner}/{repo}/pulls/{index} repository repoEditPullRequest
	// ---
	// summary: Update a pull request. If using deadline only the date will be taken into account, and time of day ignored.
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
	//   description: index of the pull request to edit
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/EditPullRequestOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/PullRequest"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     "$ref": "#/responses/error"
	//   "412":
	//     "$ref": "#/responses/error"
	//   "422":
	//     "$ref": "#/responses/validationError"

	form := web.GetForm(ctx).(*api.EditPullRequestOption)
	pr, err := issues_model.GetPullRequestByIndex(ctx, ctx.Repo().Repository.ID, ctx.ParamsInt64(":index"))
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetPullRequestByIndex", err)
		}
		return
	}

	err = pr.LoadIssue(ctx)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadIssue", err)
		return
	}
	issue := pr.Issue
	issue.Repo = ctx.Repo().Repository

	if err := issue.LoadAttributes(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadAttributes", err)
		return
	}

	if !issue.IsPoster(ctx.Doer().ID) && !ctx.Repo().CanWrite(unit.TypePullRequests) {
		ctx.Status(http.StatusForbidden)
		return
	}

	// check the new title against the new base branch before anything is written, so a refusal changes nothing
	if !pr.HasMerged && len(form.Base) != 0 && form.Base != pr.BaseBranch {
		err = issue_service.CheckPRTitleRule(ctx, ctx.Repo().Repository, form.Base, cmp.Or(form.Title, issue.Title), false)
		if message, ok := issue_service.PRTitleRuleMessage(ctx.Locale, err); ok {
			ctx.Error(http.StatusUnprocessableEntity, "PRTitleRule", message)
			return
		} else if err != nil {
			ctx.Error(http.StatusInternalServerError, "CheckPRTitleRule", err)
			return
		}
	}

	if len(form.Title) > 0 {
		err = issue_service.ChangeTitle(ctx, issue, ctx.Doer(), form.Title)
		if message, ok := issue_service.PRTitleRuleMessage(ctx.Locale, err); ok {
			ctx.Error(http.StatusUnprocessableEntity, "PRTitleRule", message)
			return
		} else if err != nil {
			ctx.Error(http.StatusInternalServerError, "ChangeTitle", err)
			return
		}
	}
	if form.Body != nil {
		err = issue_service.ChangeContent(ctx, issue, ctx.Doer(), *form.Body, issue.ContentVersion)
		if err != nil {
			if errors.Is(err, issues_model.ErrIssueAlreadyChanged) {
				ctx.Error(http.StatusBadRequest, "ChangeContent", err)
				return
			}

			ctx.Error(http.StatusInternalServerError, "ChangeContent", err)
			return
		}
	}

	// Update or remove deadline if set
	if form.Deadline != nil || form.RemoveDeadline != nil {
		var deadlineUnix timeutil.TimeStamp
		if (form.RemoveDeadline == nil || !*form.RemoveDeadline) && !form.Deadline.IsZero() {
			deadline := time.Date(form.Deadline.Year(), form.Deadline.Month(), form.Deadline.Day(),
				23, 59, 59, 0, form.Deadline.Location())
			deadlineUnix = timeutil.TimeStamp(deadline.Unix())
		}

		if err := issues_model.UpdateIssueDeadline(ctx, issue, deadlineUnix, ctx.Doer()); err != nil {
			ctx.Error(http.StatusInternalServerError, "UpdateIssueDeadline", err)
			return
		}
		issue.DeadlineUnix = deadlineUnix
	}

	// Add/delete assignees

	// Deleting is done the GitHub way (quote from their api documentation):
	// https://developer.github.com/v3/issues/#edit-an-issue
	// "assignees" (array): Logins for Users to assign to this issue.
	// Pass one or more user logins to replace the set of assignees on this Issue.
	// Send an empty array ([]) to clear all assignees from the Issue.

	if ctx.Repo().CanWrite(unit.TypePullRequests) && (form.Assignees != nil || len(form.Assignee) > 0) {
		err = issue_service.UpdateAssignees(ctx, issue, form.Assignee, form.Assignees, ctx.Doer())
		if err != nil {
			if user_model.IsErrUserNotExist(err) {
				ctx.Error(http.StatusUnprocessableEntity, "", fmt.Sprintf("Assignee does not exist: [name: %s]", err))
			} else {
				ctx.Error(http.StatusInternalServerError, "UpdateAssignees", err)
			}
			return
		}
	}

	if ctx.Repo().CanWrite(unit.TypePullRequests) && form.Milestone != 0 &&
		issue.MilestoneID != form.Milestone {
		oldMilestoneID := issue.MilestoneID
		issue.MilestoneID = form.Milestone
		if err = issue_service.ChangeMilestoneAssign(ctx, issue, ctx.Doer(), oldMilestoneID); err != nil {
			ctx.Error(http.StatusInternalServerError, "ChangeMilestoneAssign", err)
			return
		}
	}

	if ctx.Repo().CanWrite(unit.TypePullRequests) && form.Labels != nil {
		labels, err := issues_model.GetLabelsInRepoByIDs(ctx, ctx.Repo().Repository.ID, form.Labels)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "GetLabelsInRepoByIDsError", err)
			return
		}

		if ctx.Repo().Owner.IsOrganization() {
			orgLabels, err := issues_model.GetLabelsInOrgByIDs(ctx, ctx.Repo().Owner.ID, form.Labels)
			if err != nil {
				ctx.Error(http.StatusInternalServerError, "GetLabelsInOrgByIDs", err)
				return
			}

			labels = append(labels, orgLabels...)
		}

		if err = issues_model.ReplaceIssueLabels(ctx, issue, labels, ctx.Doer()); err != nil {
			ctx.Error(http.StatusInternalServerError, "ReplaceLabelsError", err)
			return
		}
	}

	if form.State != nil {
		if pr.HasMerged {
			ctx.Error(http.StatusPreconditionFailed, "MergedPRState", "cannot change state of this pull request, it was already merged")
			return
		}
		isClosed := api.StateClosed == api.StateType(*form.State)
		if issue.IsClosed != isClosed {
			if err := issue_service.ChangeStatus(ctx, issue, ctx.Doer(), &issues_model.PRNotificationInfo{MergedCommitID: ""}, isClosed); err != nil {
				if issues_model.IsErrDependenciesLeft(err) {
					ctx.Error(http.StatusPreconditionFailed, "DependenciesLeft", "cannot close this pull request because it still has open dependencies")
					return
				}
				ctx.Error(http.StatusInternalServerError, "ChangeStatus", err)
				return
			}
		}
	}

	// change pull target branch
	if !pr.HasMerged && len(form.Base) != 0 && form.Base != pr.BaseBranch {
		if !ctx.Repo().GitRepo.IsBranchExist(form.Base) {
			ctx.Error(http.StatusNotFound, "NewBaseBranchNotExist", fmt.Errorf("new base '%s' not exist", form.Base))
			return
		}
		if err := pull_service.ChangeTargetBranch(ctx, pr, ctx.Doer(), form.Base); err != nil {
			if issues_model.IsErrPullRequestAlreadyExists(err) {
				ctx.Error(http.StatusConflict, "IsErrPullRequestAlreadyExists", err)
				return
			} else if issues_model.IsErrIssueIsClosed(err) {
				ctx.Error(http.StatusUnprocessableEntity, "IsErrIssueIsClosed", err)
				return
			} else if models.IsErrPullRequestHasMerged(err) {
				ctx.Error(http.StatusConflict, "IsErrPullRequestHasMerged", err)
				return
			} else if message, ok := issue_service.PRTitleRuleMessage(ctx.Locale, err); ok {
				ctx.Error(http.StatusUnprocessableEntity, "PRTitleRule", message)
				return
			}
			ctx.InternalServerError(err)
			return
		}
		notify_service.PullRequestChangeTargetBranch(ctx, ctx.Doer(), pr, form.Base)
	}

	// update allow edits
	if form.AllowMaintainerEdit != nil {
		if err := pull_service.SetAllowEdits(ctx, ctx.Doer(), pr, *form.AllowMaintainerEdit); err != nil {
			if errors.Is(err, pull_service.ErrUserHasNoPermissionForAction) {
				ctx.Error(http.StatusForbidden, "SetAllowEdits", fmt.Sprintf("SetAllowEdits: %s", err))
				return
			}
			ctx.ServerError("SetAllowEdits", err)
			return
		}
	}

	// Refetch from database
	pr, err = issues_model.GetPullRequestByIndex(ctx, ctx.Repo().Repository.ID, pr.Index)
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetPullRequestByIndex", err)
		}
		return
	}

	// TODO this should be 200, not 201
	ctx.JSON(http.StatusCreated, convert.ToAPIPullRequest(ctx, pr, ctx.Doer()))
}

// IsPullRequestMerged checks if a PR exists given an index
func IsPullRequestMerged(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/pulls/{index}/merge repository repoPullRequestIsMerged
	// ---
	// summary: Check if a pull request has been merged
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
	//     description: pull request has been merged
	//   "404":
	//     description: pull request has not been merged

	pr, err := issues_model.GetPullRequestByIndex(ctx, ctx.Repo().Repository.ID, ctx.ParamsInt64(":index"))
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetPullRequestByIndex", err)
		}
		return
	}

	if pr.HasMerged {
		ctx.Status(http.StatusNoContent)
	}
	ctx.NotFound()
}

// mergeStyleError says why style is refused: the branch rules limit it (naming them), or the repository's setting
func mergeStyleError(err error, style repo_model.MergeStyle) error {
	if e, ok := errors.AsType[models.ErrInvalidMergeStyle](err); ok && e.Rules != "" {
		return fmt.Errorf("%s is not an allowed merge style: the branch rules allow only what all of them allow: %s", style, e.Rules)
	}
	return fmt.Errorf("%s is not an allowed merge style for this repository", style)
}

// MergePullRequest merges a PR given an index
func MergePullRequest(ctx *context.APIContext) {
	// swagger:operation POST /repos/{owner}/{repo}/pulls/{index}/merge repository repoMergePullRequest
	// ---
	// summary: Merge a pull request
	// description: When the head branch is kept although deleting it was asked or enforced, the response header X-Branch-Kept holds the reason (default, development, production, release, protected, base, open_pr, merge_queue, new_commits, permission or failed); a kept branch never fails a merge that enforced the deletion, and answers 403 when the request asked for it.
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
	//   description: index of the pull request to merge
	//   type: integer
	//   format: int64
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     $ref: "#/definitions/MergePullRequestOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "405":
	//     "$ref": "#/responses/empty"
	//   "409":
	//     "$ref": "#/responses/error"
	//   "413":
	//     "$ref": "#/responses/quotaExceeded"
	//   "422":
	//     "$ref": "#/responses/validationError"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"

	form := web.GetForm(ctx).(*forms.MergePullRequestForm)

	pr, err := issues_model.GetPullRequestByIndex(ctx, ctx.Repo().Repository.ID, ctx.ParamsInt64(":index"))
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound("GetPullRequestByIndex", err)
		} else {
			ctx.Error(http.StatusInternalServerError, "GetPullRequestByIndex", err)
		}
		return
	}

	if err := pr.LoadHeadRepo(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadHeadRepo", err)
		return
	}

	if err := pr.LoadIssue(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadIssue", err)
		return
	}
	pr.Issue.Repo = ctx.Repo().Repository

	if ctx.IsSigned() {
		// Update issue-user.
		if err = activities_model.SetIssueReadBy(ctx, pr.Issue.ID, ctx.Doer().ID); err != nil {
			ctx.Error(http.StatusInternalServerError, "ReadBy", err)
			return
		}
	}

	mergeStyle := repo_model.MergeStyle(form.Do)
	manuallyMerged := mergeStyle == repo_model.MergeStyleManuallyMerged

	mergeCheckType := pull_service.MergeCheckTypeGeneral
	if form.MergeWhenChecksSucceed {
		mergeCheckType = pull_service.MergeCheckTypeAuto
	}
	if manuallyMerged {
		mergeCheckType = pull_service.MergeCheckTypeManually
	}

	scheduledAfter, giveUpAfter, err := form.ScheduleTimeStamps()
	if err != nil {
		ctx.Error(http.StatusUnprocessableEntity, "ScheduledAfter", err)
		return
	}

	// a branch with a merge queue merges only through it; a merge when checks succeed joins it when they do
	queueRule, err := mergequeue.Rule(ctx, pr)
	if err != nil {
		ctx.InternalServerError(err)
		return
	}
	if queueRule != nil && (!form.MergeWhenChecksSucceed || manuallyMerged) {
		ctx.Error(http.StatusMethodNotAllowed, "Merge", "the base branch requires a merge queue: add the pull request to it with POST .../pulls/{index}/merge-queue")
		return
	}

	// start with merging by checking
	if err := pull_service.CheckPullMergeable(ctx, ctx.Doer(), &ctx.Repo().Permission, pr, mergeCheckType, form.ForceMerge, mergeStyle); err != nil {
		if errors.Is(err, pull_service.ErrIsClosed) {
			ctx.NotFound()
		} else if errors.Is(err, pull_service.ErrUserNotAllowedToMerge) {
			ctx.Error(http.StatusMethodNotAllowed, "Merge", "User not allowed to merge PR")
		} else if errors.Is(err, pull_service.ErrHasMerged) {
			ctx.Error(http.StatusMethodNotAllowed, "PR already merged", "")
		} else if errors.Is(err, pull_service.ErrIsWorkInProgress) {
			ctx.Error(http.StatusMethodNotAllowed, "PR is a work in progress", "Work in progress PRs cannot be merged")
		} else if models.IsErrInvalidMergeStyle(err) {
			ctx.Error(http.StatusUnprocessableEntity, "Invalid merge style", mergeStyleError(err, repo_model.MergeStyle(form.Do)))
		} else if message, ok := issue_service.PRTitleRuleMessage(ctx.Locale, err); ok {
			ctx.Error(http.StatusMethodNotAllowed, "PRTitleRule", message)
		} else if errors.Is(err, pull_service.ErrNotMergeableState) {
			ctx.Error(http.StatusMethodNotAllowed, "PR not in mergeable state", "Please try again later")
		} else if models.IsErrDisallowedToMerge(err) {
			ctx.Error(http.StatusMethodNotAllowed, "PR is not ready to be merged", err)
		} else if asymkey_service.IsErrWontSign(err) {
			ctx.Error(http.StatusMethodNotAllowed, fmt.Sprintf("Protected branch %s requires signed commits but this merge would not be signed", pr.BaseBranch), err)
		} else {
			ctx.InternalServerError(err)
		}
		return
	}

	// handle manually-merged mark
	if manuallyMerged {
		if err := pull_service.MergedManually(ctx, pr, ctx.Doer(), ctx.Repo().GitRepo, form.MergeCommitID); err != nil {
			if models.IsErrInvalidMergeStyle(err) {
				ctx.Error(http.StatusUnprocessableEntity, "Invalid merge style", mergeStyleError(err, repo_model.MergeStyle(form.Do)))
				return
			}
			if strings.Contains(err.Error(), "Wrong commit ID") {
				ctx.JSON(http.StatusConflict, err)
				return
			}
			ctx.Error(http.StatusInternalServerError, "Manually-Merged", err)
			return
		}
		ctx.Status(http.StatusOK)
		return
	}

	if len(form.Do) == 0 {
		form.Do = string(repo_model.MergeStyleMerge)
	}

	var mergeCtx stdCtx.Context = ctx
	if form.SkipsMergeForward() {
		allowed, err := mergeforward.MaySkip(ctx, ctx.Doer(), ctx.Repo().Permission, ctx.Repo().Repository, pr.BaseBranch)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "MaySkip", err)
			return
		} else if !allowed {
			ctx.Error(http.StatusForbidden, "MergeForward", "not allowed to merge without merging forward")
			return
		}
		mergeCtx = pull_service.WithoutMergeForward(ctx)
	}

	message := strings.TrimSpace(form.MergeTitleField)
	if len(message) == 0 {
		message, _, err = pull_service.GetDefaultMergeMessage(ctx, ctx.Repo().GitRepo, pr, repo_model.MergeStyle(form.Do))
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "GetDefaultMergeMessage", err)
			return
		}
	}

	form.MergeMessageField = strings.TrimSpace(form.MergeMessageField)
	if len(form.MergeMessageField) > 0 {
		message += "\n\n" + form.MergeMessageField
	}

	if form.MergeWhenChecksSucceed {
		scheduled, err := automerge.ScheduleAutoMerge(mergeCtx, ctx.Doer(), pr, repo_model.MergeStyle(form.Do), message, form.DeleteBranchAfterMerge, scheduledAfter, giveUpAfter, form.HeadCommitID)
		if err != nil {
			if pull_model.IsErrAlreadyScheduledToAutoMerge(err) || models.IsErrSHADoesNotMatch(err) {
				ctx.Error(http.StatusConflict, "ScheduleAutoMerge", err)
				return
			}
			ctx.Error(http.StatusInternalServerError, "ScheduleAutoMerge", err)
			return
		} else if scheduled {
			// nothing more to do ...
			ctx.Status(http.StatusCreated)
			return
		}
	}
	if queueRule != nil {
		addToMergeQueue(ctx, form, pr)
		return
	}

	if err := pull_service.Merge(mergeCtx, pr, ctx.Doer(), ctx.Repo().GitRepo, repo_model.MergeStyle(form.Do), form.HeadCommitID, message, false); err != nil {
		if models.IsErrInvalidMergeStyle(err) {
			ctx.Error(http.StatusUnprocessableEntity, "Invalid merge style", mergeStyleError(err, repo_model.MergeStyle(form.Do)))
		} else if models.IsErrMergeConflicts(err) {
			conflictError := err.(models.ErrMergeConflicts)
			ctx.JSON(http.StatusConflict, conflictError)
		} else if models.IsErrRebaseConflicts(err) {
			conflictError := err.(models.ErrRebaseConflicts)
			ctx.JSON(http.StatusConflict, conflictError)
		} else if models.IsErrMergeUnrelatedHistories(err) {
			conflictError := err.(models.ErrMergeUnrelatedHistories)
			ctx.JSON(http.StatusConflict, conflictError)
		} else if models.IsErrPullRequestHasMerged(err) {
			conflictError := err.(models.ErrPullRequestHasMerged)
			ctx.JSON(http.StatusConflict, conflictError)
		} else if git.IsErrPushOutOfDate(err) {
			ctx.Error(http.StatusConflict, "Merge", "merge push out of date")
		} else if models.IsErrSHADoesNotMatch(err) {
			ctx.Error(http.StatusConflict, "Merge", "the head of the pull request was updated or is still being updated: try again in a moment, or push again if it doesn't settle")
		} else if git.IsErrPushRejected(err) {
			errPushRej := err.(*git.ErrPushRejected)
			if len(errPushRej.Message) == 0 {
				ctx.Error(http.StatusConflict, "Merge", "PushRejected without remote error message")
			} else {
				ctx.Error(http.StatusConflict, "Merge", "PushRejected with remote message: "+errPushRej.Message)
			}
		} else {
			ctx.Error(http.StatusInternalServerError, "Merge", err)
		}
		return
	}
	log.Trace("Pull request merged: %d", pr.ID)

	alwaysDelete, err := branchworkflow.IsAlways(ctx, ctx.Repo().Repository)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "IsAlways", err)
		return
	}
	if form.DeleteBranchAfterMerge || alwaysDelete {
		var headRepo *git.Repository
		if ctx.Repo() != nil && ctx.Repo().Repository != nil && ctx.Repo().Repository.ID == pr.HeadRepoID && ctx.Repo().GitRepo != nil {
			headRepo = ctx.Repo().GitRepo
		} else {
			headRepo, err = gitrepo.OpenRepository(ctx, pr.HeadRepo)
			if err != nil {
				ctx.ServerError(fmt.Sprintf("OpenRepository[%s]", pr.HeadRepo.FullName()), err)
				return
			}
			defer headRepo.Close()
		}

		if err := repo_service.DeleteBranchAfterMerge(ctx, ctx.Doer(), pr, headRepo); err != nil {
			if code, kept := repo_service.KeptCode(err); kept {
				ctx.Resp.Header().Set("X-Branch-Kept", code)
				if !form.DeleteBranchAfterMerge {
					// deletion was forced by the setting: a kept branch never fails the merge
					log.Info("Head branch of %-v kept after merge: %v", pr, err)
					ctx.Status(http.StatusOK)
					return
				}
			}
			switch {
			case errors.Is(err, repo_service.ErrBranchIsDefault):
				ctx.Error(http.StatusForbidden, "DefaultBranch", errors.New("the head branch is the default branch"))
			case errors.Is(err, git_model.ErrBranchIsProtected):
				ctx.Error(http.StatusForbidden, "IsProtectedBranch", errors.New("the head branch is protected"))
			case errors.Is(err, util.ErrPermissionDenied):
				ctx.Error(http.StatusForbidden, "HeadBranch", errors.New("insufficient permission to delete head branch"))
			case errors.Is(err, repo_service.ErrBranchInUse):
				ctx.Error(http.StatusForbidden, "HeadBranch", errors.New("the head branch is used by another open pull request"))
			case errors.Is(err, repo_service.ErrBranchHasNewCommits):
				ctx.Error(http.StatusForbidden, "HeadBranch", errors.New("the head branch has new commits"))
			case repo_service.IsBranchKept(err):
				code, _ := repo_service.KeptCode(err)
				ctx.Error(http.StatusForbidden, "HeadBranch", fmt.Errorf("the head branch was kept: %s", code))
			default:
				// the pull request is merged: a failed cleanup is not a server error
				log.Error("DeleteBranchAfterMerge %-v: %v", pr, err)
				ctx.Resp.Header().Set("X-Branch-Kept", "failed")
				ctx.Status(http.StatusOK)
			}
			return
		}
	}

	ctx.Status(http.StatusOK)
}

func parseCompareInfo(ctx *context.APIContext, form api.CreatePullRequestOption) (*repo_model.Repository, *git.Repository, *git.CompareInfo, string, string) {
	baseRepo := ctx.Repo().Repository

	// Get compared branches information
	// format: <base branch>...[<head repo>:]<head branch>
	// base<-head: master...head:feature
	// same repo: master...feature

	// TODO: Validate form first?

	baseBranch := form.Base

	var (
		headUser   *user_model.User
		headBranch string
		isSameRepo bool
		err        error
	)

	headInfos := strings.Split(form.Head, ":")
	if len(headInfos) == 1 {
		isSameRepo = true
		headUser = ctx.Repo().Owner
		headBranch = headInfos[0]
	} else if len(headInfos) == 2 {
		headUser, err = user_model.GetUserByName(ctx, headInfos[0])
		if err != nil {
			if user_model.IsErrUserNotExist(err) {
				ctx.NotFound(fmt.Errorf("the owner %s does not exist", headInfos[0]))
			} else {
				ctx.Error(http.StatusInternalServerError, "GetUserByName", err)
			}
			return nil, nil, nil, "", ""
		}
		headBranch = headInfos[1]
		// The head repository can also point to the same repo
		isSameRepo = ctx.Repo().Owner.ID == headUser.ID
	} else {
		ctx.NotFound(fmt.Errorf("the head part of {basehead} %s must contain zero or one colon (:) but contains %d", form.Head, len(headInfos)-1))
		return nil, nil, nil, "", ""
	}

	ctx.Repo().PullRequest.SameRepo = isSameRepo
	log.Trace("Repo path: %q, base branch: %q, head branch: %q", ctx.Repo().GitRepo.Path, baseBranch, headBranch)

	// Check if base branch is valid.
	baseIsCommit := ctx.Repo().GitRepo.IsCommitExist(baseBranch)
	baseIsBranch := ctx.Repo().GitRepo.IsBranchExist(baseBranch)
	baseIsTag := ctx.Repo().GitRepo.IsTagExist(baseBranch)
	if !baseIsCommit && !baseIsBranch && !baseIsTag {
		ctx.NotFound(fmt.Errorf("could not find '%s' to be a commit, branch or tag in the base repository %s/%s", baseBranch, baseRepo.Owner.Name, baseRepo.Name))
		return nil, nil, nil, "", ""
	}

	headRepo := repo_model.GetForkedRepo(ctx, headUser.ID, baseRepo.ID)
	if headRepo == nil && !isSameRepo {
		err := baseRepo.GetBaseRepo(ctx)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "GetBaseRepo", err)
			return nil, nil, nil, "", ""
		}

		if baseRepo.BaseRepo == nil || baseRepo.BaseRepo.OwnerID != headUser.ID {
			log.Trace("parseCompareInfo[%d]: does not have fork or in same repository", baseRepo.ID)
			ctx.NotFound(fmt.Errorf("%[1]s does not have a fork of %[2]s/%[3]s and %[2]s/%[3]s is not a fork of a repository from %[1]s", headUser.Name, baseRepo.Owner.Name, baseRepo.Name))
			return nil, nil, nil, "", ""
		}
		headRepo = baseRepo.BaseRepo
	}

	var headGitRepo *git.Repository
	if isSameRepo {
		headRepo = ctx.Repo().Repository
		headGitRepo = ctx.Repo().GitRepo
	} else {
		headGitRepo, err = gitrepo.OpenRepository(ctx, headRepo)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "OpenRepository", err)
			return nil, nil, nil, "", ""
		}
	}

	// user should have permission to read baseRepo's codes and pulls, NOT headRepo's
	permBase, err := access_model.GetUserRepoPermissionWithReducer(ctx, baseRepo, ctx.Doer(), ctx.Reducer())
	if err != nil {
		headGitRepo.Close()
		ctx.Error(http.StatusInternalServerError, "GetUserRepoPermissionWithReducer", err)
		return nil, nil, nil, "", ""
	}
	if !permBase.CanReadIssuesOrPulls(true) || !permBase.CanRead(unit.TypeCode) {
		if log.IsTrace() {
			log.Trace("Permission Denied: User %-v cannot create/read pull requests or cannot read code in Repo %-v\nUser in baseRepo has Permissions: %-+v",
				ctx.Doer(),
				baseRepo,
				permBase)
		}
		headGitRepo.Close()
		ctx.NotFound("Can't read pulls or can't read UnitTypeCode")
		return nil, nil, nil, "", ""
	}

	// user should have permission to read headrepo's codes
	permHead, err := access_model.GetUserRepoPermissionWithReducer(ctx, headRepo, ctx.Doer(), ctx.Reducer())
	if err != nil {
		headGitRepo.Close()
		ctx.Error(http.StatusInternalServerError, "GetUserRepoPermissionWithReducer", err)
		return nil, nil, nil, "", ""
	}
	if !permHead.CanRead(unit.TypeCode) {
		if log.IsTrace() {
			log.Trace("Permission Denied: User: %-v cannot read code in Repo: %-v\nUser in headRepo has Permissions: %-+v",
				ctx.Doer(),
				headRepo,
				permHead)
		}
		headGitRepo.Close()
		ctx.NotFound("Can't read headRepo UnitTypeCode")
		return nil, nil, nil, "", ""
	}

	baseBranchRef := baseBranch
	if baseIsBranch {
		baseBranchRef = git.BranchPrefix + baseBranch
	} else if baseIsTag {
		baseBranchRef = git.TagPrefix + baseBranch
	}

	// Check if head branch is valid.
	headIsCommit := headGitRepo.IsCommitExist(headBranch)
	headIsBranch := headGitRepo.IsBranchExist(headBranch)
	headIsTag := headGitRepo.IsTagExist(headBranch)
	if !headIsCommit && !headIsBranch && !headIsTag {
		headGitRepo.Close()
		ctx.NotFound(fmt.Errorf("could not find '%s' to be a commit, branch or tag in the head repository %s/%s", headBranch, headRepo.Owner.Name, headRepo.Name))
		return nil, nil, nil, "", ""
	}

	headBranchRef := headBranch
	if headIsBranch {
		headBranchRef = git.BranchPrefix + headBranch
	} else if headIsTag {
		headBranchRef = git.TagPrefix + headBranch
	}

	compareInfo, err := headGitRepo.GetCompareInfo(baseRepo.RepoPath(), baseBranchRef, headBranchRef, false, false)
	if err != nil {
		headGitRepo.Close()
		ctx.Error(http.StatusInternalServerError, "GetCompareInfo", err)
		return nil, nil, nil, "", ""
	}

	return headRepo, headGitRepo, compareInfo, baseBranch, headBranch
}

// RevertPullRequest opens a pull request that reverts a merged pull request
func RevertPullRequest(ctx *context.APIContext) {
	// swagger:operation POST /repos/{owner}/{repo}/pulls/{index}/revert repository repoRevertPullRequest
	// ---
	// summary: Open a pull request that reverts a merged pull request
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
	//   description: index of the merged pull request to revert
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "201":
	//     "$ref": "#/responses/PullRequest"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     "$ref": "#/responses/error"
	//   "413":
	//     "$ref": "#/responses/quotaExceeded"
	//   "422":
	//     "$ref": "#/responses/validationError"
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"

	pr, err := issues_model.GetPullRequestByIndex(ctx, ctx.Repo().Repository.ID, ctx.ParamsInt64(":index"))
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound("GetPullRequestByIndex", err)
		} else {
			ctx.Error(http.StatusInternalServerError, "GetPullRequestByIndex", err)
		}
		return
	}

	revert, err := files_service.RevertPullRequest(ctx, ctx.Doer(), ctx.Repo().GitRepo, pr)
	if err != nil {
		switch {
		case models.IsErrMergeConflicts(err):
			base, _ := pull_service.GetRevertBase(ctx.Repo().GitRepo, pr)
			ctx.Error(http.StatusConflict, "RevertPullRequest", "This pull request can't be reverted automatically because later changes conflict. Revert it locally:\n"+pull_service.RevertInstructions(ctx.Repo().GitRepo, pr, base))
		case git_model.IsErrPRTitleRule(err):
			message, _ := issue_service.PRTitleRuleMessage(ctx.Locale, err)
			ctx.Error(http.StatusUnprocessableEntity, "PRTitleRule", message)
		case git_model.IsErrBranchAlreadyExists(err):
			ctx.Error(http.StatusConflict, "RevertPullRequest", err)
		case errors.Is(err, util.ErrInvalidArgument):
			ctx.Error(http.StatusUnprocessableEntity, "RevertPullRequest", err)
		case errors.Is(err, util.ErrPermissionDenied), errors.Is(err, user_model.ErrBlockedByUser):
			ctx.Error(http.StatusForbidden, "RevertPullRequest", err)
		default:
			ctx.Error(http.StatusInternalServerError, "RevertPullRequest", err)
		}
		return
	}
	ctx.JSON(http.StatusCreated, convert.ToAPIPullRequest(ctx, revert, ctx.Doer()))
}

// UpdatePullRequest merge PR's baseBranch into headBranch
func UpdatePullRequest(ctx *context.APIContext) {
	// swagger:operation POST /repos/{owner}/{repo}/pulls/{index}/update repository repoUpdatePullRequest
	// ---
	// summary: Merge PR's baseBranch into headBranch
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
	//   description: index of the pull request to get
	//   type: integer
	//   format: int64
	//   required: true
	// - name: style
	//   in: query
	//   description: how to update pull request
	//   type: string
	//   enum: [merge, rebase]
	// responses:
	//   "200":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     "$ref": "#/responses/error"
	//   "413":
	//     "$ref": "#/responses/quotaExceeded"
	//   "422":
	//     "$ref": "#/responses/validationError"

	pr, err := issues_model.GetPullRequestByIndex(ctx, ctx.Repo().Repository.ID, ctx.ParamsInt64(":index"))
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetPullRequestByIndex", err)
		}
		return
	}

	if pr.HasMerged {
		ctx.Error(http.StatusUnprocessableEntity, "UpdatePullRequest", err)
		return
	}

	if err = pr.LoadIssue(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadIssue", err)
		return
	}

	if pr.Issue.IsClosed {
		ctx.Error(http.StatusUnprocessableEntity, "UpdatePullRequest", err)
		return
	}

	if err = pr.LoadBaseRepo(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadBaseRepo", err)
		return
	}
	if err = pr.LoadHeadRepo(ctx); err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadHeadRepo", err)
		return
	}
	// the update writes to the head repository
	if !ctx.CheckPersonalRepoLimit(pr.HeadRepo.OwnerID, pr.HeadRepo.OwnerName) {
		return
	}

	headRepoPerm, err := access_model.GetUserRepoPermissionWithReducer(ctx, pr.HeadRepo, ctx.Doer(), ctx.Reducer())
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetUserRepoPermissionWithReducer head repo", err)
		return
	}
	baseRepoPerm, err := access_model.GetUserRepoPermissionWithReducer(ctx, pr.BaseRepo, ctx.Doer(), ctx.Reducer())
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetUserRepoPermissionWithReducer base repo", err)
		return
	}

	rebase := ctx.FormString("style") == "rebase"

	allowedUpdateByMerge, allowedUpdateByRebase, err := pull_service.IsUserAllowedToUpdate(ctx, pr, ctx.Doer(), headRepoPerm, baseRepoPerm)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "IsUserAllowedToMerge", err)
		return
	}

	if (!allowedUpdateByMerge && !rebase) || (rebase && !allowedUpdateByRebase) {
		ctx.Status(http.StatusForbidden)
		return
	}

	// default merge commit message
	message := fmt.Sprintf("Merge branch '%s' into %s", pr.BaseBranch, pr.HeadBranch)

	if err = pull_service.Update(ctx, pr, ctx.Doer(), message, rebase); err != nil {
		if models.IsErrMergeConflicts(err) {
			ctx.Error(http.StatusConflict, "Update", "merge failed because of conflict")
			return
		} else if models.IsErrRebaseConflicts(err) {
			ctx.Error(http.StatusConflict, "Update", "rebase failed because of conflict")
			return
		} else if errors.Is(err, pull_service.ErrPullRequestIsUpdateToDate) {
			// No need to report an error -- the update operation didn't do anything, but there was nothing to be done.
			ctx.Status(http.StatusOK)
			return
		}
		ctx.Error(http.StatusInternalServerError, "pull_service.Update", err)
		return
	}

	ctx.Status(http.StatusOK)
}

// MergePullRequest cancel an auto merge scheduled for a given PullRequest by index
func CancelScheduledAutoMerge(ctx *context.APIContext) {
	// swagger:operation DELETE /repos/{owner}/{repo}/pulls/{index}/merge repository repoCancelScheduledAutoMerge
	// ---
	// summary: Cancel the scheduled auto merge for the given pull request
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
	//   description: index of the pull request to merge
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
	//   "423":
	//     "$ref": "#/responses/repoArchivedError"

	pullIndex := ctx.ParamsInt64(":index")
	pull, err := issues_model.GetPullRequestByIndex(ctx, ctx.Repo().Repository.ID, pullIndex)
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound()
			return
		}
		ctx.InternalServerError(err)
		return
	}

	if err := automerge.RemoveScheduledAutoMerge(ctx, ctx.Doer(), pull, ctx.Repo().Permission); err != nil {
		switch {
		case errors.Is(err, util.ErrPermissionDenied):
			ctx.Error(http.StatusForbidden, "No permission to cancel", "user has no permission to cancel the scheduled auto merge")
		case db.IsErrNotExist(err):
			ctx.NotFound()
		default:
			ctx.InternalServerError(err)
		}
		return
	}
	ctx.Status(http.StatusNoContent)
}

// GetPullRequestCommits gets all commits associated with a given PR
func GetPullRequestCommits(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/pulls/{index}/commits repository repoGetPullRequestCommits
	// ---
	// summary: Get commits for a pull request
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
	//   description: index of the pull request to get
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
	// - name: verification
	//   in: query
	//   description: include verification for every commit (disable for speedup, default 'true')
	//   type: boolean
	// - name: files
	//   in: query
	//   description: include a list of affected files for every commit (disable for speedup, default 'true')
	//   type: boolean
	// responses:
	//   "200":
	//     "$ref": "#/responses/CommitList"
	//   "404":
	//     "$ref": "#/responses/notFound"

	pr, err := issues_model.GetPullRequestByIndex(ctx, ctx.Repo().Repository.ID, ctx.ParamsInt64(":index"))
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetPullRequestByIndex", err)
		}
		return
	}

	if err := pr.LoadBaseRepo(ctx); err != nil {
		ctx.InternalServerError(err)
		return
	}

	var prInfo *git.CompareInfo
	baseGitRepo, closer, err := gitrepo.RepositoryFromContextOrOpen(ctx, pr.BaseRepo)
	if err != nil {
		ctx.ServerError("OpenRepository", err)
		return
	}
	defer closer.Close()

	if pr.HasMerged {
		prInfo, err = baseGitRepo.GetCompareInfo(pr.BaseRepo.RepoPath(), pr.MergeBase, pr.GetGitRefName(), false, false)
	} else {
		prInfo, err = baseGitRepo.GetCompareInfo(pr.BaseRepo.RepoPath(), pr.BaseBranch, pr.GetGitRefName(), false, false)
	}
	if err != nil {
		ctx.ServerError("GetCompareInfo", err)
		return
	}
	commits := prInfo.Commits

	listOptions := utils.GetListOptions(ctx)

	totalNumberOfCommits := len(commits)
	totalNumberOfPages := int(math.Ceil(float64(totalNumberOfCommits) / float64(listOptions.PageSize)))

	userCache := make(map[string]*user_model.User)

	start, limit := listOptions.GetSkipTake()

	limit = min(limit, totalNumberOfCommits-start)
	limit = max(limit, 0)

	verification := ctx.FormString("verification") == "" || ctx.FormBool("verification")
	files := ctx.FormString("files") == "" || ctx.FormBool("files")

	apiCommits := make([]*api.Commit, 0, limit)
	for i := start; i < start+limit; i++ {
		apiCommit, err := convert.ToCommit(ctx, ctx.Repo().Repository, baseGitRepo, commits[i], userCache,
			convert.ToCommitOptions{
				Stat:         true,
				Verification: verification,
				Files:        files,
			})
		if err != nil {
			ctx.ServerError("toCommit", err)
			return
		}
		apiCommits = append(apiCommits, apiCommit)
	}

	ctx.SetLinkHeader(totalNumberOfCommits, listOptions.PageSize)
	ctx.SetTotalCountHeader(int64(totalNumberOfCommits))

	ctx.RespHeader().Set("X-Page", strconv.Itoa(listOptions.Page))
	ctx.RespHeader().Set("X-PerPage", strconv.Itoa(listOptions.PageSize))
	ctx.RespHeader().Set("X-PageCount", strconv.Itoa(totalNumberOfPages))
	ctx.RespHeader().Set("X-HasMore", strconv.FormatBool(listOptions.Page < totalNumberOfPages))
	ctx.AppendAccessControlExposeHeaders("X-Page", "X-PerPage", "X-PageCount", "X-HasMore")

	ctx.JSON(http.StatusOK, &apiCommits)
}

// GetPullRequestApprovals gets the status of the approval rules of a pull request
func GetPullRequestApprovals(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/pulls/{index}/approvals repository repoGetPullRequestApprovals
	// ---
	// summary: Get the approval rules of a pull request and whether each is satisfied
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
	//     "$ref": "#/responses/PullApprovalRuleList"
	//   "404":
	//     "$ref": "#/responses/notFound"

	pr, err := issues_model.GetPullRequestByIndex(ctx, ctx.Repo().Repository.ID, ctx.ParamsInt64(":index"))
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetPullRequestByIndex", err)
		}
		return
	}

	rules := []*api.PullApprovalRule{}
	pbs, err := git_model.GetMatchedProtectedBranchRules(ctx, pr.BaseRepoID, pr.BaseBranch)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetMatchedProtectedBranchRules", err)
		return
	}
	for _, pb := range pbs {
		statuses, err := pull_service.ApprovalRuleStatuses(ctx, pb, pr)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, "ApprovalRuleStatuses", err)
			return
		}
		for _, s := range statuses {
			approvers := make([]string, len(s.Approvers))
			for i, u := range s.Approvers {
				approvers[i] = u.Name
			}
			rules = append(rules, &api.PullApprovalRule{Name: s.Name, Required: s.Required, Granted: s.Granted, Satisfied: s.Satisfied, Approvers: approvers})
		}
	}
	ctx.JSON(http.StatusOK, rules)
}

// GetPullRequestStack gets the stack of a pull request
func GetPullRequestStack(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/pulls/{index}/stack repository repoGetPullRequestStack
	// ---
	// summary: Get the stack of a pull request, the open pull requests based on each other's head branch
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
	//     "$ref": "#/responses/PullRequestStack"
	//   "404":
	//     "$ref": "#/responses/notFound"

	pr, err := issues_model.GetPullRequestByIndex(ctx, ctx.Repo().Repository.ID, ctx.ParamsInt64(":index"))
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetPullRequestByIndex", err)
		}
		return
	}

	stack, err := pull_service.GetStack(ctx, pr)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetStack", err)
		return
	}
	res := &api.PullRequestStack{PullRequests: []*api.StackedPullRequest{}}
	if len(stack.Entries) == 0 {
		ctx.JSON(http.StatusOK, res)
		return
	}
	res.BaseBranch, res.Truncated = stack.BaseBranch, stack.Truncated

	statuses, err := pull_service.StackStatuses(ctx, ctx.Repo().Repository, ctx.Repo().GitRepo, stack)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "StackStatuses", err)
		return
	}

	for _, e := range stack.Entries {
		status := statuses[e.PR.ID]
		res.PullRequests = append(res.PullRequests, &api.StackedPullRequest{
			Number:       e.PR.Index,
			Title:        e.PR.Issue.Title,
			HTMLURL:      e.PR.Issue.HTMLURL(),
			HeadBranch:   e.PR.HeadBranch,
			BaseBranch:   e.PR.BaseBranch,
			ParentNumber: e.ParentIndex,
			Depth:        e.Depth,
			Current:      e.PR.ID == pr.ID,
			Draft:        e.PR.IsWorkInProgress(ctx),
			ReviewState:  status.Review,
			CheckState:   status.Check,
		})
	}
	ctx.JSON(http.StatusOK, res)
}

// GetPullRequestFiles gets all changed files associated with a given PR
func GetPullRequestFiles(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/pulls/{index}/files repository repoGetPullRequestFiles
	// ---
	// summary: Get changed files for a pull request
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
	//   description: index of the pull request to get
	//   type: integer
	//   format: int64
	//   required: true
	// - name: skip-to
	//   in: query
	//   description: skip to given file
	//   type: string
	// - name: whitespace
	//   in: query
	//   description: whitespace behavior
	//   type: string
	//   enum: [ignore-all, ignore-change, ignore-eol, show-all]
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
	//     "$ref": "#/responses/ChangedFileListWithPagination"
	//   "404":
	//     "$ref": "#/responses/notFound"

	pr, err := issues_model.GetPullRequestByIndex(ctx, ctx.Repo().Repository.ID, ctx.ParamsInt64(":index"))
	if err != nil {
		if issues_model.IsErrPullRequestNotExist(err) {
			ctx.NotFound()
		} else {
			ctx.Error(http.StatusInternalServerError, "GetPullRequestByIndex", err)
		}
		return
	}

	if err := pr.LoadBaseRepo(ctx); err != nil {
		ctx.InternalServerError(err)
		return
	}

	if err := pr.LoadHeadRepo(ctx); err != nil {
		ctx.InternalServerError(err)
		return
	}

	baseGitRepo := ctx.Repo().GitRepo

	baseRef := pr.BaseBranch
	if pr.HasMerged {
		baseRef = pr.MergeBase
	}
	startCommitID, err := baseGitRepo.GetMergeBaseSimple(baseRef, pr.GetGitRefName())
	if err != nil {
		// No merge base exists, fallback to use base reference.
		startCommitID = baseRef
	}

	endCommitID, err := baseGitRepo.GetRefCommitID(pr.GetGitRefName())
	if err != nil {
		ctx.ServerError("GetRefCommitID", err)
		return
	}

	maxLines := setting.Git.MaxGitDiffLines

	listOptions := utils.GetListOptions(ctx)
	start, end := listOptions.GetSkipTake()
	end += start

	diffFileMetadata, err := gitdiff.GetDiffNameStatus(ctx, baseGitRepo, startCommitID, endCommitID, listOptions.PageSize)
	if err != nil {
		ctx.ServerError("GetDiffNameStatus", err)
		return
	}

	skipTo := ctx.FormString("skip-to")
	if skipTo != "" {
		diffFileMetadata = skipFilesTo(diffFileMetadata, skipTo)
	}

	if end > len(diffFileMetadata) {
		end = len(diffFileMetadata)
	}

	var apiFiles []*api.ChangedFile
	if start < len(diffFileMetadata) {
		diff, _, err := gitdiff.GetDiffSimple(ctx, baseGitRepo,
			&gitdiff.DiffOptions{
				BeforeCommitID:     startCommitID,
				AfterCommitID:      endCommitID,
				MaxLines:           maxLines,
				MaxLineCharacters:  setting.Git.MaxGitDiffLineCharacters,
				WhitespaceBehavior: gitdiff.GetWhitespaceFlag(ctx.FormString("whitespace")),
			}, gitdiff.GetFileNames(diffFileMetadata[start:end])...)
		if err != nil {
			ctx.ServerError("GetDiff", err)
			return
		}
		apiFiles = make([]*api.ChangedFile, len(diff.Files))
		for i, diffFile := range diff.Files {
			apiFiles[i] = convert.ToChangedFile(diffFile, pr.HeadRepo, endCommitID)
		}
	}

	totalNumberOfFiles := len(diffFileMetadata)
	totalNumberOfPages := int(math.Ceil(float64(totalNumberOfFiles) / float64(listOptions.PageSize)))

	ctx.SetLinkHeader(totalNumberOfFiles, listOptions.PageSize)
	ctx.SetTotalCountHeader(int64(totalNumberOfFiles))

	ctx.RespHeader().Set("X-Page", strconv.Itoa(listOptions.Page))
	ctx.RespHeader().Set("X-PerPage", strconv.Itoa(listOptions.PageSize))
	ctx.RespHeader().Set("X-PageCount", strconv.Itoa(totalNumberOfPages))
	ctx.RespHeader().Set("X-HasMore", strconv.FormatBool(listOptions.Page < totalNumberOfPages))
	ctx.AppendAccessControlExposeHeaders("X-Page", "X-PerPage", "X-PageCount", "X-HasMore")

	ctx.JSON(http.StatusOK, &apiFiles)
}

func skipFilesTo(list []*gitdiff.DiffFileMetadata, target string) []*gitdiff.DiffFileMetadata {
	i := slices.IndexFunc(list, func(diff *gitdiff.DiffFileMetadata) bool {
		return diff.Name == target
	})
	if i != -1 {
		return list[i:]
	}
	return []*gitdiff.DiffFileMetadata{}
}
