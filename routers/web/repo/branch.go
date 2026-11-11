// Copyright 2014 The Gogs Authors. All rights reserved.
// Copyright 2018 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"errors"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"forgejo.org/models"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/modules/base"
	"forgejo.org/modules/git"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/routers/utils"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/context"
	"forgejo.org/services/cron"
	"forgejo.org/services/forms"
	release_service "forgejo.org/services/release"
	repo_service "forgejo.org/services/repository"
)

const (
	tplBranch base.TplName = "repo/branch/list"
)

// Branches render repository branch page
func Branches(ctx *context.Context) {
	ctx.Data["Title"] = "Branches"
	ctx.Data["IsRepoToolbarBranches"] = true
	ctx.Data["AllowsPulls"] = ctx.Repo.Repository.AllowsPulls(ctx)
	ctx.Data["IsWriter"] = ctx.Repo.CanWrite(unit.TypeCode)
	ctx.Data["IsMirror"] = ctx.Repo.Repository.IsMirror
	ctx.Data["CanPull"] = ctx.Repo.CanWrite(unit.TypeCode) ||
		(ctx.IsSigned && repo_model.HasForkedRepo(ctx, ctx.Doer.ID, ctx.Repo.Repository.ID))
	ctx.Data["PageIsViewCode"] = true
	ctx.Data["PageIsBranches"] = true

	page := max(ctx.FormInt("page"), 1)
	pageSize := setting.Git.BranchesRangeSize

	kw := ctx.FormString("q")

	model, err := branchworkflow.GetEffectiveModel(ctx, ctx.Repo.Repository)
	if err != nil {
		ctx.ServerError("GetEffectiveModel", err)
		return
	}
	typeFilter, untyped := ctx.FormString("type"), ctx.FormBool("untyped")
	defaultBranch, branches, branchesCount, err := repo_service.LoadBranches(ctx, ctx.Doer, ctx.Repo.Repository, ctx.Repo.GitRepo, optional.None[bool](), kw, branchworkflow.TypeFilter(model.Model, typeFilter, untyped), page, pageSize)
	if err != nil {
		ctx.ServerError("LoadBranches", err)
		return
	}

	commitIDs := []string{defaultBranch.DBBranch.CommitID}
	for _, branch := range branches {
		commitIDs = append(commitIDs, branch.DBBranch.CommitID)
	}

	commitStatuses, err := git_model.GetLatestCommitStatusForRepoCommitIDs(ctx, ctx.Repo.Repository.ID, commitIDs)
	if err != nil {
		ctx.ServerError("LoadBranches", err)
		return
	}

	commitStatus := make(map[string]*git_model.CommitStatus)
	for commitID, cs := range commitStatuses {
		commitStatus[commitID] = git_model.CalcCommitStatus(cs)
	}

	ctx.Data["Keyword"] = kw
	ctx.Data["Branches"] = branches
	prepareBranchGroups(ctx, model.Model, branches, typeFilter, untyped)
	if ctx.Repo.CanCreateBranch() && !PrepareBranchDialog(ctx, model) {
		return
	}
	ctx.Data["CommitStatus"] = commitStatus
	ctx.Data["CommitStatuses"] = commitStatuses
	ctx.Data["DefaultBranchBranch"] = defaultBranch
	pager := context.NewPagination(int(branchesCount), pageSize, page, 5)
	pager.SetDefaultParams(ctx)
	ctx.Data["Page"] = pager

	ctx.HTML(http.StatusOK, tplBranch)
}

// branchRow is a branch of the list with its place in the page, so the flat list can restore the order.
type branchRow struct {
	*repo_service.Branch
	Order int
}

// branchGroup is the branches of one type; Name is empty when the model has no types and the list is flat.
type branchGroup struct {
	Name     string
	Branches []branchRow
}

// prepareBranchGroups groups the branches of the page by the type their name matches (the enabled types in the order
// of the model, then Release, then "No type" as an empty name with Untyped set) and sets the filter chips. The
// groups are those of the page: the list is paginated by the database order.
func prepareBranchGroups(ctx *context.Context, m repo_model.BranchingModel, branches []*repo_service.Branch, typeFilter string, untyped bool) {
	var names []string
	for _, t := range m.Types {
		if !t.Off {
			names = append(names, t.Name)
		}
	}
	if len(m.ReleasePrefixes) > 0 {
		names = append(names, branchworkflow.ReleaseTypeName)
	}
	if len(names) == 0 {
		rows := make([]branchRow, 0, len(branches))
		for i, b := range branches {
			rows = append(rows, branchRow{b, i})
		}
		ctx.Data["BranchGroups"] = []branchGroup{{Branches: rows}}
		return
	}
	groups := map[string]*branchGroup{}
	var ordered []*branchGroup
	for _, name := range append(slices.Clone(names), "") {
		groups[name] = &branchGroup{Name: name}
		ordered = append(ordered, groups[name])
	}
	for i, b := range branches {
		name := ""
		if t, ok := branchworkflow.MatchType(m, b.DBBranch.Name); ok {
			name = t.Name
		}
		groups[name].Branches = append(groups[name].Branches, branchRow{b, i})
	}
	ctx.Data["BranchGroups"] = slices.DeleteFunc(ordered, func(g *branchGroup) bool { return len(g.Branches) == 0 })
	ctx.Data["HasBranchTypes"] = true
	ctx.Data["BranchTypeNames"] = names
	ctx.Data["BranchTypeFilter"] = typeFilter
	ctx.Data["BranchUntypedFilter"] = untyped
}

// PrepareBranchDialog sets what the create branch dialog needs for the viewer: the types of the model with the
// branch each starts from, whether a type is required of this user, and the names of the branches to start from.
func PrepareBranchDialog(ctx *context.Context, model branchworkflow.EffectiveModel) bool {
	choices, err := branchworkflow.DialogChoices(ctx, ctx.Repo.Repository, model, ctx.Doer)
	if err != nil {
		ctx.ServerError("DialogChoices", err)
		return false
	}
	names, err := git_model.FindBranchNames(ctx, git_model.FindBranchOptions{
		RepoID: ctx.Repo.Repository.ID, IsDeletedBranch: optional.Some(false), ListOptions: db.ListOptions{Page: 1, PageSize: 100},
	})
	if err != nil {
		ctx.ServerError("FindBranchNames", err)
		return false
	}
	ctx.Data["BranchDialog"] = choices
	ctx.Data["BranchDialogBranches"] = names
	if choices.Required {
		setBy := ctx.Locale.TrString("repo.branch.dialog.set_by_repo")
		if choices.SetBy != "" {
			setBy = ctx.Locale.TrString("repo.branch.type_required_set_by", choices.SetBy)
		}
		if exc := choices.Model.BranchExceptions; len(exc) > 0 {
			listed := strings.Join(exc[:min(len(exc), 5)], ", ")
			if more := len(exc) - 5; more > 0 {
				listed = ctx.Locale.TrString("repo.branch.type_required_more", listed, more)
			}
			setBy += " " + ctx.Locale.TrString("repo.branch.dialog.exceptions", listed)
		}
		ctx.Data["BranchDialogSetBy"] = setBy
	}
	return true
}

// DeleteBranchPost responses for delete merged branch
func DeleteBranchPost(ctx *context.Context) {
	defer redirect(ctx)
	branchName := ctx.FormString("name")

	locked := repo_service.PersonalRepoLocked(ctx, ctx.Repo.Repository)
	if err := repo_service.DeleteBranch(ctx, ctx.Doer, ctx.Repo.Repository, ctx.Repo.GitRepo, branchName, ""); err != nil {
		switch {
		case git.IsErrBranchNotExist(err):
			log.Debug("DeleteBranch: Can't delete non existing branch '%s'", branchName)
			ctx.Flash.Error(ctx.Tr("repo.branch.deletion_failed", branchName))
		case errors.Is(err, repo_service.ErrBranchIsDefault):
			log.Debug("DeleteBranch: Can't delete default branch '%s'", branchName)
			ctx.Flash.Error(ctx.Tr("repo.branch.default_deletion_failed", branchName))
		case errors.Is(err, git_model.ErrBranchIsProtected):
			log.Debug("DeleteBranch: Can't delete protected branch '%s'", branchName)
			ctx.Flash.Error(ctx.Tr("repo.branch.protected_deletion_failed", branchName))
		case errors.Is(err, repo_service.ErrBranchHasNewCommits):
			ctx.Flash.Error(ctx.Tr("repo.branch.moved_deletion_failed", branchName))
		default:
			log.Error("DeleteBranch: %v", err)
			ctx.Flash.Error(ctx.Tr("repo.branch.deletion_failed", branchName))
		}

		return
	}

	repo_service.ShrinkAfterDelete(ctx, ctx.Repo.Repository, locked)
	ctx.Flash.Success(ctx.Tr("repo.branch.deletion_success", branchName))
}

// RestoreBranchPost responses for delete merged branch
func RestoreBranchPost(ctx *context.Context) {
	defer redirect(ctx)

	branchID := ctx.FormInt64("branch_id")
	branchName := ctx.FormString("name")

	// a restore adds a branch, and the size limit's gc may have pruned its objects
	if repo_service.PersonalRepoLocked(ctx, ctx.Repo.Repository) {
		ctx.Flash.Error(ctx.Tr("repo.personal_repos.limit_reached_short"))
		return
	}

	deletedBranch, err := git_model.GetDeletedBranchByID(ctx, ctx.Repo.Repository.ID, branchID)
	if err != nil {
		log.Error("GetDeletedBranchByID: %v", err)
		ctx.Flash.Error(ctx.Tr("repo.branch.restore_failed", branchName))
		return
	} else if deletedBranch == nil {
		log.Debug("RestoreBranch: Can't restore branch[%d] '%s', as it does not exist", branchID, branchName)
		ctx.Flash.Error(ctx.Tr("repo.branch.restore_failed", branchName))
		return
	}

	if err := git.Push(ctx, ctx.Repo.Repository.RepoPath(), git.PushOptions{
		Remote: ctx.Repo.Repository.RepoPath(),
		Branch: fmt.Sprintf("%s:%s%s", deletedBranch.CommitID, git.BranchPrefix, deletedBranch.Name),
		Env:    repo_module.PushingEnvironment(ctx, ctx.Doer, ctx.Repo.Repository),
	}); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			log.Debug("RestoreBranch: Can't restore branch '%s', since one with same name already exist", deletedBranch.Name)
			ctx.Flash.Error(ctx.Tr("repo.branch.already_exists", deletedBranch.Name))
			return
		}
		log.Error("RestoreBranch: CreateBranch: %v", err)
		ctx.Flash.Error(ctx.Tr("repo.branch.restore_failed", deletedBranch.Name))
		return
	}

	objectFormat := git.ObjectFormatFromName(ctx.Repo.Repository.ObjectFormatName)

	// Don't return error below this
	if err := repo_service.PushUpdate(
		&repo_module.PushUpdateOptions{
			RefFullName:  git.RefNameFromBranch(deletedBranch.Name),
			OldCommitID:  objectFormat.EmptyObjectID().String(),
			NewCommitID:  deletedBranch.CommitID,
			PusherID:     ctx.Doer.ID,
			PusherName:   ctx.Doer.Name,
			RepoID:       ctx.Repo.Repository.ID,
			RepoUserName: ctx.Repo.Owner.Name,
			RepoName:     ctx.Repo.Repository.Name,
		},
	); err != nil {
		log.Error("RestoreBranch: Update: %v", err)
	}

	ctx.Flash.Success(ctx.Tr("repo.branch.restore_success", deletedBranch.Name))
}

func redirect(ctx *context.Context) {
	ctx.JSONRedirect(ctx.Repo.RepoLink + "/branches?page=" + url.QueryEscape(ctx.FormString("page")))
}

// CreateBranch creates new branch in repository
func CreateBranch(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.NewBranchForm)
	if !ctx.Repo.CanCreateBranch() {
		ctx.NotFound("CreateBranch", nil)
		return
	}

	if ctx.HasError() {
		ctx.Flash.Error(ctx.GetErrMsg())
		ctx.Redirect(ctx.Repo.RepoLink + "/src/" + ctx.Repo.BranchNameSubURL())
		return
	}

	var err error

	if form.CreateTag {
		target := ctx.Repo.CommitID
		if ctx.Repo.IsViewBranch {
			target = ctx.Repo.BranchName
		}
		err = release_service.CreateNewTag(ctx, ctx.Doer, ctx.Repo.Repository, target, form.NewBranchName, "")
	} else if ctx.Repo.IsViewBranch {
		err = repo_service.CreateNewBranch(ctx, ctx.Doer, ctx.Repo.Repository, ctx.Repo.GitRepo, ctx.Repo.BranchName, form.NewBranchName)
	} else {
		err = repo_service.CreateNewBranchFromCommit(ctx, ctx.Doer, ctx.Repo.Repository, ctx.Repo.GitRepo, ctx.Repo.CommitID, form.NewBranchName)
	}
	if err != nil {
		if models.IsErrProtectedTagName(err) {
			ctx.Flash.Error(ctx.Tr("repo.release.tag_name_protected"))
			ctx.Redirect(ctx.Repo.RepoLink + "/src/" + ctx.Repo.BranchNameSubURL())
			return
		}

		if models.IsErrTagAlreadyExists(err) {
			e := err.(models.ErrTagAlreadyExists)
			ctx.Flash.Error(ctx.Tr("repo.branch.tag_collision", e.TagName))
			ctx.Redirect(ctx.Repo.RepoLink + "/src/" + ctx.Repo.BranchNameSubURL())
			return
		}
		if refused, ok := errors.AsType[branchworkflow.ErrBranchTypeRequired](err); ok {
			ctx.Flash.Error(html.EscapeString(refused.Text(ctx.Locale)))
			ctx.Redirect(ctx.Repo.RepoLink + "/src/" + ctx.Repo.BranchNameSubURL())
			return
		}
		if git_model.IsErrBranchNotExist(err) {
			ctx.Flash.Error(ctx.Tr("repo.branch.base_not_exist"))
			ctx.Redirect(ctx.Repo.RepoLink + "/branches")
			return
		}
		if git_model.IsErrBranchAlreadyExists(err) || git.IsErrPushOutOfDate(err) {
			ctx.Flash.Error(ctx.Tr("repo.branch.branch_already_exists", form.NewBranchName))
			ctx.Redirect(ctx.Repo.RepoLink + "/src/" + ctx.Repo.BranchNameSubURL())
			return
		}
		if git_model.IsErrBranchNameReserved(err) {
			ctx.Flash.Error(ctx.Tr("repo.branch.name_reserved", form.NewBranchName))
			ctx.Redirect(ctx.Repo.RepoLink + "/src/" + ctx.Repo.BranchNameSubURL())
			return
		}
		if models.IsErrInvalidTagName(err) {
			ctx.Flash.Error(ctx.Tr("repo.release.tag_name_invalid"))
			ctx.Redirect(ctx.Repo.RepoLink + "/src/" + ctx.Repo.BranchNameSubURL())
			return
		}
		if git_model.IsErrBranchNameConflict(err) {
			e := err.(git_model.ErrBranchNameConflict)
			ctx.Flash.Error(ctx.Tr("repo.branch.branch_name_conflict", form.NewBranchName, e.BranchName))
			ctx.Redirect(ctx.Repo.RepoLink + "/src/" + ctx.Repo.BranchNameSubURL())
			return
		}
		if git.IsErrPushRejected(err) {
			e := err.(*git.ErrPushRejected)
			if len(e.Message) == 0 {
				ctx.Flash.Error(ctx.Tr("repo.editor.push_rejected_no_message"))
			} else {
				flashError, err := ctx.RenderToHTML(tplAlertDetails, map[string]any{
					"Message": ctx.Tr("repo.editor.push_rejected"),
					"Summary": ctx.Tr("repo.editor.push_rejected_summary"),
					"Details": utils.SanitizeFlashErrorString(e.Message),
				})
				if err != nil {
					ctx.ServerError("UpdatePullRequest.HTMLString", err)
					return
				}
				ctx.Flash.Error(flashError)
			}
			ctx.Redirect(ctx.Repo.RepoLink + "/src/" + ctx.Repo.BranchNameSubURL())
			return
		}

		ctx.ServerError("CreateNewBranch", err)
		return
	}

	if form.CreateTag {
		ctx.Flash.Success(ctx.Tr("repo.tag.create_success", form.NewBranchName))
		ctx.Redirect(ctx.Repo.RepoLink + "/src/tag/" + util.PathEscapeSegments(form.NewBranchName))
		return
	}

	ctx.Flash.Success(ctx.Tr("repo.branch.create_success", form.NewBranchName))
	ctx.Redirect(ctx.Repo.RepoLink + "/src/branch/" + util.PathEscapeSegments(form.NewBranchName) + "/" + util.PathEscapeSegments(form.CurrentPath))
}

// RestoreText says for how long a deleted branch can be restored from the Branches page, from the configured
// deleted-branch cleanup; empty when it can't be (the cleanup purges at once).
func RestoreText(ctx *context.Context) template.HTML {
	hours, ok := cron.DeletedBranchRestoreWindow()
	switch {
	case !ok:
		return ""
	case hours == 0:
		return ctx.Tr("repo.settings.delete_merged.restore")
	}
	return ctx.Locale.TrPluralString(hours, "repo.settings.delete_merged.restore_hours", hours)
}
