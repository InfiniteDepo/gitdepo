// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"fmt"
	"html"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/translation"
	"forgejo.org/routers/common"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/context"
	repo_service "forgejo.org/services/repository"
)

const (
	// bulkConfirmAbove is how many selected branches ask for the typed name of the repository.
	bulkConfirmAbove = 10
	// maxReportedBranches is how many names a result message lists; the rest is counted.
	maxReportedBranches = 10
	// maxPreselected is how many deleted branches the result's link ticks.
	maxPreselected = 50
)

// branchFilterFromForm reads the filters of the Branches page, its preview and its flash links. A value outside the
// closed sets is a 422.
func branchFilterFromForm(ctx *context.Context) (repo_service.BranchFilter, bool) {
	f := repo_service.BranchFilter{
		Keyword:  ctx.FormString("q"),
		Type:     ctx.FormString("type"),
		Untyped:  ctx.FormBool("untyped"),
		State:    ctx.FormString("state"),
		Into:     ctx.FormString("into"),
		PushedBy: strings.TrimSpace(ctx.FormString("pusher")),
		Deleted:  ctx.FormBool("deleted"),
	}
	if s := ctx.FormString("stale"); s != "" {
		f.StaleDays, _ = strconv.Atoi(s)
		if f.StaleDays == 0 {
			f.StaleDays = -1 // not a number: refused by Validate
		}
	}
	if err := f.Validate(); err != nil {
		ctx.Error(http.StatusUnprocessableEntity, err.Error())
		return f, false
	}
	if f.State != "" { // a walk of the history: charged like the other heavy pages
		common.RateLimitHeavy(ctx)
	}
	return f, !ctx.Written()
}

// branchFilterValues is the filters other than keyword and type, for the links that keep them.
func branchFilterValues(f repo_service.BranchFilter) url.Values {
	v := url.Values{}
	if f.State != "" {
		v.Set("state", f.State)
		if f.Into != "" {
			v.Set("into", f.Into)
		}
	}
	if f.StaleDays > 0 {
		v.Set("stale", strconv.Itoa(f.StaleDays))
	}
	if f.PushedBy != "" {
		v.Set("pusher", f.PushedBy)
	}
	if f.Deleted {
		v.Set("deleted", "1")
	}
	return v
}

func branchQueryOf(ctx *context.Context, f repo_service.BranchFilter, model branchworkflow.EffectiveModel) (repo_service.BranchQuery, bool) {
	q, err := f.Query(ctx, ctx.Repo.Repository, ctx.Repo.GitRepo, model)
	if err != nil {
		ctx.ServerError("BranchFilter.Query", err)
		return q, false
	}
	return q, true
}

// prepareBranchBulk sets what the writer's selection controls need: the kept reason of each listed branch, the
// number of live branches that match the filters, the limits and the names to tick.
func prepareBranchBulk(ctx *context.Context, f repo_service.BranchFilter, q repo_service.BranchQuery, model branchworkflow.EffectiveModel, branches []*repo_service.Branch) bool {
	repo := ctx.Repo.Repository
	ctx.Data["BranchDevelopment"] = model.DevelopmentBranch(repo)
	ctx.Data["BranchFilter"] = f
	ctx.Data["BranchFilterQuery"] = template.URL(branchFilterValues(f).Encode())
	ctx.Data["BranchFilterSet"] = f.IsSet() || f.Keyword != "" || f.Type != "" || f.Untyped
	ctx.Data["RestoreText"] = RestoreText(ctx)
	selected := map[string]bool{}
	for _, n := range ctx.FormStrings("selected") {
		selected[n] = true
	}
	ctx.Data["SelectedNames"] = selected
	if !ctx.Data["IsWriter"].(bool) || repo.IsArchived || repo.IsMirror {
		return true
	}
	ctx.Data["CanBulkDelete"] = true
	ctx.Data["MaxDeleteSelected"] = repo_service.MaxDeleteMergedBranches
	ctx.Data["BulkConfirmAbove"] = bulkConfirmAbove
	ctx.Data["BulkConfirmName"] = repo.FullName()
	if f.Deleted {
		return true
	}
	kept, err := branchworkflow.NewKeptChecker(ctx, repo, true)
	if err != nil {
		ctx.ServerError("NewKeptChecker", err)
		return false
	}
	texts := map[string]string{}
	for _, b := range branches {
		if reason := kept.Reason(b.DBBranch.Name); reason != "" {
			texts[b.DBBranch.Name] = branchReasonText(ctx.Locale, reason)
		}
	}
	ctx.Data["KeptTexts"] = texts
	total, err := db.Count[git_model.Branch](ctx, git_model.FindBranchOptions{
		RepoID: repo.ID, IsDeletedBranch: optional.Some(false), Keyword: q.Keyword, Cond: q.Cond, ExcludeBranchNames: []string{repo.DefaultBranch},
	})
	if err != nil {
		ctx.ServerError("Count", err)
		return false
	}
	ctx.Data["BranchMatchingTotal"] = total
	return true
}

// branchReasonText says in words why a branch was kept or refused. The codes are a closed set.
func branchReasonText(locale translation.Locale, code string) string {
	switch code {
	case branchworkflow.KeptDefault:
		return locale.TrString("repo.branch.bulk.reason.default")
	case branchworkflow.KeptDevelopment:
		return locale.TrString("repo.branch.bulk.reason.development")
	case branchworkflow.KeptProduction:
		return locale.TrString("repo.branch.bulk.reason.production")
	case branchworkflow.KeptRelease:
		return locale.TrString("repo.branch.bulk.reason.release")
	case branchworkflow.KeptProtected:
		return locale.TrString("repo.branch.bulk.reason.protected")
	case branchworkflow.KeptOpenPR:
		return locale.TrString("repo.branch.bulk.reason.open_pr")
	case branchworkflow.KeptMergeQueue:
		return locale.TrString("repo.branch.bulk.reason.merge_queue")
	case branchworkflow.KeptBase:
		return locale.TrString("repo.branch.bulk.reason.base")
	case repo_service.KeptNewCommits:
		return locale.TrString("repo.branch.bulk.reason.new_commits")
	case repo_service.KeptPermission:
		return locale.TrString("repo.branch.bulk.reason.permission")
	case repo_service.KeptNotFound:
		return locale.TrString("repo.branch.bulk.reason.not_found")
	}
	return locale.TrString("repo.branch.bulk.reason.error")
}

// DeleteSelectedBranchesPreview answers, as JSON, exactly which branches "select all matching" would delete now: at
// most MaxDeleteMergedBranches, with how many there are in all and how many matching branches are kept.
func DeleteSelectedBranchesPreview(ctx *context.Context) {
	f, ok := branchFilterFromForm(ctx)
	if !ok {
		return
	}
	model, err := branchworkflow.GetEffectiveModel(ctx, ctx.Repo.Repository)
	if err != nil {
		ctx.ServerError("GetEffectiveModel", err)
		return
	}
	q, ok := branchQueryOf(ctx, f, model)
	if !ok {
		return
	}
	found, err := repo_service.FindDeletableBranches(ctx, ctx.Repo.Repository, q, repo_service.MaxDeleteMergedBranches)
	if err != nil {
		ctx.ServerError("FindDeletableBranches", err)
		return
	}
	items := make([]map[string]string, 0, len(found.Branches))
	for _, b := range found.Branches {
		items = append(items, map[string]string{"name": b.Name, "commit": b.Commit})
	}
	ctx.JSON(http.StatusOK, map[string]any{"branches": items, "total": found.Total, "kept": found.Kept, "max": repo_service.MaxDeleteMergedBranches})
}

// DeleteSelectedBranchesPost deletes the branches of the confirm dialog ("<commit>:<name>", the commit the doer
// saw). Each one is decided again; the result says what was deleted and what was kept and why.
func DeleteSelectedBranchesPost(ctx *context.Context) {
	back := ctx.Repo.RepoLink + "/branches"
	var selected []repo_service.SelectedBranch
	var names []string
	for _, v := range ctx.FormStrings("branch") {
		commit, name, ok := strings.Cut(v, ":")
		if !ok {
			commit, name = "", v
		}
		selected = append(selected, repo_service.SelectedBranch{Name: name, Commit: commit})
		names = append(names, name)
	}
	names, err := repo_service.CheckSelectedBranchNames(names, repo_service.MaxDeleteMergedBranches)
	if err != nil {
		ctx.Flash.Error(ctx.Tr("repo.branch.bulk.invalid", repo_service.MaxDeleteMergedBranches))
		ctx.Redirect(back)
		return
	}
	if len(names) > bulkConfirmAbove && !strings.EqualFold(strings.TrimSpace(ctx.FormString("confirm_name")), ctx.Repo.Repository.FullName()) {
		ctx.Flash.Error(ctx.Tr("repo.branch.bulk.confirm_mismatch"))
		ctx.Redirect(back)
		return
	}
	selected = slices.DeleteFunc(selected, func(b repo_service.SelectedBranch) bool { return !slices.Contains(names, b.Name) })
	results, err := repo_service.DeleteSelectedBranches(ctx, ctx.Doer, ctx.Repo.Repository, ctx.Repo.GitRepo, selected)
	if err != nil && results == nil {
		ctx.ServerError("DeleteSelectedBranches", err)
		return
	}
	var deleted []string
	var kept []string
	for _, r := range results {
		if r.Reason == "" {
			deleted = append(deleted, r.Name)
		} else {
			kept = append(kept, html.EscapeString(r.Name)+": "+html.EscapeString(branchReasonText(ctx.Locale, r.Reason)))
		}
	}
	if len(deleted) > 0 {
		link := url.Values{"deleted": {"1"}, "selected": deleted[:min(len(deleted), maxPreselected)]}
		ctx.Flash.Success(ctx.Locale.TrPluralString(len(deleted), "repo.branch.bulk.done", len(deleted),
			template.HTML(fmt.Sprintf(`<a href="%s?%s">%s</a>`, html.EscapeString(back), html.EscapeString(link.Encode()), ctx.Locale.TrString("repo.branch.bulk.show_deleted"))),
			RestoreText(ctx)))
	}
	if len(kept) > 0 {
		listed := strings.Join(kept[:min(len(kept), maxReportedBranches)], "; ")
		if more := len(kept) - maxReportedBranches; more > 0 {
			listed += "; " + html.EscapeString(ctx.Locale.TrString("repo.branch.bulk.and_more", more))
		}
		msg := ctx.Locale.TrPluralString(len(kept), "repo.branch.bulk.kept", len(kept), template.HTML(listed))
		if len(deleted) == 0 {
			ctx.Flash.Error(ctx.Locale.TrString("repo.branch.bulk.nothing_deleted") + " " + string(msg))
		} else {
			ctx.Flash.Warning(msg)
		}
	}
	ctx.Redirect(back)
}

// RestoreSelectedBranchesPost restores the deleted branches ticked on the Deleted filter, each as the single restore
// does, and reports how many came back.
func RestoreSelectedBranchesPost(ctx *context.Context) {
	back := ctx.Repo.RepoLink + "/branches?deleted=1"
	ids := ctx.FormStrings("branch_id")
	if len(ids) == 0 || len(ids) > repo_service.MaxDeleteMergedBranches {
		ctx.Flash.Error(ctx.Tr("repo.branch.bulk.invalid", repo_service.MaxDeleteMergedBranches))
		ctx.Redirect(back)
		return
	}
	if repo_service.PersonalRepoLocked(ctx, ctx.Repo.Repository) {
		ctx.Flash.Error(ctx.Tr("repo.personal_repos.limit_reached_short"))
		ctx.Redirect(back)
		return
	}
	restored, failed := 0, []string{}
	for _, v := range ids {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			continue
		}
		if name, errMsg := restoreDeletedBranch(ctx, id, v); errMsg != "" {
			failed = append(failed, html.EscapeString(name))
		} else {
			restored++
		}
	}
	if restored > 0 {
		ctx.Flash.Success(ctx.Locale.TrPluralString(restored, "repo.branch.bulk.restored", restored))
	}
	if len(failed) > 0 {
		ctx.Flash.Error(ctx.Locale.TrPluralString(len(failed), "repo.branch.bulk.restore_failed", len(failed), template.HTML(strings.Join(failed[:min(len(failed), maxReportedBranches)], ", "))))
	}
	ctx.Redirect(back)
}
