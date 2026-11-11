// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"slices"

	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/unit"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/context"
)

// issueBranch is a branch of the issue's Development section with the newest pull request from it, if the viewer may
// read pull requests (State is "open", "merged" or "closed").
type issueBranch struct {
	Name      string
	PullIndex int64
	State     string
}

// linkedPulls pairs each branch with its newest pull request in this repository. One query for all branches.
func linkedPulls(ctx *context.Context, names []string) ([]issueBranch, error) {
	list := make([]issueBranch, len(names))
	for i, n := range names {
		list[i].Name = n
	}
	repo := ctx.Repo.Repository
	if len(names) == 0 || !ctx.Repo.CanRead(unit.TypePullRequests) {
		return list, nil
	}
	var prs issues_model.PullRequestList
	if err := db.GetEngine(ctx).Where("head_repo_id = ? AND base_repo_id = ? AND flow = ?", repo.ID, repo.ID, issues_model.PullRequestFlowGithub).In("head_branch", names).Find(&prs); err != nil {
		return nil, err
	}
	if _, err := prs.LoadIssues(ctx); err != nil {
		return nil, err
	}
	for _, pr := range prs {
		i := slices.IndexFunc(list, func(b issueBranch) bool { return b.Name == pr.HeadBranch })
		if i < 0 || pr.Issue == nil || pr.Issue.Index < list[i].PullIndex {
			continue
		}
		list[i].PullIndex = pr.Issue.Index
		switch {
		case pr.HasMerged:
			list[i].State = "merged"
		case pr.Issue.IsClosed:
			list[i].State = "closed"
		default:
			list[i].State = "open"
		}
	}
	return list, nil
}

// prepareIssueBranches sets the Development section of the issue sidebar: the branches that carry the issue's number
// and the suggestion for a new one. Branch names are code: a viewer who can't read the code gets nothing (not an
// empty section), and creating needs write access to the code.
func prepareIssueBranches(ctx *context.Context, issue *issues_model.Issue) {
	repo := ctx.Repo.Repository
	if issue.IsPull || repo.IsEmpty || !ctx.Repo.CanRead(unit.TypeCode) {
		return
	}
	model, err := branchworkflow.GetEffectiveModel(ctx, repo)
	if err != nil {
		ctx.ServerError("GetEffectiveModel", err)
		return
	}
	linked, err := branchworkflow.LinkedBranches(ctx, repo, model.Model, issue.Index)
	if err != nil {
		ctx.ServerError("LinkedBranches", err)
		return
	}
	pulls, err := linkedPulls(ctx, linked)
	if err != nil {
		ctx.ServerError("linkedPulls", err)
		return
	}
	ctx.Data["IssueBranches"] = pulls
	ctx.Data["IssueCanCompare"] = repo.AllowsPulls(ctx) && ctx.Repo.CanRead(unit.TypePullRequests)
	ctx.Data["ShowIssueDevelopment"] = true
	if !ctx.Repo.CanCreateBranch() || ctx.Repo.PersonalRepoLocked || repo.IsArchived || repo.IsMirror {
		return
	}
	if !PrepareBranchDialog(ctx, model) {
		return
	}
	choices := ctx.Data["BranchDialog"].(branchworkflow.CreateChoices)
	if err := issue.LoadLabels(ctx); err != nil {
		ctx.ServerError("LoadLabels", err)
		return
	}
	labels := make([]string, 0, len(issue.Labels))
	for _, l := range issue.Labels {
		labels = append(labels, l.Name)
	}
	s, ok, err := branchworkflow.SuggestIssueBranch(ctx, repo, ctx.Doer, choices, issue.Index, issue.Title, labels)
	if err != nil {
		ctx.ServerError("SuggestIssueBranch", err)
		return
	}
	if ok {
		ctx.Data["IssueBranchSuggestion"] = s
	}
	ctx.Data["IssueBranchFrom"] = choices.Development
	for _, t := range choices.Types {
		if t.Name == s.Type {
			ctx.Data["IssueBranchFrom"] = t.Base
		}
	}
}
