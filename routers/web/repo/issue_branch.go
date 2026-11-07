// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	issues_model "forgejo.org/models/issues"
	"forgejo.org/models/unit"
	"forgejo.org/services/branchworkflow"
	"forgejo.org/services/context"
)

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
	ctx.Data["IssueBranches"] = linked
	ctx.Data["ShowIssueDevelopment"] = true
	if !ctx.Repo.CanCreateBranch() || repo.IsArchived || repo.IsMirror {
		return
	}
	if !PrepareBranchDialog(ctx) {
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
