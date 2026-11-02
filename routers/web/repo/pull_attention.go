// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"errors"

	issues_model "forgejo.org/models/issues"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
	pull_service "forgejo.org/services/pull"
)

// UpdatePullAttention adds a user to the attention set of a pull request or removes one
func UpdatePullAttention(ctx *context.Context) {
	issue := getPullTaskIssue(ctx)
	if issue == nil {
		return
	}
	link := issue.Link() + "#pull-attention"
	if ctx.HasError() {
		ctx.Flash.Error(ctx.GetErrMsg())
		ctx.Redirect(link)
		return
	}
	form := web.GetForm(ctx).(*forms.PullAttentionForm)
	target, err := user_model.GetUserByName(ctx, form.UserName)
	if err == nil {
		if ctx.Params(":action") == "add" {
			err = pull_service.AddAttention(ctx, ctx.Doer, issue, ctx.Repo.Permission, target, form.Reason)
		} else {
			err = pull_service.RemoveAttention(ctx, ctx.Doer, issue, ctx.Repo.Permission, target)
		}
	}
	switch {
	case user_model.IsErrUserNotExist(err), errors.Is(err, util.ErrInvalidArgument):
		ctx.Flash.Error(ctx.Tr("repo.pulls.attention.invalid_user"))
	case errors.Is(err, util.ErrPermissionDenied):
		ctx.Flash.Error(ctx.Tr("repo.pulls.attention.not_allowed"))
	case err != nil:
		ctx.ServerError("UpdatePullAttention", err)
		return
	}
	ctx.Redirect(link)
}

// preparePullAttention sets the attention set of the pull request for its sidebar
func preparePullAttention(ctx *context.Context, issue *issues_model.Issue) {
	sets, err := issues_model.FindPullAttention(ctx, issue.ID)
	if err != nil {
		ctx.ServerError("FindPullAttention", err)
		return
	}
	ctx.Data["PullAttention"] = sets[issue.ID]
	ctx.Data["CanChangeAttention"] = ctx.IsSigned && pull_service.CanChangeAttention(ctx, ctx.Doer, issue, ctx.Repo.Permission)
	ctx.Data["CanRemoveAttention"] = ctx.IsSigned && pull_service.CanRemoveAttention(ctx, ctx.Doer, issue, ctx.Repo.Permission)
	if !ctx.IsSigned {
		return
	}
	// the reviewer candidates of the Reviewers menu, loaded only for those who may request reviews
	var extra []*user_model.User
	reviewers, _ := ctx.Data["Reviewers"].([]*repoReviewerSelection)
	for _, r := range reviewers {
		if r.User != nil {
			extra = append(extra, r.User)
		}
	}
	ctx.Data["AttentionCandidates"], err = pull_service.AttentionCandidates(ctx, ctx.Doer, issue, ctx.Repo.Permission, extra)
	if err != nil {
		ctx.ServerError("AttentionCandidates", err)
	}
}
