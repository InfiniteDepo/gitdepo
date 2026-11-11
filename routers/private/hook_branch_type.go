// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package private

import (
	"errors"
	"net/http"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/modules/git"
	"forgejo.org/modules/log"
	"forgejo.org/modules/private"
	"forgejo.org/modules/translation"
	"forgejo.org/services/branchworkflow"
)

// checkBranchType applies the branching model's "require a branch type" to a branch the push creates. If the name is
// refused it writes the response and returns false. exempt is true when only the pusher's exemption lets it through:
// the caller records that with recordBranchTypeExempt once every check of the ref has passed. A deploy key is never exempt.
func (ctx *preReceiveContext) checkBranchType(refFullName git.RefName) (exempt, ok bool) {
	repo := ctx.Repo.Repository
	branchName := refFullName.BranchName()
	exempt, err := branchworkflow.CheckNewBranch(ctx, repo, ctx.opts.UserID, ctx.opts.DeployKeyKeyID != 0, branchName)
	if refused, ok := errors.AsType[branchworkflow.ErrBranchTypeRequired](err); ok {
		ctx.refuse(http.StatusForbidden, "branch_type", refFullName.String(), refused.Text(translation.NewLocale("en-US")))
		return false, false
	}
	if err != nil {
		log.Error("Unable to check the branch type of %s in %-v: %v", branchName, repo, err)
		ctx.JSON(http.StatusInternalServerError, private.Response{Err: "Unable to check the branch type"})
		return false, false
	}
	return exempt, true
}

// recordBranchTypeExempt records an exempt branch creation; if it can't be recorded the push is refused. A later ref of
// the same push may still be refused, so the entry says "allowed", not "created".
func (ctx *preReceiveContext) recordBranchTypeExempt(refFullName git.RefName) {
	repo := ctx.Repo.Repository
	if err := branchworkflow.RecordNamingExempt(audit_model.WithActor(ctx, hookActor(ctx, repo, ctx.opts)), repo, refFullName.BranchName(), "push"); err != nil {
		log.Error("Unable to record the branch type exemption of %s in %-v: %v", refFullName.BranchName(), repo, err)
		ctx.JSON(http.StatusInternalServerError, private.Response{Err: "Unable to check the branch type"})
	}
}
