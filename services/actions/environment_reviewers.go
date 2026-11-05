// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	org_model "forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	"forgejo.org/modules/util"
)

// errUnknownReviewer is the one answer for a reviewer that is missing, hidden from the doer or of the wrong type, so the
// list is no way to learn about accounts.
var errUnknownReviewer = util.NewInvalidArgumentErrorf("unknown reviewer")

// SaveEnvironment saves the rules of e with the users and teams as its required reviewers (at most
// actions_model.MaxEnvironmentReviewers together) in one transaction, and reports if it created it. With e.ID 0 it
// creates the environment of the repository named e.Name, or, when that name exists ignoring case, updates that one
// (keeping its name). A user is an individual account the doer can see; a team belongs to the organization that owns
// the repository, no other. The rules are the break-glass of a review, so only the doer's own act changes them
// (audit_model.ErrNotOwnAct otherwise). After an update the jobs that wait for the environment are decided again by
// the new rules.
func SaveEnvironment(ctx context.Context, doer *user_model.User, e *actions_model.ActionEnvironment, userIDs, teamIDs []int64) (bool, error) {
	if err := audit_model.CheckOwnAct(ctx); err != nil {
		return false, err
	}
	repo, err := repo_model.GetRepositoryByID(ctx, e.RepoID)
	if err != nil {
		return false, err
	}
	reviewers := make([]actions_model.ActionEnvironmentReviewer, 0, len(userIDs)+len(teamIDs))
	for _, id := range userIDs {
		u, err := user_model.GetUserByID(ctx, id)
		if user_model.IsErrUserNotExist(err) || (err == nil && (id <= 0 || !u.IsIndividual() || !user_model.IsUserVisibleToViewer(ctx, u, doer))) {
			return false, errUnknownReviewer
		} else if err != nil {
			return false, err
		}
		reviewers = append(reviewers, actions_model.ActionEnvironmentReviewer{UserID: id})
	}
	for _, id := range teamIDs {
		team, err := org_model.GetTeamByID(ctx, id)
		if org_model.IsErrTeamNotExist(err) || (err == nil && team.OrgID != repo.OwnerID) {
			return false, errUnknownReviewer
		} else if err != nil {
			return false, err
		}
		reviewers = append(reviewers, actions_model.ActionEnvironmentReviewer{TeamID: id})
	}
	if e.ID == 0 {
		stored, err := actions_model.GetRepoEnvironmentByName(ctx, e.RepoID, e.Name)
		if errors.Is(err, actions_model.ErrEnvironmentNotFound) {
			if err = actions_model.CreateEnvironment(ctx, e, reviewers); !errors.Is(err, actions_model.ErrEnvironmentExists) {
				return err == nil, err
			}
			stored, err = actions_model.GetRepoEnvironmentByName(ctx, e.RepoID, e.Name) // created by a concurrent request
		}
		if err != nil {
			return false, err
		}
		e.ID, e.Name = stored.ID, stored.Name
	}
	if err := actions_model.UpdateEnvironment(ctx, e, reviewers); err != nil {
		return false, err
	}
	emitEnvironmentRuns(ctx, e)
	return false, nil
}

// emitEnvironmentRuns queues the gate for the runs that have a job of the environment no runner took yet, after a
// change of its rules has committed, so those jobs are decided by the rules as they are now (a removed review releases
// them, a new one holds them) and don't wait for another event. It runs outside any transaction, after the change
// committed, so a failure here is logged and doesn't fail the change: the jobs are then decided at the next event of
// their run, or by the cron tasks (a wait timer that ends, a review that times out).
func emitEnvironmentRuns(ctx context.Context, e *actions_model.ActionEnvironment) {
	jobs, err := actions_model.FindUnpickedEnvironmentJobs(ctx, e.RepoID, e.ID)
	if err != nil {
		log.Error("FindUnpickedEnvironmentJobs after a change of environment %d: %v", e.ID, err)
		return
	}
	runs := map[int64]bool{}
	for _, job := range jobs {
		if runs[job.RunID] {
			continue
		}
		runs[job.RunID] = true
		if err := EmitJobsIfReady(job.RunID); err != nil {
			log.Error("EmitJobsIfReady for run %d after a change of environment %d: %v", job.RunID, e.ID, err)
		}
	}
}
