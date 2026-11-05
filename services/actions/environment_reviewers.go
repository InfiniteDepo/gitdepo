// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"slices"

	actions_model "forgejo.org/models/actions"
	org_model "forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	"forgejo.org/modules/log"
	"forgejo.org/modules/util"
	"forgejo.org/services/accessreport"
)

// Refusals of a list of reviewers. ErrUnknownReviewer is the one answer for a reviewer that is missing, hidden from
// the doer or of the wrong type, and ErrReviewerNotMember for a user without a membership path to the repository
// whatever their account, so the list is no way to learn about accounts.
var (
	ErrUnknownReviewer   = util.NewInvalidArgumentErrorf("unknown reviewer")
	ErrReviewerNotMember = util.NewInvalidArgumentErrorf("a reviewer is the owner, a member of a team of the repository or a collaborator")
	ErrTooManyReviewers  = util.NewInvalidArgumentErrorf("too many reviewers")
	ErrReviewerTwice     = util.NewInvalidArgumentErrorf("a reviewer is listed once")
)

// SaveEnvironment saves the rules of e with the users and teams as its required reviewers (at most
// actions_model.MaxEnvironmentReviewers together) in one transaction, and reports if it created it. With e.ID 0 it
// creates the environment of the repository named e.Name, or, when that name exists ignoring case, updates that one
// (keeping its name). A user is an individual account the doer can see; a team belongs to the organization that owns
// the repository, no other. The rules are the break-glass of a review, so only the doer's own act changes them
// (audit_model.ErrNotOwnAct otherwise). After an update the jobs that wait for the environment are decided again by
// the new rules.
func SaveEnvironment(ctx context.Context, doer *user_model.User, e *actions_model.ActionEnvironment, userIDs, teamIDs []int64) (bool, error) {
	reviewers, err := environmentReviewers(ctx, doer, e, userIDs, teamIDs)
	if err != nil {
		return false, err
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

// CreateEnvironment creates the environment e.Name of the repository with the rules and reviewers of e as
// SaveEnvironment does, but never changes one that exists: a name that is taken ignoring case is
// actions_model.ErrEnvironmentExists.
func CreateEnvironment(ctx context.Context, doer *user_model.User, e *actions_model.ActionEnvironment, userIDs, teamIDs []int64) error {
	reviewers, err := environmentReviewers(ctx, doer, e, userIDs, teamIDs)
	if err != nil {
		return err
	}
	return actions_model.CreateEnvironment(ctx, e, reviewers)
}

// environmentReviewers checks the list and turns the IDs into the reviewers of e (the model writers check that the
// change is the doer's own act): a user is an individual account the doer can see with a membership path to the
// repository (memberPath), a team belongs to the organization that owns the repository. Only
// entries the environment doesn't list yet are checked: keeping a listed one reveals nothing new, and one whose user
// or team was deleted or hidden meanwhile must not block every other change (it stays listed until removed, and can't
// approve, so the gate stays closed).
func environmentReviewers(ctx context.Context, doer *user_model.User, e *actions_model.ActionEnvironment, userIDs, teamIDs []int64) ([]actions_model.ActionEnvironmentReviewer, error) {
	// the size of the list and duplicates are checked before any lookup, so a long list costs nothing
	if len(userIDs)+len(teamIDs) > actions_model.MaxEnvironmentReviewers {
		return nil, ErrTooManyReviewers
	}
	for _, ids := range [][]int64{userIDs, teamIDs} {
		if len(slices.Compact(slices.Sorted(slices.Values(ids)))) != len(ids) {
			return nil, ErrReviewerTwice
		}
	}
	repo, err := repo_model.GetRepositoryByID(ctx, e.RepoID)
	if err != nil {
		return nil, err
	}
	stored := map[string]bool{}
	id := e.ID
	if id == 0 { // saved by name: the environment of that name, if there is one
		if s, err := actions_model.GetRepoEnvironmentByName(ctx, e.RepoID, e.Name); err == nil {
			id = s.ID
		} else if !errors.Is(err, actions_model.ErrEnvironmentNotFound) {
			return nil, err
		}
	}
	if id != 0 {
		rs, err := actions_model.FindEnvironmentReviewers(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			stored[r.Key()] = true
		}
	}
	reviewers := make([]actions_model.ActionEnvironmentReviewer, 0, len(userIDs)+len(teamIDs))
	var newUserIDs []int64
	for _, id := range userIDs {
		r := actions_model.ActionEnvironmentReviewer{UserID: id}
		if !stored[r.Key()] {
			if id <= 0 {
				return nil, ErrUnknownReviewer
			}
			newUserIDs = append(newUserIDs, id)
		}
		reviewers = append(reviewers, r)
	}
	if len(newUserIDs) > 0 {
		users, err := user_model.GetUsersByIDs(ctx, newUserIDs)
		if err != nil {
			return nil, err
		}
		visible, err := user_model.VisibleToViewer(ctx, users, doer)
		if err != nil {
			return nil, err
		}
		found := 0
		for _, u := range users {
			if u.IsIndividual() && !u.IsTrashed() && visible.Contains(u.ID) { // as GetUserByID, which hides a tombstone
				found++
			}
		}
		if found != len(container.SetOf(newUserIDs...)) {
			return nil, ErrUnknownReviewer
		}
		// only who relates to the repository can be listed, whoever the doer: anyone else is refused with one answer,
		// so a list never tells about the account of a stranger
		rows, err := accessreport.Compute(ctx, accessreport.Options{RepoIDs: []int64{repo.ID}, Users: newUserIDs, RepoPermission: true})
		if err != nil {
			return nil, err
		}
		members := container.Set[int64]{}
		for _, row := range rows {
			if row.User != nil && memberPath(row) {
				members.Add(row.User.ID)
			}
		}
		for _, id := range newUserIDs {
			if !members.Contains(id) {
				return nil, ErrReviewerNotMember
			}
		}
	}
	return checkReviewerTeams(ctx, repo, stored, teamIDs, reviewers)
}

// checkReviewerTeams adds the teams to the reviewers: a team not listed yet must belong to the organization that owns
// the repository.
func checkReviewerTeams(ctx context.Context, repo *repo_model.Repository, stored map[string]bool, teamIDs []int64, reviewers []actions_model.ActionEnvironmentReviewer) ([]actions_model.ActionEnvironmentReviewer, error) {
	for _, id := range teamIDs {
		r := actions_model.ActionEnvironmentReviewer{TeamID: id}
		if !stored[r.Key()] {
			team, err := org_model.GetTeamByID(ctx, id)
			if org_model.IsErrTeamNotExist(err) || (err == nil && team.OrgID != repo.OwnerID) {
				return nil, ErrUnknownReviewer
			} else if err != nil {
				return nil, err
			}
		}
		reviewers = append(reviewers, r)
	}
	return reviewers, nil
}

// emitEnvironmentRuns queues the gate for the runs that have a job of the environment no runner took yet, after a
// change of its rules has committed, so those jobs are decided by the rules as they are now (a removed review releases
// them, a new one holds them) and don't wait for another event. It runs outside any transaction, after the change
// committed, so a failure here is logged and doesn't fail the change: the jobs are then decided by the next tick of
// StartDueDeployments, which finds the deployments that wait under rules changed since.
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
