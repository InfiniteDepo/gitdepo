// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"

	actions_model "forgejo.org/models/actions"
	org_model "forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/util"
)

// SetEnvironmentReviewers makes the users and teams the required reviewers of the environment (at most
// actions_model.MaxEnvironmentReviewers together). A user is an existing individual account; a team belongs to the
// organization that owns the repository, no other.
func SetEnvironmentReviewers(ctx context.Context, e *actions_model.ActionEnvironment, userIDs, teamIDs []int64) error {
	repo, err := repo_model.GetRepositoryByID(ctx, e.RepoID)
	if err != nil {
		return err
	}
	reviewers := make([]actions_model.ActionEnvironmentReviewer, 0, len(userIDs)+len(teamIDs))
	for _, id := range userIDs {
		u, err := user_model.GetUserByID(ctx, id)
		if err != nil {
			return util.NewInvalidArgumentErrorf("unknown reviewer")
		} else if id <= 0 || !u.IsIndividual() {
			return util.NewInvalidArgumentErrorf("a reviewer is a user or a team")
		}
		reviewers = append(reviewers, actions_model.ActionEnvironmentReviewer{UserID: id})
	}
	for _, id := range teamIDs {
		team, err := org_model.GetTeamByID(ctx, id)
		if err != nil || team.OrgID != repo.OwnerID {
			return util.NewInvalidArgumentErrorf("unknown reviewer team") // the same for a team of another organization
		}
		reviewers = append(reviewers, actions_model.ActionEnvironmentReviewer{TeamID: id})
	}
	return actions_model.ReplaceEnvironmentReviewers(ctx, e, reviewers)
}
