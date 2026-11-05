// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"fmt"
	"slices"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/modules/util"

	"xorm.io/builder"
)

// MaxEnvironmentReviewers is how many users and teams an environment can list.
const MaxEnvironmentReviewers = 6

// ActionEnvironmentReviewer is one required reviewer of an environment: a user, or a team of the organization that
// owns the repository. Exactly one of UserID and TeamID is set. Who may review is decided when somebody reviews, not
// here: a team member is read at that time.
type ActionEnvironmentReviewer struct {
	ID            int64
	EnvironmentID int64 `xorm:"INDEX UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
	UserID        int64 `xorm:"UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
	TeamID        int64 `xorm:"UNIQUE(environment_user_team) NOT NULL DEFAULT 0"`
}

func init() {
	db.RegisterModel(new(ActionEnvironmentReviewer))
}

// Key is how the audit log names the reviewer: "user:<id>" or "team:<id>".
func (r *ActionEnvironmentReviewer) Key() string {
	if r.TeamID > 0 {
		return fmt.Sprintf("team:%d", r.TeamID)
	}
	return fmt.Sprintf("user:%d", r.UserID)
}

// reviewerKeys returns the sorted keys of the reviewers.
func reviewerKeys(reviewers []*ActionEnvironmentReviewer) []string {
	keys := make([]string, 0, len(reviewers))
	for _, r := range reviewers {
		keys = append(keys, r.Key())
	}
	slices.Sort(keys)
	return keys
}

// FindEnvironmentReviewers lists the reviewers of the environment, users first.
func FindEnvironmentReviewers(ctx context.Context, environmentID int64) ([]*ActionEnvironmentReviewer, error) {
	var reviewers []*ActionEnvironmentReviewer
	return reviewers, db.GetEngine(ctx).Where("environment_id = ?", environmentID).OrderBy("team_id, user_id").Find(&reviewers)
}

// ReplaceEnvironmentReviewers makes reviewers the whole list of the environment, sets whether the environment
// requires reviews (it does when the list is not empty) and records the change. It checks only the shape of the list (at
// most MaxEnvironmentReviewers, each entry a user or a team, no duplicate); the caller checks that they exist and that a
// team belongs to the owner of the repository. Editing the list is how the rule is changed, also to none at all.
func ReplaceEnvironmentReviewers(ctx context.Context, e *ActionEnvironment, reviewers []ActionEnvironmentReviewer) error {
	if len(reviewers) > MaxEnvironmentReviewers {
		return util.NewInvalidArgumentErrorf("too many reviewers")
	}
	keys := make([]string, 0, len(reviewers))
	for _, r := range reviewers {
		if (r.UserID > 0) == (r.TeamID > 0) || r.UserID < 0 || r.TeamID < 0 {
			return util.NewInvalidArgumentErrorf("a reviewer is a user or a team")
		}
		if slices.Contains(keys, r.Key()) {
			return util.NewInvalidArgumentErrorf("a reviewer is listed once")
		}
		keys = append(keys, r.Key())
	}
	slices.Sort(keys)
	required := len(keys) > 0
	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := LockEnvironment(ctx, e.RepoID, e.ID); err != nil { // concurrent edits and a delete run in order
			return err
		}
		stored, err := GetRepoEnvironmentByID(ctx, e.RepoID, e.ID)
		if err != nil {
			return err
		}
		before, err := FindEnvironmentReviewers(ctx, stored.ID)
		if err != nil {
			return err
		}
		old := reviewerKeys(before)
		if slices.Equal(old, keys) && stored.ReviewsRequired == required {
			return nil
		}
		if _, err := db.GetEngine(ctx).Where("environment_id = ?", stored.ID).Delete(new(ActionEnvironmentReviewer)); err != nil {
			return err
		}
		for _, r := range reviewers {
			if err := db.Insert(ctx, &ActionEnvironmentReviewer{EnvironmentID: stored.ID, UserID: r.UserID, TeamID: r.TeamID}); err != nil {
				return err
			}
		}
		if _, err := db.Exec(ctx, "UPDATE `action_environment` SET reviews_required = ? WHERE id = ?", required, stored.ID); err != nil {
			return err
		}
		return recordEnvironment(ctx, audit_model.LevelActions{Repo: "repo.actions_env.updated"}, stored,
			audit_model.Changes(map[string]any{"reviewers": old, "reviews_required": stored.ReviewsRequired}, map[string]any{"reviewers": keys, "reviews_required": required}))
	})
}

// RemoveReviewers removes the reviewer rows that cond selects (UserReviewerCond and TeamReviewerCond for a deleted
// user or team, ForeignTeamReviewerCond after a transfer) and records one change of rules per environment, in the
// caller's transaction. It does not clear ReviewsRequired: an
// environment that lost all its reviewers this way holds its deployments until someone edits its rules.
func RemoveReviewers(ctx context.Context, cond builder.Cond) error {
	var rows []*ActionEnvironmentReviewer
	find := func() error {
		rows = rows[:0]
		return db.GetEngine(ctx).Where(cond).OrderBy("environment_id, id").Find(&rows)
	}
	if err := find(); err != nil {
		return err
	}
	// like every write of the reviewers: lock each environment (in ascending order), then read its rows again, so an
	// edit that committed first isn't recorded as a removal that didn't happen
	locked := map[int64]bool{}
	for _, r := range rows {
		if locked[r.EnvironmentID] {
			continue
		}
		locked[r.EnvironmentID] = true
		if env, has, err := db.GetByID[ActionEnvironment](ctx, r.EnvironmentID); err != nil {
			return err
		} else if has {
			if err := LockEnvironment(ctx, env.RepoID, env.ID); err != nil && !errors.Is(err, ErrEnvironmentNotFound) {
				return err
			}
		}
	}
	if len(locked) > 0 {
		if err := find(); err != nil {
			return err
		}
	}
	byEnv := map[int64][]*ActionEnvironmentReviewer{}
	var order []int64
	for _, r := range rows {
		if _, ok := byEnv[r.EnvironmentID]; !ok {
			order = append(order, r.EnvironmentID)
		}
		byEnv[r.EnvironmentID] = append(byEnv[r.EnvironmentID], r)
	}
	for _, envID := range order {
		env, has, err := db.GetByID[ActionEnvironment](ctx, envID)
		if err != nil {
			return err
		}
		if has {
			if err := recordEnvironment(ctx, audit_model.LevelActions{Repo: "repo.actions_env.updated"}, env,
				map[string]any{"reviewers_removed": reviewerKeys(byEnv[envID])}); err != nil {
				return err
			}
		}
		ids := make([]int64, 0, len(byEnv[envID]))
		for _, r := range byEnv[envID] {
			ids = append(ids, r.ID)
		}
		if _, err := db.GetEngine(ctx).In("id", ids).Delete(new(ActionEnvironmentReviewer)); err != nil {
			return err
		}
	}
	return nil
}

// UserReviewerCond selects the rows of a user, TeamReviewerCond those of a team.
func UserReviewerCond(userID int64) builder.Cond { return builder.Eq{"user_id": userID} }
func TeamReviewerCond(teamID int64) builder.Cond { return builder.Eq{"team_id": teamID} }

// ForeignTeamReviewerCond selects the team rows of the repository's environments whose team does not belong to the
// organization ownerID.
func ForeignTeamReviewerCond(repoID, ownerID int64) builder.Cond {
	return builder.And(
		builder.Gt{"team_id": 0},
		builder.In("environment_id", builder.Select("id").From("action_environment").Where(builder.Eq{"repo_id": repoID})),
		builder.NotIn("team_id", builder.Select("id").From("team").Where(builder.Eq{"org_id": ownerID})),
	)
}
