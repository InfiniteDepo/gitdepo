// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
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

// FindEnvironmentReviewers lists the reviewers of the environment, users first.
func FindEnvironmentReviewers(ctx context.Context, environmentID int64) ([]*ActionEnvironmentReviewer, error) {
	var reviewers []*ActionEnvironmentReviewer
	return reviewers, db.GetEngine(ctx).Where("environment_id = ?", environmentID).OrderBy("team_id, user_id").Find(&reviewers)
}

// HasEnvironmentReviewers tells if the environment lists a reviewer.
func HasEnvironmentReviewers(ctx context.Context, environmentID int64) (bool, error) {
	return db.Exist[ActionEnvironmentReviewer](ctx, builder.Eq{"environment_id": environmentID})
}

// ReplaceEnvironmentReviewers makes reviewers the whole list of the environment and records the change. It checks
// only the shape of the list (at most MaxEnvironmentReviewers, each entry a user or a team, no duplicate); the caller
// checks that they exist and that a team belongs to the owner of the repository.
func ReplaceEnvironmentReviewers(ctx context.Context, e *ActionEnvironment, reviewers []ActionEnvironmentReviewer) error {
	if len(reviewers) > MaxEnvironmentReviewers {
		return util.NewInvalidArgumentErrorf("too many reviewers")
	}
	keys := make([]string, 0, len(reviewers))
	for _, r := range reviewers {
		if (r.UserID > 0) == (r.TeamID > 0) || r.UserID < 0 || r.TeamID < 0 {
			return util.NewInvalidArgumentErrorf("a reviewer is a user or a team")
		}
		key := fmt.Sprintf("user:%d", r.UserID)
		if r.TeamID > 0 {
			key = fmt.Sprintf("team:%d", r.TeamID)
		}
		if slices.Contains(keys, key) {
			return util.NewInvalidArgumentErrorf("a reviewer is listed once")
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return db.WithTx(ctx, func(ctx context.Context) error {
		stored, err := GetRepoEnvironmentByID(ctx, e.RepoID, e.ID) // also the lock: a deleted environment is an error
		if err != nil {
			return err
		}
		before, err := FindEnvironmentReviewers(ctx, stored.ID)
		if err != nil {
			return err
		}
		old := make([]string, 0, len(before))
		for _, r := range before {
			if r.TeamID > 0 {
				old = append(old, fmt.Sprintf("team:%d", r.TeamID))
			} else {
				old = append(old, fmt.Sprintf("user:%d", r.UserID))
			}
		}
		slices.Sort(old)
		if slices.Equal(old, keys) {
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
		return recordEnvironment(ctx, audit_model.LevelActions{Repo: "repo.actions_env.updated"}, stored,
			audit_model.Changes(map[string]any{"reviewers": old}, map[string]any{"reviewers": keys}))
	})
}
