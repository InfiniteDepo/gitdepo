// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"slices"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	user_model "forgejo.org/models/user"
)

// DeploymentData holds what a page of deployments of one repository refers to, loaded with one query per table and
// only from that repository: a run, job or environment of another one is missing. Users holds the ghost for a user
// the doer can't see.
type DeploymentData struct {
	Jobs  map[int64]*actions_model.ActionRunJob
	Runs  map[int64]*actions_model.ActionRun
	Envs  map[int64]*actions_model.ActionEnvironment
	Users map[int64]*user_model.User
}

// LoadDeploymentData loads what the deployments of the repository refer to, for the doer.
func LoadDeploymentData(ctx context.Context, doer *user_model.User, repoID int64, ds []*actions_model.ActionDeployment) (*DeploymentData, error) {
	var jobIDs, runIDs, envIDs, userIDs []int64
	for _, d := range ds {
		jobIDs, runIDs, envIDs = append(jobIDs, d.JobID), append(runIDs, d.RunID), append(envIDs, d.EnvironmentID)
		userIDs = append(userIDs, d.TriggerUserID, d.ReviewedBy)
	}
	data := &DeploymentData{}
	var err error
	if data.Jobs, err = findColumns[actions_model.ActionRunJob](ctx, repoID, jobIDs, "id", "repo_id", "name"); err != nil {
		return nil, err
	}
	if data.Runs, err = findColumns[actions_model.ActionRun](ctx, repoID, runIDs, "id", "repo_id", "index", "title", "workflow_id"); err != nil {
		return nil, err
	}
	if data.Envs, err = findColumns[actions_model.ActionEnvironment](ctx, repoID, envIDs, "id", "repo_id", "name"); err != nil {
		return nil, err
	}
	data.Users, err = VisibleUsers(ctx, doer, userIDs)
	return data, err
}

// VisibleUsers loads the users of the IDs (0 left out), with the ghost for a user the doer can't see (e.g. a private
// account on a public repository).
func VisibleUsers(ctx context.Context, doer *user_model.User, ids []int64) (map[int64]*user_model.User, error) {
	ids = slices.DeleteFunc(slices.Compact(slices.Sorted(slices.Values(ids))), func(id int64) bool { return id == 0 })
	users, err := user_model.GetUsersByIDsWithBots(ctx, ids)
	if err != nil {
		return nil, err
	}
	for id, u := range users {
		if !user_model.IsUserVisibleToViewer(ctx, u, doer) {
			users[id] = user_model.NewGhostUser()
		}
	}
	return users, nil
}

// findColumns loads the rows of ids of the repository by ID with only the named columns (run and job rows carry large
// payloads).
func findColumns[T any](ctx context.Context, repoID int64, ids []int64, columns ...string) (map[int64]*T, error) {
	rows := map[int64]*T{}
	if ids = slices.Compact(slices.Sorted(slices.Values(ids))); len(ids) == 0 {
		return rows, nil
	}
	return rows, db.GetEngine(ctx).In("id", ids).And("repo_id = ?", repoID).Cols(columns...).Find(&rows)
}
